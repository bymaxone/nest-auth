/**
 * End-to-end authentication flow.
 *
 * Exercises the real HTTP routes registered by `AuthController` through a
 * fully-bootstrapped NestJS application. Each test issues real HTTP requests
 * via supertest and asserts on the actual response payload, status code, and
 * cookies — no controller methods are called directly.
 */

import type { INestApplication } from '@nestjs/common'
import request from 'supertest'

import { bootstrapTestApp } from './setup'

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('auth flow (E2E)', () => {
  // ---------------------------------------------------------------------------
  // Bearer mode
  // ---------------------------------------------------------------------------

  describe('bearer mode', () => {
    let app: INestApplication

    beforeEach(async () => {
      const bootstrap = await bootstrapTestApp({ tokenDelivery: 'bearer' })
      app = bootstrap.app
    })

    afterEach(async () => {
      await app.close()
    })

    // Verifies that POST /register returns a 201 with access + refresh tokens and the user object.
    it('should register a new user and return tokens', async () => {
      const res = await request(app.getHttpServer()).post('/register').send({
        email: 'alice@example.com',
        password: 'SuperSecret123!',
        name: 'Alice',
        tenantId: 'tenant-1'
      })

      expect(res.status).toBe(201)
      expect(res.body).toEqual(
        expect.objectContaining({
          accessToken: expect.any(String),
          refreshToken: expect.any(String),
          user: expect.objectContaining({
            email: 'alice@example.com',
            name: 'Alice',
            tenantId: 'tenant-1'
          })
        })
      )
      expect(res.body.user).not.toHaveProperty('passwordHash')
    })

    // Verifies that POST /login authenticates a registered user and returns fresh tokens.
    it('should log in with valid credentials and return tokens', async () => {
      // Arrange — pre-register the user.
      await request(app.getHttpServer()).post('/register').send({
        email: 'bob@example.com',
        password: 'AnotherSecret456!',
        name: 'Bob',
        tenantId: 'tenant-1'
      })

      // Act
      const res = await request(app.getHttpServer()).post('/login').send({
        email: 'bob@example.com',
        password: 'AnotherSecret456!',
        tenantId: 'tenant-1'
      })

      // Assert
      expect(res.status).toBe(200)
      expect(res.body).toEqual(
        expect.objectContaining({
          accessToken: expect.any(String),
          refreshToken: expect.any(String),
          user: expect.objectContaining({ email: 'bob@example.com' })
        })
      )
    })

    // Verifies that POST /refresh rotates tokens when given a valid refresh token in the body.
    it('should rotate tokens via /refresh with the refresh token in the body', async () => {
      const register = await request(app.getHttpServer()).post('/register').send({
        email: 'carol@example.com',
        password: 'CarolSecret789!',
        name: 'Carol',
        tenantId: 'tenant-1'
      })

      const oldAccessToken = register.body.accessToken as string
      const oldRefreshToken = register.body.refreshToken as string

      const res = await request(app.getHttpServer())
        .post('/refresh')
        .send({ refreshToken: oldRefreshToken })

      expect(res.status).toBe(200)
      expect(res.body.accessToken).toEqual(expect.any(String))
      expect(res.body.refreshToken).toEqual(expect.any(String))
      expect(res.body.refreshToken).not.toBe(oldRefreshToken)
      expect(res.body.accessToken).not.toBe(oldAccessToken)
    })

    // Verifies that GET /me returns the authenticated user when a valid bearer token is sent.
    it('should return the current user from /me when authenticated', async () => {
      const register = await request(app.getHttpServer()).post('/register').send({
        email: 'dave@example.com',
        password: 'DaveSecret321!',
        name: 'Dave',
        tenantId: 'tenant-1'
      })

      const accessToken = register.body.accessToken as string

      const res = await request(app.getHttpServer())
        .get('/me')
        .set('Authorization', `Bearer ${accessToken}`)

      expect(res.status).toBe(200)
      expect(res.body).toEqual(expect.objectContaining({ email: 'dave@example.com', name: 'Dave' }))
    })

    // Verifies that POST /logout succeeds for an authenticated bearer request.
    it('should log out an authenticated user', async () => {
      const register = await request(app.getHttpServer()).post('/register').send({
        email: 'eve@example.com',
        password: 'EveSecret654!',
        name: 'Eve',
        tenantId: 'tenant-1'
      })

      const accessToken = register.body.accessToken as string
      const refreshToken = register.body.refreshToken as string

      const res = await request(app.getHttpServer())
        .post('/logout')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ refreshToken })

      // Logout returns 204 No Content per AuthController.
      expect(res.status).toBe(204)
    })

    // Verifies that GET /me rejects a token that has been revoked via /logout.
    it('should reject /me with 401 after the access token is revoked by logout', async () => {
      const register = await request(app.getHttpServer()).post('/register').send({
        email: 'frank@example.com',
        password: 'FrankSecret987!',
        name: 'Frank',
        tenantId: 'tenant-1'
      })

      const accessToken = register.body.accessToken as string
      const refreshToken = register.body.refreshToken as string

      await request(app.getHttpServer())
        .post('/logout')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ refreshToken })

      const res = await request(app.getHttpServer())
        .get('/me')
        .set('Authorization', `Bearer ${accessToken}`)

      expect(res.status).toBe(401)
    })
  })

  // ---------------------------------------------------------------------------
  // Cookie mode
  // ---------------------------------------------------------------------------

  describe('cookie mode', () => {
    let app: INestApplication

    beforeEach(async () => {
      const bootstrap = await bootstrapTestApp({ tokenDelivery: 'cookie' })
      app = bootstrap.app
    })

    afterEach(async () => {
      await app.close()
    })

    // Verifies that POST /login in cookie mode returns 200 and Set-Cookie headers with HttpOnly + SameSite.
    it('should log in and return HttpOnly auth cookies', async () => {
      // Arrange — register first to persist a user. In cookie mode the response
      // body for register/login contains only `user` (no tokens) — tokens are
      // delivered via Set-Cookie headers.
      await request(app.getHttpServer()).post('/register').send({
        email: 'gary@example.com',
        password: 'GarySecret852!',
        name: 'Gary',
        tenantId: 'tenant-1'
      })

      // Act
      const res = await request(app.getHttpServer()).post('/login').send({
        email: 'gary@example.com',
        password: 'GarySecret852!',
        tenantId: 'tenant-1'
      })

      // Assert
      expect(res.status).toBe(200)
      const rawSetCookie = res.headers['set-cookie'] as string[] | string | undefined
      const cookieArray: string[] = Array.isArray(rawSetCookie)
        ? rawSetCookie
        : rawSetCookie !== undefined
          ? [rawSetCookie]
          : []

      expect(cookieArray.length).toBeGreaterThanOrEqual(2)
      const accessCookie = cookieArray.find((c) => c.startsWith('access_token='))
      const refreshCookie = cookieArray.find((c) => c.startsWith('refresh_token='))

      expect(accessCookie).toBeDefined()
      expect(refreshCookie).toBeDefined()
      // HttpOnly + SameSite are always present on auth cookies regardless of environment.
      expect(accessCookie).toMatch(/HttpOnly/i)
      expect(accessCookie).toMatch(/SameSite=Strict/i)
      expect(refreshCookie).toMatch(/HttpOnly/i)
      expect(refreshCookie).toMatch(/SameSite=Strict/i)

      // Body must contain the user but NOT the tokens (cookie mode).
      expect(res.body).toEqual(
        expect.objectContaining({ user: expect.objectContaining({ email: 'gary@example.com' }) })
      )
      expect(res.body).not.toHaveProperty('accessToken')
      expect(res.body).not.toHaveProperty('refreshToken')
    })

    // Verifies that GET /me returns 200 when cookies from a successful login are forwarded.
    it('should return the current user from /me using the auth cookies', async () => {
      await request(app.getHttpServer()).post('/register').send({
        email: 'hank@example.com',
        password: 'HankSecret741!',
        name: 'Hank',
        tenantId: 'tenant-1'
      })

      const login = await request(app.getHttpServer()).post('/login').send({
        email: 'hank@example.com',
        password: 'HankSecret741!',
        tenantId: 'tenant-1'
      })

      const rawSetCookie = login.headers['set-cookie'] as string[] | string | undefined
      const cookieArray: string[] = Array.isArray(rawSetCookie)
        ? rawSetCookie
        : rawSetCookie !== undefined
          ? [rawSetCookie]
          : []

      const res = await request(app.getHttpServer()).get('/me').set('Cookie', cookieArray)

      expect(res.status).toBe(200)
      expect(res.body).toEqual(expect.objectContaining({ email: 'hank@example.com' }))
    })
  })
})
