/**
 * End-to-end sessions flow.
 *
 * Exercises the real HTTP routes registered by `SessionController` through a
 * fully-bootstrapped NestJS application in bearer-token mode. The scenario
 * simulates a single user authenticating from three distinct devices, then
 * inspecting and revoking sessions through `GET /sessions`,
 * `DELETE /sessions/:id`, and `DELETE /sessions/all` — every step issues a
 * real HTTP request via supertest and asserts on the actual response.
 */

import type { INestApplication } from '@nestjs/common'
import request from 'supertest'

import { bootstrapTestApp } from './setup'

// ---------------------------------------------------------------------------
// Constants — distinct device User-Agent strings
// ---------------------------------------------------------------------------

/** Mac desktop User-Agent — used for the first login. */
const UA_MAC = 'Mozilla/5.0 (Mac)'

/** Linux desktop User-Agent — used for the second login. */
const UA_LINUX = 'Mozilla/5.0 (Linux X11)'

/** iPhone mobile User-Agent — used for the third login (the "current" session). */
const UA_IPHONE = 'Mozilla/5.0 (iPhone iOS)'

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('sessions flow (E2E)', () => {
  // ---------------------------------------------------------------------------
  // Scenario — three-device login → list → revoke one → revoke all
  //
  // Every step in this scenario depends on the previous one (register → 3
  // logins → list → revoke specific → list → revoke all → list), so all
  // shared state is mutated in `beforeAll` and across the chained `it()`
  // blocks. The shared variables below are intentionally reused — state IS
  // shared across these tests by design.
  // ---------------------------------------------------------------------------

  describe('three-device session lifecycle', () => {
    let app: INestApplication

    // Tokens produced by each of the three logins. The third login's tokens
    // act as the caller's "current" session for every subsequent assertion.
    let macAccessToken: string
    let macRefreshToken: string
    let linuxAccessToken: string
    let linuxRefreshToken: string
    let currentAccessToken: string
    let currentRefreshToken: string

    // Identifier of the non-current session that gets explicitly revoked
    // by the DELETE /sessions/:id step. Captured during the first list call.
    let revokedSessionHash: string

    // Shared state IS shared across the it() blocks below — each test
    // verifies one slice of the chained scenario set up in beforeAll
    // and continued by earlier it() blocks.
    beforeAll(async () => {
      const bootstrap = await bootstrapTestApp({ tokenDelivery: 'bearer' })
      app = bootstrap.app

      // Register the user once. With emailVerification.required: false (the
      // bootstrapTestApp default) registration immediately yields tokens AND
      // creates an active session for the registration request. To keep the
      // "three sessions from three devices" invariant clean, we immediately
      // logout the registration session so only the dedicated device logins
      // below contribute to the active session set.
      const register = await request(app.getHttpServer()).post('/register').send({
        email: 'multi-device@example.com',
        password: 'MultiDeviceSecret123!',
        name: 'Multi Device User',
        tenantId: 'tenant-1'
      })
      const registerAccessToken = register.body.accessToken as string
      const registerRefreshToken = register.body.refreshToken as string
      await request(app.getHttpServer())
        .post('/logout')
        .set('Authorization', `Bearer ${registerAccessToken}`)
        .send({ refreshToken: registerRefreshToken })

      // Login #1 — Mac. First session.
      const macLogin = await request(app.getHttpServer())
        .post('/login')
        .set('User-Agent', UA_MAC)
        .send({
          email: 'multi-device@example.com',
          password: 'MultiDeviceSecret123!',
          tenantId: 'tenant-1'
        })
      macAccessToken = macLogin.body.accessToken as string
      macRefreshToken = macLogin.body.refreshToken as string

      // Login #2 — Linux. Second session.
      const linuxLogin = await request(app.getHttpServer())
        .post('/login')
        .set('User-Agent', UA_LINUX)
        .send({
          email: 'multi-device@example.com',
          password: 'MultiDeviceSecret123!',
          tenantId: 'tenant-1'
        })
      linuxAccessToken = linuxLogin.body.accessToken as string
      linuxRefreshToken = linuxLogin.body.refreshToken as string

      // Login #3 — iPhone. Third session — treated as the caller's CURRENT
      // session for every subsequent request.
      const iphoneLogin = await request(app.getHttpServer())
        .post('/login')
        .set('User-Agent', UA_IPHONE)
        .send({
          email: 'multi-device@example.com',
          password: 'MultiDeviceSecret123!',
          tenantId: 'tenant-1'
        })
      currentAccessToken = iphoneLogin.body.accessToken as string
      currentRefreshToken = iphoneLogin.body.refreshToken as string
    })

    afterAll(async () => {
      await app.close()
    })

    // Verifies that all three logins produced distinct access + refresh token pairs.
    it('should produce three distinct token pairs from three device logins', () => {
      // Arrange — tokens were captured in beforeAll.

      // Act — no further action required; assertions run against captured state.

      // Assert — every token must be present and pairwise distinct so each
      // login truly identifies a unique session.
      expect(macAccessToken).toEqual(expect.any(String))
      expect(macRefreshToken).toEqual(expect.any(String))
      expect(linuxAccessToken).toEqual(expect.any(String))
      expect(linuxRefreshToken).toEqual(expect.any(String))
      expect(currentAccessToken).toEqual(expect.any(String))
      expect(currentRefreshToken).toEqual(expect.any(String))

      const refreshTokens = new Set([macRefreshToken, linuxRefreshToken, currentRefreshToken])
      expect(refreshTokens.size).toBe(3)
    })

    // Verifies that GET /sessions returns all three sessions and marks only the iPhone session as current.
    it('should list three sessions with isCurrent: true on exactly the third login', async () => {
      // Arrange — three logins were performed in beforeAll, the iPhone (3rd)
      // login's tokens act as the current session.

      // Act — call GET /sessions with the current bearer token AND forward
      // the current refresh token in the body so the server can mark the
      // caller's session as `isCurrent: true` (bearer mode reads refresh
      // tokens from the body).
      const res = await request(app.getHttpServer())
        .get('/sessions')
        .set('Authorization', `Bearer ${currentAccessToken}`)
        .send({ refreshToken: currentRefreshToken })

      // Assert
      expect(res.status).toBe(200)
      expect(Array.isArray(res.body)).toBe(true)
      const sessions = res.body as Array<{
        id: string
        sessionHash: string
        device: string
        isCurrent: boolean
      }>
      expect(sessions).toHaveLength(3)

      const currentSessions = sessions.filter((s) => s.isCurrent)
      expect(currentSessions).toHaveLength(1)
      expect(currentSessions[0]?.device).toMatch(/iOS/)

      // Capture a non-current session's hash for the next step. The session
      // hash is the full 64-char SHA-256 hex string accepted by DELETE /:id.
      const nonCurrent = sessions.find((s) => !s.isCurrent)
      expect(nonCurrent).toBeDefined()
      expect(nonCurrent?.sessionHash).toMatch(/^[0-9a-f]{64}$/)
      revokedSessionHash = nonCurrent!.sessionHash
    })

    // Verifies that DELETE /sessions/:id revokes a single non-current session and returns 204.
    it('should revoke a specific non-current session via DELETE /sessions/:id', async () => {
      // Arrange — `revokedSessionHash` was captured in the previous it().
      expect(revokedSessionHash).toMatch(/^[0-9a-f]{64}$/)

      // Act
      const res = await request(app.getHttpServer())
        .delete(`/sessions/${revokedSessionHash}`)
        .set('Authorization', `Bearer ${currentAccessToken}`)

      // Assert — controller declares HttpStatus.NO_CONTENT (204).
      expect(res.status).toBe(204)
    })

    // Verifies that GET /sessions returns only two sessions after one was explicitly revoked.
    it('should list two sessions after a single revocation', async () => {
      // Arrange — one of the three sessions was revoked in the previous it().

      // Act
      const res = await request(app.getHttpServer())
        .get('/sessions')
        .set('Authorization', `Bearer ${currentAccessToken}`)
        .send({ refreshToken: currentRefreshToken })

      // Assert — exactly two remaining sessions, and the revoked hash is gone.
      expect(res.status).toBe(200)
      const sessions = res.body as Array<{ sessionHash: string; isCurrent: boolean }>
      expect(sessions).toHaveLength(2)
      expect(sessions.map((s) => s.sessionHash)).not.toContain(revokedSessionHash)

      // Sanity — the iPhone (current) session must still be present.
      expect(sessions.filter((s) => s.isCurrent)).toHaveLength(1)
    })

    // Verifies that DELETE /sessions/all revokes every session except the caller's current one.
    it('should revoke every other session via DELETE /sessions/all', async () => {
      // Arrange — two sessions remain (iPhone + Mac OR Linux, depending on
      // which one was kept by the previous DELETE step).

      // Act — bearer mode requires the refresh token in the request body so
      // the server can identify the current session and exclude it from the
      // bulk revocation.
      const res = await request(app.getHttpServer())
        .delete('/sessions/all')
        .set('Authorization', `Bearer ${currentAccessToken}`)
        .send({ refreshToken: currentRefreshToken })

      // Assert — controller declares HttpStatus.NO_CONTENT (204).
      expect(res.status).toBe(204)
    })

    // Verifies that GET /sessions returns exactly one session marked as current after the bulk revocation.
    it('should list a single current session after bulk revocation', async () => {
      // Arrange — the bulk revocation in the previous it() removed every
      // session except the caller's current one.

      // Act
      const res = await request(app.getHttpServer())
        .get('/sessions')
        .set('Authorization', `Bearer ${currentAccessToken}`)
        .send({ refreshToken: currentRefreshToken })

      // Assert — only the iPhone (current) session remains.
      expect(res.status).toBe(200)
      const sessions = res.body as Array<{ device: string; isCurrent: boolean }>
      expect(sessions).toHaveLength(1)
      expect(sessions[0]?.isCurrent).toBe(true)
      expect(sessions[0]?.device).toMatch(/iOS/)

      // Sanity — the previously-revoked tokens must have no representation
      // here. We assert that explicitly by ensuring the lone session is the
      // current one and that the Mac/Linux refresh tokens differ from the
      // current refresh token.
      expect(macRefreshToken).not.toBe(currentRefreshToken)
      expect(linuxRefreshToken).not.toBe(currentRefreshToken)
    })
  })
})
