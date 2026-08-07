/**
 * End-to-end coverage for the platform administrator HTTP surface.
 *
 * The library mounts a dedicated `PlatformAuthController` (under
 * `controllers.platform: true` + `platform.enabled: true`) that is fully
 * isolated from the dashboard controllers — distinct repository, distinct
 * `JwtPlatformGuard`, distinct token type. The dashboard suite at
 * `test/e2e/auth-flow.e2e-spec.ts` covers regular users only and the platform
 * routes were entirely uncovered at the HTTP layer prior to this spec.
 *
 * Scenarios:
 *   1. Login + /me with bearer tokens (issued exclusively from `/platform/login`).
 *   2. Refresh rotation — old refresh token replaced with a fresh pair.
 *   3. Logout — JTI blacklisted; subsequent /me returns 401.
 *   4. Revoke-all — every active refresh token invalidated in one call.
 *   5. Cross-context rejection — a dashboard access token submitted to a
 *      platform route is rejected with `PLATFORM_AUTH_REQUIRED`.
 */

import type { INestApplication } from '@nestjs/common'
import request from 'supertest'

import { PasswordService } from '../../src/server/services/password.service'
import type { BootstrappedTestApp } from './setup'
import { bootstrapTestApp } from './setup'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PLATFORM_EMAIL = 'admin@platform.test'
const PLATFORM_PASSWORD = 'PlatformPass123!'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Boots an app with both the platform and dashboard controller surfaces and
 * pre-seeds a SUPER_ADMIN platform user. Uses the lib's own
 * {@link PasswordService} to hash the password so the format and scrypt
 * parameters match what `compare` will use during login.
 */
async function bootstrapWithPlatform(): Promise<BootstrappedTestApp & { adminId: string }> {
  const boot = await bootstrapTestApp(
    { platform: { enabled: true } },
    {
      controllers: {
        auth: true,
        mfa: true,
        passwordReset: true,
        sessions: true,
        platform: true
      }
    }
  )
  const passwordService = boot.app.get(PasswordService)
  const passwordHash = await passwordService.hash(PLATFORM_PASSWORD)
  const adminId = 'platform-admin-1'
  boot.platformRepo.seed({
    id: adminId,
    email: PLATFORM_EMAIL.toLowerCase(),
    name: 'Platform Tester',
    passwordHash,
    role: 'SUPER_ADMIN',
    status: 'active',
    mfaEnabled: false,
    createdAt: new Date(),
    updatedAt: new Date(),
    lastLoginAt: null
  })
  return Object.assign(boot, { adminId })
}

/**
 * Performs a platform login and returns the access + refresh tokens. The lib
 * always uses bearer mode for `/platform/login`, regardless of the dashboard
 * `tokenDelivery` setting.
 */
async function platformLogin(
  app: INestApplication
): Promise<{ accessToken: string; refreshToken: string }> {
  const res = await request(app.getHttpServer())
    .post('/platform/login')
    .send({ email: PLATFORM_EMAIL, password: PLATFORM_PASSWORD })
  expect(res.status).toBe(200)
  const body = res.body as { accessToken: string; refreshToken: string }
  expect(body.accessToken).toBeTruthy()
  expect(body.refreshToken).toBeTruthy()
  return body
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('platform auth flow (E2E)', () => {
  describe('login + /me bearer mode', () => {
    let boot: BootstrappedTestApp & { adminId: string }

    beforeEach(async () => {
      boot = await bootstrapWithPlatform()
    })

    afterEach(async () => {
      await boot.app.close()
    })

    // Verifies that /platform/login returns a bearer pair AND the admin record.
    it('should return access + refresh tokens plus the admin profile on success', async () => {
      const res = await request(boot.app.getHttpServer())
        .post('/platform/login')
        .send({ email: PLATFORM_EMAIL, password: PLATFORM_PASSWORD })

      expect(res.status).toBe(200)
      expect(res.body).toEqual(
        expect.objectContaining({
          accessToken: expect.any(String),
          refreshToken: expect.any(String),
          admin: expect.objectContaining({
            email: PLATFORM_EMAIL.toLowerCase(),
            role: 'SUPER_ADMIN'
          })
        })
      )
      // Credentials must never leak via the admin payload.
      expect(res.body.admin).not.toHaveProperty('passwordHash')
      expect(res.body.admin).not.toHaveProperty('mfaSecret')
    })

    // Verifies that the issued access token authenticates /platform/me.
    it('should return the admin record from /platform/me when authorised', async () => {
      const { accessToken } = await platformLogin(boot.app)

      const res = await request(boot.app.getHttpServer())
        .get('/platform/me')
        .set('Authorization', `Bearer ${accessToken}`)

      expect(res.status).toBe(200)
      expect(res.body).toEqual(
        expect.objectContaining({
          email: PLATFORM_EMAIL.toLowerCase(),
          role: 'SUPER_ADMIN'
        })
      )
    })

    // Verifies that wrong credentials are rejected with the standard auth error.
    it('should reject /platform/login with the wrong password and never set a Set-Cookie header', async () => {
      // Use a password that passes the DTO length/shape validators but does
      // not match the seeded hash — guarantees we hit the credential-check
      // path (401) rather than the DTO rejection path (400).
      const res = await request(boot.app.getHttpServer())
        .post('/platform/login')
        .send({ email: PLATFORM_EMAIL, password: 'NotTheRightPassword123!' })

      expect(res.status).toBe(401)
      // Platform auth is bearer-only — even on failure no Set-Cookie must appear.
      expect(res.headers['set-cookie']).toBeUndefined()
    })
  })

  describe('refresh rotation', () => {
    let boot: BootstrappedTestApp & { adminId: string }

    beforeEach(async () => {
      boot = await bootstrapWithPlatform()
    })

    afterEach(async () => {
      await boot.app.close()
    })

    // Verifies that /platform/refresh rotates the refresh token and returns a
    // fresh pair plus the admin record.
    it('should rotate refresh + access tokens and return the admin record on /platform/refresh', async () => {
      const initial = await platformLogin(boot.app)

      const res = await request(boot.app.getHttpServer())
        .post('/platform/refresh')
        .send({ refreshToken: initial.refreshToken })

      expect(res.status).toBe(200)
      const body = res.body as {
        accessToken: string
        refreshToken: string
        admin: { email: string; role: string }
      }
      expect(body.accessToken).toBeTruthy()
      expect(body.refreshToken).toBeTruthy()
      expect(body.refreshToken).not.toBe(initial.refreshToken)
      expect(body.admin.email).toBe(PLATFORM_EMAIL.toLowerCase())
    })
  })

  describe('logout', () => {
    let boot: BootstrappedTestApp & { adminId: string }

    beforeEach(async () => {
      boot = await bootstrapWithPlatform()
    })

    afterEach(async () => {
      await boot.app.close()
    })

    // Verifies that /platform/logout adds the JTI to the revocation list so
    // the same access token is rejected by JwtPlatformGuard on the next call.
    it('should reject /platform/me with 401 after the access token is revoked via /platform/logout', async () => {
      const { accessToken, refreshToken } = await platformLogin(boot.app)

      // Sanity — token works pre-logout.
      const meBefore = await request(boot.app.getHttpServer())
        .get('/platform/me')
        .set('Authorization', `Bearer ${accessToken}`)
      expect(meBefore.status).toBe(200)

      const logout = await request(boot.app.getHttpServer())
        .post('/platform/logout')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ refreshToken })
      expect([200, 201, 204]).toContain(logout.status)

      // The same access token must now be rejected (JTI blacklisted).
      const meAfter = await request(boot.app.getHttpServer())
        .get('/platform/me')
        .set('Authorization', `Bearer ${accessToken}`)
      expect(meAfter.status).toBe(401)
    })
  })

  describe('revoke all sessions', () => {
    let boot: BootstrappedTestApp & { adminId: string }

    beforeEach(async () => {
      boot = await bootstrapWithPlatform()
    })

    afterEach(async () => {
      await boot.app.close()
    })

    // Verifies that DELETE /platform/sessions revokes every active refresh
    // session for the admin — recommended mitigation path when an admin
    // account must be force-signed-out (no PlatformUserStatusGuard ships).
    it('should reject every previously issued refresh token after DELETE /platform/sessions', async () => {
      const sessionA = await platformLogin(boot.app)
      const sessionB = await platformLogin(boot.app)

      const revoke = await request(boot.app.getHttpServer())
        .delete('/platform/sessions')
        .set('Authorization', `Bearer ${sessionA.accessToken}`)
      expect([200, 204]).toContain(revoke.status)

      // Neither old refresh token may be usable now — both are mass-revoked.
      const tryA = await request(boot.app.getHttpServer())
        .post('/platform/refresh')
        .send({ refreshToken: sessionA.refreshToken })
      expect(tryA.status).toBeGreaterThanOrEqual(400)
      expect(tryA.status).toBeLessThan(500)

      const tryB = await request(boot.app.getHttpServer())
        .post('/platform/refresh')
        .send({ refreshToken: sessionB.refreshToken })
      expect(tryB.status).toBeGreaterThanOrEqual(400)
      expect(tryB.status).toBeLessThan(500)
    })
  })

  describe('cross-context rejection', () => {
    let boot: BootstrappedTestApp & { adminId: string }

    beforeEach(async () => {
      boot = await bootstrapWithPlatform()
    })

    afterEach(async () => {
      await boot.app.close()
    })

    // Verifies that a dashboard access token is rejected by JwtPlatformGuard
    // on a platform route — token-type-confusion attack class.
    it('should reject /platform/me with 401 when a dashboard access token is presented', async () => {
      // Mint a dashboard token by registering through the normal flow.
      const reg = await request(boot.app.getHttpServer()).post('/register').send({
        email: 'user@dashboard.test',
        password: 'DashPass123!-xyz',
        name: 'Dashboard User',
        tenantId: 'tenant-1'
      })
      expect(reg.status).toBe(201)
      const dashAccess = (reg.body as { accessToken: string }).accessToken
      expect(dashAccess).toBeTruthy()

      const res = await request(boot.app.getHttpServer())
        .get('/platform/me')
        .set('Authorization', `Bearer ${dashAccess}`)

      // JwtPlatformGuard returns 401 with `PLATFORM_AUTH_REQUIRED` when the
      // token type is wrong; AuthExceptionFilter envelops the code under
      // `body.error.code`. We only assert the status here — the code shape
      // is locked by other specs.
      expect(res.status).toBe(401)
    })

    // Verifies the inverse direction — a platform token cannot reach a
    // dashboard-only route.
    it('should reject /me with 401 when a platform access token is presented', async () => {
      const { accessToken } = await platformLogin(boot.app)

      const res = await request(boot.app.getHttpServer())
        .get('/me')
        .set('Authorization', `Bearer ${accessToken}`)

      expect(res.status).toBe(401)
    })
  })
})
