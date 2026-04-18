/**
 * End-to-end security scenarios.
 *
 * Exercises the security-critical edge cases the @bymax-one/nest-auth library is
 * expected to defend against — brute-force lockout, token revocation, JWT
 * validation invariants, token type isolation, and OTP send cooldowns — through
 * real HTTP requests issued via supertest against a fully-bootstrapped NestJS
 * application. No service or guard methods are invoked directly.
 *
 * Each scenario lives in its own `describe` block with an isolated app instance
 * so that a Redis state mutation (lockout counter, blacklisted JTI, OTP cooldown
 * key) never leaks between unrelated tests.
 *
 * Two scenarios are intentionally skipped — see the inline `describe.skip`
 * blocks for the rationale.
 */

import { JwtService } from '@nestjs/jwt'
import type { INestApplication } from '@nestjs/common'
import request from 'supertest'

import { JWT_SECRET, bootstrapTestApp } from './setup'

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('security scenarios (E2E)', () => {
  // ---------------------------------------------------------------------------
  // Scenario 1 — Brute-force lockout
  //
  // The default `bruteForce.maxAttempts` is 5 and `windowSeconds` is 900 (see
  // src/server/config/default-options.ts). The IP-based throttler from
  // @nestjs/throttler is NOT activated in the test app (the consumer is
  // expected to wire it in production), so only the per-(tenantId, email)
  // counter inside BruteForceService is exercised here.
  // ---------------------------------------------------------------------------

  describe('Scenario 1 — brute-force lockout after repeated failed logins', () => {
    let app: INestApplication

    beforeEach(async () => {
      const bootstrap = await bootstrapTestApp({ tokenDelivery: 'bearer' })
      app = bootstrap.app

      // Pre-register the target user so the brute-force counter, not a
      // user-not-found short-circuit, is the path under test.
      await request(app.getHttpServer()).post('/register').send({
        email: 'lockout@example.com',
        password: 'CorrectSecret123!',
        name: 'Lockout User',
        tenantId: 'tenant-1'
      })
    })

    afterEach(async () => {
      await app.close()
    })

    // Verifies that after five wrong-password attempts the next /login returns 429 with retryAfterSeconds.
    it('should return 429 with retryAfterSeconds after the brute-force threshold is exceeded', async () => {
      // Arrange — five wrong-password attempts saturate the counter (max=5).
      for (let i = 0; i < 5; i++) {
        const fail = await request(app.getHttpServer()).post('/login').send({
          email: 'lockout@example.com',
          password: 'WrongPassword!!!',
          tenantId: 'tenant-1'
        })
        expect(fail.status).toBe(401)
      }

      // Act — the sixth attempt must trip the lockout regardless of password.
      const locked = await request(app.getHttpServer()).post('/login').send({
        email: 'lockout@example.com',
        password: 'CorrectSecret123!',
        tenantId: 'tenant-1'
      })

      // Assert — 429 with the structured error envelope and a positive
      // `retryAfterSeconds` value derived from the remaining TTL of the
      // lockout key. The library does NOT set the `Retry-After` HTTP header —
      // the value is conveyed inside the JSON body so the client SDK can
      // render a precise countdown without parsing a separate header.
      expect(locked.status).toBe(429)
      expect(locked.body).toEqual(
        expect.objectContaining({
          error: expect.objectContaining({
            code: 'auth.account_locked',
            details: expect.objectContaining({
              retryAfterSeconds: expect.any(Number)
            })
          })
        })
      )
      const retryAfterSeconds = locked.body.error.details.retryAfterSeconds as number
      expect(retryAfterSeconds).toBeGreaterThan(0)
    })
  })

  // ---------------------------------------------------------------------------
  // Scenario 2 — Token blacklist (logout invalidates access token)
  //
  // POST /logout writes `rv:{jti}` to Redis with a TTL equal to the token's
  // remaining lifetime. The next request that presents the same access token
  // is rejected by JwtAuthGuard's revocation check.
  // ---------------------------------------------------------------------------

  describe('Scenario 2 — logout blacklists the access token', () => {
    let app: INestApplication

    beforeEach(async () => {
      const bootstrap = await bootstrapTestApp({ tokenDelivery: 'bearer' })
      app = bootstrap.app
    })

    afterEach(async () => {
      await app.close()
    })

    // Verifies that GET /me with a logged-out access token returns 401.
    it('should reject /me with 401 when the access token has been revoked by logout', async () => {
      // Arrange — register, then log out so the issued JTI lands in the blacklist.
      const register = await request(app.getHttpServer()).post('/register').send({
        email: 'blacklist@example.com',
        password: 'BlacklistSecret123!',
        name: 'Blacklist User',
        tenantId: 'tenant-1'
      })
      const accessToken = register.body.accessToken as string
      const refreshToken = register.body.refreshToken as string

      const logout = await request(app.getHttpServer())
        .post('/logout')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ refreshToken })
      expect(logout.status).toBe(204)

      // Act — replay the same access token on a protected route.
      const me = await request(app.getHttpServer())
        .get('/me')
        .set('Authorization', `Bearer ${accessToken}`)

      // Assert — JwtAuthGuard short-circuits on the `rv:{jti}` revocation key.
      expect(me.status).toBe(401)
      expect(me.body).toEqual(
        expect.objectContaining({
          error: expect.objectContaining({ code: 'auth.token_revoked' })
        })
      )
    })
  })

  // ---------------------------------------------------------------------------
  // Scenario 3 — Cross-tenant isolation (skipped)
  //
  // At the HTTP layer the library does NOT cross-check `tenantId` from the JWT
  // against a tenant scope on incoming requests — that responsibility belongs
  // to the host application, which typically pairs JwtAuthGuard with a custom
  // tenant-resolution middleware. A forged JWT signed with the same secret
  // carrying a different `tenantId` would be accepted by JwtAuthGuard (the
  // signature is valid) and surfaced to the controller as `req.user.tenantId`.
  //
  // Cross-tenant data isolation is enforced by the user repository, which
  // requires the caller to pass `tenantId` to `findById`/`findByEmail`. That
  // contract is exercised at the unit-test level — see
  // `src/server/services/auth.service.spec.ts` and
  // `test/e2e/auth-flow.e2e-spec.ts` for the happy path. There is no library
  // route that exposes tenant-scoped data to be tampered with from a forged
  // token, so this scenario has no observable HTTP-level outcome to assert.
  // ---------------------------------------------------------------------------

  describe.skip('Scenario 3 — cross-tenant isolation', () => {
    // Intentionally skipped — see block comment above for rationale.
  })

  // ---------------------------------------------------------------------------
  // Scenario 4 — Role insufficient (skipped — covered elsewhere)
  //
  // The negative path "MEMBER cannot create an ADMIN invitation" is the
  // canonical role-insufficient assertion in the library. It is already
  // exercised at the unit-test level by
  // `src/server/services/invitation.service.spec.ts` (see the
  // INSUFFICIENT_ROLE branch) and the happy path at
  // `test/e2e/invitations-flow.e2e-spec.ts`.
  //
  // Reproducing it here would require enabling the invitation controller
  // (`controllers.invitations: true`) and the `invitations` config group — a
  // setup that is orthogonal to the security guarantees this suite focuses on.
  // ---------------------------------------------------------------------------

  describe.skip('Scenario 4 — MEMBER role insufficient for admin-protected endpoint', () => {
    // Intentionally skipped — see block comment above for rationale.
  })

  // ---------------------------------------------------------------------------
  // Scenario 5 — JWT without `jti` claim
  //
  // JwtAuthGuard requires `payload.jti` to be a string for the revocation
  // check to be meaningful. A token missing the claim is rejected with
  // TOKEN_INVALID even when the signature, expiry, and `type` claim are valid.
  // ---------------------------------------------------------------------------

  describe('Scenario 5 — JWT without jti claim is rejected', () => {
    let app: INestApplication

    beforeEach(async () => {
      const bootstrap = await bootstrapTestApp({ tokenDelivery: 'bearer' })
      app = bootstrap.app

      await request(app.getHttpServer()).post('/register').send({
        email: 'no-jti@example.com',
        password: 'NoJtiSecret123!',
        name: 'No Jti User',
        tenantId: 'tenant-1'
      })
    })

    afterEach(async () => {
      await app.close()
    })

    // Verifies that a JWT signed with the correct secret but missing `jti` is rejected with 401.
    it('should reject /me with 401 TOKEN_INVALID when the access token has no jti claim', async () => {
      // Arrange — sign a payload that mirrors a real dashboard access token in
      // every claim except `jti`. Same secret + algorithm so the signature is
      // valid and the rejection comes from the explicit jti check.
      const jwtService = new JwtService({
        secret: JWT_SECRET,
        signOptions: { algorithm: 'HS256' }
      })
      const forged = jwtService.sign(
        {
          sub: 'user-1',
          tenantId: 'tenant-1',
          role: 'MEMBER',
          type: 'dashboard',
          status: 'active',
          mfaEnabled: false,
          mfaVerified: false
        },
        { expiresIn: '15m' }
      )

      // Act
      const res = await request(app.getHttpServer())
        .get('/me')
        .set('Authorization', `Bearer ${forged}`)

      // Assert — the guard rejects pre-revocation-check on the missing jti.
      expect(res.status).toBe(401)
      expect(res.body).toEqual(
        expect.objectContaining({
          error: expect.objectContaining({ code: 'auth.token_invalid' })
        })
      )
    })
  })

  // ---------------------------------------------------------------------------
  // Scenario 6 — Cross-context token isolation
  //
  // An MFA challenge token (`type: 'mfa_challenge'`) presented to a dashboard
  // route must be rejected by JwtAuthGuard's `assertTokenType` check. Forging
  // the token with the real secret + algorithm + a valid `jti` proves the
  // rejection is driven by the type discriminant, not by signature failure or
  // missing claims.
  //
  // The spec's preferred variant — submitting the token to a platform endpoint
  // — would require enabling the `platform` controller and config group, which
  // is orthogonal to the type-isolation guarantee under test. The simpler
  // dashboard-side variant exercises the exact same `assertTokenType` branch.
  // ---------------------------------------------------------------------------

  describe('Scenario 6 — MFA challenge token rejected by dashboard guard', () => {
    let app: INestApplication

    beforeEach(async () => {
      const bootstrap = await bootstrapTestApp({ tokenDelivery: 'bearer' })
      app = bootstrap.app
    })

    afterEach(async () => {
      await app.close()
    })

    // Verifies that a forged MFA challenge token sent to /me is rejected with 401.
    it('should reject /me with 401 TOKEN_INVALID when the access token has type mfa_challenge', async () => {
      // Arrange — sign a fully-formed mfa_challenge payload with the correct
      // secret and a valid `jti`. The only invalid attribute is the `type`
      // discriminant, which assertTokenType() rejects.
      const jwtService = new JwtService({
        secret: JWT_SECRET,
        signOptions: { algorithm: 'HS256' }
      })
      const forged = jwtService.sign(
        {
          jti: 'forged-jti-00000000-0000-4000-8000-000000000000',
          sub: 'user-1',
          type: 'mfa_challenge',
          context: 'dashboard'
        },
        { expiresIn: '5m' }
      )

      // Act
      const res = await request(app.getHttpServer())
        .get('/me')
        .set('Authorization', `Bearer ${forged}`)

      // Assert — token type isolation maps to TOKEN_INVALID, not a more
      // descriptive code, because the guard intentionally avoids leaking the
      // reason a token was refused.
      expect(res.status).toBe(401)
      expect(res.body).toEqual(
        expect.objectContaining({
          error: expect.objectContaining({ code: 'auth.token_invalid' })
        })
      )
    })
  })

  // ---------------------------------------------------------------------------
  // Scenario 7 — OTP resend cooldown
  //
  // The 60-second atomic cooldown lives on `POST /password/resend-otp`, not on
  // `POST /password/forgot-password` (which has no cooldown — only IP-based
  // throttling at the consumer level). The DTO is the same shape (email +
  // tenantId) and both endpoints always return 200 to prevent enumeration.
  //
  // The library captures one OTP email on the first call. The second call
  // fired within the cooldown window must also return 200 but MUST NOT
  // generate a second email — the captured emails array stays at length 1.
  // ---------------------------------------------------------------------------

  describe('Scenario 7 — resend-otp 60s cooldown suppresses duplicate emails', () => {
    let app: INestApplication
    let sentOtps: number

    beforeEach(async () => {
      // OTP method must be enabled at module configuration time — the resend
      // endpoint is meaningful only in OTP mode.
      const bootstrap = await bootstrapTestApp({
        tokenDelivery: 'bearer',
        passwordReset: { method: 'otp', otpLength: 6, otpTtlSeconds: 600 }
      })
      app = bootstrap.app

      // Track OTP sends with a focused counter — the shared MockEmailProvider
      // pushes generic strings, so a dedicated counter is more diagnostic than
      // filtering the whole `sentEmails` array.
      sentOtps = 0
      ;(
        bootstrap.email as { sendPasswordResetOtp: (to: string, otp: string) => Promise<void> }
      ).sendPasswordResetOtp = async (): Promise<void> => {
        sentOtps += 1
      }

      await request(app.getHttpServer()).post('/register').send({
        email: 'cooldown@example.com',
        password: 'CooldownSecret123!',
        name: 'Cooldown User',
        tenantId: 'tenant-1'
      })
    })

    afterEach(async () => {
      await app.close()
    })

    // Verifies that two consecutive resend-otp requests still return 200 but only one OTP email is sent.
    it('should return 200 on both /password/resend-otp calls but emit a single OTP email', async () => {
      // Act — two consecutive calls under the 60s window.
      const first = await request(app.getHttpServer()).post('/password/resend-otp').send({
        email: 'cooldown@example.com',
        tenantId: 'tenant-1'
      })
      const second = await request(app.getHttpServer()).post('/password/resend-otp').send({
        email: 'cooldown@example.com',
        tenantId: 'tenant-1'
      })

      // Wait for the fire-and-forget email send chain inside `sendOtp` to settle.
      await new Promise((resolve) => setTimeout(resolve, 50))

      // Assert — both responses succeed (anti-enumeration) but only the first
      // call passed the atomic NX cooldown gate, so exactly one OTP was sent.
      expect(first.status).toBe(200)
      expect(second.status).toBe(200)
      expect(sentOtps).toBe(1)
    })
  })
})
