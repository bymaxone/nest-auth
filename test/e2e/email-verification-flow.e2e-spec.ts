/**
 * End-to-end coverage for `POST /verify-email` and `POST /resend-verification`.
 *
 * Scenarios:
 *   1. Register with `emailVerification.required: true` issues an OTP and
 *      keeps `emailVerified` false on the persisted user.
 *   2. /verify-email with the correct OTP flips emailVerified → true and
 *      returns 204.
 *   3. /verify-email with the wrong OTP returns OTP_INVALID.
 *   4. /resend-verification dispatches a fresh OTP that successfully verifies.
 *   5. /resend-verification for an already-verified email is a 204 no-op
 *      (anti-enumeration — no error is leaked).
 *   6. /resend-verification for an unknown email also returns 204
 *      (anti-enumeration).
 */

import type { INestApplication } from '@nestjs/common'
import { Test } from '@nestjs/testing'
import request from 'supertest'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_PLATFORM_USER_REPOSITORY,
  BYMAX_AUTH_REDIS_CLIENT,
  BYMAX_AUTH_USER_REPOSITORY
} from '../../src/server/bymax-auth.constants'
import { BymaxAuthModule } from '../../src/server/bymax-auth.module'
import type { IEmailProvider } from '../../src/server/interfaces/email-provider.interface'
import {
  JWT_SECRET,
  MFA_ENCRYPTION_KEY,
  applyTestMiddleware,
  createMockEmailProvider,
  createMockPlatformUserRepository,
  createMockRedis,
  createMockUserRepository
} from './setup'

// ---------------------------------------------------------------------------
// OTP-capturing mock email provider
// ---------------------------------------------------------------------------

interface CapturingMockEmailProvider extends IEmailProvider {
  /** Latest OTP value dispatched per recipient — last one wins. */
  readonly otps: Map<string, string>
}

/**
 * Wraps the standard mock email provider to additionally capture the actual
 * OTP argument passed to `sendEmailVerificationOtp`. The base mock ignores
 * `_otp` — these tests need to read it back to call /verify-email with the
 * matching code.
 */
function createCapturingEmailProvider(): CapturingMockEmailProvider {
  const base = createMockEmailProvider()
  const otps = new Map<string, string>()
  return {
    ...base,
    otps,
    async sendEmailVerificationOtp(email: string, otp: string): Promise<void> {
      otps.set(email.toLowerCase(), otp)
      await base.sendEmailVerificationOtp(email, otp)
    }
  }
}

// ---------------------------------------------------------------------------
// Bootstrap with emailVerification.required = true
// ---------------------------------------------------------------------------

interface VerificationFixture {
  app: INestApplication
  email: CapturingMockEmailProvider
}

/**
 * Builds an app with email-verification required so /register dispatches an
 * OTP email instead of immediately marking the user verified.
 */
async function bootstrapWithVerification(): Promise<VerificationFixture> {
  const repo = createMockUserRepository()
  const platformRepo = createMockPlatformUserRepository()
  const email = createCapturingEmailProvider()
  const redis = createMockRedis()

  const moduleRef = await Test.createTestingModule({
    imports: [
      BymaxAuthModule.registerAsync({
        useFactory: () => ({
          jwt: { secret: JWT_SECRET },
          roles: { hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] } },
          tokenDelivery: 'bearer',
          emailVerification: { required: true },
          sessions: { enabled: true },
          mfa: { encryptionKey: MFA_ENCRYPTION_KEY, issuer: 'TestApp' },
          // Off for this harness: it drives many requests from one address on purpose, and a
          // 429 would mask what the scenario asserts. Declaring the source is only required
          // when limiting is ON — see `validateClientIpSource`.
          rateLimit: { enabled: false },
          secureCookies: false
        }),
        controllers: { auth: true, mfa: true, passwordReset: true, sessions: true },
        extraProviders: [
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: repo },
          { provide: BYMAX_AUTH_PLATFORM_USER_REPOSITORY, useValue: platformRepo },
          { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: email },
          { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: redis }
        ]
      })
    ]
  })
    .setLogger({
      log: () => undefined,
      error: () => undefined,
      warn: () => undefined,
      debug: () => undefined,
      verbose: () => undefined
    })
    .compile()

  const app = moduleRef.createNestApplication()
  applyTestMiddleware(app)
  await app.init()
  return { app, email }
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('email verification flow (E2E)', () => {
  describe('register + /verify-email', () => {
    let fixture: VerificationFixture

    beforeEach(async () => {
      fixture = await bootstrapWithVerification()
    })

    afterEach(async () => {
      await fixture.app.close()
    })

    // Verifies that the OTP returned in the email actually verifies the user
    // and flips the persisted emailVerified flag to true.
    it('should flip emailVerified to true on /verify-email with the correct OTP', async () => {
      const email = 'verify-happy@example.com'
      const reg = await request(fixture.app.getHttpServer())
        .post('/register')
        .send({ email, password: 'VerifyPass1!-xyz', name: 'Verify User', tenantId: 'tenant-1' })
      expect(reg.status).toBe(201)

      const otp = fixture.email.otps.get(email)
      expect(otp).toMatch(/^\d{6}$/)

      const res = await request(fixture.app.getHttpServer())
        .post('/verify-email')
        .send({ email, otp, tenantId: 'tenant-1' })
      expect(res.status).toBe(204)

      // /me reads through the user repo — confirms the column actually flipped.
      const accessToken = (reg.body as { accessToken: string }).accessToken
      const me = await request(fixture.app.getHttpServer())
        .get('/me')
        .set('Authorization', `Bearer ${accessToken}`)
      expect(me.status).toBe(200)
      expect((me.body as { emailVerified: boolean }).emailVerified).toBe(true)
    })

    // The verification requirement has to survive rotation. `register` issues a full session
    // deliberately — a consumer needs one to render the "check your inbox" screen — and the
    // specification bounds that window at one access-token lifetime. Rotation is what
    // un-bounded it: the gate lived only on `login`, a door the caller never has to open again
    // once register handed them a refresh token, so an address nobody ever proved held an
    // authenticated session forever. This is the sequence an attacker would actually run:
    // occupy someone else's address, discard the OTP, and rotate.
    it('should refuse to rotate a session whose address was never verified', async () => {
      const email = 'never-verifies@example.com'
      const reg = await request(fixture.app.getHttpServer())
        .post('/register')
        .send({ email, password: 'VerifyPass1!-xyz', name: 'Never Verifies', tenantId: 'tenant-1' })
      expect(reg.status).toBe(201)
      const refreshToken = (reg.body as { refreshToken: string }).refreshToken
      expect(refreshToken).toBeTruthy()

      const rotated = await request(fixture.app.getHttpServer())
        .post('/refresh')
        .send({ refreshToken })

      expect(rotated.status).toBeGreaterThanOrEqual(400)
      expect((rotated.body as { error?: { code?: string } }).error?.code).toBe(
        'auth.email_not_verified'
      )
    })

    // The same rotation succeeds once the address is proven — the gate must bound the
    // unverified window, not break the verified one.
    it('should rotate normally once the address has been verified', async () => {
      const email = 'verifies-then-rotates@example.com'
      const reg = await request(fixture.app.getHttpServer())
        .post('/register')
        .send({ email, password: 'VerifyPass1!-xyz', name: 'Verifies', tenantId: 'tenant-1' })
      const refreshToken = (reg.body as { refreshToken: string }).refreshToken

      const otp = fixture.email.otps.get(email)
      await request(fixture.app.getHttpServer())
        .post('/verify-email')
        .send({ email, otp, tenantId: 'tenant-1' })

      const rotated = await request(fixture.app.getHttpServer())
        .post('/refresh')
        .send({ refreshToken })

      expect(rotated.status).toBe(200)
    })

    // Verifies the OTP_INVALID error code is returned when the submitted code
    // does not match the dispatched one.
    it('should reject /verify-email with OTP_INVALID for a wrong code', async () => {
      const email = 'verify-bad-otp@example.com'
      await request(fixture.app.getHttpServer())
        .post('/register')
        .send({ email, password: 'VerifyPass1!-xyz', name: 'Bad OTP User', tenantId: 'tenant-1' })

      const res = await request(fixture.app.getHttpServer())
        .post('/verify-email')
        .send({ email, otp: '000000', tenantId: 'tenant-1' })

      expect(res.status).toBeGreaterThanOrEqual(400)
      expect(res.status).toBeLessThan(500)
      const body = res.body as { error?: { code?: string } }
      expect(body.error?.code).toBe('auth.otp_invalid')
    })
  })

  describe('/resend-verification', () => {
    let fixture: VerificationFixture

    beforeEach(async () => {
      fixture = await bootstrapWithVerification()
    })

    afterEach(async () => {
      await fixture.app.close()
    })

    // Verifies that the resend endpoint dispatches a fresh OTP that
    // successfully completes the verification.
    it('should dispatch a fresh OTP that verifies the account', async () => {
      const email = 'verify-resend@example.com'
      await request(fixture.app.getHttpServer())
        .post('/register')
        .send({ email, password: 'VerifyPass1!-xyz', name: 'Resend User', tenantId: 'tenant-1' })

      const firstOtp = fixture.email.otps.get(email)
      expect(firstOtp).toBeTruthy()

      const resend = await request(fixture.app.getHttpServer())
        .post('/resend-verification')
        .send({ email, tenantId: 'tenant-1' })
      expect([200, 204]).toContain(resend.status)

      const secondOtp = fixture.email.otps.get(email)
      expect(secondOtp).toMatch(/^\d{6}$/)

      const res = await request(fixture.app.getHttpServer())
        .post('/verify-email')
        .send({ email, otp: secondOtp, tenantId: 'tenant-1' })
      expect(res.status).toBe(204)
    })

    // Verifies that the resend endpoint returns 200/204 for an unknown
    // email — anti-enumeration. Implementation should never reveal whether
    // the email exists.
    it('should return success for an unknown email without dispatching an OTP', async () => {
      const ghost = 'ghost-resend@example.com'
      const before = fixture.email.otps.size

      const res = await request(fixture.app.getHttpServer())
        .post('/resend-verification')
        .send({ email: ghost, tenantId: 'tenant-1' })

      expect([200, 204]).toContain(res.status)
      // No OTP should be dispatched for an email that does not exist.
      expect(fixture.email.otps.has(ghost)).toBe(false)
      expect(fixture.email.otps.size).toBe(before)
    })

    // Verifies that the resend endpoint is a 200/204 no-op for an
    // already-verified account — anti-enumeration. The lib must not raise
    // an "already verified" error that would distinguish the two states.
    it('should return success for an already-verified email without re-dispatching an OTP', async () => {
      const email = 'verify-already@example.com'
      await request(fixture.app.getHttpServer()).post('/register').send({
        email,
        password: 'VerifyPass1!-xyz',
        name: 'Already Verified',
        tenantId: 'tenant-1'
      })
      const otp = fixture.email.otps.get(email)
      await request(fixture.app.getHttpServer())
        .post('/verify-email')
        .send({ email, otp, tenantId: 'tenant-1' })
      // Drop the captured OTP so we can detect re-dispatch.
      fixture.email.otps.delete(email)

      const res = await request(fixture.app.getHttpServer())
        .post('/resend-verification')
        .send({ email, tenantId: 'tenant-1' })

      expect([200, 204]).toContain(res.status)
      // No new OTP must be dispatched for an already-verified account.
      expect(fixture.email.otps.has(email)).toBe(false)
    })
  })
})
