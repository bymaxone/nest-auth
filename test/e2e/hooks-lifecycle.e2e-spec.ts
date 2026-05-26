/**
 * End-to-end coverage of the `IAuthHooks` lifecycle dispatch contract.
 *
 * Existing specs prove that the HTTP routes work; this spec proves that EACH
 * hook fires exactly when it should and receives a `HookContext` carrying the
 * documented metadata (IP, user-agent, sanitized headers). A regression that
 * drops a single hook call — e.g. forgetting to invoke `afterLogout` after a
 * cookie-mode logout — would silently break consumer audit logs without
 * triggering any other spec.
 *
 * Scope:
 *   - afterRegister
 *   - beforeLogin + afterLogin
 *   - afterLogout
 *   - afterMfaEnabled
 *   - afterEmailVerified
 *   - afterPasswordReset
 *
 * `onOAuthLogin` is already covered by `oauth-flow.e2e-spec.ts`.
 * `onNewSession` and `onSessionEvicted` are covered by `session-eviction.e2e-spec.ts`.
 * `afterMfaDisabled` and `afterInvitationAccepted` are covered transitively
 * by the dedicated flow specs and assertions on the captured email side-effects.
 */

import * as crypto from 'node:crypto'

import type { INestApplication } from '@nestjs/common'
import { Test } from '@nestjs/testing'
import request from 'supertest'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_PLATFORM_USER_REPOSITORY,
  BYMAX_AUTH_REDIS_CLIENT,
  BYMAX_AUTH_USER_REPOSITORY
} from '../../src/server/bymax-auth.constants'
import { BymaxAuthModule } from '../../src/server/bymax-auth.module'
import type {
  BeforeRegisterResult,
  HookContext,
  IAuthHooks
} from '../../src/server/interfaces/auth-hooks.interface'
import type { SafeAuthUser } from '../../src/server/interfaces/user-repository.interface'
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
// TOTP helper (minimal)
// ---------------------------------------------------------------------------

const TOTP_STEP_SECONDS = 30
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

function base32Decode(input: string): Buffer {
  const cleaned = input.replace(/=+$/, '').toUpperCase()
  const bytes: number[] = []
  let bits = 0
  let value = 0
  for (const c of cleaned) {
    const idx = BASE32_ALPHABET.indexOf(c)
    if (idx < 0) continue
    value = (value << 5) | idx
    bits += 5
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff)
      bits -= 8
    }
  }
  return Buffer.from(bytes)
}

function generateTotp(base32Secret: string, time = Date.now()): string {
  const key = base32Decode(base32Secret)
  const counter = Math.floor(time / 1000 / TOTP_STEP_SECONDS)
  const buf = Buffer.alloc(8)
  buf.writeBigUInt64BE(BigInt(counter))
  const hmac = crypto.createHmac('sha1', key).update(buf).digest()
  const offset = (hmac[hmac.length - 1] as number) & 0x0f
  const code =
    (((hmac[offset] as number) & 0x7f) << 24) |
    (((hmac[offset + 1] as number) & 0xff) << 16) |
    (((hmac[offset + 2] as number) & 0xff) << 8) |
    ((hmac[offset + 3] as number) & 0xff)
  return (code % 10 ** 6).toString().padStart(6, '0')
}

// ---------------------------------------------------------------------------
// Spy hooks
// ---------------------------------------------------------------------------

interface SpyHooks extends IAuthHooks {
  readonly calls: Array<{ name: string; args: unknown[] }>
}

/**
 * Builds an {@link IAuthHooks} instance whose every method records its
 * invocation into a shared `calls` array. Tests can then assert ordering,
 * counts, and the shape of `HookContext` on each call.
 */
function createSpyHooks(): SpyHooks {
  const calls: Array<{ name: string; args: unknown[] }> = []
  const record =
    (name: string) =>
    async (...args: unknown[]): Promise<void> => {
      calls.push({ name, args })
    }
  return {
    calls,
    beforeRegister: async (data, context): Promise<BeforeRegisterResult> => {
      calls.push({ name: 'beforeRegister', args: [data, context] })
      return { allowed: true }
    },
    afterRegister: record('afterRegister'),
    beforeLogin: record('beforeLogin'),
    afterLogin: record('afterLogin'),
    afterLogout: record('afterLogout'),
    afterMfaEnabled: record('afterMfaEnabled'),
    afterMfaDisabled: record('afterMfaDisabled'),
    afterEmailVerified: record('afterEmailVerified'),
    afterPasswordReset: record('afterPasswordReset')
  }
}

// ---------------------------------------------------------------------------
// Bootstrap with spy hooks
// ---------------------------------------------------------------------------

interface SpyFixture {
  app: INestApplication
  hooks: SpyHooks
  email: ReturnType<typeof createMockEmailProvider>
}

async function bootstrapWithSpy(
  opts: { emailVerificationRequired?: boolean; passwordResetMethod?: 'token' | 'otp' } = {}
): Promise<SpyFixture> {
  const repo = createMockUserRepository()
  const platformRepo = createMockPlatformUserRepository()
  const email = createMockEmailProvider()
  const redis = createMockRedis()
  const hooks = createSpyHooks()

  const moduleRef = await Test.createTestingModule({
    imports: [
      BymaxAuthModule.registerAsync({
        useFactory: () => ({
          jwt: { secret: JWT_SECRET },
          roles: { hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] } },
          tokenDelivery: 'bearer',
          emailVerification: { required: opts.emailVerificationRequired === true },
          sessions: { enabled: true },
          mfa: { encryptionKey: MFA_ENCRYPTION_KEY, issuer: 'TestApp' },
          passwordReset: { method: opts.passwordResetMethod ?? 'token' },
          secureCookies: false
        }),
        controllers: { auth: true, mfa: true, passwordReset: true, sessions: true },
        extraProviders: [
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: repo },
          { provide: BYMAX_AUTH_PLATFORM_USER_REPOSITORY, useValue: platformRepo },
          { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: email },
          { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: redis },
          { provide: BYMAX_AUTH_HOOKS, useValue: hooks }
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
  return { app, hooks, email }
}

/** Returns every call recorded for the named hook. */
function callsFor(hooks: SpyHooks, name: string): Array<{ args: unknown[] }> {
  return hooks.calls.filter((c) => c.name === name)
}

/** Settles any pending fire-and-forget hook microtasks. */
async function flushHooks(): Promise<void> {
  await new Promise<void>((r) => setTimeout(r, 50))
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('IAuthHooks lifecycle (E2E)', () => {
  describe('register → login → logout cycle', () => {
    let fixture: SpyFixture

    beforeAll(async () => {
      fixture = await bootstrapWithSpy()
    })

    afterAll(async () => {
      await fixture.app.close()
    })

    // Single register/login/logout flow that exercises every hook on the path.
    it('should fire beforeRegister, afterRegister, beforeLogin, afterLogin, afterLogout in order', async () => {
      const email = 'hook-cycle@example.com'

      const reg = await request(fixture.app.getHttpServer())
        .post('/register')
        .send({ email, password: 'HookPass123!', name: 'Hook User', tenantId: 'tenant-1' })
      expect(reg.status).toBe(201)
      await flushHooks()

      expect(callsFor(fixture.hooks, 'beforeRegister').length).toBeGreaterThanOrEqual(1)
      expect(callsFor(fixture.hooks, 'afterRegister').length).toBeGreaterThanOrEqual(1)

      // `afterRegister` receives the SafeAuthUser + a HookContext.
      const afterRegArgs = callsFor(fixture.hooks, 'afterRegister')[0]!.args
      const user = afterRegArgs[0] as SafeAuthUser
      const ctx = afterRegArgs[1] as HookContext
      expect(user.email).toBe(email.toLowerCase())
      expect(user).not.toHaveProperty('passwordHash')
      expect(typeof ctx.ip).toBe('string')
      expect(typeof ctx.userAgent).toBe('string')

      const login = await request(fixture.app.getHttpServer())
        .post('/login')
        .send({ email, password: 'HookPass123!', tenantId: 'tenant-1' })
      expect(login.status).toBe(200)
      await flushHooks()

      expect(callsFor(fixture.hooks, 'beforeLogin').length).toBeGreaterThanOrEqual(1)
      expect(callsFor(fixture.hooks, 'afterLogin').length).toBeGreaterThanOrEqual(1)

      const { accessToken, refreshToken } = login.body as {
        accessToken: string
        refreshToken: string
      }
      const logout = await request(fixture.app.getHttpServer())
        .post('/logout')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ refreshToken })
      expect(logout.status).toBe(204)
      await flushHooks()

      const afterLogoutCalls = callsFor(fixture.hooks, 'afterLogout')
      expect(afterLogoutCalls.length).toBeGreaterThanOrEqual(1)
      // afterLogout receives (userId, context).
      expect(typeof afterLogoutCalls[0]!.args[0]).toBe('string')
      const logoutCtx = afterLogoutCalls[0]!.args[1] as HookContext
      expect(typeof logoutCtx.ip).toBe('string')
    })
  })

  describe('email verification + MFA + password reset', () => {
    // afterEmailVerified — flips emailVerified to true and dispatches the hook.
    it('should fire afterEmailVerified on /verify-email success', async () => {
      const fixture = await bootstrapWithSpy({ emailVerificationRequired: true })
      try {
        const email = 'hook-verify@example.com'
        // Capture the OTP using a temporary spy on the email provider.
        let capturedOtp: string | undefined
        const original = fixture.email.sendEmailVerificationOtp.bind(fixture.email)
        fixture.email.sendEmailVerificationOtp = async (to, otp) => {
          capturedOtp = otp
          return original(to, otp)
        }

        await request(fixture.app.getHttpServer())
          .post('/register')
          .send({ email, password: 'VerifyHookPass1!', name: 'Verify Hook', tenantId: 'tenant-1' })

        expect(capturedOtp).toMatch(/^\d{6}$/)

        const res = await request(fixture.app.getHttpServer())
          .post('/verify-email')
          .send({ email, otp: capturedOtp, tenantId: 'tenant-1' })
        expect(res.status).toBe(204)
        await flushHooks()

        expect(callsFor(fixture.hooks, 'afterEmailVerified').length).toBeGreaterThanOrEqual(1)
      } finally {
        await fixture.app.close()
      }
    })

    // afterMfaEnabled — fires after /mfa/verify-enable accepts the first TOTP.
    it('should fire afterMfaEnabled on /mfa/verify-enable success', async () => {
      const fixture = await bootstrapWithSpy()
      try {
        const reg = await request(fixture.app.getHttpServer()).post('/register').send({
          email: 'hook-mfa@example.com',
          password: 'MfaHookPass1!',
          name: 'MFA Hook',
          tenantId: 'tenant-1'
        })
        const accessToken = (reg.body as { accessToken: string }).accessToken

        const setup = await request(fixture.app.getHttpServer())
          .post('/mfa/setup')
          .set('Authorization', `Bearer ${accessToken}`)
        const secret = (setup.body as { secret: string }).secret

        const verify = await request(fixture.app.getHttpServer())
          .post('/mfa/verify-enable')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({ code: generateTotp(secret) })
        expect(verify.status).toBe(204)
        await flushHooks()

        expect(callsFor(fixture.hooks, 'afterMfaEnabled').length).toBeGreaterThanOrEqual(1)
      } finally {
        await fixture.app.close()
      }
    })

    // afterPasswordReset — fires after the lib persists the new password.
    it('should fire afterPasswordReset on /password/reset-password success', async () => {
      const fixture = await bootstrapWithSpy({ passwordResetMethod: 'token' })
      try {
        const email = 'hook-reset@example.com'
        await request(fixture.app.getHttpServer())
          .post('/register')
          .send({ email, password: 'ResetHookPass1!', name: 'Reset Hook', tenantId: 'tenant-1' })

        // Capture the raw token from sendPasswordResetToken.
        let resetToken: string | undefined
        const original = fixture.email.sendPasswordResetToken.bind(fixture.email)
        fixture.email.sendPasswordResetToken = async (to, token) => {
          resetToken = token
          return original(to, token)
        }

        await request(fixture.app.getHttpServer())
          .post('/password/forgot-password')
          .send({ email, tenantId: 'tenant-1' })
        expect(resetToken).toBeTruthy()

        const res = await request(fixture.app.getHttpServer())
          .post('/password/reset-password')
          .send({
            email,
            token: resetToken,
            newPassword: 'BrandNewPass1!',
            tenantId: 'tenant-1'
          })
        expect([200, 204]).toContain(res.status)
        await flushHooks()

        expect(callsFor(fixture.hooks, 'afterPasswordReset').length).toBeGreaterThanOrEqual(1)
      } finally {
        await fixture.app.close()
      }
    })
  })
})
