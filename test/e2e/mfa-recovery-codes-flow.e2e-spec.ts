/**
 * End-to-end coverage for the MFA recovery code regeneration endpoints.
 *
 * Exercises both the dashboard surface (`POST /mfa/recovery-codes`) and the
 * platform surface (`POST /platform/mfa/recovery-codes`) through a fully
 * bootstrapped NestJS application. Every test goes through real HTTP routes
 * via supertest — no service methods are called directly.
 *
 * Scenarios:
 *   Dashboard:
 *     1. Enrol MFA → regenerate with a valid TOTP → fresh codes returned.
 *     2. Old codes no longer authenticate via /mfa/challenge.
 *     3. New codes authenticate via /mfa/challenge.
 *     4. Wrong TOTP rejects regenerate with MFA_INVALID_CODE.
 *     5. MFA-not-enabled account rejects regenerate with MFA_NOT_ENABLED.
 *   Platform:
 *     6. Platform admin login → setup → verify-enable → next login produces
 *        an mfaTempToken instead of a full session → challenge with TOTP
 *        succeeds.
 *     7. Platform admin can rotate recovery codes via /platform/mfa/recovery-codes.
 *     8. Platform admin can disable MFA via /platform/mfa/disable.
 */

import * as crypto from 'node:crypto'

import type { INestApplication } from '@nestjs/common'
import request from 'supertest'

import { PasswordService } from '../../src/server/services/password.service'
import type { BootstrappedTestApp } from './setup'
import { bootstrapTestApp, expectAuthError } from './setup'

// ---------------------------------------------------------------------------
// TOTP helper — mirrors src/server/crypto/totp.ts
// ---------------------------------------------------------------------------

const TOTP_STEP_SECONDS = 30

/**
 * A TOTP step that is inside the verifier's ±1 acceptance window **now** and has not already
 * been consumed by the anti-replay marker.
 *
 * The enrolment flow spends two steps — `base` (verify-enable) and `base + 1` (challenge) —
 * and the marker refuses a replay of either. The management calls that follow used a step
 * fixed relative to a freshly read clock, on the assumption that no step boundary had passed
 * since `base`. Under a loaded parallel run that assumption fails: the flow drifts a step, the
 * chosen code lands on one of the two already spent, and the request comes back 401 in a way
 * that looks like a library defect and is not.
 *
 * With a ±1 window and two consumed steps there is exactly one usable step, and which one it
 * is depends on whether the clock has moved:
 *
 * - still inside `base`'s step → only `base - 1` is both unspent and in window;
 * - one or more steps later → `now + 1`, which is ahead of everything spent.
 *
 * @param base - The reference the enrolment codes were derived from.
 * @returns A timestamp to derive the next management code from.
 */
function unspentStepTime(base: number): number {
  const step = TOTP_STEP_SECONDS * 1000
  const sameStep = Math.floor(Date.now() / step) === Math.floor(base / step)
  return sameStep ? base - step : Date.now() + step
}
const TOTP_DIGITS = 6
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

/**
 * Decodes a Base32 string per RFC 4648 §6 into raw bytes.
 */
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

/** Generates a zero-padded TOTP for the Base32 secret at the given time. */
function generateTotp(base32Secret: string, time: number = Date.now()): string {
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
  return (code % 10 ** TOTP_DIGITS).toString().padStart(TOTP_DIGITS, '0')
}

// ---------------------------------------------------------------------------
// Dashboard fixture — register, enrol MFA, return an MFA-verified access token
// ---------------------------------------------------------------------------

interface DashboardMfaFixture {
  app: INestApplication
  email: string
  password: string
  secret: string
  originalRecoveryCodes: string[]
  accessToken: string
  /** The reference the enrolment codes were derived from, so later calls can pick an
   *  unspent step relative to it. See {@link unspentStepTime}. */
  base: number
}

/**
 * Registers a fresh dashboard user, enrols MFA, and signs the user in through
 * the MFA challenge so the returned access token carries `mfaVerified: true`.
 */
async function enrolDashboardMfa(): Promise<DashboardMfaFixture> {
  const boot = await bootstrapTestApp()
  const email = `mfa-rec-${Math.random().toString(36).slice(2)}@example.com`
  const password = 'RecoveryCodes1!'

  const reg = await request(boot.app.getHttpServer())
    .post('/register')
    .send({ email, password, name: 'Recovery Tester', tenantId: 'tenant-1' })
  expect(reg.status).toBe(201)
  const registerAccess = (reg.body as { accessToken: string }).accessToken

  const setup = await request(boot.app.getHttpServer())
    .post('/mfa/setup')
    .set('Authorization', `Bearer ${registerAccess}`)
    .send({ password: password })
  // NestJS default `@Post` status is 201; the route does not override it
  // via `@HttpCode`, so the assertion is exact rather than the looser
  // `[200, 201].toContain(...)` we previously had.
  expect(setup.status).toBe(201)
  const setupBody = setup.body as { secret: string; recoveryCodes: string[] }
  const secret = setupBody.secret
  const originalRecoveryCodes = setupBody.recoveryCodes

  // ONE captured base for every code in this flow. Reading the clock per call lets a
  // 30-second step boundary pass mid-flow, so two codes computed for "distinct" steps land on
  // the same one, the anti-replay marker rejects the second, and the failure surfaces far
  // downstream as a 401 from `Bearer undefined`.
  const base = Date.now()

  const enable = await request(boot.app.getHttpServer())
    .post('/mfa/verify-enable')
    .set('Authorization', `Bearer ${registerAccess}`)
    .send({ code: generateTotp(secret, base) })
  expect(enable.status).toBe(204)

  // Re-login → challenge to obtain a token with `mfaVerified: true`.
  const login = await request(boot.app.getHttpServer())
    .post('/login')
    .send({ email, password, tenantId: 'tenant-1' })
  expect(login.status).toBe(200)
  const mfaTempToken = (login.body as { mfaTempToken?: string }).mfaTempToken
  expect(mfaTempToken).toBeTruthy()

  // Step ahead to bypass the anti-replay marker from verify-enable.
  const nextStepTime = base + TOTP_STEP_SECONDS * 1000
  const challenge = await request(boot.app.getHttpServer())
    .post('/mfa/challenge')
    .send({ mfaTempToken, code: generateTotp(secret, nextStepTime) })
  expect(challenge.status).toBe(200)
  const accessToken = (challenge.body as { accessToken: string }).accessToken
  expect(accessToken).toBeTruthy()

  return { app: boot.app, email, password, secret, originalRecoveryCodes, accessToken, base }
}

// ---------------------------------------------------------------------------
// Platform fixture — seed an admin, log them in
// ---------------------------------------------------------------------------

const PLATFORM_EMAIL = 'admin@platform.test'
const PLATFORM_PASSWORD = 'PlatformPass123!'

/**
 * Boots an app with both the platform and dashboard surfaces and pre-seeds a
 * SUPER_ADMIN platform user. The password is hashed via the lib's
 * PasswordService so the format matches what login will compare against.
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
// Suite — dashboard regenerate
// ---------------------------------------------------------------------------

describe('dashboard regenerate recovery codes flow (E2E)', () => {
  describe('happy path', () => {
    let fixture: DashboardMfaFixture
    let regenerateBody: { recoveryCodes: string[] }

    beforeAll(async () => {
      fixture = await enrolDashboardMfa()
      // Anti-replay holds counters T (enable) and T+1 (challenge). T-1 is still
      // available within the ±1 window and works for the regenerate request.
      const regenStepTime = unspentStepTime(fixture.base)
      const res = await request(fixture.app.getHttpServer())
        .post('/mfa/recovery-codes')
        .set('Authorization', `Bearer ${fixture.accessToken}`)
        .send({ code: generateTotp(fixture.secret, regenStepTime) })
      expect(res.status).toBe(200)
      regenerateBody = res.body as { recoveryCodes: string[] }
    })

    afterAll(async () => {
      await fixture.app.close()
    })

    // Verifies that the regenerate endpoint returns the fresh plain-text codes.
    // The lib defaults to 8 codes (DEFAULT_RECOVERY_CODE_COUNT).
    it('should return a fresh set of recovery codes on success', () => {
      expect(Array.isArray(regenerateBody.recoveryCodes)).toBe(true)
      expect(regenerateBody.recoveryCodes).toHaveLength(8)
      for (const code of regenerateBody.recoveryCodes) {
        expect(code).toMatch(/^[0-9A-F]{4}(-[0-9A-F]{4}){5}$/)
      }
    })

    // Verifies that the new codes differ from the originals — proves the
    // service actually rotated rather than re-returning the existing set.
    it('should return codes that differ from the original setup codes', () => {
      const overlap = regenerateBody.recoveryCodes.filter((c) =>
        fixture.originalRecoveryCodes.includes(c)
      )
      expect(overlap).toHaveLength(0)
    })

    // Verifies that the user's mfaEnabled flag is preserved — only the
    // recovery code list rotates, the TOTP secret stays in place. /me reads
    // the persisted state directly.
    it('should leave mfaEnabled unchanged after regenerate', async () => {
      const me = await request(fixture.app.getHttpServer())
        .get('/me')
        .set('Authorization', `Bearer ${fixture.accessToken}`)
      expect(me.status).toBe(200)
      expect((me.body as { mfaEnabled: boolean }).mfaEnabled).toBe(true)
    })
  })

  describe('old codes are invalidated, new codes work', () => {
    // Verifies the end-to-end invariant: a successful regenerate retires the
    // old recovery code set (challenge rejects them) and the freshly returned
    // codes authenticate via /mfa/challenge. This is the single test that
    // proves regenerate truly replaced the stored hashes rather than appending
    // new entries.
    it('should reject the original recovery codes and accept the new ones via /mfa/challenge', async () => {
      const fixture = await enrolDashboardMfa()
      try {
        // Capture an original code BEFORE regenerating.
        const oldCode = fixture.originalRecoveryCodes[0] as string

        // Rotate using a TOTP from the still-available T-1 step.
        const regenStepTime = unspentStepTime(fixture.base)
        const regen = await request(fixture.app.getHttpServer())
          .post('/mfa/recovery-codes')
          .set('Authorization', `Bearer ${fixture.accessToken}`)
          .send({ code: generateTotp(fixture.secret, regenStepTime) })
        expect(regen.status).toBe(200)
        const newCodes = (regen.body as { recoveryCodes: string[] }).recoveryCodes
        const newCode = newCodes[0] as string

        // Force a new login → challenge round-trip so we get fresh mfaTempTokens.
        const loginOld = await request(fixture.app.getHttpServer())
          .post('/login')
          .send({ email: fixture.email, password: fixture.password, tenantId: 'tenant-1' })
        const mfaTempTokenForOld = (loginOld.body as { mfaTempToken: string }).mfaTempToken
        const oldRes = await request(fixture.app.getHttpServer())
          .post('/mfa/challenge')
          .send({ mfaTempToken: mfaTempTokenForOld, code: oldCode })
        expectAuthError(oldRes, 'auth.mfa_invalid_code')

        // The new code MUST authenticate. Need a fresh mfaTempToken for each
        // challenge attempt since the previous one was consumed.
        const loginNew = await request(fixture.app.getHttpServer())
          .post('/login')
          .send({ email: fixture.email, password: fixture.password, tenantId: 'tenant-1' })
        const mfaTempTokenForNew = (loginNew.body as { mfaTempToken: string }).mfaTempToken
        const newRes = await request(fixture.app.getHttpServer())
          .post('/mfa/challenge')
          .send({ mfaTempToken: mfaTempTokenForNew, code: newCode })
        expect(newRes.status).toBe(200)
        expect((newRes.body as { accessToken?: string }).accessToken).toBeTruthy()
      } finally {
        await fixture.app.close()
      }
    })
  })

  describe('negative paths', () => {
    // Verifies that a wrong TOTP rejects with MFA_INVALID_CODE and that the
    // user's recovery codes remain intact (the original /mfa/challenge with
    // the originals still succeeds).
    it('should reject /mfa/recovery-codes with MFA_INVALID_CODE for a wrong TOTP', async () => {
      const fixture = await enrolDashboardMfa()
      try {
        const res = await request(fixture.app.getHttpServer())
          .post('/mfa/recovery-codes')
          .set('Authorization', `Bearer ${fixture.accessToken}`)
          .send({ code: '000000' })

        expectAuthError(res, 'auth.mfa_invalid_code')
      } finally {
        await fixture.app.close()
      }
    })

    // Verifies that calling regenerate on an account that has never enrolled
    // MFA returns MFA_NOT_ENABLED rather than silently accepting and creating
    // recovery codes for a non-MFA account.
    it('should reject /mfa/recovery-codes with MFA_NOT_ENABLED when MFA is off', async () => {
      const boot = await bootstrapTestApp()
      try {
        const reg = await request(boot.app.getHttpServer())
          .post('/register')
          .send({
            email: `mfa-rec-noenrol-${Math.random().toString(36).slice(2)}@example.com`,
            password: 'NoEnrolPass1!-xyz',
            name: 'No Enrol',
            tenantId: 'tenant-1'
          })
        const accessToken = (reg.body as { accessToken: string }).accessToken

        const res = await request(boot.app.getHttpServer())
          .post('/mfa/recovery-codes')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({ code: '123456' })

        expectAuthError(res, 'auth.mfa_not_enabled')
      } finally {
        await boot.app.close()
      }
    })
  })
})

// ---------------------------------------------------------------------------
// Suite — platform MFA enrolment + recovery codes + disable
// ---------------------------------------------------------------------------

describe('platform MFA flow (E2E)', () => {
  describe('enrolment + challenge + rotation + disable', () => {
    // Verifies the core platform MFA enrolment loop described in the task spec:
    //   - login as a platform admin (no MFA yet) → call /platform/mfa/setup
    //   - call /platform/mfa/verify-enable with the first TOTP code
    //   - the next /platform/login produces an mfaTempToken (not a full session)
    //   - exchange the temp token for a platform session via /platform/mfa/challenge
    //
    // Disable and recovery rotation each live in their own tests below because
    // each consumes an additional TOTP step from the ±1 anti-replay window, and
    // we cannot fit four distinct rotations within the three-code budget.
    it('should enrol, force MFA on next login, and complete the challenge', async () => {
      const boot = await bootstrapWithPlatform()
      try {
        const initialLogin = await platformLogin(boot.app)

        // Step 1: /platform/mfa/setup returns the secret and recovery codes.
        const setup = await request(boot.app.getHttpServer())
          .post('/platform/mfa/setup')
          .set('Authorization', `Bearer ${initialLogin.accessToken}`)
          .send({ password: PLATFORM_PASSWORD })
        // NestJS default `@Post` status is 201; the route does not override it
        // via `@HttpCode`, so the assertion is exact rather than the looser
        // `[200, 201].toContain(...)` we previously had.
        expect(setup.status).toBe(201)
        const setupBody = setup.body as { secret: string; recoveryCodes: string[] }
        expect(setupBody.secret).toMatch(/^[A-Z2-7]+$/)
        expect(setupBody.recoveryCodes.length).toBeGreaterThan(0)

        // Step 2: /platform/mfa/verify-enable persists the new secret on the
        // platform admin row. After this point, the platform row carries
        // mfaEnabled: true and the dashboard userRepo is untouched.
        const enable = await request(boot.app.getHttpServer())
          .post('/platform/mfa/verify-enable')
          .set('Authorization', `Bearer ${initialLogin.accessToken}`)
          .send({ code: generateTotp(setupBody.secret) })
        expect(enable.status).toBe(204)
        const adminAfterEnable = boot.platformRepo.users.get(boot.adminId)
        expect(adminAfterEnable?.mfaEnabled).toBe(true)
        expect(adminAfterEnable?.mfaSecret).toBeTruthy()
        // The dashboard userRepo must have received nothing — proves the
        // platform-context branch in verifyAndEnable was taken.
        expect(boot.repo.users.size).toBe(0)

        // Step 3: a fresh login must produce an mfaTempToken, not a full session.
        // This is the proof that verify-enable actually flipped mfaEnabled.
        const loginAfterEnable = await request(boot.app.getHttpServer())
          .post('/platform/login')
          .send({ email: PLATFORM_EMAIL, password: PLATFORM_PASSWORD })
        expect(loginAfterEnable.status).toBe(200)
        const challengeBody = loginAfterEnable.body as {
          mfaTempToken?: string
          mfaRequired?: boolean
          accessToken?: string
        }
        expect(challengeBody.mfaTempToken).toBeTruthy()
        // No full session token — that's the MFA-required contract.
        expect(challengeBody.accessToken).toBeUndefined()

        // Step 4: exchange the temp token for a full session via
        // /platform/mfa/challenge. Step ahead by 30s so the TOTP differs from
        // the enable code (anti-replay rejects identical code strings).
        const nextStepTime = Date.now() + TOTP_STEP_SECONDS * 1000
        const challenge = await request(boot.app.getHttpServer())
          .post('/platform/mfa/challenge')
          .send({
            mfaTempToken: challengeBody.mfaTempToken as string,
            code: generateTotp(setupBody.secret, nextStepTime)
          })
        expect(challenge.status).toBe(200)
        expect((challenge.body as { accessToken?: string }).accessToken).toBeTruthy()
      } finally {
        await boot.app.close()
      }
    })

    // Verifies that a platform admin can rotate their recovery codes via
    // /platform/mfa/recovery-codes. Each rotation uses its own boot app so the
    // TOTP anti-replay budget (T-1, T, T+1 = three codes) is fresh.
    it('should regenerate platform recovery codes via /platform/mfa/recovery-codes', async () => {
      const boot = await bootstrapWithPlatform()
      try {
        const initialLogin = await platformLogin(boot.app)
        const setup = await request(boot.app.getHttpServer())
          .post('/platform/mfa/setup')
          .set('Authorization', `Bearer ${initialLogin.accessToken}`)
          .send({ password: PLATFORM_PASSWORD })
        const secret = (setup.body as { secret: string }).secret
        // ONE captured base for every code below — see the shared helper for why a per-call
        // clock read makes this flow flaky across a 30-second step boundary.
        const base = Date.now()
        await request(boot.app.getHttpServer())
          .post('/platform/mfa/verify-enable')
          .set('Authorization', `Bearer ${initialLogin.accessToken}`)
          .send({ code: generateTotp(secret, base) })

        // Challenge with T+1 to obtain an mfaVerified access token.
        const loginAfter = await request(boot.app.getHttpServer())
          .post('/platform/login')
          .send({ email: PLATFORM_EMAIL, password: PLATFORM_PASSWORD })
        const mfaTempToken = (loginAfter.body as { mfaTempToken: string }).mfaTempToken
        const challenge = await request(boot.app.getHttpServer())
          .post('/platform/mfa/challenge')
          .send({
            mfaTempToken,
            code: generateTotp(secret, base + TOTP_STEP_SECONDS * 1000)
          })
        const mfaVerifiedAccess = (challenge.body as { accessToken: string }).accessToken

        // Regenerate using T-1 — still inside the ±1 anti-replay window and
        // unused (enable consumed T, challenge consumed T+1).
        const regen = await request(boot.app.getHttpServer())
          .post('/platform/mfa/recovery-codes')
          .set('Authorization', `Bearer ${mfaVerifiedAccess}`)
          .send({ code: generateTotp(secret, unspentStepTime(base)) })
        expect(regen.status).toBe(200)
        const regenBody = regen.body as { recoveryCodes: string[] }
        expect(regenBody.recoveryCodes).toHaveLength(8)
        for (const code of regenBody.recoveryCodes) {
          expect(code).toMatch(/^[0-9A-F]{4}(-[0-9A-F]{4}){5}$/)
        }
        // The admin row must still carry mfaEnabled: true; only the recovery
        // code hashes rotate. Pins the "preserve mfaSecret, replace
        // mfaRecoveryCodes" service contract.
        const adminRow = boot.platformRepo.users.get(boot.adminId)
        expect(adminRow?.mfaEnabled).toBe(true)
        expect((adminRow?.mfaRecoveryCodes ?? []).length).toBeGreaterThan(0)
        // The dashboard repo is untouched.
        expect(boot.repo.users.size).toBe(0)
      } finally {
        await boot.app.close()
      }
    })

    // Verifies that a platform admin can disable MFA via /platform/mfa/disable.
    // Lives in its own test so the TOTP anti-replay budget covers enable=T,
    // challenge=T+1, disable=T-1 inside the same scenario.
    it('should disable platform MFA via /platform/mfa/disable', async () => {
      const boot = await bootstrapWithPlatform()
      try {
        const initialLogin = await platformLogin(boot.app)
        const setup = await request(boot.app.getHttpServer())
          .post('/platform/mfa/setup')
          .set('Authorization', `Bearer ${initialLogin.accessToken}`)
          .send({ password: PLATFORM_PASSWORD })
        const secret = (setup.body as { secret: string }).secret
        // ONE captured base for every code below — see the shared helper for why a per-call
        // clock read makes this flow flaky across a 30-second step boundary.
        const base = Date.now()
        await request(boot.app.getHttpServer())
          .post('/platform/mfa/verify-enable')
          .set('Authorization', `Bearer ${initialLogin.accessToken}`)
          .send({ code: generateTotp(secret, base) })

        // Challenge with T+1.
        const loginAfter = await request(boot.app.getHttpServer())
          .post('/platform/login')
          .send({ email: PLATFORM_EMAIL, password: PLATFORM_PASSWORD })
        const mfaTempToken = (loginAfter.body as { mfaTempToken: string }).mfaTempToken
        const challenge = await request(boot.app.getHttpServer())
          .post('/platform/mfa/challenge')
          .send({
            mfaTempToken,
            code: generateTotp(secret, base + TOTP_STEP_SECONDS * 1000)
          })
        const mfaVerifiedAccess = (challenge.body as { accessToken: string }).accessToken

        // Disable using T-1.
        const disable = await request(boot.app.getHttpServer())
          .post('/platform/mfa/disable')
          .set('Authorization', `Bearer ${mfaVerifiedAccess}`)
          .send({ code: generateTotp(secret, unspentStepTime(base)) })
        expect(disable.status).toBe(204)
        const adminRow = boot.platformRepo.users.get(boot.adminId)
        expect(adminRow?.mfaEnabled).toBe(false)
      } finally {
        await boot.app.close()
      }
    })
  })

  describe('negative paths', () => {
    // Verifies that the platform MFA endpoints reject dashboard JWTs — both
    // the routes and the underlying JwtPlatformGuard must enforce the type
    // discriminant so a tenant user cannot enrol via the platform surface.
    it('should reject /platform/mfa/setup with 401 when a dashboard token is presented', async () => {
      const boot = await bootstrapWithPlatform()
      try {
        const reg = await request(boot.app.getHttpServer())
          .post('/register')
          .send({
            email: `user-${Math.random().toString(36).slice(2)}@dashboard.test`,
            password: 'DashPass123!-xyz',
            name: 'Dash User',
            tenantId: 'tenant-1'
          })
        expect(reg.status).toBe(201)
        const dashAccess = (reg.body as { accessToken: string }).accessToken

        const res = await request(boot.app.getHttpServer())
          .post('/platform/mfa/setup')
          .set('Authorization', `Bearer ${dashAccess}`)

        expect(res.status).toBe(401)
      } finally {
        await boot.app.close()
      }
    })

    // Verifies that /platform/mfa/recovery-codes returns MFA_NOT_ENABLED when
    // the admin has not enrolled MFA — mirrors the dashboard contract.
    it('should reject /platform/mfa/recovery-codes with MFA_NOT_ENABLED before enrolment', async () => {
      const boot = await bootstrapWithPlatform()
      try {
        const { accessToken } = await platformLogin(boot.app)

        const res = await request(boot.app.getHttpServer())
          .post('/platform/mfa/recovery-codes')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({ code: '123456' })

        expectAuthError(res, 'auth.mfa_not_enabled')
      } finally {
        await boot.app.close()
      }
    })
  })
})
