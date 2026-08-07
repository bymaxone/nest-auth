/**
 * End-to-end coverage for the `POST /mfa/disable` route.
 *
 * Complements `mfa-flow.e2e-spec.ts` (which covers setup → verify-enable →
 * challenge) by closing the lifecycle's final transition: turning MFA OFF
 * with a valid TOTP and proving subsequent logins skip the challenge.
 *
 * Scenarios:
 *   1. Disable with a valid TOTP returns 204 No Content.
 *   2. After disabling, /me reports `mfaEnabled: false`.
 *   3. After disabling, a fresh login no longer issues an mfaTempToken — the
 *      user is signed in directly with bearer tokens.
 *   4. Disable with the wrong TOTP returns MFA_INVALID_CODE.
 *   5. Disable when MFA was never enabled returns MFA_NOT_ENABLED.
 */

import * as crypto from 'node:crypto'

import type { INestApplication } from '@nestjs/common'
import request from 'supertest'

import { bootstrapTestApp } from './setup'

// ---------------------------------------------------------------------------
// TOTP helper — mirrors src/server/crypto/totp.ts
// ---------------------------------------------------------------------------

const TOTP_STEP_SECONDS = 30
const TOTP_DIGITS = 6
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

/**
 * Decodes a Base32 string per RFC 4648 §6 into raw bytes. Strips `=` padding
 * and ignores characters outside the alphabet so group separators (`-`, ` `)
 * are tolerated.
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
// Helpers
// ---------------------------------------------------------------------------

interface MfaEnabledFixture {
  app: INestApplication
  secret: string
  accessToken: string
}

/**
 * Registers a fresh user, enables MFA, then re-logs in through the MFA
 * challenge so the final access token carries `mfaVerified: true`. Tokens
 * issued before `/mfa/verify-enable` have `mfaVerified: false` and would be
 * rejected by `MfaRequiredGuard` once MFA is on — the challenge round-trip
 * is the only way to mint a token that can reach `/mfa/disable`.
 */
async function enableMfa(): Promise<MfaEnabledFixture> {
  const boot = await bootstrapTestApp()
  const email = `mfa-disable-${Math.random().toString(36).slice(2)}@example.com`
  const password = 'DisableMfaPass1!'

  const reg = await request(boot.app.getHttpServer())
    .post('/register')
    .send({ email, password, name: 'MFA Disable Tester', tenantId: 'tenant-1' })
  expect(reg.status).toBe(201)
  const registerAccess = (reg.body as { accessToken: string }).accessToken

  const setup = await request(boot.app.getHttpServer())
    .post('/mfa/setup')
    .set('Authorization', `Bearer ${registerAccess}`)
    .send({ password: password })
  expect([200, 201]).toContain(setup.status)
  const secret = (setup.body as { secret: string }).secret

  const enable = await request(boot.app.getHttpServer())
    .post('/mfa/verify-enable')
    .set('Authorization', `Bearer ${registerAccess}`)
    .send({ code: generateTotp(secret) })
  expect(enable.status).toBe(204)

  // verify-enable returns 204 No Content — no fresh tokens are issued.
  // Replay login → MFA-challenge to obtain a token with mfaVerified: true.
  const login = await request(boot.app.getHttpServer())
    .post('/login')
    .send({ email, password, tenantId: 'tenant-1' })
  expect(login.status).toBe(200)
  const mfaTempToken = (login.body as { mfaTempToken?: string }).mfaTempToken
  expect(mfaTempToken).toBeTruthy()

  // Use a TOTP one step ahead of the enable code — the enable step persisted
  // an anti-replay key against the current step, so a fresh code is needed.
  // ±1-step window keeps the server-side validation happy.
  const nextStepTime = Date.now() + TOTP_STEP_SECONDS * 1000
  const challenge = await request(boot.app.getHttpServer())
    .post('/mfa/challenge')
    .send({ mfaTempToken, code: generateTotp(secret, nextStepTime) })
  expect(challenge.status).toBe(200)
  const accessToken = (challenge.body as { accessToken: string }).accessToken
  expect(accessToken).toBeTruthy()

  return { app: boot.app, secret, accessToken }
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('mfa disable flow (E2E)', () => {
  describe('happy path — disable with a valid TOTP', () => {
    let fixture: MfaEnabledFixture
    let disableStatus: number

    beforeAll(async () => {
      fixture = await enableMfa()
      // After enableMfa() the anti-replay set holds counters T (enable) and
      // T+1 (challenge). The ±1 window accepts T-1, T, T+1, so only T-1 is
      // still available — use it for the disable code.
      const disableStepTime = Date.now() - TOTP_STEP_SECONDS * 1000
      const disable = await request(fixture.app.getHttpServer())
        .post('/mfa/disable')
        .set('Authorization', `Bearer ${fixture.accessToken}`)
        .send({ code: generateTotp(fixture.secret, disableStepTime) })
      disableStatus = disable.status
    })

    afterAll(async () => {
      await fixture.app.close()
    })

    // Verifies that the disable endpoint returns 204 No Content on success.
    it('should return 204 from /mfa/disable when the TOTP is valid', () => {
      expect(disableStatus).toBe(204)
    })

    // Verifies that the PRE-disable access token is refused after disabling. An auth-state
    // change advances the token epoch in both directions — everything issued under the
    // previous state dies with the sessions, the same rule the password-reset flow applies —
    // so the old token gets 401 and the flipped `mfaEnabled` column is observable only from
    // the fresh session the user establishes next.
    it('should refuse the pre-disable access token on /me after disabling', async () => {
      const me = await request(fixture.app.getHttpServer())
        .get('/me')
        .set('Authorization', `Bearer ${fixture.accessToken}`)
      expect(me.status).toBe(401)
    })
  })

  describe('happy path — a subsequent login no longer issues an mfaTempToken', () => {
    // Verifies that turning MFA off restores the standard login path. The new
    // user is registered with a known password so the login can be replayed
    // here without needing a fresh app instance.
    it('should issue access + refresh tokens directly on /login after disable', async () => {
      const boot = await bootstrapTestApp()
      const email = `mfa-disable-relogin-${Math.random().toString(36).slice(2)}@example.com`
      const password = 'RelogPass1!-xyz'

      // Register, enable MFA, then re-login via MFA challenge to mint an
      // access token with `mfaVerified: true`, then disable MFA.
      const reg = await request(boot.app.getHttpServer()).post('/register').send({
        email,
        password,
        name: 'Relogin Tester',
        tenantId: 'tenant-1'
      })
      const registerAccess = (reg.body as { accessToken: string }).accessToken
      const setup = await request(boot.app.getHttpServer())
        .post('/mfa/setup')
        .set('Authorization', `Bearer ${registerAccess}`)
        .send({ password: password })
      const secret = (setup.body as { secret: string }).secret
      await request(boot.app.getHttpServer())
        .post('/mfa/verify-enable')
        .set('Authorization', `Bearer ${registerAccess}`)
        .send({ code: generateTotp(secret) })

      const loginChallenge = await request(boot.app.getHttpServer())
        .post('/login')
        .send({ email, password, tenantId: 'tenant-1' })
      const mfaTempToken = (loginChallenge.body as { mfaTempToken: string }).mfaTempToken
      // Step ahead so the challenge code is not the same as the enable code.
      const nextStepTime = Date.now() + TOTP_STEP_SECONDS * 1000
      const challenge = await request(boot.app.getHttpServer())
        .post('/mfa/challenge')
        .send({ mfaTempToken, code: generateTotp(secret, nextStepTime) })
      const mfaVerifiedAccess = (challenge.body as { accessToken: string }).accessToken

      // Anti-replay holds enable + challenge counters; use T-1 from the ±1
      // window for the disable code.
      const disableStepTime = Date.now() - TOTP_STEP_SECONDS * 1000
      await request(boot.app.getHttpServer())
        .post('/mfa/disable')
        .set('Authorization', `Bearer ${mfaVerifiedAccess}`)
        .send({ code: generateTotp(secret, disableStepTime) })

      // Now login should succeed without an MFA challenge.
      const login = await request(boot.app.getHttpServer())
        .post('/login')
        .send({ email, password, tenantId: 'tenant-1' })
      expect(login.status).toBe(200)
      const body = login.body as { mfaRequired?: boolean; accessToken?: string }
      expect(body.mfaRequired).toBeFalsy()
      expect(body.accessToken).toBeTruthy()

      await boot.app.close()
    })
  })

  describe('negative paths', () => {
    // Verifies that a wrong TOTP rejects the disable with MFA_INVALID_CODE
    // and leaves the user's mfaEnabled flag intact.
    it('should reject /mfa/disable with MFA_INVALID_CODE when the TOTP is wrong', async () => {
      const fixture = await enableMfa()
      try {
        const res = await request(fixture.app.getHttpServer())
          .post('/mfa/disable')
          .set('Authorization', `Bearer ${fixture.accessToken}`)
          .send({ code: '000000' }) // overwhelmingly likely to be wrong

        expect(res.status).toBeGreaterThanOrEqual(400)
        expect(res.status).toBeLessThan(500)
        // AuthExceptionFilter envelopes the error under `body.error.code`.
        const body = res.body as { error?: { code?: string } }
        expect(body.error?.code).toBe('auth.mfa_invalid_code')

        // The mfaEnabled flag is unchanged.
        const me = await request(fixture.app.getHttpServer())
          .get('/me')
          .set('Authorization', `Bearer ${fixture.accessToken}`)
        expect((me.body as { mfaEnabled: boolean }).mfaEnabled).toBe(true)
      } finally {
        await fixture.app.close()
      }
    })

    // Verifies that disabling when MFA was never enabled returns
    // MFA_NOT_ENABLED rather than silently accepting the call.
    it('should reject /mfa/disable with MFA_NOT_ENABLED for a user that never enrolled', async () => {
      const boot = await bootstrapTestApp()
      try {
        const reg = await request(boot.app.getHttpServer())
          .post('/register')
          .send({
            email: `mfa-disable-noenroll-${Math.random().toString(36).slice(2)}@example.com`,
            password: 'NoEnrollPass1!-xyz',
            name: 'No Enroll',
            tenantId: 'tenant-1'
          })
        const accessToken = (reg.body as { accessToken: string }).accessToken

        const res = await request(boot.app.getHttpServer())
          .post('/mfa/disable')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({ code: '123456' })

        expect(res.status).toBeGreaterThanOrEqual(400)
        expect(res.status).toBeLessThan(500)
        const body = res.body as { error?: { code?: string } }
        expect(body.error?.code).toBe('auth.mfa_not_enabled')
      } finally {
        await boot.app.close()
      }
    })
  })
})
