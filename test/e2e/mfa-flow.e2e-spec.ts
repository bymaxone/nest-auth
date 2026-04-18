/**
 * End-to-end MFA flow.
 *
 * Exercises the full TOTP MFA lifecycle (setup → enable → challenge with TOTP
 * → challenge with recovery code) through the real HTTP routes registered by
 * `MfaController` and `AuthController`. All requests are issued via supertest
 * against a fully-bootstrapped NestJS application — no controller methods are
 * called directly.
 *
 * The TOTP helper at the bottom of this file is a self-contained RFC 6238
 * implementation that mirrors `src/server/crypto/totp.ts` so the test never
 * imports library internals beyond the bootstrap helpers in `setup.ts`.
 */

import * as crypto from 'node:crypto'

import type { INestApplication } from '@nestjs/common'
import request from 'supertest'

import { bootstrapTestApp } from './setup'

// ---------------------------------------------------------------------------
// Constants — TOTP parameters mirroring src/server/crypto/totp.ts
// ---------------------------------------------------------------------------

/** TOTP time step in seconds (RFC 6238 §5.2). */
const TOTP_STEP_SECONDS = 30

/** Number of digits in a TOTP code (RFC 4226 §5.3). */
const TOTP_DIGITS = 6

/** Base32 alphabet per RFC 4648 §6 (uppercase A–Z and digits 2–7). */
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('mfa flow (E2E)', () => {
  // ---------------------------------------------------------------------------
  // Scenario 1 — Setup + verify-enable
  //
  // Each step in this scenario depends on the previous one (register → setup →
  // verify-enable → logout), so all setup work is performed in a single
  // `beforeAll` and the assertions are split across focused `it()` blocks. The
  // shared variables below are mutated by the chain — never reuse them across
  // scenarios.
  // ---------------------------------------------------------------------------

  describe('Scenario 1 — setup + verify-enable', () => {
    let app: INestApplication
    let accessToken: string
    let refreshToken: string
    let setupResponseBody: Record<string, unknown>
    let secret: string
    let recoveryCodes: string[]
    let logoutStatus: number

    // Shared state mutates step-by-step inside this beforeAll. Each `it()` below
    // verifies one slice of that chain.
    beforeAll(async () => {
      const bootstrap = await bootstrapTestApp({ tokenDelivery: 'bearer' })
      app = bootstrap.app

      // Step 1 — register a regular user. With emailVerification.required: false
      // (the bootstrapTestApp default), registration immediately yields tokens.
      const register = await request(app.getHttpServer()).post('/register').send({
        email: 'mfa-setup@example.com',
        password: 'SetupSecret123!',
        name: 'Setup User',
        tenantId: 'tenant-1'
      })
      accessToken = register.body.accessToken as string
      refreshToken = register.body.refreshToken as string

      // Step 2 — initiate MFA setup. The response body is captured here for the
      // dedicated assertion below.
      const setup = await request(app.getHttpServer())
        .post('/mfa/setup')
        .set('Authorization', `Bearer ${accessToken}`)
      setupResponseBody = setup.body as Record<string, unknown>
      secret = setupResponseBody['secret'] as string
      // Recovery codes are returned at the SETUP step (single-use display per the
      // service contract), not at verify-enable. The verify-enable step only
      // confirms the first TOTP code and persists the secret + hashed codes.
      recoveryCodes = setupResponseBody['recoveryCodes'] as string[]

      // Step 3 — generate a valid TOTP code from the returned secret.
      const totp = generateTotp(secret)

      // Step 4 — verify-enable with the TOTP code. The real route is
      // POST /mfa/verify-enable and returns 204 No Content — the recoveryCodes
      // were already returned at the setup step above.
      const verify = await request(app.getHttpServer())
        .post('/mfa/verify-enable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ code: totp })
      // Capture the verify response separately for assertions.
      ;(setupResponseBody as { verifyStatus: number }).verifyStatus = verify.status

      // Step 5 — logout. The access token used here remains valid up to its TTL
      // for the consumer's perspective but the refresh session is revoked.
      const logout = await request(app.getHttpServer())
        .post('/logout')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ refreshToken })
      logoutStatus = logout.status
    })

    afterAll(async () => {
      await app.close()
    })

    // Verifies that POST /mfa/setup returns a Base32 secret and a QR code URI for the authenticated user.
    it('should return a TOTP secret and QR code URI from /mfa/setup', () => {
      // Arrange — performed in beforeAll.

      // Act — performed in beforeAll.

      // Assert
      expect(secret).toEqual(expect.any(String))
      expect(secret.length).toBeGreaterThanOrEqual(32)
      expect(secret).toMatch(/^[A-Z2-7]+$/)
      // The library exposes the QR payload as `qrCodeUri` (otpauth:// URI). The
      // task brief mentions `qrCodeDataUrl` as an "or equivalent" alias — both
      // variants are accepted here so the test does not couple to either name.
      const qrField = setupResponseBody['qrCodeUri'] ?? setupResponseBody['qrCodeDataUrl']
      expect(typeof qrField).toBe('string')
      expect(qrField as string).toContain('otpauth://')
    })

    // Verifies that /mfa/setup also returns the one-time recovery codes the user must save.
    it('should return between 8 and 10 recovery codes from /mfa/setup', () => {
      // Arrange — performed in beforeAll.

      // Act — performed in beforeAll.

      // Assert — recovery codes are issued at setup, not at verify-enable. The
      // library's default count is 8 per `DEFAULT_RECOVERY_CODE_COUNT`.
      expect(Array.isArray(recoveryCodes)).toBe(true)
      expect(recoveryCodes.length).toBeGreaterThanOrEqual(8)
      expect(recoveryCodes.length).toBeLessThanOrEqual(10)
      for (const code of recoveryCodes) {
        expect(code).toMatch(/^\d{4}-\d{4}-\d{4}$/)
      }
    })

    // Verifies that POST /mfa/verify-enable accepts a valid TOTP code and returns 204 No Content.
    it('should accept the first TOTP code at /mfa/verify-enable and return 204', () => {
      // Arrange — performed in beforeAll.

      // Act — performed in beforeAll.

      // Assert — the controller is annotated with @HttpCode(NO_CONTENT) so a
      // successful enable returns 204. The MFA flag flips to true on the user
      // record; the assertion in Scenario 2 confirms this via /me after a
      // subsequent MFA challenge issues a fresh access token.
      expect((setupResponseBody as { verifyStatus: number }).verifyStatus).toBe(204)
    })

    // Verifies that POST /logout returns 204 once MFA is enabled on the account.
    it('should log out the user after MFA is enabled', () => {
      // Arrange — performed in beforeAll.

      // Act — performed in beforeAll.

      // Assert — AuthController.logout is decorated with @HttpCode(NO_CONTENT).
      // The task brief mentions 200 but the actual contract is 204; the test
      // asserts the actual contract.
      expect(logoutStatus).toBe(204)
    })
  })

  // ---------------------------------------------------------------------------
  // Scenario 2 — Challenge with TOTP
  //
  // A fresh test app is bootstrapped per scenario so that the in-memory
  // repository, Redis, and brute-force counters do not bleed between scenarios.
  // The chain (register → setup → enable → re-login → challenge → /me) runs in
  // beforeAll and the assertions are split across focused `it()` blocks.
  // ---------------------------------------------------------------------------

  describe('Scenario 2 — challenge with TOTP', () => {
    let app: INestApplication
    let secret: string
    let loginResponseBody: Record<string, unknown>
    let challengeResponseBody: Record<string, unknown>
    let challengeStatus: number
    let meResponseBody: Record<string, unknown>
    let meStatus: number

    // Shared state mutates step-by-step inside this beforeAll.
    beforeAll(async () => {
      const bootstrap = await bootstrapTestApp({ tokenDelivery: 'bearer' })
      app = bootstrap.app

      // Pre-flight — register, setup, enable MFA. These steps are duplicated
      // from Scenario 1 because each scenario gets a fresh app instance.
      const register = await request(app.getHttpServer()).post('/register').send({
        email: 'mfa-totp@example.com',
        password: 'TotpSecret456!',
        name: 'Totp User',
        tenantId: 'tenant-1'
      })
      const initialAccessToken = register.body.accessToken as string

      const setup = await request(app.getHttpServer())
        .post('/mfa/setup')
        .set('Authorization', `Bearer ${initialAccessToken}`)
      secret = setup.body.secret as string

      // Use the current step's TOTP for the enable step.
      const enableCode = generateTotp(secret)
      await request(app.getHttpServer())
        .post('/mfa/verify-enable')
        .set('Authorization', `Bearer ${initialAccessToken}`)
        .send({ code: enableCode })

      // Step 1 — re-login with the same credentials. With MFA enabled the
      // service returns the `mfaRequired: true` discriminator and a temp token
      // instead of issuing full auth tokens.
      const login = await request(app.getHttpServer()).post('/login').send({
        email: 'mfa-totp@example.com',
        password: 'TotpSecret456!',
        tenantId: 'tenant-1'
      })
      loginResponseBody = login.body as Record<string, unknown>

      // Step 2 — generate a fresh TOTP code one step ahead of the enable code.
      // Two effects matter here: (a) the enable step stored an anti-replay key
      // for `enableCode`, so reusing the same code would be rejected;
      // (b) using `currentStep + 1` is still inside the default ±1 acceptance
      // window so the server validates it.
      const nextStepTime = Date.now() + TOTP_STEP_SECONDS * 1000
      const challengeCode = generateTotp(secret, nextStepTime)

      // Step 3 — exchange the temp token + fresh TOTP for full auth tokens.
      const tempToken = loginResponseBody['mfaTempToken'] as string
      const challenge = await request(app.getHttpServer())
        .post('/mfa/challenge')
        .send({ mfaTempToken: tempToken, code: challengeCode })
      challengeStatus = challenge.status
      challengeResponseBody = challenge.body as Record<string, unknown>

      // Step 4 — /me with the new accessToken to confirm `mfaEnabled: true`
      // is reflected on the persisted user record.
      const newAccessToken = challengeResponseBody['accessToken'] as string
      const meRes = await request(app.getHttpServer())
        .get('/me')
        .set('Authorization', `Bearer ${newAccessToken}`)
      meStatus = meRes.status
      meResponseBody = meRes.body as Record<string, unknown>
    })

    afterAll(async () => {
      await app.close()
    })

    // Verifies that login on an MFA-enabled account returns the mfaRequired discriminator and a temp token.
    it('should return mfaRequired and an mfaTempToken from /login when MFA is enabled', () => {
      // Arrange — performed in beforeAll.

      // Act — performed in beforeAll.

      // Assert
      expect(loginResponseBody['mfaRequired']).toBe(true)
      expect(loginResponseBody['mfaTempToken']).toEqual(expect.any(String))
      // Tokens must NOT be issued on the password step when MFA is required.
      expect(loginResponseBody['accessToken']).toBeUndefined()
      expect(loginResponseBody['refreshToken']).toBeUndefined()
    })

    // Verifies that POST /mfa/challenge with a valid TOTP returns 200 and full auth tokens plus the user.
    it('should return access + refresh tokens and the user from /mfa/challenge with a valid TOTP', () => {
      // Arrange — performed in beforeAll.

      // Act — performed in beforeAll.

      // Assert
      expect(challengeStatus).toBe(200)
      expect(challengeResponseBody['accessToken']).toEqual(expect.any(String))
      expect(challengeResponseBody['refreshToken']).toEqual(expect.any(String))
      expect(challengeResponseBody['user']).toEqual(
        expect.objectContaining({ email: 'mfa-totp@example.com' })
      )
    })

    // Verifies that GET /me with the post-challenge accessToken reflects mfaEnabled === true.
    it('should reflect mfaEnabled === true on /me after the MFA challenge succeeds', () => {
      // Arrange — performed in beforeAll.

      // Act — performed in beforeAll.

      // Assert
      expect(meStatus).toBe(200)
      expect(meResponseBody).toEqual(
        expect.objectContaining({ email: 'mfa-totp@example.com', mfaEnabled: true })
      )
    })
  })

  // ---------------------------------------------------------------------------
  // Scenario 3 — Challenge with recovery code
  //
  // A fresh test app is bootstrapped per scenario. The chain registers a user,
  // enables MFA (capturing the recovery codes from setup), logs out and back
  // in, exchanges a recovery code for full tokens, and finally re-attempts the
  // same recovery code to confirm single-use semantics.
  // ---------------------------------------------------------------------------

  describe('Scenario 3 — challenge with recovery code', () => {
    let app: INestApplication
    let firstChallengeStatus: number
    let firstChallengeBody: Record<string, unknown>
    let replayChallengeStatus: number

    // Shared state mutates step-by-step inside this beforeAll.
    beforeAll(async () => {
      const bootstrap = await bootstrapTestApp({ tokenDelivery: 'bearer' })
      app = bootstrap.app

      // Step 1 — register and enable MFA in a fresh app.
      const register = await request(app.getHttpServer()).post('/register').send({
        email: 'mfa-recovery@example.com',
        password: 'RecoverySecret789!',
        name: 'Recovery User',
        tenantId: 'tenant-1'
      })
      const initialAccessToken = register.body.accessToken as string

      const setup = await request(app.getHttpServer())
        .post('/mfa/setup')
        .set('Authorization', `Bearer ${initialAccessToken}`)
      const secret = setup.body.secret as string
      // Step 2 — save the first recovery code for use in the challenge.
      const recoveryCodes = setup.body.recoveryCodes as string[]
      const firstRecoveryCode = recoveryCodes[0] as string

      const enableCode = generateTotp(secret)
      await request(app.getHttpServer())
        .post('/mfa/verify-enable')
        .set('Authorization', `Bearer ${initialAccessToken}`)
        .send({ code: enableCode })

      // Step 3 — logout and re-login. Logout revokes the refresh session;
      // re-login on an MFA-enabled account returns the temp token.
      await request(app.getHttpServer())
        .post('/logout')
        .set('Authorization', `Bearer ${initialAccessToken}`)
        .send({ refreshToken: register.body.refreshToken as string })

      const login = await request(app.getHttpServer()).post('/login').send({
        email: 'mfa-recovery@example.com',
        password: 'RecoverySecret789!',
        tenantId: 'tenant-1'
      })
      const tempToken = login.body.mfaTempToken as string

      // Step 4 — exchange the recovery code for full tokens.
      const firstChallenge = await request(app.getHttpServer())
        .post('/mfa/challenge')
        .send({ mfaTempToken: tempToken, code: firstRecoveryCode })
      firstChallengeStatus = firstChallenge.status
      firstChallengeBody = firstChallenge.body as Record<string, unknown>

      // Step 5 — re-login to obtain a fresh temp token, then re-attempt the
      // same recovery code. The token is single-use, so this call must be
      // rejected even though the temp token is fresh.
      const secondLogin = await request(app.getHttpServer()).post('/login').send({
        email: 'mfa-recovery@example.com',
        password: 'RecoverySecret789!',
        tenantId: 'tenant-1'
      })
      const secondTempToken = secondLogin.body.mfaTempToken as string

      const replayChallenge = await request(app.getHttpServer())
        .post('/mfa/challenge')
        .send({ mfaTempToken: secondTempToken, code: firstRecoveryCode })
      replayChallengeStatus = replayChallenge.status
    })

    afterAll(async () => {
      await app.close()
    })

    // Verifies that POST /mfa/challenge accepts a valid recovery code and returns 200 with full tokens.
    it('should issue tokens when /mfa/challenge is called with a valid recovery code', () => {
      // Arrange — performed in beforeAll.

      // Act — performed in beforeAll.

      // Assert
      expect(firstChallengeStatus).toBe(200)
      expect(firstChallengeBody['accessToken']).toEqual(expect.any(String))
      expect(firstChallengeBody['refreshToken']).toEqual(expect.any(String))
      expect(firstChallengeBody['user']).toEqual(
        expect.objectContaining({ email: 'mfa-recovery@example.com' })
      )
    })

    // Verifies that the same recovery code cannot be used a second time (single-use semantics).
    it('should reject a re-attempt of the same recovery code as already consumed', () => {
      // Arrange — performed in beforeAll.

      // Act — performed in beforeAll.

      // Assert — the service splices the matched recovery code out of the
      // stored list after the first successful exchange. A second submission
      // matches no stored hash → MFA_INVALID_CODE → 401 Unauthorized.
      expect(replayChallengeStatus).toBe(401)
    })
  })
})

// ---------------------------------------------------------------------------
// TOTP helper — RFC 6238 / RFC 4226 implementation using node:crypto only.
//
// Mirrors `src/server/crypto/totp.ts` so the test stays decoupled from library
// internals beyond the bootstrap helpers in `setup.ts`. Uses HMAC-SHA1 + 30s
// step + 6-digit code, matching Google Authenticator and the verifier in
// `verifyTotp()` on the server side.
// ---------------------------------------------------------------------------

/**
 * Generates a 6-digit TOTP code for the given Base32 secret at the given time.
 *
 * @param base32Secret - Base32-encoded TOTP secret (RFC 4648 §6, no padding).
 * @param time - Unix epoch milliseconds. Defaults to `Date.now()`.
 * @returns Zero-padded 6-digit TOTP code as a string.
 */
function generateTotp(base32Secret: string, time: number = Date.now()): string {
  const key = base32Decode(base32Secret)
  const counter = Math.floor(time / 1000 / TOTP_STEP_SECONDS)

  // 8-byte big-endian counter per RFC 4226 §5.3.
  const buf = Buffer.alloc(8)
  buf.writeBigUInt64BE(BigInt(counter))

  const hmac = crypto.createHmac('sha1', key).update(buf).digest()

  // Dynamic truncation per RFC 4226 §5.4.
  const offset = (hmac[hmac.length - 1] as number) & 0x0f
  const code =
    (((hmac[offset] as number) & 0x7f) << 24) |
    (((hmac[offset + 1] as number) & 0xff) << 16) |
    (((hmac[offset + 2] as number) & 0xff) << 8) |
    ((hmac[offset + 3] as number) & 0xff)

  return (code % 10 ** TOTP_DIGITS).toString().padStart(TOTP_DIGITS, '0')
}

/**
 * Decodes a Base32 string per RFC 4648 §6 into raw bytes.
 *
 * Strips trailing `=` padding and silently ignores characters outside the
 * Base32 alphabet so user-friendly group separators (spaces, hyphens) are
 * accepted.
 *
 * @param input - Base32-encoded input.
 * @returns Decoded bytes as a Buffer.
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
