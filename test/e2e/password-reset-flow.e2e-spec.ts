/**
 * End-to-end password-reset flow.
 *
 * Exercises the full password-reset lifecycle for both reset methods exposed by
 * `PasswordResetController` — the token-based flow and the OTP-based flow that
 * exchanges an OTP for a `verifiedToken` before applying the new password. Each
 * step issues a real HTTP request via supertest against a fully-bootstrapped
 * NestJS application — no controller or service methods are invoked directly.
 *
 * The shared in-memory email mock in `setup.ts` discards the raw token / OTP
 * values it receives because production code never logs them. To verify the
 * end-to-end flow this suite installs a thin per-test override on the email
 * provider that embeds the real value into the captured `html` field, mirroring
 * what a real consumer (Resend, SendGrid, …) would render. The override is the
 * only piece of state shared between the chain steps inside each scenario.
 */

import type { INestApplication } from '@nestjs/common'
import request from 'supertest'

import type { CapturedEmail, MockEmailProvider } from './setup'
import { bootstrapTestApp } from './setup'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Patches a {@link MockEmailProvider} so that password-reset sends embed the
 * raw token or OTP into the captured `html` body, the way a real provider
 * would render its template. Returning the same `sentEmails` reference allows
 * callers to keep a stable handle on the captures across the chain steps.
 */
function instrumentPasswordResetEmails(email: MockEmailProvider): CapturedEmail[] {
  // Reassign the methods directly — the same `email` instance is held by the
  // NestJS DI container via `useValue`, so the service will call our overrides.
  ;(
    email as { sendPasswordResetToken: MockEmailProvider['sendPasswordResetToken'] }
  ).sendPasswordResetToken = async (to: string, token: string): Promise<void> => {
    const html = `<p>Reset your password: <a href="https://app.example.com/reset?token=${token}">Click here</a></p>`
    email.sentEmails.push({ to, subject: 'Password reset', html })
  }
  ;(
    email as { sendPasswordResetOtp: MockEmailProvider['sendPasswordResetOtp'] }
  ).sendPasswordResetOtp = async (to: string, otp: string): Promise<void> => {
    const html = `<p>Your password reset code is <strong>${otp}</strong></p>`
    email.sentEmails.push({ to, subject: 'Password reset OTP', html })
  }

  return email.sentEmails
}

/**
 * Polls the captured emails array until at least one entry matching `predicate`
 * exists, returning that entry. Required because the service fires the email
 * call as fire-and-forget (`void Promise.resolve(...)`) — the HTTP response
 * may return before the email is appended to the array.
 *
 * @throws Error when no matching email arrives within `timeoutMs`.
 */
async function waitForEmail(
  sentEmails: CapturedEmail[],
  predicate: (email: CapturedEmail) => boolean,
  timeoutMs = 1_000
): Promise<CapturedEmail> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    const found = sentEmails.find(predicate)
    if (found) return found
    await new Promise((resolve) => setTimeout(resolve, 5))
  }
  throw new Error(`Timed out waiting for email after ${timeoutMs}ms`)
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('password reset flow (E2E)', () => {
  // ---------------------------------------------------------------------------
  // Token method
  //
  // The chain (register → forgot-password → extract token from email → reset →
  // login with new password → login with old password) runs in a single
  // `beforeAll` and the assertions are split across focused `it()` blocks. The
  // shared variables below mutate step-by-step inside that hook.
  // ---------------------------------------------------------------------------

  describe('token method', () => {
    let app: INestApplication
    let forgotStatus: number
    let resetStatus: number
    let loginNewStatus: number
    let loginNewBody: Record<string, unknown>
    let loginOldStatus: number
    let extractedToken: string

    // Shared state mutates step-by-step inside this beforeAll. Each `it()` below
    // verifies one slice of that chain.
    beforeAll(async () => {
      const bootstrap = await bootstrapTestApp({
        tokenDelivery: 'bearer',
        passwordReset: { method: 'token', tokenTtlSeconds: 3_600 }
      })
      app = bootstrap.app
      const sentEmails = instrumentPasswordResetEmails(bootstrap.email)

      // Step 1 — register the user whose password will be reset.
      await request(app.getHttpServer()).post('/register').send({
        email: 'reset-token@example.com',
        password: 'OldSecret123!',
        name: 'Token Reset User',
        tenantId: 'tenant-1'
      })

      // Step 2 — POST /password/forgot-password initiates the flow. Always 200
      // regardless of whether the email exists (anti-enumeration).
      const forgot = await request(app.getHttpServer()).post('/password/forgot-password').send({
        email: 'reset-token@example.com',
        tenantId: 'tenant-1'
      })
      forgotStatus = forgot.status

      // Step 3 — extract the token from the captured email's HTML body. The
      // service generates a 64-char hex token and the instrumented provider
      // embeds it as `?token=<hex>` in the URL.
      const resetEmail = await waitForEmail(
        sentEmails,
        (e) => e.to === 'reset-token@example.com' && e.subject === 'Password reset'
      )
      const match = /[?&]token=([a-f0-9]+)/i.exec(resetEmail.html)
      extractedToken = match ? (match[1] as string) : ''

      // Step 4 — POST /password/reset-password with the extracted token. The
      // controller is annotated with @HttpCode(NO_CONTENT) so the response is 204.
      const reset = await request(app.getHttpServer()).post('/password/reset-password').send({
        email: 'reset-token@example.com',
        tenantId: 'tenant-1',
        token: extractedToken,
        newPassword: 'NewSecret456!'
      })
      resetStatus = reset.status

      // Step 5 — login with the new password should succeed and issue tokens.
      const loginNew = await request(app.getHttpServer()).post('/login').send({
        email: 'reset-token@example.com',
        password: 'NewSecret456!',
        tenantId: 'tenant-1'
      })
      loginNewStatus = loginNew.status
      loginNewBody = loginNew.body as Record<string, unknown>

      // Step 6 — login with the OLD password must be rejected. The brute-force
      // counter at 5 attempts/window leaves plenty of headroom here for the
      // single attempt this scenario performs.
      const loginOld = await request(app.getHttpServer()).post('/login').send({
        email: 'reset-token@example.com',
        password: 'OldSecret123!',
        tenantId: 'tenant-1'
      })
      loginOldStatus = loginOld.status
    })

    afterAll(async () => {
      await app.close()
    })

    // Verifies that POST /password/forgot-password returns 200 without revealing whether the email exists.
    it('should return 200 from /password/forgot-password without leaking account existence', () => {
      // Arrange — performed in beforeAll.

      // Act — performed in beforeAll.

      // Assert — the controller is annotated with @HttpCode(OK) and the
      // anti-enumeration design returns 200 regardless of outcome.
      expect(forgotStatus).toBe(200)
    })

    // Verifies that the captured email contains a 64-character hex token embedded in the reset URL.
    it('should embed a 64-character hex token in the reset email URL', () => {
      // Arrange — performed in beforeAll.

      // Act — performed in beforeAll.

      // Assert — `generateSecureToken()` always produces exactly 64 hex chars.
      expect(extractedToken).toMatch(/^[a-f0-9]{64}$/)
    })

    // Verifies that POST /password/reset-password with a valid token returns 204 No Content.
    it('should accept the token at /password/reset-password and return 204', () => {
      // Arrange — performed in beforeAll.

      // Act — performed in beforeAll.

      // Assert — PasswordResetController.resetPassword is annotated with
      // @HttpCode(NO_CONTENT). A successful reset has no response body.
      expect(resetStatus).toBe(204)
    })

    // Verifies that POST /login with the new password returns 200 and issues a fresh token pair.
    it('should issue tokens when logging in with the new password', () => {
      // Arrange — performed in beforeAll.

      // Act — performed in beforeAll.

      // Assert
      expect(loginNewStatus).toBe(200)
      expect(loginNewBody['accessToken']).toEqual(expect.any(String))
      expect(loginNewBody['refreshToken']).toEqual(expect.any(String))
      expect(loginNewBody['user']).toEqual(
        expect.objectContaining({ email: 'reset-token@example.com' })
      )
    })

    // Verifies that POST /login with the old password is rejected with 401 after the reset.
    it('should reject /login with the old password after the reset succeeds', () => {
      // Arrange — performed in beforeAll.

      // Act — performed in beforeAll.

      // Assert — the password hash was rotated by `applyPasswordReset`, so the
      // old plaintext no longer matches and the credential check fails.
      expect(loginOldStatus).toBe(401)
    })
  })

  // ---------------------------------------------------------------------------
  // OTP method
  //
  // The chain (register → forgot-password (OTP) → extract OTP → verify-otp for
  // verifiedToken → reset with verifiedToken → login with new password) runs
  // in a single `beforeAll` and the assertions are split across focused `it()`
  // blocks. The shared variables below mutate step-by-step inside that hook.
  // ---------------------------------------------------------------------------

  describe('otp method', () => {
    let app: INestApplication
    let forgotStatus: number
    let verifyOtpStatus: number
    let verifyOtpBody: Record<string, unknown>
    let resetStatus: number
    let loginNewStatus: number
    let loginNewBody: Record<string, unknown>
    let extractedOtp: string
    let verifiedToken: string

    // Shared state mutates step-by-step inside this beforeAll. Each `it()` below
    // verifies one slice of that chain.
    beforeAll(async () => {
      // OTP mode is selected at module configuration time (not per-request) —
      // see `PasswordResetService.initiateReset` which branches on
      // `options.passwordReset.method`. Bootstrap a fresh app with method 'otp'.
      const bootstrap = await bootstrapTestApp({
        tokenDelivery: 'bearer',
        passwordReset: { method: 'otp', otpLength: 6, otpTtlSeconds: 600 }
      })
      app = bootstrap.app
      const sentEmails = instrumentPasswordResetEmails(bootstrap.email)

      // Step 1 — register a fresh user with a distinct email to keep this
      // scenario independent from the token-method scenario above.
      await request(app.getHttpServer()).post('/register').send({
        email: 'reset-otp@example.com',
        password: 'OldOtpSecret123!',
        name: 'Otp Reset User',
        tenantId: 'tenant-1'
      })

      // Step 2 — POST /password/forgot-password. The DTO carries no `method`
      // field — the server-side configuration determines whether a token or an
      // OTP is sent. Always 200 (anti-enumeration).
      const forgot = await request(app.getHttpServer()).post('/password/forgot-password').send({
        email: 'reset-otp@example.com',
        tenantId: 'tenant-1'
      })
      forgotStatus = forgot.status

      // Step 3 — extract the 6-digit OTP from the captured email's HTML body.
      const otpEmail = await waitForEmail(
        sentEmails,
        (e) => e.to === 'reset-otp@example.com' && e.subject === 'Password reset OTP'
      )
      const match = /<strong>(\d{6})<\/strong>/.exec(otpEmail.html)
      extractedOtp = match ? (match[1] as string) : ''

      // Step 4 — POST /password/verify-otp exchanges the OTP for a 64-char
      // single-use `verifiedToken` valid for 5 minutes.
      const verify = await request(app.getHttpServer()).post('/password/verify-otp').send({
        email: 'reset-otp@example.com',
        tenantId: 'tenant-1',
        otp: extractedOtp
      })
      verifyOtpStatus = verify.status
      verifyOtpBody = verify.body as Record<string, unknown>
      verifiedToken = verifyOtpBody['verifiedToken'] as string

      // Step 5 — POST /password/reset-password with the verifiedToken. Returns
      // 204 No Content per the controller's @HttpCode(NO_CONTENT) decorator.
      const reset = await request(app.getHttpServer()).post('/password/reset-password').send({
        email: 'reset-otp@example.com',
        tenantId: 'tenant-1',
        verifiedToken,
        newPassword: 'NewOtpSecret456!'
      })
      resetStatus = reset.status

      // Step 6 — login with the new password should succeed.
      const loginNew = await request(app.getHttpServer()).post('/login').send({
        email: 'reset-otp@example.com',
        password: 'NewOtpSecret456!',
        tenantId: 'tenant-1'
      })
      loginNewStatus = loginNew.status
      loginNewBody = loginNew.body as Record<string, unknown>
    })

    afterAll(async () => {
      await app.close()
    })

    // Verifies that POST /password/forgot-password returns 200 in OTP mode without leaking existence.
    it('should return 200 from /password/forgot-password in OTP mode', () => {
      // Arrange — performed in beforeAll.

      // Act — performed in beforeAll.

      // Assert
      expect(forgotStatus).toBe(200)
    })

    // Verifies that the captured email contains a 6-digit OTP code.
    it('should embed a 6-digit OTP in the reset email body', () => {
      // Arrange — performed in beforeAll.

      // Act — performed in beforeAll.

      // Assert — the configured `otpLength: 6` causes `OtpService.generate(6)`
      // to emit a zero-padded numeric code of exactly 6 digits.
      expect(extractedOtp).toMatch(/^\d{6}$/)
    })

    // Verifies that POST /password/verify-otp returns 200 with a 64-character hex verifiedToken.
    it('should exchange the OTP for a 64-character hex verifiedToken', () => {
      // Arrange — performed in beforeAll.

      // Act — performed in beforeAll.

      // Assert
      expect(verifyOtpStatus).toBe(200)
      expect(verifiedToken).toMatch(/^[a-f0-9]{64}$/)
    })

    // Verifies that POST /password/reset-password with a verifiedToken returns 204 No Content.
    it('should accept the verifiedToken at /password/reset-password and return 204', () => {
      // Arrange — performed in beforeAll.

      // Act — performed in beforeAll.

      // Assert
      expect(resetStatus).toBe(204)
    })

    // Verifies that POST /login with the new password returns 200 and issues fresh tokens after the OTP-based reset.
    it('should issue tokens when logging in with the new password after the OTP reset', () => {
      // Arrange — performed in beforeAll.

      // Act — performed in beforeAll.

      // Assert
      expect(loginNewStatus).toBe(200)
      expect(loginNewBody['accessToken']).toEqual(expect.any(String))
      expect(loginNewBody['refreshToken']).toEqual(expect.any(String))
      expect(loginNewBody['user']).toEqual(
        expect.objectContaining({ email: 'reset-otp@example.com' })
      )
    })
  })
})
