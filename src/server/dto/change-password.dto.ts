import { IsOptional, IsString, MaxLength, MinLength } from 'class-validator'

/**
 * Data Transfer Object for changing the password of an already-authenticated account.
 *
 * Submitted to `POST {prefix}/password/change`. Distinct from {@link ResetPasswordDto}, which
 * serves the *unauthenticated* recovery flow and proves identity with an emailed token or OTP:
 * here the proof is the current password, which is the only thing a stolen session does not
 * carry.
 *
 * @layer DTO
 */
export class ChangePasswordDto {
  /**
   * The account's current password, re-proving who is asking.
   *
   * ASVS v5 §6.2.3 requires a password change to take both the current and the new password,
   * and the reason is exactly the session-theft case: an access token lifted by XSS or from a
   * shared machine would otherwise be enough to rotate the credential, lock the real owner
   * out of their own account, and keep the attacker in.
   *
   * `@MinLength(1)` is the only floor, matching `LoginDto`: rejecting the empty string keeps a
   * caller from spending a scrypt derivation for free, while enforcing the deployment's real
   * policy length here would leak it as a pre-KDF timing signal — and the value is a *current*
   * password, which may predate whatever the policy says today.
   */
  @IsString()
  @MinLength(1)
  @MaxLength(128)
  currentPassword!: string

  /**
   * New plaintext password chosen by the user.
   * The 8-character floor here is STRUCTURAL, not the deployment's policy: it is the lowest
   * NIST SP 800-63B-4 §3.1.1.1 permits under any circumstance, and it is what a decorator
   * can express — decorators are evaluated when the class is defined, before any
   * configuration exists. The policy floor is `password.minLength` (default 15, as the
   * standard requires of a single-factor password), enforced by `PasswordService` and
   * answering this same `auth.validation` code and details shape.
   *
   * Maximum 128 characters as a practical bound.
   * Hashed immediately by the service layer — never persisted in plaintext.
   */
  @IsString()
  @MinLength(8)
  @MaxLength(128)
  newPassword!: string

  /**
   * The caller's own refresh token, so the device making the change stays signed in.
   *
   * Declared because the handler reads it. `TokenDeliveryService.extractRefreshToken` takes it
   * from the refresh cookie under `tokenDelivery: 'cookie'` and from **this body field** under
   * `'bearer'`, cookie-first-then-body under `'both'` — and the controller pipe runs
   * `forbidNonWhitelisted: true`, so an undeclared property is refused. A bearer-mode caller
   * therefore could not send the field the endpoint needs: the request was answered
   * `auth.validation` naming `refreshToken`, and the only way to change a password was to give
   * up every other session.
   *
   * It stayed invisible because the E2E harness installed a global `ValidationPipe` with
   * `whitelist: true`, which STRIPPED the property before the controller's own pipe could refuse
   * it — so the suite exercised a request production never sees. Optional, because under cookie
   * delivery the credential arrives in the cookie and no body field exists to declare.
   */
  @IsOptional()
  @IsString()
  @MaxLength(512)
  refreshToken?: string
}
