import { IsString, MaxLength, MinLength } from 'class-validator'

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
}
