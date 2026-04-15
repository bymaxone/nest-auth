import { Transform } from 'class-transformer'
import { IsEmail, IsNotEmpty, IsString, Length, MaxLength } from 'class-validator'

/**
 * Data Transfer Object for the verify-email endpoint.
 *
 * Verifies the user's email address by submitting the OTP that was sent
 * after registration (when `emailVerification.required` is enabled).
 */
export class VerifyEmailDto {
  /**
   * Email address to be verified.
   * Normalized to lowercase and trimmed for consistent OTP key lookups.
   */
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.trim().toLowerCase() : value
  )
  @IsEmail()
  @MaxLength(255)
  email!: string

  /**
   * One-time password code sent to the email for verification.
   * Email-verification OTPs are always 6 digits (fixed — `emailVerification`
   * does not expose an `otpLength` option).
   */
  @IsString()
  @Length(6, 6)
  otp!: string

  /**
   * Tenant identifier that scopes the verification to a specific organization.
   */
  @IsString()
  @IsNotEmpty()
  @MaxLength(128)
  tenantId!: string
}
