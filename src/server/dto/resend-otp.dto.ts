import { Transform } from 'class-transformer'
import { IsEmail, IsNotEmpty, IsString, MaxLength } from 'class-validator'

/**
 * Data Transfer Object for the resend-otp endpoint.
 *
 * Requests a new password-reset OTP to be sent to the user's email.
 * Subject to a 60-second atomic cooldown enforced via a Redis NX key to
 * prevent OTP flooding. Always returns success regardless of user existence
 * to prevent enumeration.
 */
export class ResendOtpDto {
  /**
   * Email address of the account requesting a new OTP.
   * Normalized to lowercase and trimmed for consistent Redis cooldown key derivation.
   */
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.trim().toLowerCase() : value
  )
  @IsEmail()
  @MaxLength(255)
  email!: string

  /**
   * Tenant identifier that scopes the resend request to a specific organization.
   */
  @IsString()
  @IsNotEmpty()
  @MaxLength(128)
  tenantId!: string
}
