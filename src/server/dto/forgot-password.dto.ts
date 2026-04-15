import { Transform } from 'class-transformer'
import { IsEmail, IsNotEmpty, IsString, MaxLength } from 'class-validator'

/**
 * Data Transfer Object for the forgot-password endpoint.
 *
 * Initiates the password reset flow by sending a token or OTP to the user's
 * email. Always returns success regardless of whether the email exists to
 * prevent user enumeration.
 */
export class ForgotPasswordDto {
  /**
   * Email address of the account requesting a password reset.
   * Normalized to lowercase and trimmed to ensure consistent Redis key derivation
   * and brute-force counter lookups.
   */
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.trim().toLowerCase() : value
  )
  @IsEmail()
  @MaxLength(255)
  email!: string

  /**
   * Tenant identifier that scopes the reset request to a specific organization.
   */
  @IsString()
  @IsNotEmpty()
  @MaxLength(128)
  tenantId!: string
}
