import { Transform } from 'class-transformer'
import { IsEmail, IsNotEmpty, IsOptional, IsString, Matches, MaxLength } from 'class-validator'

import { NO_CONTROL_CHARACTERS } from './no-control-characters'

/**
 * Data Transfer Object for the forgot-password endpoint.
 *
 * Initiates the password reset flow by sending a token or OTP to the user's
 * email. Always returns success regardless of whether the email exists to
 * prevent user enumeration.
 *
 * @layer DTO
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
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  @MaxLength(128)
  @Matches(NO_CONTROL_CHARACTERS, { message: 'tenantId must not contain control characters' })
  tenantId?: string
}
