import { Transform } from 'class-transformer'
import {
  IsEmail,
  IsNotEmpty,
  IsOptional,
  IsString,
  Length,
  Matches,
  MaxLength
} from 'class-validator'

import { NO_CONTROL_CHARACTERS } from './no-control-characters'

/**
 * Data Transfer Object for the verify-otp endpoint.
 *
 * Validates a password-reset OTP and exchanges it for a short-lived
 * `verifiedToken` (5-minute TTL) that can then be used with `ResetPasswordDto`
 * to complete the reset without re-submitting the OTP.
 *
 * @layer DTO
 */
export class VerifyOtpDto {
  /**
   * Email address of the account whose OTP is being verified.
   * Normalized to lowercase and trimmed for consistent Redis key derivation.
   */
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.trim().toLowerCase() : value
  )
  @IsEmail()
  @MaxLength(255)
  email!: string

  /**
   * One-time password code to verify.
   * Minimum 4 characters (minimum configurable `otpLength`); maximum 8 characters
   * (maximum configurable `otpLength` in `BymaxAuthModuleOptions.passwordReset`).
   * Using the full 4–8 range prevents DTO rejection from bypassing the OTP attempt counter.
   */
  @IsString()
  @Length(4, 8)
  otp!: string

  /**
   * Tenant identifier that scopes the verification to a specific organization.
   */
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  @MaxLength(128)
  @Matches(NO_CONTROL_CHARACTERS, { message: 'tenantId must not contain control characters' })
  tenantId?: string
}
