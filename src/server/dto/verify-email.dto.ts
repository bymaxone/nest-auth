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
 * Data Transfer Object for the verify-email endpoint.
 *
 * Verifies the user's email address by submitting the OTP that was sent
 * after registration (when `emailVerification.required` is enabled).
 *
 * @layer DTO
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
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  @MaxLength(128)
  @Matches(NO_CONTROL_CHARACTERS, { message: 'tenantId must not contain control characters' })
  tenantId?: string
}
