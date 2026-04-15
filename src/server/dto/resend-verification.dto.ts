import { Transform } from 'class-transformer'
import { IsEmail, IsNotEmpty, IsString, MaxLength } from 'class-validator'

/**
 * Data Transfer Object for the resend-verification endpoint.
 *
 * Requests a new email verification OTP to be sent to the user's address.
 * Subject to IP-level throttling configured in `AUTH_THROTTLE_CONFIGS.resendVerification`.
 * Always returns success regardless of user existence to prevent enumeration.
 */
export class ResendVerificationDto {
  /**
   * Email address to send the new verification OTP to.
   * Normalized to lowercase and trimmed for consistent identity lookups.
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
