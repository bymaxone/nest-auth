import { Transform } from 'class-transformer'
import {
  IsEmail,
  IsNotEmpty,
  IsOptional,
  IsString,
  Length,
  MaxLength,
  MinLength
} from 'class-validator'

/**
 * Data Transfer Object for the reset-password endpoint.
 *
 * Exactly one of `token`, `otp`, or `verifiedToken` must be present.
 * The service layer validates this mutual exclusivity after DTO validation passes.
 *
 * @remarks
 * Optional fields enforce non-empty constraints so that if a value is submitted it
 * cannot be an empty string. `token` uses `@IsNotEmpty()`; `otp` uses `@Length(4, 8)`;
 * `verifiedToken` uses `@Length(64, 64)`. Without these guards, an empty string would
 * pass `@IsOptional()` and produce a valid (but incorrect) `sha256("")` key in Redis,
 * potentially allowing a crafted request to bypass token validation.
 */
export class ResetPasswordDto {
  /**
   * Email address of the account resetting its password.
   * Normalized to lowercase and trimmed for consistent identity lookups.
   */
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.trim().toLowerCase() : value
  )
  @IsEmail()
  @MaxLength(255)
  email!: string

  /**
   * New plaintext password chosen by the user.
   * Minimum 8 characters for usability; maximum 128 characters as a practical bound.
   * Hashed immediately by the service layer — never persisted in plaintext.
   */
  @IsString()
  @MinLength(8)
  @MaxLength(128)
  newPassword!: string

  /**
   * Signed reset token from the token-based flow (emailed as a URL parameter).
   * Mutually exclusive with `otp` and `verifiedToken`.
   */
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  @MaxLength(2048)
  token?: string

  /**
   * One-time password from the OTP-based flow (emailed as a numeric/alphanumeric code).
   * Mutually exclusive with `token` and `verifiedToken`.
   */
  @IsOptional()
  @IsString()
  @Length(4, 8)
  otp?: string

  /**
   * Temporary verification token issued by the `/verify-otp` endpoint (5-minute TTL).
   * Allows password reset without re-submitting the OTP.
   * Mutually exclusive with `token` and `otp`.
   * Exactly 64 characters — `generateSecureToken()` always produces exactly 64 hex chars.
   */
  @IsOptional()
  @IsString()
  @Length(64, 64)
  verifiedToken?: string

  /**
   * Tenant identifier that scopes the reset to a specific organization.
   * Validated against the stored tenant in the verifiedToken flow to prevent
   * cross-tenant password reset attacks.
   */
  @IsString()
  @IsNotEmpty()
  @MaxLength(128)
  tenantId!: string
}
