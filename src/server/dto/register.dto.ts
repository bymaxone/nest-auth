import { Transform } from 'class-transformer'
import {
  IsEmail,
  IsNotEmpty,
  IsOptional,
  IsString,
  Matches,
  MaxLength,
  MinLength
} from 'class-validator'

import { NO_CONTROL_CHARACTERS } from './no-control-characters'

/**
 * Data Transfer Object for the user registration endpoint.
 *
 * Validated via NestJS `ValidationPipe` before reaching the service layer.
 * All validation rules are enforced at the HTTP boundary.
 *
 * @layer DTO
 */
export class RegisterDto {
  /**
   * User's primary email address.
   * Must be a valid RFC 5321 email format. Bounded to 255 characters — the
   * RFC-recommended practical maximum for addr-spec — matching the limit on
   * every other email-accepting DTO in the library.
   *
   * Normalized to lowercase and trimmed so the stored identity matches the
   * canonical form used by the case-insensitive login lookup and every other
   * e-mail-keyed control (brute-force counter, reset tokens, verification OTP).
   */
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.trim().toLowerCase() : value
  )
  @IsEmail()
  @MaxLength(255)
  email!: string

  /**
   * Plaintext password supplied by the user.
   *
   * @remarks
   * The 8-character floor here is STRUCTURAL, not the deployment's policy: it is the lowest
   * NIST SP 800-63B-4 §3.1.1.1 permits under any circumstance, and it is what a decorator
   * can express — decorators are evaluated when the class is defined, before any
   * configuration exists. The policy floor is `password.minLength` (default 15, as the
   * standard requires of a single-factor password), enforced by `PasswordService` and
   * answering this same `auth.validation` code and details shape.
   *
   * Maximum 128 characters as a practical
   * input bound. The service layer hashes this value immediately after receipt —
   * it is never logged or persisted in plaintext BY THIS LIBRARY — a breach checker or repository
   * you supply receives it, and an error either raises is a place it can be. See
   * `PasswordService.assertNotCompromised` for the ceiling and how the library holds its own half.
   */
  @IsString()
  @MinLength(8)
  @MaxLength(128)
  password!: string

  /**
   * User's display name.
   * At least 2 characters (prevents single-character placeholders); capped at
   * 128 characters so an unbounded string cannot inflate DB columns or logs.
   */
  @IsString()
  @MinLength(2)
  @MaxLength(128)
  name!: string

  /**
   * Tenant identifier that scopes the new user to a specific organization.
   * Bounded to 128 characters — part of HMAC pre-images and Redis keys.
   */
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  @MaxLength(128)
  @Matches(NO_CONTROL_CHARACTERS, { message: 'tenantId must not contain control characters' })
  tenantId?: string
}
