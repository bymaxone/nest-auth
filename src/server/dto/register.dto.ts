import { IsEmail, IsNotEmpty, IsString, MaxLength, MinLength } from 'class-validator'

/**
 * Data Transfer Object for the user registration endpoint.
 *
 * Validated via NestJS `ValidationPipe` before reaching the service layer.
 * All validation rules are enforced at the HTTP boundary.
 */
export class RegisterDto {
  /**
   * User's primary email address.
   * Must be a valid RFC 5321 email format. Bounded to 255 characters — the
   * RFC-recommended practical maximum for addr-spec — matching the limit on
   * every other email-accepting DTO in the library.
   */
  @IsEmail()
  @MaxLength(255)
  email!: string

  /**
   * Plaintext password supplied by the user.
   *
   * @remarks
   * Minimum 8 characters for usability; maximum 128 characters as a practical
   * input bound. The service layer hashes this value immediately after receipt —
   * it is never logged or persisted in plaintext.
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
  @IsString()
  @IsNotEmpty()
  @MaxLength(128)
  tenantId!: string
}
