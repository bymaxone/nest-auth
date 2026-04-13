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
   * Must be a valid RFC 5321 email format.
   */
  @IsEmail()
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
   * Must be at least 2 characters to prevent single-character placeholders.
   */
  @IsString()
  @MinLength(2)
  name!: string

  /**
   * Tenant identifier that scopes the new user to a specific organization.
   * Must be a non-empty string.
   */
  @IsString()
  @IsNotEmpty()
  tenantId!: string
}
