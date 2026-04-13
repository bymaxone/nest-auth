import { IsEmail, IsNotEmpty, IsString, MaxLength } from 'class-validator'

/**
 * Data Transfer Object for the user login endpoint.
 *
 * Validated via NestJS `ValidationPipe` before reaching the service layer.
 */
export class LoginDto {
  /**
   * User's primary email address.
   */
  @IsEmail()
  email!: string

  /**
   * Plaintext password supplied by the user.
   *
   * @remarks
   * Deliberately without `@MinLength` — every password string (including very
   * short ones) is passed through to the scrypt comparison. This prevents timing
   * attacks that could reveal the application's minimum password length
   * requirement by observing which requests fail validation before reaching the
   * hash comparison.
   */
  @IsString()
  @MaxLength(128)
  password!: string

  /**
   * Tenant identifier used to scope the login attempt.
   */
  @IsString()
  @IsNotEmpty()
  tenantId!: string
}
