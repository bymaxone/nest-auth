import { Transform } from 'class-transformer'
import { IsEmail, IsNotEmpty, IsString, Matches, MaxLength, MinLength } from 'class-validator'

/**
 * Data Transfer Object for the platform admin login endpoint.
 *
 * Platform users are not tenant-scoped, so no `tenantId` field is required.
 * Validated via NestJS `ValidationPipe` before reaching the service layer.
 */
export class PlatformLoginDto {
  /**
   * Platform admin's primary email address.
   *
   * Automatically trimmed and lowercased before validation.
   */
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.trim().toLowerCase() : value
  )
  @IsEmail()
  @IsNotEmpty()
  @MaxLength(255)
  email!: string

  /**
   * Plaintext password supplied by the platform admin.
   *
   * @remarks
   * A minimum of 12 characters is enforced as a library-level floor.
   * The `@MaxLength` guard prevents DoS via oversized payloads.
   * Credentials are provisioned externally — the consuming application
   * may add stricter validation at the provisioning layer.
   */
  @IsString()
  @IsNotEmpty()
  @Matches(/\S/, { message: 'password must not be blank' })
  @MinLength(12)
  @MaxLength(128)
  password!: string
}
