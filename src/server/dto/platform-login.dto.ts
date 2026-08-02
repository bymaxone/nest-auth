import { Transform } from 'class-transformer'
import { IsEmail, IsNotEmpty, IsString, Matches, MaxLength, MinLength } from 'class-validator'

/**
 * Data Transfer Object for the platform admin login endpoint.
 *
 * Platform users are not tenant-scoped, so no `tenantId` field is required.
 * Validated via NestJS `ValidationPipe` before reaching the service layer.
 *
 * @layer DTO
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
   * The floor is 1, not the deployment's policy length. This is a *login*: the password may
   * predate whatever the policy says today, and refusing it here locks an operator out of the
   * console with a validation error rather than an authentication one — while telling an
   * unauthenticated caller what the policy is, before any key derivation runs. The policy
   * belongs on the paths that SET a password. `@Matches(/\S/)` still rejects a blank value, so
   * nobody buys a KDF derivation for free, and `@MaxLength` bounds the payload.
   *
   * rust-auth bounds this field the same way, and the dashboard login always has.
   * Credentials are provisioned externally — the consuming application
   * may add stricter validation at the provisioning layer.
   */
  @IsString()
  @IsNotEmpty()
  @Matches(/\S/, { message: 'password must not be blank' })
  @MinLength(1)
  @MaxLength(128)
  password!: string
}
