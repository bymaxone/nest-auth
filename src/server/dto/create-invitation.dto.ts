import { Transform } from 'class-transformer'
import { IsEmail, IsNotEmpty, IsOptional, IsString, MaxLength } from 'class-validator'

/**
 * Data Transfer Object for the create invitation endpoint.
 *
 * Validated via NestJS `ValidationPipe` before reaching the service layer.
 *
 * @remarks
 * `tenantId` is intentionally absent — it is always extracted from the
 * authenticated inviter's JWT payload in the controller, never from the
 * request body. Accepting `tenantId` from the body would allow an attacker
 * to invite users into a different tenant.
 *
 * Role validation against the configured hierarchy is performed in
 * `InvitationService.invite()` — not here — because `class-validator`
 * decorators have no access to the NestJS DI container at validation time.
 */
export class CreateInvitationDto {
  /**
   * Email address of the user being invited.
   * Must be a valid RFC 5321 email format.
   * Normalized to lowercase and trimmed for consistent identity lookups.
   */
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.trim().toLowerCase() : value
  )
  @IsEmail()
  @IsNotEmpty()
  @MaxLength(255)
  email!: string

  /**
   * Role to assign to the invited user upon acceptance.
   *
   * @remarks
   * Validated against `roles.hierarchy` in the service layer.
   * The inviter must hold a role >= the role being invited (enforced by `hasRole()`).
   */
  @IsString()
  @IsNotEmpty()
  @MaxLength(64)
  role!: string

  /**
   * Optional human-readable tenant name for the invitation email.
   *
   * When omitted, `InvitationService` falls back to `tenantId` as the display value.
   * This field was added to satisfy the `IEmailProvider.sendInvitation()` contract —
   * it is not part of the original spec DTO but is safe to accept from the caller.
   *
   * `@MaxLength(128)` prevents oversized display values from being stored in the
   * Redis invitation payload and forwarded to the email provider.
   */
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  @MaxLength(128)
  tenantName?: string
}
