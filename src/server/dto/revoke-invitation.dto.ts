import { Transform } from 'class-transformer'
import { IsEmail, IsNotEmpty, MaxLength } from 'class-validator'

/**
 * Data Transfer Object for the revoke invitation endpoint.
 *
 * Validated via NestJS `ValidationPipe` before reaching the service layer.
 *
 * @remarks
 * `tenantId` is intentionally absent for the same reason it is absent from
 * `CreateInvitationDto` — it comes from the authenticated caller's JWT, never from the
 * body. Accepting it here would let a caller withdraw invitations in a tenant they have
 * no authority over.
 *
 * The address is the whole payload because it is the only handle the issuing side has:
 * the invitation record is keyed by the hash of a token that only the invitee's mailbox
 * ever held.
 *
 * @layer DTO
 */
export class RevokeInvitationDto {
  /**
   * Email address whose pending invitation is being withdrawn.
   * Normalized to lowercase and trimmed so it matches the address the invitation was
   * indexed under.
   */
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.trim().toLowerCase() : value
  )
  @IsEmail()
  @IsNotEmpty()
  @MaxLength(255)
  email!: string
}
