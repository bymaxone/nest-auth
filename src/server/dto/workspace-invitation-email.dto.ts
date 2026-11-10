/**
 * @fileoverview The body of the invitation routes that name a pending invitation by its address:
 * resend and revoke.
 *
 * @layer DTO
 */

import { Transform } from 'class-transformer'
import { IsEmail, IsNotEmpty, MaxLength } from 'class-validator'

/**
 * The address of a pending invitation.
 *
 * The address is the only handle the issuing side has: the record is keyed by the digest of a token
 * only the invitee's mailbox held.
 */
export class WorkspaceInvitationEmailDto {
  /** The invitee; trimmed and lowercased so it matches the address the invitation is indexed under. */
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.trim().toLowerCase() : value
  )
  @IsEmail()
  @IsNotEmpty()
  @MaxLength(255)
  email!: string
}
