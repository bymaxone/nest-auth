/**
 * @fileoverview The body of `POST /workspaces/invitations/accept`.
 *
 * @layer DTO
 */

import { IsNotEmpty, IsString, Length } from 'class-validator'

/**
 * A workspace invitation token to accept as the signed-in account.
 *
 * A token this library issues is 64 hex characters; the fixed length keeps an oversized value away
 * from the hash.
 */
export class AcceptWorkspaceInvitationDto {
  /** The raw token from the invitation message. */
  @IsString()
  @IsNotEmpty()
  @Length(64, 64)
  token!: string
}
