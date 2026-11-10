/**
 * @fileoverview The body of `POST /workspaces/invitations/preview`.
 *
 * @layer DTO
 */

import { IsNotEmpty, IsString, Length } from 'class-validator'

/**
 * A workspace invitation token to preview.
 *
 * A token this library issues is 64 hex characters; the fixed length keeps an oversized value away
 * from the hash on a route that needs no sign-in.
 */
export class PreviewWorkspaceInvitationDto {
  /** The raw token from the invitation message. */
  @IsString()
  @IsNotEmpty()
  @Length(64, 64)
  token!: string
}
