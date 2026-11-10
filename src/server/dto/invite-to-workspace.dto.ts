/**
 * @fileoverview The body of `POST /workspaces/:workspaceId/invitations`: who to invite and as what.
 *
 * @layer DTO
 */

import { Transform } from 'class-transformer'
import { IsEmail, IsNotEmpty, IsString, Matches, MaxLength } from 'class-validator'

import { NO_CONTROL_CHARACTERS } from './no-control-characters'

/**
 * An invitation to a workspace.
 *
 * The workspace is the path segment and the inviter is the verified caller, so neither is in the
 * body. Whether the role exists, and whether the caller may grant it, is decided by the service.
 */
export class InviteToWorkspaceDto {
  /** The invitee; trimmed and lowercased so it matches the address the invitation is indexed under. */
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.trim().toLowerCase() : value
  )
  @IsEmail()
  @IsNotEmpty()
  @MaxLength(255)
  email!: string

  /** The workspace role the invitation grants, 1 to 64 characters with no control character. */
  @IsString()
  @IsNotEmpty()
  @MaxLength(64)
  @Matches(NO_CONTROL_CHARACTERS, { message: 'role must not contain control characters' })
  role!: string
}
