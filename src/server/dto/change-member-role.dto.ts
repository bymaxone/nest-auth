/**
 * @fileoverview The body of `PATCH /workspaces/:workspaceId/members/:userId`: the role to give.
 *
 * @layer DTO
 */

import { IsNotEmpty, IsString, Matches, MaxLength } from 'class-validator'

import { NO_CONTROL_CHARACTERS } from './no-control-characters'

/**
 * The role a member should hold.
 *
 * Only the shape is checked here. Whether the role is one of the workspace's roles, and whether
 * the caller may grant it, is decided by the service against the configured hierarchy.
 */
export class ChangeMemberRoleDto {
  /** The role name, 1 to 64 characters with no control character. */
  @IsString()
  @IsNotEmpty()
  @MaxLength(64)
  @Matches(NO_CONTROL_CHARACTERS, { message: 'role must not contain control characters' })
  role!: string
}
