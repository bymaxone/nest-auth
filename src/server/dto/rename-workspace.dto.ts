/**
 * @fileoverview The body of `PATCH /workspaces/:workspaceId`: the workspace's new name.
 *
 * @layer DTO
 */

import { IsNotEmpty, IsString, Matches, MaxLength } from 'class-validator'

import { NO_CONTROL_CHARACTERS } from './no-control-characters'

/** Longest workspace name accepted, in characters; the service trims before it counts. */
const NAME_MAX = 120

/**
 * The new name of a workspace, under the same rules as the name it was created with.
 */
export class RenameWorkspaceDto {
  /** The display name, 1 to 120 characters with no control character. */
  @IsString()
  @IsNotEmpty()
  @MaxLength(NAME_MAX)
  @Matches(NO_CONTROL_CHARACTERS, { message: 'name must not contain control characters' })
  name!: string
}
