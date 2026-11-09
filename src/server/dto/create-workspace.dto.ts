/**
 * @fileoverview The body of `POST /workspaces`: the new workspace's name.
 *
 * @layer DTO
 */

import { IsNotEmpty, IsString, Matches, MaxLength } from 'class-validator'

import { NO_CONTROL_CHARACTERS } from './no-control-characters'

/** Longest workspace name accepted, in characters; the service trims before it counts. */
const NAME_MAX = 120

/**
 * The workspace to create.
 *
 * The service trims the name and refuses one that is blank, so a name of spaces passes the shape
 * checks here and is refused there under the same `name` field.
 */
export class CreateWorkspaceDto {
  /** The display name, 1 to 120 characters with no control character. */
  @IsString()
  @IsNotEmpty()
  @MaxLength(NAME_MAX)
  @Matches(NO_CONTROL_CHARACTERS, { message: 'name must not contain control characters' })
  name!: string
}
