/**
 * @fileoverview The path parameters of the member routes.
 *
 * @layer DTO
 */

import { IsNotEmpty, IsString, Matches, MaxLength } from 'class-validator'

import { NO_CONTROL_CHARACTERS } from './no-control-characters'

/**
 * The two identifiers of a member route.
 *
 * The workspace is checked by the guard against the caller's membership; both are shape-checked
 * here so a path segment cannot carry an unbounded or control-character value into a key.
 */
export class MemberRouteParamsDto {
  /** The workspace, 1 to 128 characters with no control character. */
  @IsString()
  @IsNotEmpty()
  @MaxLength(128)
  @Matches(NO_CONTROL_CHARACTERS, { message: 'workspaceId must not contain control characters' })
  workspaceId!: string

  /** The member, 1 to 128 characters with no control character. */
  @IsString()
  @IsNotEmpty()
  @MaxLength(128)
  @Matches(NO_CONTROL_CHARACTERS, { message: 'userId must not contain control characters' })
  userId!: string
}
