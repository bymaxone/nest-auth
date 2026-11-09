/**
 * @fileoverview The body of `POST /workspaces/:workspaceId/schedule-deletion`: the caller's proof
 * of who they are.
 *
 * @layer DTO
 */

import { IsOptional, IsString, MaxLength, MinLength } from 'class-validator'

/**
 * Re-proves the caller before a workspace is scheduled for deletion.
 *
 * The password travels in a POST body, never on a DELETE: RFC 9110 gives a DELETE body no defined
 * semantics, so an intermediary may drop it.
 */
export class ScheduleWorkspaceDeletionDto {
  /**
   * The account's current password.
   *
   * Bounded at 128 to match the hasher's input limit, so the field cannot be used to make someone
   * else pay for a key derivation. Optional because an account with no password (OAuth only)
   * proves itself by a recent sign-in and has none to send; for an account that has one, an absent
   * password is refused as a wrong one.
   */
  @IsOptional()
  @IsString()
  @MinLength(1)
  @MaxLength(128)
  password?: string
}
