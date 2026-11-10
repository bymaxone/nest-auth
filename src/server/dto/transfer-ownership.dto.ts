/**
 * @fileoverview The body of `POST /workspaces/:workspaceId/transfer-ownership`: who receives
 * ownership, what the giver keeps, and the giver's proof.
 *
 * @layer DTO
 */

import { IsNotEmpty, IsOptional, IsString, Matches, MaxLength, MinLength } from 'class-validator'

import { NO_CONTROL_CHARACTERS } from './no-control-characters'

/**
 * A hand-over of ownership to another member.
 *
 * Only shapes are checked here; that the receiver is an active member, that the giver is the
 * owner and that the role they keep exists is decided by the service, after the caller has been
 * checked as the owner and before the password is looked at.
 */
export class TransferOwnershipDto {
  /** The member who becomes an owner, 1 to 128 characters with no control character. */
  @IsString()
  @IsNotEmpty()
  @MaxLength(128)
  @Matches(NO_CONTROL_CHARACTERS, { message: 'userId must not contain control characters' })
  userId!: string

  /**
   * The role the giver keeps, 1 to 64 characters with no control character; absent keeps both as
   * owners.
   */
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  @MaxLength(64)
  @Matches(NO_CONTROL_CHARACTERS, { message: 'demoteSelfTo must not contain control characters' })
  demoteSelfTo?: string

  /**
   * The giver's current password, bounded at 128 like every proven password. Optional because an
   * account with no password proves itself by a recent sign-in; for an account that has one, an
   * absent password is refused as a wrong one.
   */
  @IsOptional()
  @IsString()
  @MinLength(1)
  @MaxLength(128)
  password?: string
}
