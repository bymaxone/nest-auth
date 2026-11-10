/**
 * @fileoverview The body of `POST /workspaces/invitations/accept-signup`.
 *
 * @layer DTO
 */

import { IsNotEmpty, IsString, Length } from 'class-validator'

/**
 * A workspace invitation token and the account to create with it.
 *
 * The bounds are those of the tenant invitation's accept body. The 8-character password floor is
 * structural; the deployment's policy floor is enforced by `PasswordService`, and answers the same
 * `auth.validation` code.
 */
export class AcceptWorkspaceInvitationSignupDto {
  /** The raw token from the invitation message, exactly 64 characters. */
  @IsString()
  @IsNotEmpty()
  @Length(64, 64)
  token!: string

  /** Display name of the new account, 2 to 100 characters. */
  @IsString()
  @IsNotEmpty()
  @Length(2, 100)
  name!: string

  /** Password of the new account, 8 to 128 characters; hashed at once and never stored in clear. */
  @IsString()
  @Length(8, 128)
  password!: string
}
