import { IsNotEmpty, IsString, Length } from 'class-validator'

/**
 * Data Transfer Object for confirming an address change.
 *
 * Validated via NestJS `ValidationPipe` before reaching the service layer.
 *
 * @remarks
 * The token is the whole payload: it names the account, the target address and the tenant,
 * all of which were fixed when it was minted. Accepting any of those from the body would let
 * the holder of one link redirect it at a different account.
 *
 * @layer DTO
 */
export class ConfirmEmailChangeDto {
  /**
   * The single-use token that was mailed to the new address.
   *
   * Exactly 64 hex characters — the shape `generateSecureToken(32)` produces. Bounding it
   * here means a malformed value is refused before it is hashed into a key lookup.
   */
  @IsString()
  @IsNotEmpty()
  @Length(64, 64)
  token!: string
}
