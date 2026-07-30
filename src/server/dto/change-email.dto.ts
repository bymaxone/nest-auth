import { Transform } from 'class-transformer'
import { IsEmail, IsNotEmpty, IsString, MaxLength, MinLength } from 'class-validator'

/**
 * Data Transfer Object for requesting an address change.
 *
 * Validated via NestJS `ValidationPipe` before reaching the service layer.
 *
 * @remarks
 * The account is never named here — it comes from the caller's own claims. A body that could
 * name a user id would let anyone holding any session move any account's recovery address,
 * which is account takeover in one field.
 *
 * @layer DTO
 */
export class ChangeEmailDto {
  /**
   * The address to move to. Normalized to lowercase and trimmed so it is compared, stored,
   * and checked for uniqueness in the same form login resolves an account by.
   */
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.trim().toLowerCase() : value
  )
  @IsEmail()
  @IsNotEmpty()
  @MaxLength(255)
  newEmail!: string

  /**
   * The account's current password.
   *
   * Re-proved because the address is the recovery credential: without this, a stolen access
   * token alone would be enough to point the account at a mailbox the thief controls.
   * Bounded at 128 to match the hasher's input limit — an unbounded field is a cheap way to
   * make someone else pay for a key derivation.
   */
  @IsString()
  @MinLength(1)
  @MaxLength(128)
  currentPassword!: string
}
