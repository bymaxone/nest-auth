import { IsOptional, IsString, MaxLength, MinLength } from 'class-validator'

/**
 * Data Transfer Object for starting MFA enrolment.
 *
 * Submitted to `POST /mfa/setup` to obtain the TOTP secret and recovery codes.
 *
 * @layer DTO
 */
export class MfaSetupDto {
  /**
   * The account password, re-proving who is asking before a factor is minted.
   *
   * Enabling MFA changes how the account authenticates, and an access token alone is not
   * proof of identity: a token lifted by XSS or from a shared machine could otherwise enrol
   * an authenticator the attacker holds, and the enable would then invalidate every session
   * and lock the real owner out of an account they still know the password to.
   *
   * Optional in the DTO, required by the service **whenever the account has a password**. An
   * account provisioned purely through OAuth has none, and refusing those would make MFA
   * unreachable for them — their credential belongs to the provider, which this library
   * cannot re-verify inline.
   *
   * `@MinLength(1)` is the only floor, matching `LoginDto`: rejecting the empty string keeps
   * a caller from spending a scrypt derivation for free, while enforcing the deployment's
   * real policy length here would leak it as a pre-KDF timing signal.
   */
  @IsOptional()
  @IsString()
  @MinLength(1)
  @MaxLength(128)
  password?: string
}
