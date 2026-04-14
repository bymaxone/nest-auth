import { IsNotEmpty, IsString, Matches, MaxLength } from 'class-validator'

/**
 * Data Transfer Object for the MFA challenge endpoint.
 *
 * Submitted during the login flow when the user has MFA enabled.
 * Contains the short-lived MFA temp token issued at login alongside
 * either a 6-digit TOTP code or a recovery code.
 */
export class MfaChallengeDto {
  /**
   * The short-lived MFA temporary JWT issued after a successful password login.
   *
   * This token is single-use and expires in 5 minutes. It encodes the user ID
   * and the authentication context (`'dashboard'` or `'platform'`).
   *
   * `@MaxLength(512)` prevents oversized payloads from reaching `jwtService.verify()`
   * on this public (unauthenticated) endpoint. A compact HS256 JWT is ~200 chars;
   * 512 is a safe upper bound.
   */
  @IsString()
  @IsNotEmpty()
  @MaxLength(512)
  mfaTempToken!: string

  /**
   * Either a 6-digit TOTP code or a recovery code in `xxxx-xxxx-xxxx` format.
   *
   * Accepted formats:
   * - TOTP: exactly 6 decimal digits (e.g. `"123456"`)
   * - Recovery code: three 4-digit groups separated by hyphens (e.g. `"1234-5678-9012"`)
   *
   * The service layer determines the code type from the format. Non-matching
   * strings are rejected at the DTO layer before any service logic runs.
   */
  @Matches(/^(\d{6}|\d{4}-\d{4}-\d{4})$/, {
    message: 'code must be a 6-digit TOTP code or a recovery code in xxxx-xxxx-xxxx format'
  })
  @IsString()
  @IsNotEmpty()
  @MaxLength(14)
  code!: string
}
