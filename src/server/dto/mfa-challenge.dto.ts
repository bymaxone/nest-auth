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
   * Either a 6-digit TOTP code or a 24-hex-char recovery code in
   * `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` format (96 bits of entropy).
   *
   * Accepted formats:
   * - TOTP: exactly 6 decimal digits (e.g. `"123456"`)
   * - Recovery code: six 4-hex-char groups separated by hyphens
   *   (e.g. `"A1B2-C3D4-E5F6-0789-ABCD-EF01"`)
   *
   * The service layer determines the code type from the format. Non-matching
   * strings are rejected at the DTO layer before any service logic runs.
   */
  @Matches(
    /^(\d{6}|[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4})$/,
    {
      message:
        'code must be a 6-digit TOTP code or a recovery code in XXXX-XXXX-XXXX-XXXX-XXXX-XXXX format'
    }
  )
  @IsString()
  @IsNotEmpty()
  @MaxLength(29)
  code!: string
}
