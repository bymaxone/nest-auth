import { Transform } from 'class-transformer'
import { IsEmail, IsNotEmpty, IsString, MaxLength, MinLength } from 'class-validator'

/**
 * Data Transfer Object for the user login endpoint.
 *
 * Validated via NestJS `ValidationPipe` before reaching the service layer.
 *
 * @layer DTO
 */
export class LoginDto {
  /**
   * User's primary email address.
   * Bounded to 255 characters — the RFC-recommended practical maximum for
   * addr-spec — so that an unbounded string cannot inflate downstream hashing,
   * Redis keys, or error logs.
   *
   * Normalized to lowercase and trimmed BEFORE it reaches the service, so the
   * brute-force lockout identifier (`hmac(tenantId + ":" + email)`) is derived
   * from the same canonical value that the case-insensitive user lookup resolves.
   * Without this, an attacker defeats the lockout by rotating the e-mail letter-
   * case: each casing is a distinct lockout bucket yet resolves the same account.
   */
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.trim().toLowerCase() : value
  )
  @IsEmail()
  @MaxLength(255)
  email!: string

  /**
   * Plaintext password supplied by the user.
   *
   * @remarks
   * `@MinLength(1)` is deliberately the ONLY floor applied — rejecting the
   * empty string at the validation boundary prevents attackers from triggering
   * a full scrypt computation against `""` (a trivial DoS amplification vector
   * that bypasses the brute-force counter's cooldown window). The library
   * intentionally does NOT enforce the application's configured password-policy
   * minimum here; doing so would leak the policy length as a pre-scrypt timing
   * oracle (a request failing validation returns before reaching
   * `passwordService.compare`, which is timing-distinguishable from a request
   * that runs the full hash).
   */
  @IsString()
  @MinLength(1)
  @MaxLength(128)
  password!: string

  /**
   * Tenant identifier used to scope the login attempt.
   * Bounded to 128 characters — tenant IDs are part of HMAC pre-images and
   * Redis keys, so an unbounded string is rejected at the boundary.
   */
  @IsString()
  @IsNotEmpty()
  @MaxLength(128)
  tenantId!: string
}
