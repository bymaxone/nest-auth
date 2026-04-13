import { Inject, Injectable, Logger } from '@nestjs/common'

import { BYMAX_AUTH_OPTIONS } from '../bymax-one-nest-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'

/**
 * Redis key prefix for brute-force lockout counters.
 *
 * Full key pattern: `{namespace}:lf:{identifier}`
 * Example: `bymaxauth:lf:a3f2b8c1` (hashed identifier)
 */
const LOCKOUT_PREFIX = 'lf:'

/**
 * Maximum allowed byte length of an identifier passed to brute-force methods.
 * Prevents oversized Redis keys. SHA-256 hex strings are always 64 chars.
 */
const MAX_IDENTIFIER_LENGTH = 512

/**
 * Guards authentication endpoints against brute-force attacks by tracking
 * failed attempt counts in Redis.
 *
 * @remarks
 * Each failed authentication attempt for an `identifier` (typically a hashed
 * email address or IP address) increments a Redis counter under `lf:{identifier}`.
 * When the counter reaches `maxAttempts` the identifier is considered locked out.
 * The counter expires after `windowSeconds` from the **first** failed attempt,
 * implementing a fixed-window lockout.
 *
 * **Identifier choice:** Always pass a hashed identifier — e.g.
 * `hmacSha256(email, serverSecret)` or `sha256(ip)`. Both utilities are exported
 * from `@bymax-one/nest-auth`. Never pass raw email addresses or IP strings because:
 * 1. Redis keys are plaintext — raw PII should not appear there.
 * 2. Colons (`:`) in identifiers would corrupt the namespaced key structure.
 *
 * **Lockout check order:** Always call `isLockedOut` before `recordFailure` to
 * prevent an extra increment on an already-locked account.
 */
@Injectable()
export class BruteForceService {
  private readonly logger = new Logger(BruteForceService.name)
  private readonly maxAttempts: number
  private readonly windowSeconds: number

  constructor(
    private readonly redis: AuthRedisService,
    @Inject(BYMAX_AUTH_OPTIONS) options: ResolvedOptions
  ) {
    this.maxAttempts = options.bruteForce.maxAttempts
    this.windowSeconds = options.bruteForce.windowSeconds
  }

  /**
   * Returns `true` when the identifier has reached or exceeded the failure threshold.
   *
   * @param identifier - The value to check. Must not contain `:` or newline characters
   *   and must be at most 512 bytes. Use a hashed value for PII inputs.
   * @returns `true` if the identifier is locked out, `false` otherwise.
   */
  async isLockedOut(identifier: string): Promise<boolean> {
    this.validateIdentifier(identifier)
    const raw = await this.redis.get(`${LOCKOUT_PREFIX}${identifier}`)
    if (raw === null) return false
    const count = parseInt(raw, 10)
    return !isNaN(count) && count >= this.maxAttempts
  }

  /**
   * Records a single failed authentication attempt for the identifier.
   *
   * Uses an atomic Lua script that increments the counter and sets a fixed TTL
   * only on the first increment. Subsequent failures do not extend the window,
   * preventing an attacker from perpetually deferring the lockout expiry.
   *
   * @param identifier - The value to penalize. Must not contain `:` or newline
   *   characters and must be at most 512 bytes. Use a hashed value for PII inputs.
   */
  async recordFailure(identifier: string): Promise<void> {
    this.validateIdentifier(identifier)
    await this.redis.incrWithFixedTtl(`${LOCKOUT_PREFIX}${identifier}`, this.windowSeconds)
  }

  /**
   * Clears all recorded failures for the identifier.
   *
   * Called after a successful authentication to prevent a legitimately
   * authenticated user from becoming locked out by previous failures.
   *
   * @param identifier - The value to reset. Must not contain `:` or newline characters.
   */
  async resetFailures(identifier: string): Promise<void> {
    this.validateIdentifier(identifier)
    await this.redis.del(`${LOCKOUT_PREFIX}${identifier}`)
  }

  /**
   * Returns the remaining lockout duration in seconds.
   *
   * @param identifier - The value to query. Must not contain `:` or newline characters.
   * @returns Seconds until the lockout expires, or `0` if not locked out or
   *   the key has no TTL set.
   */
  async getRemainingLockoutSeconds(identifier: string): Promise<number> {
    this.validateIdentifier(identifier)
    const ttl = await this.redis.ttl(`${LOCKOUT_PREFIX}${identifier}`)
    return ttl > 0 ? ttl : 0
  }

  /**
   * Validates an identifier before it is used as a Redis key suffix.
   *
   * Throws {@link AuthException} with `FORBIDDEN` so the error is caught by the
   * NestJS exception filter and does not leak internal implementation details
   * (key structure, service name) to HTTP responses. The root cause is logged
   * at error level for developer diagnosis.
   *
   * @throws {@link AuthException} with `FORBIDDEN` if the identifier contains
   *   `:`, `\n`, or `\r` characters, or exceeds the maximum allowed byte length.
   */
  private validateIdentifier(identifier: string): void {
    if (identifier.includes(':') || identifier.includes('\n') || identifier.includes('\r')) {
      this.logger.error(
        'Invalid identifier passed to BruteForceService — contains forbidden characters. ' +
          'Pass a hashed value (e.g. hmacSha256(email, secret)) instead of a raw email or IP.'
      )
      throw new AuthException(AUTH_ERROR_CODES.FORBIDDEN)
    }
    if (Buffer.byteLength(identifier, 'utf8') > MAX_IDENTIFIER_LENGTH) {
      this.logger.error(
        `Identifier exceeds the maximum allowed length of ${MAX_IDENTIFIER_LENGTH} bytes.`
      )
      throw new AuthException(AUTH_ERROR_CODES.FORBIDDEN)
    }
  }
}
