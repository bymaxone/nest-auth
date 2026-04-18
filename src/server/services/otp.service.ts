import { randomInt } from 'node:crypto'

import { Injectable } from '@nestjs/common'

import { timingSafeCompare } from '../crypto/secure-token'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { sleep } from '../utils/sleep'

/** Maximum allowed OTP verification attempts before the code is locked. */
const MAX_ATTEMPTS = 5

/** Minimum duration in milliseconds for all OTP verify paths (timing normalization). */
const MIN_VERIFY_MS = 100

/**
 * OTP record stored in Redis as JSON.
 *
 * Storing `attempts` alongside the `code` avoids a separate Redis key for
 * the attempt counter, reducing the number of round-trips.
 */
interface OtpRecord {
  code: string
  attempts: number
}

/**
 * Manages one-time passwords for email verification and password reset flows.
 *
 * OTPs are generated with `crypto.randomInt` (cryptographically secure) and
 * stored in Redis with an expiry. Each verification atomically reads the stored
 * record and checks the attempt counter before comparing the code.
 *
 * @remarks
 * **Timing normalization** — all code paths inside {@link verify} wait at least
 * `MIN_VERIFY_MS` (100 ms) before returning, regardless of whether the OTP was
 * found, the code matched, or the attempt limit was reached. This prevents an
 * attacker from distinguishing "OTP not found" from "wrong code" by measuring
 * response time.
 *
 * **Constant-time comparison** — codes of different lengths are rejected
 * immediately (before `timingSafeEqual`) because Node.js throws a `RangeError`
 * when the buffer sizes differ. This short-circuit does NOT leak timing
 * information about the correct code length beyond what the OTP digit count
 * already implies.
 */
@Injectable()
export class OtpService {
  constructor(private readonly redis: AuthRedisService) {}

  // ---------------------------------------------------------------------------
  // Generate
  // ---------------------------------------------------------------------------

  /**
   * Generates a cryptographically secure numeric OTP string.
   *
   * @param length - Number of digits. Defaults to 6.
   * @returns Zero-padded numeric string of the specified length.
   */
  generate(length: number = 6): string {
    const max = 10 ** length
    const num = randomInt(0, max)
    return String(num).padStart(length, '0')
  }

  // ---------------------------------------------------------------------------
  // Store
  // ---------------------------------------------------------------------------

  /**
   * Stores an OTP in Redis under `otp:{purpose}:{identifier}`.
   *
   * @param purpose - Logical purpose (e.g. `'email_verification'`, `'password_reset'`).
   * @param identifier - User-scoped identifier (e.g. `sha256(tenantId + ':' + email)`).
   * @param code - The OTP string to store.
   * @param ttlSeconds - Time-to-live in seconds after which the OTP expires.
   */
  async store(
    purpose: string,
    identifier: string,
    code: string,
    ttlSeconds: number
  ): Promise<void> {
    const record: OtpRecord = { code, attempts: 0 }
    await this.redis.set(`otp:${purpose}:${identifier}`, JSON.stringify(record), ttlSeconds)
  }

  // ---------------------------------------------------------------------------
  // Verify
  // ---------------------------------------------------------------------------

  /**
   * Verifies an OTP and consumes it on success.
   *
   * Reads the stored record, checks the attempt counter, performs a
   * constant-time comparison, and deletes the key on successful verification.
   * On failure, the attempt count is incremented in Redis.
   *
   * All code paths are delayed to at least {@link MIN_VERIFY_MS} to prevent
   * timing side-channel attacks.
   *
   * @param purpose - Logical purpose matching the one used in {@link store}.
   * @param identifier - User-scoped identifier matching the one used in {@link store}.
   * @param code - The OTP code supplied by the user.
   * @throws {@link AuthException} with `OTP_EXPIRED` if the key is not in Redis.
   * @throws {@link AuthException} with `OTP_MAX_ATTEMPTS` if the attempt limit is reached.
   * @throws {@link AuthException} with `OTP_INVALID` if the code does not match.
   */
  async verify(purpose: string, identifier: string, code: string): Promise<void> {
    const start = Date.now()
    const key = `otp:${purpose}:${identifier}`

    const raw = await this.redis.get(key)
    if (raw === null) {
      await sleep(Math.max(0, MIN_VERIFY_MS - (Date.now() - start)))
      throw new AuthException(AUTH_ERROR_CODES.OTP_EXPIRED)
    }

    let record: OtpRecord
    try {
      record = JSON.parse(raw) as OtpRecord
    } catch {
      // Corrupted Redis value — delete the unusable key and surface as OTP_EXPIRED
      // so callers cannot distinguish corruption from natural expiry (timing oracle
      // safe, anti-enumeration safe).
      await this.redis.del(key)
      await sleep(Math.max(0, MIN_VERIFY_MS - (Date.now() - start)))
      throw new AuthException(AUTH_ERROR_CODES.OTP_EXPIRED)
    }

    if (record.attempts >= MAX_ATTEMPTS) {
      // Delete the exhausted key so it no longer occupies Redis until TTL expires.
      await this.redis.del(key)
      await sleep(Math.max(0, MIN_VERIFY_MS - (Date.now() - start)))
      throw new AuthException(AUTH_ERROR_CODES.OTP_MAX_ATTEMPTS)
    }

    // Constant-time comparison — short-circuit on length mismatch to avoid
    // RangeError from crypto.timingSafeEqual when buffer sizes differ.
    // Length mismatch does NOT leak the correct code length beyond the OTP digit
    // count that is already known from the flow (e.g. 6 digits).
    if (code.length !== record.code.length || !timingSafeCompare(code, record.code)) {
      await this.incrementAttempts(purpose, identifier, record)
      await sleep(Math.max(0, MIN_VERIFY_MS - (Date.now() - start)))
      throw new AuthException(AUTH_ERROR_CODES.OTP_INVALID)
    }

    // Success — consume the OTP.
    await this.redis.del(key)
    await sleep(Math.max(0, MIN_VERIFY_MS - (Date.now() - start)))
  }

  // ---------------------------------------------------------------------------
  // Internal helpers
  // ---------------------------------------------------------------------------

  /**
   * Increments the attempt counter for an existing OTP record atomically.
   *
   * Uses a Lua script to read the TTL and update the record in a single round-trip,
   * preserving the expiry and avoiding a GET + TTL + SET sequence.
   * If the key has no TTL or is gone the update is silently skipped.
   *
   * @param purpose - Purpose segment of the key.
   * @param identifier - Identifier segment of the key.
   * @param currentRecord - The already-parsed OTP record (avoids a redundant GET).
   */
  private async incrementAttempts(
    purpose: string,
    identifier: string,
    currentRecord: OtpRecord
  ): Promise<void> {
    const key = `otp:${purpose}:${identifier}`
    const updated: OtpRecord = { ...currentRecord, attempts: currentRecord.attempts + 1 }
    // Lua: read TTL atomically, then SET with the same TTL if the key still exists.
    await this.redis.eval(
      `local ttl = redis.call('TTL', KEYS[1])
       if ttl > 0 then redis.call('SET', KEYS[1], ARGV[1], 'EX', ttl) end`,
      [key],
      [JSON.stringify(updated)]
    )
  }
}
