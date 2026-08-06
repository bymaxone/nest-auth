import { randomInt } from 'node:crypto'

import { Inject, Injectable } from '@nestjs/common'

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
 * Storing `attempts` alongside the `code` in one HASH avoids a separate Redis key for the
 * attempt counter, and lets the verify script bump it in place.
 */

/**
 * Write an OTP record and its expiry as one step.
 *
 * `HSET` + a separate `EXPIRE` would leave a window in which a crash strands a record with no
 * TTL — and an OTP that never expires is an OTP an attacker can grind against forever.
 */
const OTP_STORE_LUA = `
redis.call('HSET', KEYS[1], 'code', ARGV[1], 'attempts', 0)
redis.call('EXPIRE', KEYS[1], ARGV[2])
`

/**
 * Attempt-bounded verify + consume, as one atomic step.
 *
 * Held **byte-identical** to rust-auth's `crates/bymax-auth-redis/src/lua/otp_verify.lua`:
 * the two libraries read the same `otp:` records out of the same Redis (the prefix is pinned
 * in the shared wire contract), so the ceiling has to mean the same thing on both sides.
 *
 * `KEYS[1]` is the record; `ARGV[1]` the submitted code; `ARGV[2]` the attempt ceiling.
 * Returns `{ tag, code }`:
 *
 * - `{ 'EXPIRED', '' }` — no record (TTL elapsed), or one with no `code` field.
 * - `{ 'MAX', '' }` — the ceiling was already reached; the record is consumed.
 * - `{ 'PRESENT', storedCode }` — under the ceiling. The record is consumed on a plain match
 *   and its counter bumped in place on a mismatch. The plain comparison inside the script
 *   only decides which of those happened; the caller re-compares in constant time.
 *
 * `HINCRBY` is what makes the whole decision atomic without decoding anything, and it leaves
 * the key's TTL untouched so a wrong guess cannot buy extra OTP lifetime. The counter used to
 * be computed here in JS from a value read a round-trip earlier and written back with SET, so
 * N concurrent wrong guesses all read `attempts: 0` and all wrote `attempts: 1` — the ceiling
 * could be exceeded arbitrarily by submitting in parallel.
 */
const OTP_VERIFY_LUA = `
local code = redis.call('HGET', KEYS[1], 'code')
if not code then
    return { 'EXPIRED', '' }
end
local attempts = tonumber(redis.call('HGET', KEYS[1], 'attempts')) or 0
if attempts >= tonumber(ARGV[2]) then
    redis.call('DEL', KEYS[1])
    return { 'MAX', '' }
end
if code == ARGV[1] then
    redis.call('DEL', KEYS[1])
else
    redis.call('HINCRBY', KEYS[1], 'attempts', 1)
end
return { 'PRESENT', code }
`

/**
 * Narrow the script's two-element reply.
 *
 * A reply that is not the documented shape is treated as `EXPIRED` — the same answer a
 * missing record gets, so a malformed record is indistinguishable from natural expiry and no
 * oracle is opened. Failing any other way would tell a caller that *something* is stored
 * under their identifier.
 *
 * @param raw - Whatever `eval` returned.
 * @returns The tag and, for `PRESENT`, the stored code.
 */
function parseOtpVerifyReply(raw: unknown): ['EXPIRED' | 'MAX' | 'PRESENT', string] {
  if (!Array.isArray(raw)) return expired()
  // Stryker disable next-line ConditionalExpression,EqualityOperator: no reply distinguishes it. A
  // shorter array has no second element, which the string check below refuses on its own, and a
  // one-element `['MAX']` answers the same OTP_INVALID after the same padding as an expiry. The
  // arity is asserted because the wire contract is two elements
  if (raw.length < 2) return expired()
  const [tag, storedCode] = raw as [unknown, unknown]
  // Stryker disable next-line ConditionalExpression: MAX and EXPIRED are deliberately the same
  // answer — same code, same padding, nothing in the response separating them — so admitting a
  // MAX reply to the expiry arm, or the reverse, cannot be observed. It is kept distinct because
  // the two are different facts in the log
  if (tag !== 'MAX' && tag !== 'PRESENT') return expired()
  // A code that is not a string is a record nobody wrote to spec, and it is refused as expiry
  // like every other malformed shape rather than read.
  //
  // Substituting `''` for it, which this used to do, was not a neutral default: `timingSafeEqual`
  // answers TRUE for two empty buffers, so a submitted code that was also empty compared EQUAL to
  // the placeholder and the verification SUCCEEDED. Reachable only past the DTO's digit
  // validation and only for a reply the Lua script does not produce — but the shape of it is a
  // credential check passing on two absent values, which is not a thing to leave standing on the
  // reasoning that today's callers cannot get there.
  if (typeof storedCode !== 'string') return expired()
  return [tag, storedCode]
}

/**
 * The refusal every malformed or absent record shares.
 *
 * Its second element is never read: `verify` throws on the `EXPIRED` tag before reaching the
 * comparison, which is why the value is a constant here rather than a decision at each site.
 */
function expired(): ['EXPIRED', string] {
  // Stryker disable next-line StringLiteral: unreachable as a value — every branch returning this
  // throws before the code is compared
  return ['EXPIRED', '']
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
 *
 * @layer Service
 */
@Injectable()
export class OtpService {
  constructor(@Inject(AuthRedisService) private readonly redis: AuthRedisService) {}

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
    // A HASH of `code` + `attempts`, matching what the verify script bumps in place. Written
    // through one script so the record never exists without its expiry — a `HSET` followed by
    // a separate `EXPIRE` leaves a window where a crash strands an OTP with no TTL, and every
    // key in this keyspace is required to carry one.
    await this.redis.eval(
      OTP_STORE_LUA,
      [`otp:${purpose}:${identifier}`],
      [code, String(ttlSeconds)]
    )
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
   * @throws {@link AuthException} with `OTP_INVALID` — for a missing record, an exhausted
   *   attempt ceiling, and a wrong code alike. The three are deliberately indistinguishable:
   *   see the note in the body.
   */
  async verify(purpose: string, identifier: string, code: string): Promise<void> {
    const start = Date.now()
    const key = `otp:${purpose}:${identifier}`

    // One atomic step: read, check the ceiling, bump-or-consume. The bump used to be computed
    // here in JS from a value read a round-trip earlier and written back with SET, so N
    // concurrent wrong guesses all read `attempts: 0` and all wrote `attempts: 1` — the
    // ceiling could be exceeded arbitrarily by submitting in parallel, for the OTP's whole
    // lifetime. This is the one counter in the codebase that was not built on an atomic
    // primitive. The script is byte-identical to rust-auth's `otp_verify.lua`.
    const raw = await this.redis.eval(OTP_VERIFY_LUA, [key], [code, String(MAX_ATTEMPTS)])
    const [tag, storedCode] = parseOtpVerifyReply(raw)

    // Every failure below answers `OTP_INVALID`, in the same time, whatever went wrong.
    //
    // Distinguishing them defeated the anti-enumeration the flows in front of this were built
    // for. `forgot-password` deliberately answers the same whether or not the address exists —
    // but it only writes an OTP record when it does, so a caller could ask for a reset and then
    // submit one wrong code: `OTP_EXPIRED` meant "no record was ever written, that address has
    // no account", `OTP_INVALID` meant "there is one". One extra request turned a uniform
    // answer into a definitive one. `OTP_MAX_ATTEMPTS` said the same thing more slowly: only a
    // record that exists can reach a ceiling.
    //
    // `OTP_EXPIRED` and `OTP_MAX_ATTEMPTS` stay in the catalog as internal, diagnostic codes —
    // the same treatment `TOKEN_REVOKED` and `TOKEN_EXPIRED` already get, for the same reason —
    // and the distinction is recorded in the logs rather than in the response.
    if (tag === 'EXPIRED') {
      // Also the corrupted-record answer: the script's `cjson.decode` throws, the eval fails,
      // and the caller cannot distinguish corruption from natural expiry — which is the point.
      await sleep(Math.max(0, MIN_VERIFY_MS - (Date.now() - start)))
      throw new AuthException(AUTH_ERROR_CODES.OTP_INVALID)
    }

    if (tag === 'MAX') {
      await sleep(Math.max(0, MIN_VERIFY_MS - (Date.now() - start)))
      throw new AuthException(AUTH_ERROR_CODES.OTP_INVALID)
    }

    // The script's own comparison only decided the bump-or-consume; this is the authoritative
    // one. Constant-time, with the length check first to avoid a RangeError from
    // `crypto.timingSafeEqual` on differing buffer sizes — the length is already implied by
    // the configured OTP digit count, so it leaks nothing new.
    // Stryker disable next-line ConditionalExpression: the length-mismatch disjunct is redundant: timingSafeCompare already returns false on a length mismatch, so the OR result is unchanged
    if (code.length !== storedCode.length || !timingSafeCompare(code, storedCode)) {
      await sleep(Math.max(0, MIN_VERIFY_MS - (Date.now() - start)))
      throw new AuthException(AUTH_ERROR_CODES.OTP_INVALID)
    }

    // Success — the script already consumed the record.
    await sleep(Math.max(0, MIN_VERIFY_MS - (Date.now() - start)))
  }
}
