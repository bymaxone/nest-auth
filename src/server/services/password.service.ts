import {
  randomBytes,
  ScryptOptions,
  scrypt as nodeScrypt,
  timingSafeEqual as cryptoTimingSafeEqual
} from 'node:crypto'
import { promisify } from 'node:util'

import { Inject, Injectable, Logger } from '@nestjs/common'

import { BYMAX_AUTH_BREACH_CHECKER, BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import { MAX_KDF_BYTES_PER_DERIVATION } from '../config/resolved-options'
import type { ResolvedOptions } from '../config/resolved-options'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { IPasswordBreachChecker } from '../interfaces/password-breach-checker.interface'

// promisify picks the 3-arg overload (no options); cast to the 4-arg form we need.
const scrypt = promisify(nodeScrypt) as (
  password: string | Buffer,
  salt: string | Buffer,
  keylen: number,
  options: ScryptOptions
) => Promise<Buffer>

/**
 * Output length of the derived key in bytes.
 * 64 bytes = 512 bits — sufficiently large to prevent key recovery by brute force.
 */
const SCRYPT_KEY_LEN = 64

/**
 * Number of random salt bytes to generate per hash.
 * 16 bytes = 128 bits — provides sufficient collision resistance for a per-password salt.
 */
const SALT_BYTES = 16

/**
 * A fixed salt for the decoy derivation, so the "user not found" branch spends the same work
 * as a real verify without needing a stored hash to read parameters from.
 *
 * Deliberately not a decoy *hash*: a hash records the parameters it was written under, and a
 * constant one would record whatever they were the day it was generated. The moment a
 * deployment configured a different cost, the decoy would stop taking the same time as a real
 * verify and the timing oracle it exists to close would reopen. Deriving under the CONFIGURED
 * parameters is what keeps the two paths equal.
 */
// Stryker disable next-line StringLiteral: the decoy salt's VALUE is meaningless — the branch
// exists to spend one derivation at the configured cost, and any salt (including an empty one)
// costs the same and still compares unequal
const DUMMY_SALT = Buffer.from('d6732149f98b3938274691d8c2f3ee63', 'hex')

/**
 * A value no derivation will produce, compared against so the decoy path ends in the same
 * constant-time comparison a real verify does.
 */
const DUMMY_EXPECTED = Buffer.alloc(SCRYPT_KEY_LEN, 0x5a)

/**
 * Ceiling for the `r` and `p` cost parameters read out of a stored hash.
 *
 * Not a policy limit — a bound on what the KDF can be handed at all. Both are passed straight
 * to `scrypt` and into the `maxmem` arithmetic, where a large value throws rather than
 * refusing, which would break this module's contract that a malformed record returns `null`.
 * Both implementations write 8 and 1.
 */
const MAX_SCRYPT_PARAMETER = 255

/**
 * Smallest and largest derived-key length this library will verify, in bytes.
 *
 * The bounds are `password_hash::Output`'s, not ours: rust-auth stores its hashes through that
 * type, and a length outside 10..=64 is a string it cannot represent. Accepting a wider range
 * here would mean minting hashes the sibling implementation refuses to parse, which is the
 * failure this whole format exists to prevent.
 */
const MIN_KEY_LEN = 10
const MAX_KEY_LEN = 64

/** A stored hash, decomposed into the parameters it was written under, its salt and its key. */
type ParsedHash = {
  N: number
  r: number
  p: number
  salt: Buffer
  derived: Buffer
}

/**
 * Encode bytes in PHC "B64" — the standard base64 alphabet with the padding stripped.
 *
 * Not base64url: PHC uses `+` and `/`, and a hash written with `-`/`_` is one rust-auth's
 * parser rejects.
 *
 * @param value - The bytes to encode.
 * @returns The unpadded standard-base64 rendering.
 */
function toPhcB64(value: Buffer): string {
  // Stryker disable next-line Regex: dropping the `$` anchor is equivalent — base64 padding is
  // only ever trailing, so `/=+/` and `/=+$/` strip the same characters from any encoder output
  return value.toString('base64').replace(/=+$/, '')
}

/**
 * Decode a PHC "B64" field, rejecting anything that is not its own canonical encoding.
 *
 * `Buffer.from(_, 'base64')` is permissive: it skips characters outside the alphabet and
 * tolerates trailing bits that no encoder produces, so two different strings can decode to the
 * same bytes. Round-tripping the result closes that — a value only parses if it is exactly what
 * encoding those bytes would have written.
 *
 * @param value - The field text.
 * @returns The decoded bytes, or `null` when the field is not canonical B64.
 */
function fromPhcB64(value: string): Buffer | null {
  // Only the empty case needs its own guard: it decodes to zero bytes and re-encodes to `''`,
  // so the round-trip below would accept it. An alphabet check is NOT needed — a character
  // outside base64 is skipped by the decoder, and re-encoding what survived cannot reproduce
  // the input, so the round-trip already rejects it. (Mutation testing found that guard: every
  // mutant of it lived, because nothing it rejected reached a different outcome.)
  if (value === '') return null
  const decoded = Buffer.from(value, 'base64')
  return toPhcB64(decoded) === value ? decoded : null
}

/**
 * Read the `ln`, `r` and `p` fields out of a PHC parameter string.
 *
 * Looked up by name rather than by position: the PHC spec fixes neither the order nor the set,
 * and rust-auth reads them by name too (`PasswordHash::params::get_decimal`). A parser that
 * assumed `ln,r,p` would reject a hash the sibling implementation wrote and considers valid.
 *
 * @param text - The comma-separated `key=value` segment.
 * @returns The three costs, or `null` when any is absent, repeated or not a plain integer.
 */
function parsePhcParams(text: string): { ln: number; r: number; p: number } | null {
  const found = new Map<string, number>()
  for (const pair of text.split(',')) {
    const eq = pair.indexOf('=')
    if (eq <= 0) return null
    const key = pair.slice(0, eq)
    const raw = pair.slice(eq + 1)
    // A repeated key is ambiguous rather than merely odd — the two sides could disagree about
    // which wins — so it is refused instead of resolved.
    if (found.has(key)) return null
    if (!/^(0|[1-9][0-9]*)$/.test(raw)) return null
    found.set(key, Number(raw))
  }
  const [ln, r, p] = [found.get('ln'), found.get('r'), found.get('p')]
  if (ln === undefined || r === undefined || p === undefined) return null
  // `ln` is log2(N), and only its FLOOR is checked here. A ceiling would be dead code: the
  // working-set bound below refuses every `ln >= 23` on its own, because `128 * 2 ** 23` already
  // exceeds MAX_KDF_BYTES_PER_DERIVATION at the smallest legal `r`. This parser carried
  // `ln > 31` until mutation testing showed that no input distinguishes it from `>= 31`, or from
  // no ceiling at all — every value it would have caught is refused eleven powers of two earlier.
  // A malformed `ln` of a thousand digits is safe for the same reason rather than in spite of it:
  // `2 ** 1e21` is `Infinity`, and `Infinity` is greater than the ceiling.
  //
  // `r` and `p` DO need a ceiling of their own, which the first version of this parser missed.
  // They reach `scrypt` directly, so a stored value of `999999999` makes Node throw
  // `Invalid scrypt params` — an exception out of a function whose whole contract is that a
  // malformed record returns `null` and the caller answers "wrong password" with no branch
  // whose timing distinguishes the two. 255 is far above any parameter either implementation
  // writes (8 and 1) and far below where the arithmetic stops being representable.
  if (ln < 1) return null
  if (r < 1 || r > MAX_SCRYPT_PARAMETER || p < 1 || p > MAX_SCRYPT_PARAMETER) return null
  // The working set the record ASKS FOR, held to the same ceiling the configured cost is held
  // to at startup. `compare` now caps `maxmem` with a constant, so a record above this one no
  // longer GETS the allocation it asks for — it gets an exception out of `scrypt`, which is a
  // 500 from every credential path rather than the `false` the contract promises. Refusing it
  // here is what keeps that answer a `false`. (Before the cap, `maxmem` was computed from the
  // record and widened to fit whatever it claimed, and this check was the only thing standing
  // between a crafted `ln = 31, r = 8` and a 2 TiB allocation that OOM-kills the process. The
  // two bounds are independent now, which is the point: neither is a single point of failure.)
  //
  // A hash written under a validated configuration is always inside this, because the same
  // ceiling is what let that configuration boot. So nothing legitimate is refused — this only
  // rejects a record no deployment of either implementation could have produced.
  if (128 * 2 ** ln * r > MAX_KDF_BYTES_PER_DERIVATION) return null
  return { ln, r, p }
}

/**
 * Decompose a PHC scrypt string — `$scrypt$ln=17,r=8,p=1$<saltB64>$<hashB64>`.
 *
 * @param hash - The stored hash string.
 * @returns The decomposition, or `null` when the value is not a scrypt PHC string.
 */
function parsePhcHash(hash: string): ParsedHash | null {
  // A PHC string opens with `$`, so splitting yields a leading empty field, and `version` is
  // absent for scrypt (which records none) — five fields exactly.
  //
  // The arity is checked through the destructured names rather than through `parts.length`:
  // with `length` guarding first, the `undefined` checks below become unreachable, and an
  // unreachable guard is one no test can hold in place. Here `extra` catches a sixth field and
  // the trio catches a short one, so every branch is a shape some input actually has.
  const [leading, algorithm, paramText, saltText, hashText, extra] = hash.split('$')
  if (extra !== undefined) return null
  if (leading !== '' || algorithm !== 'scrypt') return null
  if (paramText === undefined || saltText === undefined || hashText === undefined) return null

  const params = parsePhcParams(paramText)
  if (params === null) return null

  const salt = fromPhcB64(saltText)
  const derived = fromPhcB64(hashText)
  if (salt === null || derived === null) return null
  if (derived.length < MIN_KEY_LEN || derived.length > MAX_KEY_LEN) return null

  return { N: 2 ** params.ln, r: params.r, p: params.p, salt, derived }
}

/**
 * Decompose a stored hash into its parameters, salt and derived key.
 *
 * PHC (`$scrypt$ln=…,r=…,p=…$salt$hash`) is the only encoding this library reads, and the only
 * one it writes. rust-auth writes the same, so a hash from either backend verifies under the
 * other with nothing in the credential path branching on which one wrote it. The format is
 * pinned by `conformance/wire-contract.json` (`passwordHashFormat`) with a known-answer vector
 * from each implementation.
 *
 * There is deliberately no compatibility reader for an older shape. Both libraries are new and
 * have never backed a deployment, so such a reader would be an unused branch sitting in the
 * credential-verification core — which is where an unused branch is most expensive.
 *
 * The cost travels with the hash, so a value can be verified years later regardless of what
 * the deployment is configured to write today. That is what makes `password.costFactor`
 * changeable at all — a hash that did not record its cost can only be verified by guessing it,
 * and guessing wrong is every password on the system becoming unverifiable at once.
 *
 * A malformed value returns `null` rather than throwing, so the caller answers "wrong password"
 * without a branch whose timing distinguishes a corrupt record from a wrong one.
 *
 * @param hash - The stored hash string.
 * @returns The decomposition, or `null` when the value is not a scrypt PHC string.
 */
function parseStoredHash(hash: string): ParsedHash | null {
  return parsePhcHash(hash)
}

/**
 * Password hashing and verification service using `node:crypto` scrypt.
 *
 * Uses scrypt (RFC 7914) — a memory-hard key derivation function designed to
 * resist brute-force and GPU/ASIC attacks. **Never use SHA-256, MD5, or
 * unsalted hashes for passwords.**
 *
 * Wire format: PHC — `$scrypt$ln={log2(N)},r={r},p={p}${saltB64}${derivedB64}`
 *  - `saltB64` — 16 random bytes in PHC "B64" (standard base64, no padding)
 *  - `derivedB64` — 64 derived bytes in the same encoding
 *
 * The only encoding, read and written. rust-auth writes the same, and the format is pinned by
 * `conformance/wire-contract.json` with a known-answer vector from each implementation.
 *
 * @remarks
 * **Cost parameters:** Taken from `options.password` at construction time.
 * Defaults are `costFactor = 131072 (2^17)`, `blockSize = 8`, `parallelization = 1` — OWASP's
 * recommended minimum for scrypt. Override in
 * `BymaxAuthModule.forRoot({ password: { costFactor: 65536 } })`.
 * Validated at startup by `resolveOptions()` — values below `16384 (2^14)` are rejected.
 *
 * **Security:** Comparison uses `crypto.timingSafeEqual` to prevent timing
 * attacks. All comparison failures return `false` — never throw on bad input.
 *
 * **Thread safety:** scrypt is CPU-intensive. In production, calls will block
 * the Node.js event loop for ~100–200 ms. Consider running behind a worker
 * thread or rate-limiting authentication endpoints.
 *
 * @layer Service
 */
@Injectable()
export class PasswordService {
  private readonly logger = new Logger(PasswordService.name)
  private readonly N: number
  private readonly minLength: number
  private readonly r: number
  private readonly p: number
  private readonly maxmem: number

  constructor(
    @Inject(BYMAX_AUTH_OPTIONS) options: ResolvedOptions,
    @Inject(BYMAX_AUTH_BREACH_CHECKER) private readonly breachChecker: IPasswordBreachChecker
  ) {
    this.minLength = options.password.minLength
    this.N = options.password.costFactor
    this.r = options.password.blockSize
    this.p = options.password.parallelization
    // Memory limit: double the actual scrypt requirement (N * r * 128 bytes) to
    // prevent spurious "memory limit exceeded" errors on resource-constrained hosts.
    // The OpenSSL default of 32 MB matches the requirement exactly for N=2^15, r=8;
    // doubling provides headroom without changing attacker cost.
    // Stryker disable next-line ArithmeticOperator: arg1 (= 2x the scrypt requirement) always dominates `Math.max`, so reducing the 64*1024*1024 floor never lowers maxmem below the requirement
    this.maxmem = Math.max(this.N * this.r * 128 * 2, 64 * 1024 * 1024)
  }

  /**
   * Hashes a plaintext password using scrypt with a random salt.
   *
   * @param plain - Plaintext password (UTF-8 string).
   * @returns Hashed password as a PHC string.
   *
   * @example
   * ```typescript
   * const hash = await passwordService.hash('my-password')
   * // '$scrypt$ln=17,r=8,p=1$YmFzZTY0c2FsdA$…'
   * ```
   */
  /**
   * The whole password policy, applied wherever a password is being *set*.
   *
   * One entry point so the four call sites — registration, reset, authenticated change and
   * invitation acceptance — cannot drift into applying different halves of it.
   *
   * Order matters: length first, because it is decided locally and for free, and the breach
   * check may reach a network corpus. A password refused for being short should not cost a
   * round trip, and should not be sent anywhere first.
   *
   * @param plain - The plaintext password the user is trying to set.
   * @param field - The request field to name in a length failure's `details`.
   * @throws {@link AuthException} with `VALIDATION` when it is too short, or
   *   `PASSWORD_COMPROMISED` when the corpus knows it.
   */
  async assertAcceptable(plain: string, field: string): Promise<void> {
    this.assertLongEnough(plain, field)
    await this.assertNotCompromised(plain)
  }

  /**
   * Rejects a password shorter than the configured minimum.
   *
   * The DTOs carry a structural `@MinLength(8)` — the lowest NIST SP 800-63B-4 permits under any
   * circumstance — and this is the deployment's policy on top of it, which is configurable and
   * defaults to 15 because that is what §3.1.1.1 requires of a single-factor password. The check
   * lives here rather than in a decorator because a decorator is evaluated when the class is
   * defined, before any configuration exists.
   *
   * It answers the same `auth.validation` code and the same `{ field, message }[]` details the
   * validation pipe produces for a length failure, so a client already handling a short password
   * sees no new shape and the shared error catalog gains no entry. The breach and
   * common-password screens run after: they remove passwords that are already *known*, which is
   * a different question from how many guesses the password is worth.
   *
   * @param plain - The plaintext password the user is trying to set.
   * @param field - The request field to name in `details`, so the message points at the input
   *   the caller actually sent (`password` on registration, `newPassword` on a reset).
   * @throws {@link AuthException} with `VALIDATION` when the password is too short.
   */
  assertLongEnough(plain: string, field: string): void {
    if (plain.length >= this.minLength) return

    throw new AuthException(AUTH_ERROR_CODES.VALIDATION, [
      { field, message: `${field} must be at least ${String(this.minLength)} characters` }
    ])
  }

  /**
   * Rejects a password that appears in a known-breach corpus.
   *
   * Called wherever a password is being *set* — registration, reset, invitation acceptance —
   * and never on login: refusing a breached password someone already has would lock them out
   * of the account they need to get into to change it.
   *
   * The checker fails open by contract — {@link IPasswordBreachChecker.isBreached} is
   * documented to answer `false`, never throw, when the corpus cannot be consulted — so an
   * unreachable corpus admits the password rather than blocking the credential path.
   *
   * That contract is enforced here rather than assumed. The implementation is the consumer's:
   * a `fetch` that rejects outside their own `try`, a client library that throws on a DNS
   * failure, or an ordinary bug is enough to break it, and the exception would propagate out of
   * every path that *sets* a password. Registration, reset and invitation acceptance would all
   * start failing because an advisory corpus was unreachable — the exact inversion of the
   * documented behaviour, and worst during an incident, when changing the password is the
   * urgent thing. A refusal to answer is not evidence against the password.
   *
   * The plaintext is not passed to the logger, and neither is the checker's ERROR — which is the
   * part that took a measurement to learn. A breach checker receives the plaintext by contract, so
   * an error it raises is a place the plaintext can be: an HTTP client that echoes the request it
   * failed on, a validation error quoting the value it rejected. `logger.error(msg, err)` then
   * publishes that, plus the stack and whatever properties the client hung on it. Same shape as
   * the mail-channel leak this library fixed in `DefaultAuthEmailProvider`, one port over.
   *
   * @param plain - The plaintext password the user is trying to set.
   * @throws {@link AuthException} with `PASSWORD_COMPROMISED` when the corpus knows it.
   */
  async assertNotCompromised(plain: string): Promise<void> {
    let breached: boolean
    try {
      breached = await this.breachChecker.isBreached(plain)
    } catch {
      // NOTHING from the error reaches the line — not the object, not a description of it, not a
      // status parsed off its front. A checker is consumer code that received the plaintext, so
      // its error is a place the plaintext can be. There is no binding at all, so that is a
      // property of the code rather than a promise in a comment: a later edit that wants the error
      // has to reintroduce it and meet this paragraph on the way.
      //
      // `describeChannelStatus` was used here first and was wrong, which is worth recording
      // because the mistake is reusable. That function then kept a status parsed off the SMTP
      // reply grammar, and a breach checker is not an SMTP channel: the guarantee was that a
      // relay's prose could not masquerade as a reply code, which said nothing about text that is
      // not a reply at all. A password of `424 Correct Horse!` echoed back as the error message
      // parsed as the reply `424` and published the first three characters of the credential.
      // Right tool, wrong port — and the parse is gone from that function now, for a related
      // reason, but choosing it here would still have been wrong on the day.
      //
      // There is no status to preserve here either, so nothing is lost: an HTTP checker's own
      // code would have to come from a structured field it exposes, never parsed out of prose,
      // and this interface exposes none. The line already carries the two facts an operator acts
      // on — the check did not answer, and the password was admitted.
      //
      // Stryker disable next-line StringLiteral: diagnostic-only log text; the behaviour under
      // test is that the password is ADMITTED and a line is emitted, neither of which the
      // wording changes
      this.logger.error('breach check threw; admitting the password (the checker fails open)')
      return
    }
    if (breached) {
      throw new AuthException(AUTH_ERROR_CODES.PASSWORD_COMPROMISED)
    }
  }

  async hash(plain: string): Promise<string> {
    const salt = randomBytes(SALT_BYTES)
    const derived = await scrypt(plain, salt, SCRYPT_KEY_LEN, {
      N: this.N,
      r: this.r,
      p: this.p,
      maxmem: this.maxmem
    })
    // The parameters travel WITH the hash. Without them a verify has to assume the currently
    // configured cost, which makes `password.costFactor` unchangeable: raise it and every
    // stored hash becomes unreproducible — every user locked out, irreversibly, because the
    // value they were derived under is gone.
    //
    // Written as a PHC string, which is what rust-auth writes. This library used to write
    // `scrypt:N:r:p:salt:derived`, and the two shapes are mutually unreadable: a hash from one
    // backend verified as `invalid_credentials` on the other, and because the brute-force
    // counter is keyed identically on both, five legitimate attempts locked the account out of
    // the pair. The contract called the format "self-describing", which both encodings are —
    // and which is why the divergence survived: prose neither side could test against. It is
    // pinned by a known-answer vector now.
    //
    // `ln` is log2(N). The cost factor is validated as a power of two at startup, so the
    // exponent is exact rather than rounded.
    const ln = Math.log2(this.N)
    return `$scrypt$ln=${ln},r=${this.r},p=${this.p}$${toPhcB64(salt)}$${toPhcB64(derived)}`
  }

  /**
   * Whether a stored hash was written under weaker parameters than the ones configured now.
   *
   * A `true` here is what drives the transparent upgrade on the login path: the password has
   * just been proven, so it can be re-derived at the current cost and the stronger hash stored,
   * without the user doing anything.
   *
   * @param hash - The stored hash.
   * @returns `true` when the hash should be rewritten at the current parameters.
   */
  needsRehash(hash: string): boolean {
    const parsed = parseStoredHash(hash)
    if (parsed === null) return false
    // Deliberately NOT a comparison of derived-key length. The two libraries write different
    // lengths (64 here, 32 there) and both are recorded in the hash and verified under what
    // they record, so treating a shorter one as stale would make every hash written by the
    // other backend rehash on sight — an unbounded ping-pong across a shared user table, one
    // full KDF per crossing, that never converges.
    return parsed.N < this.N || parsed.r < this.r || parsed.p < this.p
  }

  /**
   * Verifies a plaintext password against a stored scrypt hash.
   *
   * @param plain - Plaintext password supplied by the user.
   * @param hash - Stored hash, as a PHC string.
   * @returns `true` if the password matches, `false` otherwise.
   *
   * @remarks
   * Returns `false` for malformed hash strings rather than throwing, to
   * prevent timing discrepancies caused by error-path vs. success-path
   * branching. Callers should treat `false` as an authentication failure
   * without revealing the reason (invalid hash vs. wrong password).
   */
  async compare(plain: string, hash: string): Promise<boolean> {
    const parsed = parseStoredHash(hash)
    if (parsed === null) return false

    // Verified under the parameters the hash RECORDS, never under whatever is configured
    // today. Getting this wrong is not a failed login — it is every password on the system
    // becoming unverifiable the moment someone raises the cost factor.
    const { N, r, p } = parsed

    // Derived to the length the STORED hash carries, not to this library's own. rust-auth
    // writes a 32-byte key and this one writes 64; both are valid, both record their length
    // implicitly, and deriving to a fixed length would fail every hash the other backend wrote
    // — not as a mismatch, but as `timingSafeEqual` throwing on unequal buffers.
    const candidate = await scrypt(plain, parsed.salt, parsed.derived.length, {
      N,
      r,
      p,
      // A FIXED ceiling, deliberately not derived from the record.
      //
      // This used to be `Math.max(N * r * 128 * 2, this.maxmem)` — sized to the parameters
      // actually being used, on the reasoning that `parsePhcParams` had already refused any
      // record above `MAX_KDF_BYTES_PER_DERIVATION` so it could never widen far. That is true,
      // and it made this line the second half of a single point of failure: the parser's ceiling
      // was the ONLY thing between a crafted record and a `128 * N * r` allocation, because a
      // ceiling computed FROM the record grows to fit whatever the record claims. Remove that one
      // check and `ln = 31, r = 8` asks for 2 TiB, which does not fail the request — it OOM-kills
      // the process and every in-flight connection with it.
      //
      // A constant cannot be widened by input. Nothing legitimate notices: the parser admits only
      // records needing at most `MAX_KDF_BYTES_PER_DERIVATION`, and `this.maxmem` cannot exceed
      // twice that ceiling either (startup holds the configured cost to the same limit), so this
      // is at or above every value the old expression could produce for a reachable input.
      // Above it, scrypt throws instead of allocating — a failed verification rather than a dead
      // host.
      // Stryker disable next-line ArithmeticOperator: `maxmem` is a CEILING and only its being too
      // LOW is observable (scrypt throws). Halving it leaves it above what any hash these tests
      // verify actually needs, so the derivation and its result are identical
      maxmem: MAX_KDF_BYTES_PER_DERIVATION * 2
    })

    return cryptoTimingSafeEqual(candidate, parsed.derived)
  }

  /**
   * Runs a full scrypt derivation against a fixed decoy hash and always returns
   * `false`.
   *
   * @returns Always `false`.
   *
   * @remarks
   * Call this on the login "user not found" (or "no local password") branch,
   * where there is no stored hash to compare against, so the request spends the
   * same CPU time as a real wrong-password comparison before failing. Without it,
   * an unknown e-mail returns before any hashing (~single-digit ms) while a known
   * e-mail runs scrypt (~tens of ms) — a reliable timing oracle an attacker uses
   * to enumerate which accounts exist despite an identical error message.
   *
   * The cost is bounded to a single scrypt derivation (identical to a normal
   * failed login), so it adds no amplification beyond what a valid-e-mail wrong-
   * password request already costs; pair it with route-level rate limiting.
   */
  async compareDummy(plain: string): Promise<boolean> {
    // Stryker disable next-line ObjectLiteral: emptying the options makes scrypt fall back to
    // its own defaults, which still derives a key and still compares unequal — so the RESULT is
    // identical and no assertion can separate them. What the mutant actually breaks is the
    // property this method exists for: that the decoy costs the same as a real verify, which is
    // a timing equivalence and not a value any test can read without measuring the clock
    const candidate = await scrypt(plain, DUMMY_SALT, SCRYPT_KEY_LEN, {
      N: this.N,
      r: this.r,
      p: this.p,
      maxmem: this.maxmem
    })
    // Always false — the comparison is here so the branch ends the same way a real verify
    // does, not because the result carries information.
    return cryptoTimingSafeEqual(candidate, DUMMY_EXPECTED)
  }
}
