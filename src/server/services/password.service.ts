import {
  randomBytes,
  ScryptOptions,
  scrypt as nodeScrypt,
  timingSafeEqual as cryptoTimingSafeEqual
} from 'node:crypto'
import { promisify } from 'node:util'

import { HttpStatus, Inject, Injectable, Logger } from '@nestjs/common'

import { BYMAX_AUTH_BREACH_CHECKER, BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
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
const DUMMY_SALT = Buffer.from('d6732149f98b3938274691d8c2f3ee63', 'hex')

/**
 * A value no derivation will produce, compared against so the decoy path ends in the same
 * constant-time comparison a real verify does.
 */
const DUMMY_EXPECTED = Buffer.alloc(SCRYPT_KEY_LEN, 0x5a)

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
  /** `true` when the value came from the pre-PHC `scrypt:N:r:p:salt:derived` encoding. */
  legacy: boolean
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
  if (!/^[A-Za-z0-9+/]+$/.test(value)) return null
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
  // `ln` is log2(N) and N must fit the KDF: 1..=31 covers every value either library will
  // accept, and bounding it here keeps `2 ** ln` from overflowing into a nonsense cost.
  if (ln < 1 || ln > 31 || r < 1 || p < 1) return null
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

  return { N: 2 ** params.ln, r: params.r, p: params.p, salt, derived, legacy: false }
}

/**
 * Decompose the pre-PHC encoding — `scrypt:N:r:p:{saltHex}:{derivedHex}`.
 *
 * Kept as a **read** path only. Every hash this library wrote before the two implementations
 * agreed on PHC is in this shape, and a stored corpus cannot be rewritten without the
 * plaintext — so it is verified here and marked stale, which migrates it on the owner's next
 * successful sign-in. Nothing mints it any more.
 *
 * @param hash - The stored hash string.
 * @returns The decomposition, or `null` when the value is not in the legacy encoding.
 */
function parseLegacyHash(hash: string): ParsedHash | null {
  const parts = hash.split(':')
  if (parts.length !== 6 || parts[0] !== 'scrypt') return null

  const [, nRaw, rRaw, pRaw, saltHex, derivedHex] = parts
  if (saltHex === undefined || derivedHex === undefined || saltHex === '' || derivedHex === '') {
    return null
  }

  const derived = Buffer.from(derivedHex, 'hex')
  // Guard the length before `timingSafeEqual`, which throws on a mismatch.
  if (derived.length !== SCRYPT_KEY_LEN) return null

  const [N, r, p] = [Number(nRaw), Number(rRaw), Number(pRaw)]
  if (!(Number.isInteger(N) && Number.isInteger(r) && Number.isInteger(p))) return null
  if (N <= 0 || r <= 0 || p <= 0) return null

  return { N, r, p, salt: Buffer.from(saltHex, 'hex'), derived, legacy: true }
}

/**
 * Decompose a stored hash into its parameters, salt and derived key.
 *
 * Both encodings are accepted, and which one a value is in is not a detail the caller sees:
 *
 * - **PHC** (`$scrypt$ln=…,r=…,p=…$salt$hash`) — what this library writes, and what rust-auth
 *   has always written. Pinned by `conformance/wire-contract.json` with a known-answer vector
 *   each side verifies against the other's output.
 * - **Legacy** (`scrypt:N:r:p:salt:derived`) — read-only, and reported as needing a rehash.
 *
 * Accepting both is not politeness. The two libraries share one user table and one brute-force
 * counter, so a hash one side cannot read is not a failed parse — it is `invalid_credentials`,
 * indistinguishable from a wrong password, five of which lock the account out of **both**
 * backends. A format the sibling cannot verify is an outage for every account it touches.
 *
 * The cost travels with the hash either way, so a value can be verified years later regardless
 * of what the deployment is configured to write today. That is what makes `password.costFactor`
 * changeable at all — a hash that did not record its cost can only be verified by guessing it,
 * and guessing wrong is every password on the system becoming unverifiable at once.
 *
 * A malformed value returns `null` rather than throwing, so the caller answers "wrong password"
 * without a branch whose timing distinguishes a corrupt record from a wrong one.
 *
 * @param hash - The stored hash string.
 * @returns The decomposition, or `null` when the value is in neither encoding.
 */
function parseStoredHash(hash: string): ParsedHash | null {
  // PHC first: it is what every new hash is written in, so the common path is one branch deep.
  // The two shapes are unambiguous — a PHC string starts with `$`, which the legacy encoding
  // never contains — so the order is a matter of cost, not of correctness.
  return parsePhcHash(hash) ?? parseLegacyHash(hash)
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
 * The pre-PHC `scrypt:N:r:p:{salt_hex}:{derived_hex}` encoding is still **read**, and reported
 * as needing a rehash so a stored corpus migrates on each owner's next successful sign-in.
 * Both encodings are held byte-compatible with rust-auth, which shares the user table.
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
  private readonly r: number
  private readonly p: number
  private readonly maxmem: number

  constructor(
    @Inject(BYMAX_AUTH_OPTIONS) options: ResolvedOptions,
    @Inject(BYMAX_AUTH_BREACH_CHECKER) private readonly breachChecker: IPasswordBreachChecker
  ) {
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
   * The plaintext is never passed to the logger; only the checker's own error is.
   *
   * @param plain - The plaintext password the user is trying to set.
   * @throws {@link AuthException} with `PASSWORD_COMPROMISED` when the corpus knows it.
   */
  async assertNotCompromised(plain: string): Promise<void> {
    let breached: boolean
    try {
      breached = await this.breachChecker.isBreached(plain)
    } catch (err: unknown) {
      this.logger.error('breach check threw; admitting the password (the checker fails open)', err)
      return
    }
    if (breached) {
      throw new AuthException(AUTH_ERROR_CODES.PASSWORD_COMPROMISED, HttpStatus.BAD_REQUEST)
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
    // Written as a PHC string, which is what rust-auth has always written. This library used to
    // write `scrypt:N:r:p:salt:derived` instead, and the two shapes are mutually unreadable: a
    // hash from one backend verified as `invalid_credentials` on the other, and because the
    // brute-force counter is keyed identically on both, five legitimate attempts locked the
    // account out of the pair. The contract called the format "self-describing", which both
    // encodings are — and which is why the divergence survived: prose neither side could test
    // against. It is pinned by a known-answer vector now.
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
    // A legacy-encoded hash is stale whatever its cost: rust-auth cannot read it, so leaving it
    // in place keeps that account unable to sign in on the other backend. The login that
    // reaches this has just proven the password, which is the only moment the value can be
    // rewritten at all — so this is the migration, and skipping it means the account never
    // migrates.
    if (parsed.legacy) return true
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
   * @param hash - Stored hash, in either the PHC or the legacy encoding.
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
      // Sized for the parameters actually being used, which may exceed the configured ones.
      maxmem: Math.max(N * r * 128 * 2, this.maxmem)
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
