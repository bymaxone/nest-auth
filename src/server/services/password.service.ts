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
 * Password hashing and verification service using `node:crypto` scrypt.
 *
 * Uses scrypt (RFC 7914) — a memory-hard key derivation function designed to
 * resist brute-force and GPU/ASIC attacks. **Never use SHA-256, MD5, or
 * unsalted hashes for passwords.**
 *
 * Wire format: `scrypt:{salt_hex}:{derived_hex}`
 *  - `salt_hex` — 32-char hex string (16 random bytes)
 *  - `derived_hex` — 128-char hex string (64 derived bytes)
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
/** A stored hash, decomposed into the parameters it was written under, its salt and its key. */
type ParsedHash = {
  N: number
  r: number
  p: number
  salt: Buffer
  derived: Buffer
}

/**
 * Decompose a stored hash into its parameters, salt and derived key.
 *
 * The format is `scrypt:N:r:p:salt:derived`: the cost travels with the hash, so it can be
 * verified years later regardless of what the deployment is configured to write today. That is
 * what makes `password.costFactor` changeable at all — a hash that did not record its cost can
 * only be verified by guessing it, and guessing wrong is every password on the system becoming
 * unverifiable at once.
 *
 * A malformed value returns `null` rather than throwing, so the caller answers "wrong password"
 * without a branch whose timing distinguishes a corrupt record from a wrong one.
 *
 * @param hash - The stored hash string.
 * @returns The decomposition, or `null` when the value is not a hash this library wrote.
 */
function parseStoredHash(hash: string): ParsedHash | null {
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

  return { N, r, p, salt: Buffer.from(saltHex, 'hex'), derived }
}

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
   * @returns Hashed password in `scrypt:{salt_hex}:{derived_hex}` format.
   *
   * @example
   * ```typescript
   * const hash = await passwordService.hash('my-password')
   * // 'scrypt:4a3b...:{128 hex chars}'
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
    // value they were derived under is gone. rust-auth has always carried them (PHC strings);
    // this is the same guarantee in the shape this library already writes.
    return `scrypt:${this.N}:${this.r}:${this.p}:${salt.toString('hex')}:${derived.toString('hex')}`
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
    return parsed.N < this.N || parsed.r < this.r || parsed.p < this.p
  }

  /**
   * Verifies a plaintext password against a stored scrypt hash.
   *
   * @param plain - Plaintext password supplied by the user.
   * @param hash - Stored hash in `scrypt:{salt_hex}:{derived_hex}` format.
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

    const candidate = await scrypt(plain, parsed.salt, SCRYPT_KEY_LEN, {
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
