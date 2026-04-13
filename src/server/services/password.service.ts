import {
  randomBytes,
  ScryptOptions,
  scrypt as nodeScrypt,
  timingSafeEqual as cryptoTimingSafeEqual
} from 'node:crypto'
import { promisify } from 'node:util'

import { Inject, Injectable } from '@nestjs/common'

import { BYMAX_AUTH_OPTIONS } from '../bymax-one-nest-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'

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
 * Defaults are `costFactor = 32768 (2^15)`, `blockSize = 8`, `parallelization = 1`.
 * Override in `BymaxAuthModule.forRoot({ password: { costFactor: 65536 } })`.
 * Validated at startup by `resolveOptions()` — values below `16384 (2^14)` are rejected.
 *
 * **Security:** Comparison uses `crypto.timingSafeEqual` to prevent timing
 * attacks. All comparison failures return `false` — never throw on bad input.
 *
 * **Thread safety:** scrypt is CPU-intensive. In production, calls will block
 * the Node.js event loop for ~100–200 ms. Consider running behind a worker
 * thread or rate-limiting authentication endpoints.
 */
@Injectable()
export class PasswordService {
  private readonly N: number
  private readonly r: number
  private readonly p: number
  private readonly maxmem: number

  constructor(@Inject(BYMAX_AUTH_OPTIONS) options: ResolvedOptions) {
    this.N = options.password.costFactor
    this.r = options.password.blockSize
    this.p = options.password.parallelization
    // Memory limit: double the actual scrypt requirement (N * r * 128 bytes) to
    // prevent spurious "memory limit exceeded" errors on resource-constrained hosts.
    // The OpenSSL default of 32 MB matches the requirement exactly for N=2^15, r=8;
    // doubling provides headroom without changing attacker cost.
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
  async hash(plain: string): Promise<string> {
    const salt = randomBytes(SALT_BYTES)
    const derived = await scrypt(plain, salt, SCRYPT_KEY_LEN, {
      N: this.N,
      r: this.r,
      p: this.p,
      maxmem: this.maxmem
    })
    return `scrypt:${salt.toString('hex')}:${derived.toString('hex')}`
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
    const parts = hash.split(':')
    if (parts.length !== 3 || parts[0] !== 'scrypt') return false

    const saltHex = parts[1]
    const derivedHex = parts[2]

    if (!saltHex || !derivedHex) return false

    const salt = Buffer.from(saltHex, 'hex')
    const storedDerived = Buffer.from(derivedHex, 'hex')

    // Guard against buffers of unexpected length to avoid timingSafeEqual throwing.
    if (storedDerived.length !== SCRYPT_KEY_LEN) return false

    const candidate = await scrypt(plain, salt, SCRYPT_KEY_LEN, {
      N: this.N,
      r: this.r,
      p: this.p,
      maxmem: this.maxmem
    })

    return cryptoTimingSafeEqual(candidate, storedDerived)
  }
}
