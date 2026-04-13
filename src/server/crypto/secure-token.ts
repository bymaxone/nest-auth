import {
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual as cryptoTimingSafeEqual
} from 'node:crypto'

/**
 * Generates a cryptographically secure random token as a hex string.
 *
 * Used for password-reset tokens, email-verification tokens, and invitation
 * tokens that are stored in Redis and verified by the client. The hex encoding
 * is safe for use in URLs and query parameters.
 *
 * @param bytes - Number of random bytes to generate. Must be a positive integer.
 *   Defaults to 32 (256 bits), producing a 64-character hex string.
 * @returns Hex-encoded random string of length `bytes * 2`.
 * @throws If `bytes` is not a positive integer.
 *
 * @example
 * ```typescript
 * const token = generateSecureToken()    // 64-char hex (default 32 bytes)
 * const short  = generateSecureToken(16) // 32-char hex (16 bytes)
 * ```
 */
export function generateSecureToken(bytes = 32): string {
  if (!Number.isInteger(bytes) || bytes < 1) {
    throw new Error(`[secure-token] bytes must be a positive integer (got ${bytes}).`)
  }
  return randomBytes(bytes).toString('hex')
}

/**
 * Computes the SHA-256 hash of a string and returns it as a lowercase hex digest.
 *
 * Used to derive a safe Redis key from a high-entropy secret value (e.g. random
 * token) without storing the secret in plaintext. The hash is also used for
 * brute-force tracking: `sha256(email).substring(0, 8)` appears in logs
 * instead of the raw email.
 *
 * @remarks
 * SHA-256 is a one-way function — the output cannot be reversed to recover the input.
 * It is deterministic: the same input always produces the same output.
 *
 * **Security warning:** Do NOT use `sha256` to hash low-entropy inputs (such as
 * email addresses or short codes) as Redis keys that may be visible to attackers.
 * Bare SHA-256 (without a key) is reversible by dictionary or rainbow-table lookup
 * for common values. For low-entropy inputs, use `hmacSha256(input, serverSecret)`
 * instead. Use `sha256` only for hashing high-entropy random tokens.
 *
 * **Password storage:** Do NOT use this for passwords — use the scrypt-based
 * `PasswordService` instead.
 *
 * @param input - The string to hash (UTF-8 encoded).
 * @returns 64-character lowercase hex digest.
 *
 * @example
 * ```typescript
 * // CORRECT — token is high-entropy random bytes
 * const tokenHash = sha256(rawToken) // stored in Redis; rawToken sent to user
 *
 * // INCORRECT — email is low-entropy; use hmacSha256 instead
 * // const key = `brute:${sha256(email)}`
 * ```
 */
export function sha256(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex')
}

/**
 * Performs a constant-time equality comparison between two strings.
 *
 * Required when comparing secrets, tokens, or hashes to prevent timing attacks.
 * Uses `crypto.timingSafeEqual` internally, padded to equal length before comparison.
 *
 * @remarks
 * Returns `false` immediately (without constant-time behavior) if the strings
 * have different byte lengths. This length comparison leaks the length of the
 * expected value — if this is a concern, compare hashes of fixed length (e.g.
 * SHA-256 digests) rather than raw tokens.
 *
 * @param a - First string to compare.
 * @param b - Second string to compare.
 * @returns `true` if both strings are identical, `false` otherwise.
 *
 * @example
 * ```typescript
 * const storedHash = sha256(storedToken)
 * const incomingHash = sha256(incomingToken)
 * if (!timingSafeCompare(storedHash, incomingHash)) {
 *   throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
 * }
 * ```
 */
export function timingSafeCompare(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8')
  const bufB = Buffer.from(b, 'utf8')
  if (bufA.length !== bufB.length) return false
  return cryptoTimingSafeEqual(bufA, bufB)
}

/**
 * Computes an HMAC-SHA-256 of a message using a server secret and returns
 * the result as a lowercase hex digest.
 *
 * Use this instead of bare {@link sha256} when the input has low entropy
 * (e.g. email addresses, IP addresses). A keyed HMAC prevents rainbow-table
 * or dictionary reversal of the stored identifier:
 *
 * ```
 * bruteForceService.isLockedOut(hmacSha256(email, serverSecret))
 * ```
 *
 * @param message - The value to authenticate (UTF-8 encoded).
 * @param secret - A high-entropy server secret. Should be at least 32 bytes,
 *   generated with `crypto.randomBytes(32).toString('base64')`.
 * @returns 64-character lowercase hex HMAC digest.
 *
 * @example
 * ```typescript
 * // Produce a stable, non-reversible identifier for brute-force tracking
 * const identifier = hmacSha256(email, process.env.BRUTE_FORCE_SECRET)
 * const locked = await bruteForceService.isLockedOut(identifier)
 * ```
 */
export function hmacSha256(message: string, secret: string): string {
  return createHmac('sha256', secret).update(message, 'utf8').digest('hex')
}
