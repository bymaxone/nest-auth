import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'

/**
 * TOTP (Time-based One-Time Password) implementation per RFC 6238 / HOTP per RFC 4226.
 *
 * Uses HMAC-SHA1 with 30-second time steps and 6-digit codes, matching the
 * configuration expected by Google Authenticator, Authy, and compatible apps.
 *
 * All operations are pure functions — no I/O, no side effects. The caller is
 * responsible for storage, encryption, and verification window selection.
 *
 * @remarks
 * **Security constraints:**
 * - TOTP secrets must be at least 20 bytes (160 bits) as required by RFC 4226 §4.
 * - Never store secrets in plaintext — always encrypt before persistence using
 *   `src/server/crypto/aes-gcm.ts`.
 * - Anti-replay: the caller must track used codes in Redis with a TTL equal to
 *   the validation window to prevent reuse within the same time step.
 * - Verification window of 1 (default) accepts the previous, current, and next
 *   30-second periods (±30 s drift). Do not increase beyond 2.
 *
 * **Algorithm note:** HMAC-SHA1 is intentional and mandated by RFC 6238 for
 * interoperability with authenticator apps. SHA-1 collision weaknesses do not
 * apply to HMAC-SHA1 constructions (NIST SP 800-107). Do not replace with
 * HMAC-SHA256 — it would break compatibility with all standard TOTP apps.
 */

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** TOTP time step in seconds (RFC 6238 §5.2 recommends 30 s). */
const TOTP_STEP_SECONDS = 30

/** Number of digits in a generated TOTP code (RFC 4226 §5.3 allows 6–8). */
const TOTP_DIGITS = 6

/** Base32 alphabet per RFC 4648 §6 (uppercase A–Z and digits 2–7). */
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

/** Minimum secret length in bytes (RFC 4226 §4 recommends 20 bytes / 160 bits). */
const MIN_SECRET_BYTES = 20

// ---------------------------------------------------------------------------
// Base32 encoding
// ---------------------------------------------------------------------------

/**
 * Encodes a Buffer as a Base32 string (RFC 4648 §6, no padding).
 *
 * Authenticator apps require Base32-encoded secrets in the `otpauth://` URI.
 * Padding (`=`) is omitted — it is optional per RFC and most apps accept both forms.
 *
 * @param input - Raw bytes to encode.
 * @returns Uppercase Base32 string without `=` padding.
 */
export function toBase32(input: Buffer): string {
  let bits = 0
  let value = 0
  let output = ''

  for (let i = 0; i < input.length; i++) {
    value = (value << 8) | input.readUInt8(i)
    bits += 8

    while (bits >= 5) {
      bits -= 5
      output += BASE32_ALPHABET[(value >>> bits) & 0x1f]
    }
  }

  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 0x1f]
  }

  return output
}

/**
 * Decodes a Base32 string (RFC 4648 §6) back to a Buffer.
 *
 * Accepts both uppercase and lowercase input. Padding characters (`=`) and
 * whitespace are silently stripped, matching lenient handling recommended for
 * user-facing secrets (e.g. secrets displayed as `XXXX XXXX XXXX` groups).
 *
 * @param input - Base32-encoded string (with or without `=` padding or spaces).
 * @returns Raw decoded bytes.
 * @throws If the string contains characters outside the Base32 alphabet.
 */
export function fromBase32(input: string): Buffer {
  // Strip whitespace, hyphens, and padding characters before processing.
  // Handles user-friendly group separators (spaces, hyphens) common in displayed secrets.
  const normalized = input.toUpperCase().replace(/[\s=-]/g, '')
  let bits = 0
  let value = 0
  const output: number[] = []

  for (const char of normalized) {
    const idx = BASE32_ALPHABET.indexOf(char)
    if (idx === -1) {
      // Use JSON.stringify to safely represent any control character in the error message.
      throw new Error(`[totp] Invalid Base32 character: ${JSON.stringify(char)}`)
    }
    value = (value << 5) | idx
    bits += 5

    if (bits >= 8) {
      bits -= 8
      output.push((value >>> bits) & 0xff)
    }
  }

  return Buffer.from(output)
}

// ---------------------------------------------------------------------------
// TOTP secret generation
// ---------------------------------------------------------------------------

/**
 * Generates a cryptographically secure TOTP secret.
 *
 * Produces 20 random bytes (160 bits) — the minimum recommended by RFC 4226 §4.
 * The secret is returned both as a raw Buffer (for encryption) and as a Base32
 * string (for QR code generation and authenticator apps).
 *
 * @returns Object with `raw` (Buffer) and `base32` (string) representations.
 *
 * @example
 * ```typescript
 * const { base32, raw } = generateTotpSecret()
 * const encrypted = encrypt(base32, options.mfa.encryptionKey)
 * const qrUri = buildTotpUri(base32, user.email, options.mfa.issuer)
 * ```
 */
export function generateTotpSecret(): { raw: Buffer; base32: string } {
  const raw = randomBytes(MIN_SECRET_BYTES)
  return { raw, base32: toBase32(raw) }
}

// ---------------------------------------------------------------------------
// OTPAuth URI
// ---------------------------------------------------------------------------

/**
 * Builds an `otpauth://totp/` URI for QR code generation.
 *
 * The URI follows the Key URI Format specification used by Google Authenticator
 * and compatible apps. Scanning the QR code pre-fills the secret and issuer.
 *
 * Query parameters are encoded with `encodeURIComponent` (RFC 3986), not
 * `application/x-www-form-urlencoded` (URLSearchParams), to produce `%20` for
 * spaces rather than `+`. Some strict TOTP clients reject `+`-encoded spaces.
 *
 * @param secretBase32 - Base32-encoded TOTP secret (from `generateTotpSecret`).
 *   Must encode at least 20 bytes (≥ 32 base32 characters).
 * @param accountEmail - User's email address (displayed in the authenticator app).
 *   Must not be empty.
 * @param issuer - Application name shown alongside the account in the app.
 *   Must not be empty.
 * @returns A fully-qualified `otpauth://totp/` URI.
 * @throws If any argument is empty or if `secretBase32` is shorter than 32 characters.
 *
 * @example
 * ```typescript
 * const uri = buildTotpUri('JBSWY3DPEHPK3PXP', 'user@example.com', 'My App')
 * // otpauth://totp/My%20App%3Auser%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=My%20App&...
 * ```
 */
export function buildTotpUri(secretBase32: string, accountEmail: string, issuer: string): string {
  if (!secretBase32 || secretBase32.length < 32) {
    throw new Error(
      '[totp] secretBase32 must encode at least 20 bytes (minimum 32 base32 characters)'
    )
  }
  if (!issuer) {
    throw new Error('[totp] issuer must not be empty')
  }
  if (!accountEmail) {
    throw new Error('[totp] accountEmail must not be empty')
  }

  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(accountEmail)}`

  // Build query string with encodeURIComponent (RFC 3986 percent-encoding).
  // URLSearchParams is intentionally avoided — it uses application/x-www-form-urlencoded
  // which encodes spaces as '+' rather than '%20', violating the Key URI Format spec.
  const qs = [
    `secret=${encodeURIComponent(secretBase32)}`,
    `issuer=${encodeURIComponent(issuer)}`,
    `algorithm=SHA1`,
    `digits=${String(TOTP_DIGITS)}`,
    `period=${String(TOTP_STEP_SECONDS)}`
  ].join('&')

  return `otpauth://totp/${label}?${qs}`
}

// ---------------------------------------------------------------------------
// HOTP (RFC 4226)
// ---------------------------------------------------------------------------

/**
 * Generates an HOTP (HMAC-based One-Time Password) code for a given counter.
 *
 * Implements RFC 4226 §5:
 * 1. Compute HMAC-SHA1 of the 8-byte big-endian counter with the secret.
 * 2. Dynamic truncation: extract 4 bytes starting at offset = last nibble of the digest.
 * 3. Reduce to `TOTP_DIGITS` digits via modulo.
 *
 * @param secretBase32 - Base32-encoded secret (minimum 20 decoded bytes).
 * @param counter - The HOTP counter value. Must be a non-negative safe integer.
 * @returns Zero-padded string of length `TOTP_DIGITS`.
 * @throws If the secret decodes to fewer than `MIN_SECRET_BYTES` bytes or the counter
 *   is outside the safe integer range.
 *
 * @internal Exported for unit testing against RFC 4226 Appendix D vectors only.
 */
export function generateHotp(secretBase32: string, counter: number): string {
  const key = fromBase32(secretBase32)

  if (key.length < MIN_SECRET_BYTES) {
    throw new Error(
      `[totp] Secret too short: ${key.length} bytes (minimum ${MIN_SECRET_BYTES}). ` +
        'Generate secrets with generateTotpSecret().'
    )
  }

  // Guard against floating-point precision loss above Number.MAX_SAFE_INTEGER.
  // TOTP counters derived from Date.now() are always well within the 32-bit low word,
  // but an explicit guard prevents silent correctness issues in edge cases.
  if (!Number.isInteger(counter) || counter < 0 || counter > Number.MAX_SAFE_INTEGER) {
    throw new Error(`[totp] Counter must be a non-negative safe integer (got ${counter}).`)
  }

  // Encode counter as 8-byte big-endian unsigned integer.
  // JavaScript bitwise operators work on 32-bit integers, so split into two 32-bit words.
  const counterBuffer = Buffer.allocUnsafe(8)
  const hi = Math.floor(counter / 0x100000000)
  const lo = counter >>> 0
  counterBuffer.writeUInt32BE(hi, 0)
  counterBuffer.writeUInt32BE(lo, 4)

  const hmac = createHmac('sha1', key).update(counterBuffer).digest()

  // Dynamic truncation per RFC 4226 §5.4
  // readUInt8 is used instead of indexed access to avoid non-null assertions.
  // HMAC-SHA1 is always 20 bytes; offset is masked to 0–15, so offset+3 ≤ 18 — always in range.
  const offset = hmac.readUInt8(hmac.length - 1) & 0x0f
  const truncated =
    ((hmac.readUInt8(offset) & 0x7f) << 24) |
    ((hmac.readUInt8(offset + 1) & 0xff) << 16) |
    ((hmac.readUInt8(offset + 2) & 0xff) << 8) |
    hmac.readUInt8(offset + 3)

  const mod = 10 ** TOTP_DIGITS
  return String(truncated % mod).padStart(TOTP_DIGITS, '0')
}

// ---------------------------------------------------------------------------
// TOTP (RFC 6238)
// ---------------------------------------------------------------------------

/**
 * Generates the current TOTP code for a secret.
 *
 * Uses the current system clock and a 30-second time step.
 *
 * @param secretBase32 - Base32-encoded TOTP secret.
 * @returns The 6-digit TOTP code for the current 30-second window.
 *
 * @internal Production code should use `verifyTotp`. This export exists for
 *   integration testing flows where the test generates a code to submit.
 *   Do not use in application logic — it would allow generating codes on behalf
 *   of users, which is a privilege that must remain outside the auth library.
 */
export function generateTotp(secretBase32: string): string {
  const counter = Math.floor(Date.now() / 1000 / TOTP_STEP_SECONDS)
  return generateHotp(secretBase32, counter)
}

/**
 * Verifies a submitted TOTP code against a secret within an acceptable time window.
 *
 * Checks `window` steps before and after the current time step to tolerate
 * clock drift between the server and the user's authenticator device.
 *
 * Uses constant-time comparison via `crypto.timingSafeEqual` to prevent
 * timing side-channels, consistent with the project's security policy.
 *
 * @param secretBase32 - Base32-encoded TOTP secret stored for the user.
 * @param code - The 6-digit code submitted by the user.
 * @param window - Number of 30-second periods to check on each side of now.
 *   Default: `1` (accepts codes ±30 s from current time).
 *   Maximum recommended: `2` (±60 s).
 * @returns `true` if the code matches any step within the window, `false` otherwise.
 *
 * @remarks
 * Anti-replay is the caller's responsibility: a valid code should be stored in
 * Redis with a TTL of at least `(2 * window + 1) * 30` seconds to prevent reuse
 * within the same verification window.
 *
 * @example
 * ```typescript
 * const valid = verifyTotp(user.decryptedSecret, dto.code, options.mfa.totpWindow)
 * if (!valid) throw new AuthException(AUTH_ERROR_CODES.MFA_INVALID_CODE)
 * ```
 */
export function verifyTotp(secretBase32: string, code: string, window = 1): boolean {
  if (!/^\d{6}$/.test(code)) return false

  const currentStep = Math.floor(Date.now() / 1000 / TOTP_STEP_SECONDS)

  for (let delta = -window; delta <= window; delta++) {
    const expected = generateHotp(secretBase32, currentStep + delta)
    // Use constant-time comparison to prevent timing attacks.
    // Both strings are always exactly TOTP_DIGITS characters, so the length
    // guard in timingSafeEqual never short-circuits on valid expected values.
    const expectedBuf = Buffer.from(expected, 'utf8')
    const codeBuf = Buffer.from(code, 'utf8')
    if (expectedBuf.length === codeBuf.length && timingSafeEqual(expectedBuf, codeBuf)) {
      return true
    }
  }

  return false
}
