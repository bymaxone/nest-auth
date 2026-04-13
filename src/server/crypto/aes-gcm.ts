import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'

/**
 * AES-256-GCM authenticated encryption and decryption.
 *
 * Uses a random 12-byte IV per encryption call, ensuring ciphertext uniqueness
 * even when the same plaintext is encrypted multiple times with the same key.
 * The GCM authentication tag provides tamper detection — decryption throws
 * if the ciphertext or key has been modified.
 *
 * Wire format: `base64(iv):base64(authTag):base64(ciphertext)`
 *
 * @remarks
 * **Key:** Must be exactly 32 bytes when base64-decoded (AES-256 requirement).
 * Use `crypto.randomBytes(32).toString('base64')` to generate a valid key.
 * Validate at startup via `resolveOptions` — do NOT generate keys at runtime.
 *
 * **Empty plaintext:** Encrypting an empty string is valid and produces a non-empty
 * ciphertext (due to the 12-byte IV and 16-byte auth tag). Callers should validate
 * that the plaintext is non-empty if their domain requires it.
 *
 * **Error normalization:** `decrypt` can throw errors with different messages
 * depending on failure mode (format error vs. auth tag failure). Callers must
 * catch all errors from `decrypt` and re-throw a single opaque error to clients
 * to prevent an error-type oracle attack.
 *
 * @example
 * ```typescript
 * const key = process.env.MFA_ENCRYPTION_KEY // 44-char base64 = 32 bytes
 * const ciphertext = encrypt('JBSWY3DPEHPK3PXP', key)
 * const plaintext  = decrypt(ciphertext, key)
 * ```
 */

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** IV length recommended by NIST SP 800-38D for AES-GCM (12 bytes = 96 bits). */
const IV_LENGTH = 12

/** GCM authentication tag length in bytes (16 bytes = 128 bits — NIST recommended maximum). */
const AUTH_TAG_BYTE_LENGTH = 16

// ---------------------------------------------------------------------------
// encrypt
// ---------------------------------------------------------------------------

/**
 * Encrypts a plaintext string using AES-256-GCM.
 *
 * @param plaintext - The string to encrypt (UTF-8 encoded). May be empty.
 * @param keyBase64 - A base64-encoded 32-byte AES-256 key.
 * @returns Encoded as `base64(iv):base64(authTag):base64(ciphertext)`.
 * @throws If the key does not decode to exactly 32 bytes.
 */
export function encrypt(plaintext: string, keyBase64: string): string {
  const key = Buffer.from(keyBase64, 'base64')
  if (key.length !== 32) {
    throw new Error(
      `[aes-gcm] Key must decode to exactly 32 bytes (got ${key.length}). ` +
        `Generate with: crypto.randomBytes(32).toString('base64')`
    )
  }

  const iv = randomBytes(IV_LENGTH)
  const cipher = createCipheriv('aes-256-gcm', key, iv)

  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
  const authTag = cipher.getAuthTag()

  return [iv.toString('base64'), authTag.toString('base64'), encrypted.toString('base64')].join(':')
}

// ---------------------------------------------------------------------------
// decrypt
// ---------------------------------------------------------------------------

/**
 * Decrypts an AES-256-GCM ciphertext produced by `encrypt`.
 *
 * @param ciphertext - Encoded as `base64(iv):base64(authTag):base64(ciphertext)`.
 * @param keyBase64 - The same base64-encoded 32-byte key used for encryption.
 * @returns The original plaintext string.
 * @throws If the ciphertext format is invalid, segment lengths are wrong, the
 *   key is incorrect, or the GCM auth tag verification fails (indicating
 *   tampering or corruption).
 *
 * @remarks
 * This function may throw errors with different messages depending on the failure
 * mode. Callers should catch all errors and re-throw a single opaque error to
 * clients to avoid leaking information about the failure type.
 */
export function decrypt(ciphertext: string, keyBase64: string): string {
  // ':' is not part of the standard base64 alphabet (A-Za-z0-9+/=), so splitting on it
  // is safe for the wire format produced by encrypt(). If the encoding is ever changed
  // to base64url (-_) or another alphabet, verify that ':' is still not a valid character.
  const parts = ciphertext.split(':')
  if (parts.length !== 3) {
    throw new Error(
      `[aes-gcm] Invalid ciphertext format. Expected 'base64(iv):base64(authTag):base64(ciphertext)'.`
    )
  }

  const [ivBase64, authTagBase64, encryptedBase64] = parts as [string, string, string]

  const key = Buffer.from(keyBase64, 'base64')
  if (key.length !== 32) {
    throw new Error(`[aes-gcm] Key must decode to exactly 32 bytes (got ${key.length}).`)
  }

  const iv = Buffer.from(ivBase64, 'base64')
  if (iv.length !== IV_LENGTH) {
    throw new Error(`[aes-gcm] Invalid IV length (got ${iv.length}, expected ${IV_LENGTH}).`)
  }

  const authTag = Buffer.from(authTagBase64, 'base64')
  if (authTag.length !== AUTH_TAG_BYTE_LENGTH) {
    throw new Error(
      `[aes-gcm] Invalid auth tag length (got ${authTag.length}, expected ${AUTH_TAG_BYTE_LENGTH}).`
    )
  }

  const encrypted = Buffer.from(encryptedBase64, 'base64')

  const decipher = createDecipheriv('aes-256-gcm', key, iv)
  decipher.setAuthTag(authTag)

  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8')
}
