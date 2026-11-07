/**
 * @fileoverview The TOTP secret's at-rest cipher: encrypt under the current key, decrypt under the
 * current key or any key a rotation retired, and compare a stored ciphertext to a known secret.
 *
 * @layer Utility
 */

import { decrypt, encrypt } from '../crypto/aes-gcm'
import { timingSafeCompare } from '../crypto/secure-token'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'

/** The keys the secret cipher works with: the one in force and those a rotation retired. */
export interface MfaSecretKeys {
  readonly encryptionKey: string
  readonly previousEncryptionKeys?: readonly string[]
}

/**
 * Whether `stored` decrypts, under the current or a retired key, to `secretBase32`.
 *
 * Compares plaintext, so a record that was only re-encrypted still matches and one holding a
 * different secret does not. A ciphertext no key opens does not match either.
 *
 * @param stored - The ciphertext on the record, if any.
 * @param secretBase32 - The plaintext secret to compare against.
 * @param keys - The keys to try.
 * @returns `true` when `stored` opens to exactly `secretBase32`.
 */
export function holdsSecret(
  stored: string | null | undefined,
  secretBase32: string,
  keys: MfaSecretKeys
): boolean {
  if (!stored) return false
  try {
    return timingSafeCompare(decryptWithRotation(stored, keys).secret, secretBase32)
  } catch {
    return false
  }
}

/**
 * Encrypts a TOTP secret for storage in the database using AES-256-GCM.
 *
 * @param secret - The Base32 secret.
 * @param keys - The keys; only the current one is used.
 * @returns The ciphertext to store.
 */
export function encryptMfaSecret(secret: string, keys: MfaSecretKeys): string {
  return encrypt(secret, keys.encryptionKey)
}

/**
 * Decrypts a stored TOTP secret, falling back to keys retired by a rotation.
 *
 * The ciphertext records no key identifier, so without the retired keys, changing
 * `mfa.encryptionKey` makes every stored secret undecryptable — every enrolled user's
 * authenticator stops matching at once, with no way back. AES-GCM authenticates, so a wrong
 * key fails unambiguously rather than returning garbage; trying them in order is safe.
 *
 * Re-throws any decryption failure as an opaque `TOKEN_INVALID` to prevent
 * error-type oracle attacks (callers cannot distinguish format vs. tamper errors).
 *
 * @param encrypted - The stored ciphertext.
 * @param keys - The keys to try.
 * @returns The plaintext secret.
 */
export function decryptMfaSecret(encrypted: string, keys: MfaSecretKeys): string {
  return decryptWithRotation(encrypted, keys).secret
}

/**
 * Decrypt under the current key, then under each retired one.
 *
 * @param encrypted - The stored ciphertext.
 * @param keys - The keys to try, the current one first.
 * @returns The plaintext and whether a retired key produced it — the signal that the record
 *   should be re-encrypted under the current key.
 * @throws {@link AuthException} `TOKEN_INVALID` when no key decrypts it.
 */
export function decryptWithRotation(
  encrypted: string,
  keys: MfaSecretKeys
): { secret: string; stale: boolean } {
  try {
    return { secret: decrypt(encrypted, keys.encryptionKey), stale: false }
  } catch {
    for (const key of keys.previousEncryptionKeys ?? []) {
      try {
        return { secret: decrypt(encrypted, key), stale: true }
      } catch {
        // Try the next retired key. A ciphertext none of them opens is tampered, truncated,
        // or from a key nobody holds any more — all the same opaque failure to the caller.
      }
    }
    throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
  }
}
