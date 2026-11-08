/**
 * @fileoverview MFA recovery codes: minting them, deriving their stored digest, and finding a
 * submitted code among the stored digests in time that does not depend on where it sits.
 *
 * @layer Utility
 */

import { randomBytes } from 'node:crypto'

import { hmacSha256, timingSafeCompare } from '../crypto/secure-token'

/** Number of recovery codes generated when none is configured. */
export const DEFAULT_RECOVERY_CODE_COUNT = 8

/**
 * Derives the stored digest for a recovery code: a keyed HMAC-SHA-256, hex encoded.
 *
 * A recovery code is 96 bits of CSPRNG output, not a human-chosen password, so a
 * memory-hard KDF buys nothing against it — there is no dictionary to walk and brute
 * forcing 2^96 is out of reach whatever the hash costs. What the KDF did buy was an
 * attacker-reachable CPU amplifier: a challenge submitting a wrong recovery code scanned
 * every stored digest, so one request cost as many scrypt derivations as the user had
 * codes. The keyed MAC is the right primitive here — the secret key is what stops an
 * offline attacker precomputing digests from a leaked table, and it costs microseconds.
 *
 * @param code - The plain recovery code.
 * @param hmacKey - The key in force.
 * @returns The digest to store.
 */
export function digestRecoveryCode(code: string, hmacKey: string): string {
  return hmacSha256(code, hmacKey)
}

/**
 * Generates `count` recovery codes in `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` format
 * (96 bits of entropy per code, hex-encoded).
 *
 * Returns both the plain-text (shown once to the user) and keyed-digest
 * versions (stored in the database).
 *
 * @remarks
 * Each code carries 96 bits of entropy (12 random bytes → 24 hex chars grouped
 * as 6 × 4). This is well above the NIST SP 800-63B recommendation for
 * offline-resistant credentials.
 *
 * @param count - How many codes to mint.
 * @param hmacKey - The key the stored digests are derived under.
 * @returns The plain codes and their digests, index for index.
 */
export function generateRecoveryCodes(
  count: number,
  hmacKey: string
): { plainCodes: string[]; hashedCodes: string[] } {
  const plainCodes: string[] = []
  const hashedCodes: string[] = []

  for (let i = 0; i < count; i++) {
    // 12 random bytes → 24 hex characters → 96-bit entropy.
    // Grouped as 6 × 4 for better user readability when typed manually.
    // Build the groups via a deterministic slice loop rather than RegExp.match,
    // so the type narrows cleanly without a non-null assertion.
    const hex = randomBytes(12).toString('hex')
    const groups: string[] = []
    for (let offset = 0; offset < hex.length; offset += 4) {
      groups.push(hex.slice(offset, offset + 4))
    }
    const code = groups.join('-').toUpperCase()
    plainCodes.push(code)
    hashedCodes.push(digestRecoveryCode(code, hmacKey))
  }

  return { plainCodes, hashedCodes }
}

/**
 * Compares a submitted recovery code against every stored digest.
 *
 * One storage format only: a keyed MAC over the code. Every digest is compared in constant
 * time and the scan always runs to completion — including the step that picks the winner out
 * of the recorded results — so neither the position of a match nor the number of codes still
 * unused is observable in the response time.
 *
 * @param code - The submitted code.
 * @param hashedCodes - The digests stored on the account.
 * @param hmacKey - The key in force.
 * @param previousHmacKeys - Keys retired by a rotation, which still verify.
 * @returns Index of the first matching digest, or `-1` if none match.
 */
export async function verifyRecoveryCode(
  code: string,
  hashedCodes: string[],
  hmacKey: string,
  previousHmacKeys: readonly string[]
): Promise<number> {
  // One candidate per key in play: the current one, then any retired by a rotation. The
  // digest is keyed by an HMAC derived from the identifier secret (`identifierKey`, else
  // `jwt.secret`), so without the retired keys a
  // rotation would silently invalidate every code a user has printed and filed — they would
  // discover it at the moment they most need it. Retired keys verify only; a code that
  // matches one is consumed and the set is regenerated under the current key.
  const candidates = [
    digestRecoveryCode(code, hmacKey),
    ...previousHmacKeys.map((key) => hmacSha256(code, key))
  ]
  const macMatches: boolean[] = []

  for (const hashedCode of hashedCodes) {
    // Every candidate is compared, never short-circuited: stopping at the first hit would
    // make the scan's duration report how many keys were tried before the match. `reduce`
    // visits the whole list by construction, and the comparison is the left operand of `||`
    // so it is evaluated on every step regardless of what has already matched.
    const hit = candidates.reduce(
      (found, candidate) => timingSafeCompare(candidate, hashedCode) || found,
      false
    )
    macMatches.push(hit)
  }

  // Recording every comparison and picking the first hit afterwards, rather than tracking the
  // winner inside the loop, keeps the scan uniform: the same work happens whether the match
  // is at the front, at the back, or absent.
  //
  // Reduced rather than `indexOf`, which stops at the first hit — the tail of the scan then
  // runs shorter for an early match than for a late one or none, which is the position signal
  // the loop above exists to avoid, reintroduced on the last line of it. The reduction visits
  // every entry, and the first hit wins because a later one cannot overwrite a set index.
  // `-1` means no digest matched.
  return macMatches.reduce((found, hit, index) => (found === -1 && hit ? index : found), -1)
}
