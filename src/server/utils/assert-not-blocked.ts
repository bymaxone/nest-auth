/**
 * @fileoverview Account lifecycle status gate shared by every credential flow.
 *
 * @layer Utility
 */

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import type { AuthErrorCode } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'

/**
 * Maps a canonical (lowercased) blocked status to the error code that names it, so the
 * caller learns *why* the account is refused rather than a generic rejection. A status
 * that is configured as blocked but absent from this map falls back to `ACCOUNT_INACTIVE`,
 * which is why `inactive` itself carries no entry — listing it would be a second spelling
 * of the fallback, indistinguishable at runtime and therefore untestable.
 *
 * A `Map` rather than an object literal: the status is application-defined data, and a
 * plain-object lookup would resolve inherited keys, so a status of `'constructor'` or
 * `'toString'` would yield a truthy prototype member that defeats the `??` fallback and
 * reach {@link AuthException} as a non-code value. A `Map` has no prototype chain to walk.
 */
const BLOCKED_STATUS_CODES = new Map<string, AuthErrorCode>([
  ['banned', AUTH_ERROR_CODES.ACCOUNT_BANNED],
  ['suspended', AUTH_ERROR_CODES.ACCOUNT_SUSPENDED],
  ['pending', AUTH_ERROR_CODES.PENDING_APPROVAL],
  ['pending_approval', AUTH_ERROR_CODES.PENDING_APPROVAL]
])

/**
 * Throws when `status` is one of the configured blocked account statuses.
 *
 * Both sides of the comparison are lowercased because the status is application-defined
 * (a consumer may persist `'Suspended'`) while `blockedStatuses` defaults to uppercase
 * values — matching on raw strings would silently let a blocked account through.
 *
 * Call this **before** the password KDF. A blocked account must never consume scrypt
 * CPU, otherwise an attacker who knows a disabled address can force unbounded hashing
 * work with requests that could never succeed. Callers must still run the KDF (or its
 * sentinel) on the account-not-found branch so an unknown address and a wrong password
 * stay indistinguishable in elapsed time.
 *
 * @example
 * assertNotBlocked('SUSPENDED', ['BANNED', 'INACTIVE', 'SUSPENDED'])
 * // throws AuthException(auth.account_suspended, 403)
 *
 * @param status - The account's lifecycle status, as persisted by the consumer.
 * @param blockedStatuses - Configured statuses that deny authentication.
 * @throws {@link AuthException} with the matching status code and HTTP 403.
 */
export function assertNotBlocked(status: string, blockedStatuses: readonly string[]): void {
  const canonical = status.toLowerCase()

  if (!blockedStatuses.some((blocked) => blocked.toLowerCase() === canonical)) {
    return
  }

  throw new AuthException(
    BLOCKED_STATUS_CODES.get(canonical) ?? AUTH_ERROR_CODES.ACCOUNT_INACTIVE,
    403
  )
}
