/**
 * The recent-authentication marker: how the library knows a caller authenticated *just now*
 * rather than merely that it holds a token minted at some point.
 *
 * @layer Constants
 */

import { hmacSha256 } from '../crypto/secure-token'

/**
 * How long a completed authentication counts as recent, in seconds.
 *
 * Five minutes, matching the MFA temp token's lifetime — the same span the library already
 * treats as "the user is still at the keyboard, mid-flow". Long enough that a user who signs
 * in and then goes to their security settings is not sent back through the door; short enough
 * that a session lifted hours later cannot spend it.
 */
export const RECENT_AUTH_TTL_SECONDS = 300

/**
 * The Redis key holding the marker for one account on one authentication plane.
 *
 * Keyed by HMAC rather than the raw id, like every other user-derived key in this library: the
 * keyspace is shared with rust-auth and readable by anyone with access to the store, and a
 * bare id there is an account identifier in the clear. The plane is part of the preimage
 * because a dashboard user and a platform admin can carry the same id from different consumer
 * repositories — without it, one could satisfy the other's freshness check.
 *
 * @param plane - The authentication plane the marker belongs to.
 * @param userId - The account that authenticated.
 * @param hmacKey - The library's identifier-HMAC key.
 * @returns The fully-qualified Redis key.
 */
export function recentAuthKey(
  plane: 'dashboard' | 'platform',
  userId: string,
  hmacKey: string
): string {
  return `ra:${hmacSha256(`${plane}:${userId}`, hmacKey)}`
}
