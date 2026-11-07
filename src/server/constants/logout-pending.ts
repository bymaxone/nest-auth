/**
 * @fileoverview The marker that lets a logout retried after a failure still name whose logout it
 * is: its key and how long it lives.
 *
 * @layer Constants
 */

import { durationToSeconds } from '../config/resolved-options'

/** Which authentication plane a refresh session, and so its marker, belongs to. */
export type LogoutPlane = 'dashboard' | 'platform'

/**
 * The shortest a marker lives, in seconds.
 *
 * Five minutes, the span of "the user is still at the keyboard" used for recent authentication:
 * long enough for a client's own retry, and the floor for a deployment whose access tokens are
 * shorter.
 */
export const LOGOUT_PENDING_MIN_TTL_SECONDS = 300

/**
 * The Redis key holding the marker for one refresh session: `lp:{hash}` on the dashboard plane and
 * `plp:{hash}` on the platform plane, under the configured namespace.
 *
 * The plane is part of the key, like every other keyspace here, because dashboard and platform ids
 * come from different repositories and may collide.
 *
 * @param plane - The plane the refresh session belongs to.
 * @param sessionHash - The SHA-256 of the raw refresh token, the same hash the session key uses.
 * @returns The un-namespaced marker key.
 */
export function logoutPendingKey(plane: LogoutPlane, sessionHash: string): string {
  return `${plane === 'dashboard' ? 'lp' : 'plp'}:${sessionHash}`
}

/**
 * How long a marker lives: the configured access-token lifetime, and never less than
 * {@link LOGOUT_PENDING_MIN_TTL_SECONDS}.
 *
 * A retry later than the access token's lifetime has nothing left to blacklist, so the marker
 * outliving the token buys nothing; a flat five minutes would, on a deployment whose access tokens
 * live longer, drop a retry that still has a token to revoke.
 *
 * @param accessExpiresIn - The `jwt.accessExpiresIn` time span, e.g. `'15m'`.
 * @returns The marker's lifetime in seconds.
 */
export function logoutPendingTtlSeconds(accessExpiresIn: string | undefined): number {
  const lifetime = accessExpiresIn === undefined ? undefined : durationToSeconds(accessExpiresIn)
  return Math.max(LOGOUT_PENDING_MIN_TTL_SECONDS, Math.ceil(lifetime ?? 0))
}
