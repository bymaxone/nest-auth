/**
 * @fileoverview The entry that ends the access tokens of one session: its key, how long it lives,
 * and the write.
 *
 * An access token is stateless and a refresh session does not know the `jti` of the tokens issued
 * from it, so ending one session writes an entry under the family id every one of them carries as
 * `sid`.
 *
 * @layer Utility
 */

import { rethrowRefusal } from './object-prototype-guard'
import { pinned } from './settle'
import { durationToSeconds } from '../config/duration'
import { sessionId } from '../constants/session-id'
import type { AuthRedisService } from '../redis/auth-redis.service'

/** Seconds an entry outlives the access-token lifetime, for the clocks of two hosts. */
const CLOCK_MARGIN_SECONDS = 60

/** The identity plane a session belongs to. */
export type SessionPlane = 'dashboard' | 'platform'

/**
 * The key of the entry for one session: `rvs:{sid}`, or `prvs:{sid}` on the platform plane.
 *
 * @param plane - The plane the session belongs to.
 * @param sid - The refresh family id, in the shape {@link sessionId} accepts.
 * @returns The un-namespaced key.
 */
export function sessionRevocationKey(plane: SessionPlane, sid: string): string {
  return `${plane === 'dashboard' ? 'rvs' : 'prvs'}:${sid}`
}

/**
 * How long an entry lives: past the last access token that could carry its `sid`.
 *
 * @param accessExpiresIn - The resolved `jwt.accessExpiresIn` time span.
 * @returns A whole number of seconds.
 */
export function sessionRevocationTtlSeconds(accessExpiresIn: string): number {
  return Math.ceil(durationToSeconds(accessExpiresIn) ?? 0) + CLOCK_MARGIN_SECONDS
}

/**
 * Ends the access tokens of one session. A family id that no token can carry as `sid` — absent, as
 * on a record written before families existed, or malformed — writes nothing.
 *
 * @param redis - The store.
 * @param plane - The plane the session belongs to.
 * @param familyId - The family id read from the session's own record.
 * @param accessExpiresIn - The resolved `jwt.accessExpiresIn` time span.
 */
export async function revokeSessionAccess(
  redis: Pick<AuthRedisService, 'set'>,
  plane: SessionPlane,
  familyId: unknown,
  accessExpiresIn: string
): Promise<void> {
  const sid = sessionId(familyId)
  if (sid === undefined) return
  const ttl = sessionRevocationTtlSeconds(accessExpiresIn)
  await pinned(redis.set(sessionRevocationKey(plane, sid), '1', ttl))
}

/** The session a logout ends, and how long an access token lives. */
export interface EndedSessionAccess {
  plane: SessionPlane
  familyId: string | undefined
  accessExpiresIn: string
}

/**
 * The writes of a logout that end access tokens: the blacklist entry of the presented token, and
 * the entry of its whole session.
 *
 * `verify` checks signature and algorithm but not expiry: an expired token is the normal case at a
 * logout, and a forged one must not blacklist an id it does not own. Only the verification is
 * tolerant — absent, malformed or signed by a secret nobody holds yields no blacklist write.
 *
 * @param redis - The store.
 * @param ended - The plane and family id from the session's own record, and the access lifetime.
 * @param verify - Verifies the presented access token, ignoring its expiry.
 * @returns The writes to hand to `settleWrites`.
 */
export function logoutAccessWrites(
  redis: Pick<AuthRedisService, 'set'>,
  { plane, familyId, accessExpiresIn }: EndedSessionAccess,
  verify: () => { jti: string; exp: number }
): Array<() => Promise<unknown>> {
  const endSession = (): Promise<unknown> =>
    revokeSessionAccess(redis, plane, familyId, accessExpiresIn)
  try {
    const payload = verify()
    const remainingTtl = payload.exp - Math.floor(Date.now() / 1000)
    if (remainingTtl > 0) {
      return [(): Promise<unknown> => redis.set(`rv:${payload.jti}`, '1', remainingTtl), endSession]
    }
  } catch (error) {
    rethrowRefusal(error)
  }
  return [endSession]
}
