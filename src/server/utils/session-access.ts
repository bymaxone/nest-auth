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
import { checked, pinned } from './settle'
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

/**
 * Ends one sign-in: every live refresh session of the family, then their access tokens.
 *
 * A grace-window recovery leaves two sessions under one family id, so the entry refuses the access
 * tokens of both. The sessions are removed first and the entry written only once they are, so no
 * session is left able to refresh into an access token that is then refused.
 *
 * @param redis - The store.
 * @param plane - The plane the sessions belong to.
 * @param familyId - The family id read from the record of the session being ended.
 * @param accessExpiresIn - The resolved `jwt.accessExpiresIn` time span.
 * @returns The hashes the family named; empty when `familyId` is not one a token could carry.
 */
export async function endSignIn(
  redis: Pick<AuthRedisService, 'revokeFamily' | 'set'>,
  plane: SessionPlane,
  familyId: unknown,
  accessExpiresIn: string
): Promise<string[]> {
  const sid = sessionId(familyId)
  if (sid === undefined) return checked([])
  const { sessionHashes } = await pinned(redis.revokeFamily(sid, plane))
  await pinned(revokeSessionAccess(redis, plane, sid, accessExpiresIn))
  return checked(sessionHashes)
}

/** The session a logout ends, and how long an access token lives. */
export interface EndedSessionAccess {
  plane: SessionPlane
  familyId: string | undefined
  accessExpiresIn: string
  /** Told every session hash the sign-in held, once they are ended. */
  ended: (sessionHashes: string[]) => void
}

/**
 * The writes of a logout that end access tokens: the blacklist entry of the presented token, and
 * the end of its whole sign-in.
 *
 * `verify` checks signature and algorithm but not expiry: an expired token is the normal case at a
 * logout, and a forged one must not blacklist an id it does not own. Only the verification is
 * tolerant — absent, malformed or signed by a secret nobody holds yields no blacklist write.
 *
 * @param redis - The store.
 * @param session - The plane and family id from the session's own record, the access lifetime, and
 *   who is told which sessions ended.
 * @param verify - Verifies the presented access token, ignoring its expiry.
 * @returns The writes to hand to `settleWrites`.
 */
export function logoutAccessWrites(
  redis: Pick<AuthRedisService, 'revokeFamily' | 'set'>,
  { plane, familyId, accessExpiresIn, ended }: EndedSessionAccess,
  verify: () => { jti: string; exp: number }
): Array<() => Promise<unknown>> {
  const endSession = async (): Promise<void> => {
    ended(await pinned(endSignIn(redis, plane, familyId, accessExpiresIn)))
  }
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
