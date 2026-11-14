/**
 * @fileoverview The two halves of the marker a failed logout leaves for its retry: writing it when
 * an attempt fails, and settling it when a logout completes.
 *
 * The guarantee is exactly-once for sequential retries: a failed attempt, then retries one after
 * another, announce the logout once. It is at-least-once when attempts of one logout run
 * concurrently, because attempts that all read the live session each announce on completing, and
 * a failed attempt that is slower than a successful one can write its marker after that one has
 * cleared it, leaving a marker a later retry claims.
 *
 * @layer Utility
 */

import type { Logger } from '@nestjs/common'

import { describeChannelStatus } from './describe-error'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { AuthRedisService } from '../redis/auth-redis.service'
import { isServiceUnavailable } from '../redis/redis-outage'

/** The account a logout belongs to, as the marker records it. */
export interface PendingLogoutOwner {
  readonly userId: string
  readonly tenantId: string | undefined
}

/**
 * Records who a failed logout belonged to, for the retry that will complete it.
 *
 * An attempt that fails has usually deleted the refresh session already, so the retry would find
 * no record naming its owner. The write is best effort: the logout is already failing, and a
 * marker that cannot be written leaves the retry exactly where it would have been without one.
 *
 * @param redis - The Redis wrapper.
 * @param key - The un-namespaced marker key.
 * @param owner - The account the session record named.
 * @param ttlSeconds - How long the marker lives.
 * @param logger - Where a refused write is reported, without the key.
 */
export async function rememberPendingLogout(
  redis: AuthRedisService,
  key: string,
  owner: PendingLogoutOwner,
  ttlSeconds: number,
  logger: Logger
): Promise<void> {
  try {
    // `JSON.stringify` omits an undefined `tenantId`, which is how a record with no tenant is
    // written: the field is absent, never the string `undefined`.
    await redis.set(
      key,
      JSON.stringify({ userId: owner.userId, tenantId: owner.tenantId }),
      ttlSeconds
    )
  } catch (err: unknown) {
    logger.warn(`logout: the owner could not be kept for a retry — ${describeChannelStatus(err)}`)
  }
}

/**
 * Settles the marker once a logout has completed, and says whether the logout is announced.
 *
 * The marker is removed whatever its source, so a later repeat finds nothing. When the owner came
 * from the marker the logout is announced only if this call removed it, which is what keeps the
 * announcement to one when retries race: the removal is a single atomic operation and only one
 * caller sees it succeed. A claim the store refuses answers an error and announces nothing: the
 * marker is left, and the retry claims it and announces once.
 *
 * When the owner came from the stored session the logout is announced regardless, but a stale
 * marker whose removal the store refuses would let a later retry claim it and announce the same
 * logout again. A second read decides: no marker left, announce; a marker left, answer an error
 * and announce nothing, because the session is already gone and the retry claims the marker and
 * announces once; the read refused too, so whether a marker is left is unknown: the owner is
 * recorded again, best effort, and the error is answered, so the retry has a marker to claim.
 *
 * @param redis - The Redis wrapper.
 * @param key - The un-namespaced marker key.
 * @param fromSession - Whether the owner came from the stored session rather than the marker.
 * @param owner - The account the logout belongs to, recorded again when the marker cannot be
 *   shown absent.
 * @param ttlSeconds - The lifetime a marker written again is given.
 * @param logger - Where a refused removal is reported, without the key.
 * @returns `true` when the completed logout is to be announced.
 * @throws {@link AuthException} `INTERNAL` when the claim of a marker-sourced owner is refused, or
 *   when a stale marker may remain, so the client retries.
 */
export async function settlePendingLogout(
  redis: AuthRedisService,
  key: string,
  fromSession: boolean,
  owner: PendingLogoutOwner,
  ttlSeconds: number,
  logger: Logger
): Promise<boolean> {
  try {
    const removed = await redis.del(key)
    return fromSession || removed
  } catch (err: unknown) {
    logger.warn(`logout: the retry marker could not be cleared — ${describeChannelStatus(err)}`)
    // A claim that cannot be made answers an error too: success would keep the client from
    // retrying, and the marker that is left is what lets the retry announce once.
    if (!fromSession)
      throw isServiceUnavailable(err) ? err : new AuthException(AUTH_ERROR_CODES.INTERNAL)
    return confirmNoStaleMarker(redis, key, owner, ttlSeconds, logger)
  }
}

/**
 * Decides whether a stale marker that could not be removed is still there.
 *
 * @returns `true` when a second read finds no marker.
 * @throws {@link AuthException} `SERVICE_UNAVAILABLE` when the store cannot answer, `INTERNAL` when a
 *   marker is left, or when that cannot be told.
 */
async function confirmNoStaleMarker(
  redis: AuthRedisService,
  key: string,
  owner: PendingLogoutOwner,
  ttlSeconds: number,
  logger: Logger
): Promise<boolean> {
  try {
    if ((await redis.get(key)) === null) return true
  } catch (err: unknown) {
    await rememberPendingLogout(redis, key, owner, ttlSeconds, logger)
    // A store that cannot answer is a 503 the client retries, not a failure to report as internal.
    if (isServiceUnavailable(err)) throw err
  }
  throw new AuthException(AUTH_ERROR_CODES.INTERNAL)
}
