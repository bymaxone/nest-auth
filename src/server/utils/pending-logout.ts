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
import type { AuthRedisService } from '../redis/auth-redis.service'

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
 * from the stored session the logout is announced regardless. When it came from a marker the
 * logout is announced only if this call removed it, which is what keeps the announcement to one
 * when retries race: the removal is a single atomic operation and only one caller sees it succeed.
 * A removal the store refuses never turns a completed logout into a failure.
 *
 * @param redis - The Redis wrapper.
 * @param key - The un-namespaced marker key.
 * @param fromSession - Whether the owner came from the stored session rather than the marker.
 * @param logger - Where a refused removal is reported, without the key.
 * @returns `true` when the completed logout is to be announced.
 */
export async function settlePendingLogout(
  redis: AuthRedisService,
  key: string,
  fromSession: boolean,
  logger: Logger
): Promise<boolean> {
  try {
    const removed = await redis.del(key)
    return fromSession || removed
  } catch (err: unknown) {
    logger.warn(`logout: the retry marker could not be cleared — ${describeChannelStatus(err)}`)
    return fromSession
  }
}
