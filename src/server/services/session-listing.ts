/**
 * @fileoverview Reading one member of a session index for the listing.
 *
 * @layer Service
 */

import type { Logger } from '@nestjs/common'

import type { SessionInfo } from './session.service'
import { timingSafeCompare } from '../crypto/secure-token'
import { logStore } from '../observability/log-event'
import type { AuthRedisService } from '../redis/auth-redis.service'
import { parseStoredDetail, storedFamilyId } from '../utils/session-detail'
import { checked, pinned } from '../utils/settle'

/**
 * What reading one index member came to.
 *
 * `stale` is a data state, an absent or malformed detail record, and the member is only a
 * candidate for pruning. `failed` is an infrastructure fault: the session may be live, so the
 * listing that could not show it has to say so instead of omitting it.
 */
export type MemberRead =
  | { kind: 'session'; info: SessionInfo }
  | { kind: 'stale'; member: string }
  | { kind: 'failed'; member: string; error: unknown }

/** Where the listing reads from, and where it reports a read that failed. */
export interface ListingStore {
  redis: AuthRedisService
  logger: Logger
}

/** What names the caller's own session: the hash of its refresh token, else its family. */
export interface ListingCaller {
  hash: string | undefined
  familyId: string | undefined
}

/**
 * Reads one index member and shapes it for the listing.
 *
 * @param store - See {@link ListingStore}.
 * @param member - The `rt:{hash}` index member.
 * @param caller - See {@link ListingCaller}.
 * @returns The session, or why this member is not one: a data state or a read fault.
 */
export async function readListedSession(
  store: ListingStore,
  member: string,
  caller: ListingCaller
): Promise<MemberRead> {
  const hash = member.slice(3)
  let raw: string | null

  try {
    raw = await pinned(store.redis.get(`sd:${hash}`))
  } catch (error: unknown) {
    // A read that throws is an infrastructure fault, not a stale member. The guarded prune
    // still sees the member as a candidate, and only this line says which one happened, so a
    // Redis outage does not read as a tidy-up.
    logStore(store.logger, 'AUTH_STORE_DEGRADED', 'session_detail_read', error)
    return checked({ kind: 'failed', member, error })
  }

  const detail = raw === null ? null : parseStoredDetail(raw)
  if (detail === null) return checked({ kind: 'stale', member })

  let isCurrent: boolean
  try {
    isCurrent = await pinned(isCallers(store.redis, hash, caller))
  } catch (error: unknown) {
    logStore(store.logger, 'AUTH_STORE_DEGRADED', 'session_record_read', error)
    return checked({ kind: 'failed', member, error })
  }

  const { device, ip, createdAt, lastActivityAt } = detail
  const id = hash.slice(0, 8)
  return checked({
    kind: 'session',
    info: { id, sessionHash: hash, device, ip, isCurrent, createdAt, lastActivityAt }
  })
}

/**
 * Whether a listed session is the caller's. A refresh token that was presented decides alone;
 * without one the family in the session's refresh record is compared, and read only then.
 */
async function isCallers(
  redis: AuthRedisService,
  hash: string,
  caller: ListingCaller
): Promise<boolean> {
  if (caller.hash !== undefined) return checked(timingSafeCompare(hash, caller.hash))
  if (caller.familyId === undefined) return checked(false)
  const record = await pinned(redis.get(`rt:${hash}`))
  return checked(record !== null && storedFamilyId(record) === caller.familyId)
}
