/**
 * @fileoverview What the Redis service reads off the records of refresh sessions.
 *
 * @layer Infrastructure
 */

import { sessionId } from '../constants/session-id'
import { checked } from '../utils/settle'

/** What a family revocation removed, and whose it was. */
export interface RevokedFamily {
  /** How many live sessions the transaction removed. */
  removed: number
  /** The session hashes the family index named. */
  sessionHashes: string[]
  /** The family's account; `''` when no member record was readable. */
  ownerId: string
  /** The account's tenant, when the record names one. */
  tenantId?: string | undefined
}

/** The owner a session record names. */
export interface SessionOwner {
  /** `''` when there is no usable record. */
  userId: string
  tenantId: string | undefined
  /** Absent when the record names no family id a token could carry. */
  familyId?: string
}

/**
 * Reads the owner off a record whose `userId` is already known to be a string.
 *
 * A BLANK tenant is normalised to absent, not returned as a usable value. Callers test presence to
 * decide whether they can name an index, and `''` builds `dashboard:0::{userId}`, a keyspace
 * belonging to no tenant. One shape of "no tenant" at the boundary gives every caller the same
 * answer. The family id goes into a key, so it is returned only in the shape a token carries.
 *
 * @param userId - The record's owner.
 * @param record - The parsed session record.
 */
export function sessionOwner(userId: string, record: Record<string, unknown>): SessionOwner {
  const tenantId = record['tenantId']
  const familyId = sessionId(record['familyId'])
  return checked({
    userId,
    tenantId: typeof tenantId === 'string' && tenantId !== '' ? tenantId : undefined,
    ...(familyId === undefined ? {} : { familyId })
  })
}
