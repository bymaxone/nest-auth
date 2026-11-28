/**
 * @fileoverview What the Redis service reads off the records of refresh sessions.
 *
 * @layer Infrastructure
 */

import { sessionId } from '../constants/session-id'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { checked, pinned } from '../utils/settle'

/** What a family revocation removed, and whose it was. */
export interface RevokedFamily {
  /** How many live sessions the transaction removed. */
  removed: number
  /** The session hashes the transaction removed, and any the family index named before it. */
  sessionHashes: string[]
  /** The family's account; `''` when no member record was readable. */
  ownerId: string
  /** The account's tenant, when the record names one. */
  tenantId?: string | undefined
}

/**
 * Reads what a family revocation removed. A rotation between the caller's read of the family and
 * the script moves the session to a new hash, so each side can name one the other does not.
 *
 * A reply that is no list of strings is refused rather than read as an empty family.
 *
 * @param readBefore - The members the caller read before the script ran.
 * @param reply - The members the script answered it removed.
 * @returns The script's count, and every hash of either side once.
 * @throws {@link AuthException} `auth.internal` for a reply that is no list of strings.
 */
export function removedSessions(
  readBefore: string[],
  reply: unknown
): Pick<RevokedFamily, 'removed' | 'sessionHashes'> {
  if (!Array.isArray(reply) || !reply.every((member) => typeof member === 'string')) {
    throw new AuthException(AUTH_ERROR_CODES.INTERNAL, undefined, {
      cause: new Error('Redis answered a reply that is not a list of members')
    })
  }
  return checked({ removed: reply.length, sessionHashes: [...new Set([...readBefore, ...reply])] })
}

/** How many times a family is read while no member read so far has a record naming an owner. */
const OWNER_READS = 3

/**
 * Reads a family's members and the owner their records name.
 *
 * A rotation deletes the record of the member it replaces, so one that lands between the read of
 * the members and the read of their records leaves none to name the owner: the family is read
 * again.
 *
 * @param read - Reads the family's members.
 * @param ownerOf - Reads the owner off the members' records.
 * @returns Every member any read saw, and the owner.
 */
export async function readFamily(
  read: () => Promise<string[]>,
  ownerOf: (members: string[]) => Promise<SessionOwner>
): Promise<SessionOwner & { members: string[] }> {
  let members: string[] = []
  let owner: SessionOwner = { userId: '', tenantId: undefined }
  for (let reads = 0; reads < OWNER_READS && owner.userId === ''; reads += 1) {
    const latest = await pinned(read())
    members = [...members, ...latest]
    owner = await pinned(ownerOf(latest))
  }
  return checked({ ...owner, members })
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
