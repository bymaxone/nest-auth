/**
 * @fileoverview Stores a new invitation over the pending one its inviter judged, and the Lua that does it.
 *
 * @layer Redis
 */

import type { AuthRedisService } from './auth-redis.service'
import { integerReply } from './integer-reply'
import { pinned } from '../utils/settle'

/**
 * Only while the index in `KEYS[1]` still holds `ARGV[1]`, the hash the caller judged (empty for no
 * index): deletes the record of that hash in `KEYS[3]`, writes the record `ARGV[3]` to `KEYS[2]` and
 * points the index at `ARGV[2]`, both for `ARGV[4]` seconds. Answers `1`, or `0` when it differs.
 */
export const PUBLISH_INVITATION_SCRIPT = `
if (redis.call('GET', KEYS[1]) or '') ~= ARGV[1] then
  return 0
end
if ARGV[1] ~= '' then
  redis.call('DEL', KEYS[3])
end
redis.call('SET', KEYS[2], ARGV[3], 'EX', ARGV[4])
redis.call('SET', KEYS[1], ARGV[2], 'EX', ARGV[4])
return 1`

/** A new invitation and what it replaces. */
export interface InvitationPublication {
  /** The invitee index key. */
  indexKey: string
  /** The hash of the new invitation's token. */
  tokenHash: string
  /** The record to store. */
  record: string
  /** The lifetime of the record and the index, in seconds. */
  ttl: number
  /** The hash the caller judged in the index, or `null` when there was none. */
  superseded: string | null
}

/**
 * Stores the record and points the index at it, removing the superseded record, in one step.
 *
 * A failed command never leaves an index without its record, or a record without its index.
 *
 * @param redis - The store holding them.
 * @param publication - The new invitation and what it replaces.
 * @returns `false` when the index no longer holds what the caller judged, and nothing was written.
 */
export async function publishInvitation(
  redis: AuthRedisService,
  publication: InvitationPublication
): Promise<boolean> {
  const { indexKey, tokenHash, record, ttl, superseded } = publication
  const recordKey = `inv:${tokenHash}`
  // With nothing superseded the third key is not touched; the new record's key fills the place.
  const supersededKey = superseded === null ? recordKey : `inv:${superseded}`
  const reply = await pinned(
    redis.eval(
      PUBLISH_INVITATION_SCRIPT,
      [indexKey, recordKey, supersededKey],
      [superseded ?? '', tokenHash, record, String(ttl)]
    )
  )
  return integerReply(reply) === 1
}
