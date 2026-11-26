/**
 * @fileoverview Removes a pending invitation on behalf of whoever judged it, and the Lua that does it.
 *
 * @layer Redis
 */

import type { AuthRedisService } from './auth-redis.service'
import { integerReply } from './integer-reply'
import { pinned } from '../utils/settle'

/**
 * Deletes the record in `KEYS[2]` and the index in `KEYS[1]` only while the index still holds
 * `ARGV[1]` and the record is still `ARGV[2]`, what the caller read there (empty for no record).
 * Answers `-1` when either differs, otherwise how many records it deleted.
 */
export const WITHDRAW_INVITATION_SCRIPT = `
if redis.call('GET', KEYS[1]) ~= ARGV[1] then
  return -1
end
if (redis.call('GET', KEYS[2]) or '') ~= ARGV[2] then
  return -1
end
local removed = redis.call('DEL', KEYS[2])
redis.call('DEL', KEYS[1])
return removed`

/**
 * Removes the invitation the index names, while it is still the one the caller read.
 *
 * The record and the index go in one step, so a failed command never leaves one without the other.
 * A record written or replaced after the caller read it is left, because nobody has judged it.
 *
 * @param redis - The store holding both.
 * @param indexKey - The invitee index key.
 * @param tokenHash - What the caller read in the index.
 * @param judged - The record the caller read under that hash, or `null` when there was none.
 * @returns `'removed'` when a record was deleted, `'absent'` when only the index was there to drop,
 *   `'changed'` when the address no longer holds what the caller read, and nothing was deleted.
 */
export async function withdrawInvitation(
  redis: AuthRedisService,
  indexKey: string,
  tokenHash: string,
  judged: string | null
): Promise<'removed' | 'absent' | 'changed'> {
  const keys = [indexKey, `inv:${tokenHash}`]
  const reply = await pinned(
    redis.eval(WITHDRAW_INVITATION_SCRIPT, keys, [tokenHash, judged ?? ''])
  )
  const removed = integerReply(reply)
  return removed < 0 ? 'changed' : removed > 0 ? 'removed' : 'absent'
}
