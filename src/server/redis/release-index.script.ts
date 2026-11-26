/**
 * @fileoverview Drops an invitee index on behalf of whoever read it, and the Lua that does it.
 *
 * @layer Redis
 */

import type { AuthRedisService } from './auth-redis.service'
import { integerReply } from './integer-reply'
import { pinned } from '../utils/settle'

/** Deletes the index in `KEYS[1]` only while it still holds `ARGV[1]`, the value the caller read. */
export const RELEASE_INDEX_SCRIPT = `
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0`

/**
 * Drops the invitee index while it still names `named`.
 *
 * A later invite can claim the index between a caller's read and this removal. Its entry is the
 * only handle a revoke has on its record, so it stays.
 *
 * @param redis - The store holding the index.
 * @param indexKey - The invitee index key.
 * @param named - What the caller read in the index.
 * @returns Whether this call dropped the index.
 */
export async function releaseIndex(
  redis: AuthRedisService,
  indexKey: string,
  named: string
): Promise<boolean> {
  return integerReply(await pinned(redis.eval(RELEASE_INDEX_SCRIPT, [indexKey], [named]))) === 1
}
