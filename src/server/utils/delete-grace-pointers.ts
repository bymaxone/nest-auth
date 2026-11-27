/**
 * @fileoverview The removal of an account's rotation grace pointers.
 *
 * @layer Utility
 */

import { pinned } from './settle'
import type { AuthRedisService } from '../redis/auth-redis.service'

/** Deletes every rotation grace pointer in `members`, the contents of the session `index`. */
export async function deleteGracePointers(
  redis: Pick<AuthRedisService, 'del' | 'srem'>,
  index: string,
  members: readonly string[]
): Promise<void> {
  // Every rotation grace pointer the account holds goes too.
  //
  // Removing one session only deletes `rt:`/`sd:` keys, and the removal of the other sessions
  // only visits `rt:` members, so a `rp:{predecessor}` pointer survives both. For a *revoked*
  // session that is harmless — the grace branch requires the successor's `rt:` key, which is
  // gone. The gap is the *preserved* session: its predecessor's pointer names a hash that is
  // deliberately still alive, so anyone holding that predecessor token could take the grace branch
  // and mint a brand-new full-lifetime session for the rest of the window. The epoch bump that
  // follows does not help — a recovered session signs its access token from the current epoch.
  //
  // "Sign out my other devices" is a statement about right now, so no credential minted before
  // this moment may still produce a session. `logout` clears the same pointer for the single
  // token it is handed, for the same reason.
  const gracePointers = members.filter((m) => m.startsWith('rp:'))
  for (const member of gracePointers) {
    await pinned(redis.del(member))
    await pinned(redis.srem(index, member))
  }
}
