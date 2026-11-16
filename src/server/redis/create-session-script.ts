/**
 * The Lua script that writes a new refresh session, and the check of what is passed to it.
 *
 * @layer Redis
 */

/** A record written in the same step as the session: its key, its value and its lifetime in seconds. */
export interface SessionExtra {
  readonly key: string
  readonly value: string
  readonly ttl: number
}

/**
 * Writes a freshly-issued refresh session: the record, the `rt:` member in the owner's session
 * index, and the family membership, each with the refresh TTL, in ONE step.
 *
 * Held equivalent to rust-auth's `create_session_inner`, which does the same work in a
 * `MULTI/EXEC` transaction. The records must be written in one step, for two reasons:
 *
 * - A live session that no index names escapes `invalidateUserSessions`, run by a password reset,
 *   a ban, or an MFA enable, which walks only the index. Such a session survives a revocation the
 *   user was told had happened, and the next `SADD` rebuilds the index around it. It keeps
 *   rotating, and `buildRotatedResult` re-reads the CURRENT epoch, so its next refresh mints a
 *   fully valid access token under the post-bump epoch. An attacker who knows the password, the
 *   reason the victim is resetting, can keep logins in flight to aim at it.
 * - A dropped connection or a failover between the `SADD` and the `EXPIRE` leaves `sess:{userId}`
 *   with **no expiry at all**. Its members die with the refresh lifetime; the set does not. For an
 *   account that never signs in again, the key would be permanent.
 *
 * ```text
 * KEYS[1] = rt:{hash}   KEYS[2] = sess:{userId}   KEYS[3] = fam:{familyId}
 * ARGV[1] = session JSON   ARGV[2] = refresh TTL
 * ARGV[3] = family id, or '' for a session belonging to no lineage
 * ARGV[4] = live prefix   ARGV[5] = token hash
 * KEYS[4..] = the records of the session itself, each with its OWN lifetime
 * ARGV[6 + 2i] = value   ARGV[7 + 2i] = its TTL, for the extra whose key is KEYS[4 + i]
 * ```
 *
 * The extras are the recent-authentication mark and the session detail. They belong in the same
 * step as the refresh record, because a write that can fail after the session exists leaves a live
 * session no caller was told about; no other command runs between them. A failing command does
 * not undo what the script wrote before it, so the index and the family, the only keys that can
 * fail on a wrong type, come before the refresh record. The extras are plain `SET`s with a
 * validated lifetime and cannot fail that way. They keep their own lifetimes: the mark counts as
 * recent for a few minutes, not for as long as the refresh token.
 */
export const CREATE_SESSION_LUA = `
-- The commands that can fail on a key of the wrong type come FIRST: Redis does not undo the
-- writes a script made before one of its commands fails, so an error here must leave no refresh
-- record behind. The index and the family are the only keys this script adds to a set.
redis.call('SADD', KEYS[2], ARGV[4] .. ':' .. ARGV[5])
redis.call('EXPIRE', KEYS[2], ARGV[2])
-- The family index holds bare hashes: it only ever tracks live sessions, so the prefix is
-- implied. A session with no lineage skips it rather than writing an unkeyed member.
if ARGV[3] ~= '' then
  redis.call('SADD', KEYS[3], ARGV[5])
  redis.call('EXPIRE', KEYS[3], ARGV[2])
end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
-- The records of the session itself, each with its own lifetime.
for i = 4, #KEYS do
  redis.call('SET', KEYS[i], ARGV[2 * i - 2], 'EX', ARGV[2 * i - 1])
end
return 1
`

/**
 * The keys and arguments the script takes for the records beyond the three it writes for every session.
 *
 * A TTL of zero, a fractional or a negative one would make `SET ... EX` fail inside the script and
 * abort the whole birth of a session. That is a bug in the caller, so it is refused here, before
 * anything is sent, rather than found as a failed login.
 *
 * @param extras - The extra records, in the order their keys are passed.
 * @returns The extra keys, and the value and TTL arguments that follow the five fixed ones.
 * @throws {TypeError} when a key or value is empty, or a TTL is not a positive integer.
 */
export function sessionExtraArgs(extras: readonly SessionExtra[]): {
  keys: string[]
  argv: string[]
} {
  for (const { key, value, ttl } of extras) {
    if (key === '' || value === '' || !Number.isInteger(ttl) || ttl <= 0) {
      throw new TypeError('A session record needs a key, a value and a positive whole-second TTL.')
    }
  }
  return {
    keys: extras.map(({ key }) => key),
    argv: extras.flatMap(({ value, ttl }) => [value, String(ttl)])
  }
}
