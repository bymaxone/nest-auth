/**
 * @fileoverview The removal of one stored refresh session, and the checks on what names it.
 *
 * Not exported by the package: a removal announces nothing, so each caller is a revocation that
 * fires `onSessionsRevoked` itself, once, under its own reason.
 *
 * @layer Util
 */

import { sessionRevocationKey, sessionRevocationTtlSeconds } from './session-access'
import { pinned } from './settle'
import { sessionId } from '../constants/session-id'
import { sessionIndexKey } from '../constants/user-keys'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { AuthRedisService } from '../redis/auth-redis.service'
import { integerReply } from '../redis/integer-reply'
import { removedSessions } from '../redis/session-records'

/** Regex for a valid SHA-256 hex session hash (64 lowercase hex characters). */
export const SESSION_HASH_RE = /^[a-f0-9]{64}$/

/**
 * Lua script for atomic session revocation.
 *
 * Performs SISMEMBER check and all deletions in a single round-trip to
 * prevent TOCTOU race conditions between the ownership check and deletion.
 *
 * KEYS[1] = `sess:{userId}` (auto-namespaced by AuthRedisService)
 * KEYS[2] = `rt:{sessionHash}` (auto-namespaced)
 * KEYS[3] = `sd:{sessionHash}` (auto-namespaced)
 * ARGV[1] = `rt:{sessionHash}` (SET member value — stored WITHOUT namespace, matching
 *   the format written by `TokenManagerService.sadd('sess:{userId}', 'rt:{hash}')`)
 *
 * Returns: 1 if revoked, 0 if the session was not a member of the SET.
 */
const REVOKE_SESSION_LUA = `
local is_member = redis.call('SISMEMBER', KEYS[1], ARGV[1])
if is_member == 0 then return 0 end
redis.call('DEL', KEYS[2])
redis.call('SREM', KEYS[1], ARGV[1])
redis.call('DEL', KEYS[3])
return 1
`

/**
 * Lua script that ends the whole sign-in of one owned session, access tokens included, at once.
 *
 * One script, so no refusal can leave the named session gone and a sibling out of a retry's reach:
 * the keys in KEYS are checked by a key ACL before anything runs, and the named
 * session leaves the account's index last, so a call refused part-way still passes the ownership
 * check when it is repeated. Redis does not undo the writes of a script that stops part-way.
 *
 * KEYS[1] = `sess:{subject}`   KEYS[2] = `rt:{hash}`   KEYS[3] = `sd:{hash}`
 * KEYS[4] = `fam:{sid}`        KEYS[5] = `rvs:{sid}`
 * ARGV[1] = `rt:{hash}`, the index member   ARGV[2] = the entry's lifetime in seconds
 *
 * The names of the other sessions are built from the prefix KEYS[2] was stored under, which is what
 * is left of it once the member is taken off its end.
 *
 * Returns: 0 if the account does not own the session, else the hashes the family named.
 */
const END_OWNED_SIGN_IN_LUA = `
local member = ARGV[1]
if redis.call('SISMEMBER', KEYS[1], member) == 0 then return 0 end
redis.call('SET', KEYS[5], '1', 'EX', ARGV[2])
local base = string.sub(KEYS[2], 1, #KEYS[2] - #member)
local family = redis.call('SMEMBERS', KEYS[4])
for _, hash in ipairs(family) do
  local name = 'rt:' .. hash
  if name ~= member then
    redis.call('DEL', base .. name)
    redis.call('DEL', base .. 'sd:' .. hash)
    redis.call('SREM', KEYS[1], name)
  end
end
redis.call('DEL', KEYS[4])
redis.call('DEL', KEYS[2])
redis.call('DEL', KEYS[3])
redis.call('SREM', KEYS[1], member)
return family
`

/**
 * Refuses a dashboard tenant that names nothing, at the public boundary.
 *
 * Every method of the session service takes the tenant as a REQUIRED named field, and all of them are
 * exported — the object form replaced the positional one precisely so a `string` tenant could
 * not be transposed with a `string` user id or session hash. Naming it removes the transposition
 * but not the empty string: a caller can still pass `''`, and that is what this refuses.
 *
 * `userSubject` cannot enforce it instead: the rotation scripts must be
 * called with the empty PLACEHOLDER identity to discover a grace pointer, so the innermost
 * builder has to stay total, and an empty key in a script's KEYS array is not "no key" — the
 * `eval` wrapper prefixes it into a real key named `auth:`.
 *
 * So the refusal lives here, where a caller can actually be wrong. `''` derived
 * `dashboard:0::{userId}`, swept and bumped keys nobody writes, and returned normally — a
 * revocation reported as done while every session and access token it named stayed valid.
 *
 * @param tenantId - The tenant supplied by the caller.
 * @throws {@link AuthException} `VALIDATION` when it is blank.
 */
export function assertTenant(tenantId: string): void {
  if (tenantId === '') {
    throw new AuthException(AUTH_ERROR_CODES.VALIDATION, [
      { field: 'tenantId', message: 'tenantId is required to name a session index' }
    ])
  }
}

/**
 * Asserts that a session hash string is a valid 64-character lowercase hex string.
 *
 * Rejects malformed inputs before they reach Redis to prevent unexpected key
 * construction and to avoid leaking timing information via Redis operations on
 * attacker-controlled key names.
 *
 * @remarks
 * **This used to answer `SESSION_NOT_FOUND`, and that was wrong.** The stated reason was to stop
 * callers enumerating valid hash formats — but the format is not a secret. It is 64 hex
 * characters, `SessionInfo.sessionHash` publishes it on every listed session, and the route's
 * own documentation describes it. Nothing is protected by hiding it, and the pairing had a real
 * cost: a consumer sending a malformed hash got the same answer as one sending a hash that had
 * already been revoked, so a UI bug read as a race between the session list and the click. That
 * is measured, not hypothetical — it cost a consumer session twenty minutes chasing a race that
 * cannot happen.
 *
 * A malformed hash is a caller error and now says so. A well-formed hash that names nothing
 * still answers `SESSION_NOT_FOUND`, which is where the no-enumeration argument does apply:
 * that one really would tell the caller whether a session exists.
 *
 * @param sessionHash - The session hash to validate.
 * @throws {@link AuthException} `VALIDATION` when the value is not 64 lowercase hex characters.
 */
export function assertSessionHash(sessionHash: string, field = 'sessionHash'): void {
  if (!SESSION_HASH_RE.test(sessionHash)) {
    throw new AuthException(AUTH_ERROR_CODES.VALIDATION, [
      {
        field,
        message: `${field} must be 64 lowercase hexadecimal characters`
      }
    ])
  }
}

/**
 * Removes one refresh session of a dashboard account, and nothing else.
 *
 * Verifies ownership via `SISMEMBER` before deleting the refresh token, the session detail and the
 * member of the account's session SET.
 *
 * @throws {@link AuthException} `SESSION_NOT_FOUND` when the session is not owned by the account.
 */
export async function removeStoredSession(
  redis: Pick<AuthRedisService, 'eval'>,
  hmacKey: string,
  { userId, tenantId, sessionHash }: { userId: string; tenantId: string; sessionHash: string }
): Promise<void> {
  assertTenant(tenantId)
  assertSessionHash(sessionHash)

  // Atomic Lua script: ownership check (SISMEMBER) + all deletions in one
  // round-trip to eliminate TOCTOU between the membership check and DEL/SREM.
  const result = await pinned(
    redis.eval(
      REVOKE_SESSION_LUA,
      [
        sessionIndexKey('dashboard', userId, hmacKey, tenantId),
        `rt:${sessionHash}`,
        `sd:${sessionHash}`
      ],
      [`rt:${sessionHash}`]
    )
  )

  if (integerReply(result) === 0) {
    throw new AuthException(AUTH_ERROR_CODES.SESSION_NOT_FOUND)
  }
}

/**
 * Ends the sign-in of one refresh session, access tokens included, and announces the removal.
 *
 * The family id is read first, and the script that uses it writes only once it has seen that the
 * account owns the session. A refused write announces nothing and leaves the call to be repeated.
 *
 * @param announce - Given the named hash and those of the other sessions of the sign-in.
 * @param withoutFamily - Runs when the record names no family a token could carry, after the
 *   ownership check and before the session is removed. By default nothing does, and those access
 *   tokens last until they expire.
 * @throws {@link AuthException} `SESSION_NOT_FOUND` when the session is not owned by the account.
 */
export async function endStoredSession(
  redis: Pick<AuthRedisService, 'eval' | 'readSessionOwner' | 'sismember'>,
  { hmacKey, jwt }: { hmacKey: string; jwt: { accessExpiresIn: string } },
  session: { userId: string; tenantId: string; sessionHash: string },
  announce: (sessionIds: string[]) => void,
  withoutFamily?: () => Promise<unknown>
): Promise<void> {
  const { userId, tenantId, sessionHash } = session
  assertTenant(tenantId)
  assertSessionHash(sessionHash)
  const member = `rt:${sessionHash}`
  const index = sessionIndexKey('dashboard', userId, hmacKey, tenantId)
  const sid = sessionId((await pinned(redis.readSessionOwner(member))).familyId)

  if (sid === undefined) {
    if (withoutFamily !== undefined) {
      const owned = await pinned(redis.sismember(index, member))
      if (!owned) throw new AuthException(AUTH_ERROR_CODES.SESSION_NOT_FOUND)
      await pinned(withoutFamily())
    }
    await pinned(removeStoredSession(redis, hmacKey, session))
    announce([sessionHash])
    return
  }

  const keys = [index, member, `sd:${sessionHash}`, `fam:${sid}`]
  const reply = await pinned(
    redis.eval(
      END_OWNED_SIGN_IN_LUA,
      [...keys, sessionRevocationKey('dashboard', sid)],
      [member, String(sessionRevocationTtlSeconds(jwt.accessExpiresIn))]
    )
  )
  if (!Array.isArray(reply) && integerReply(reply) === 0) {
    throw new AuthException(AUTH_ERROR_CODES.SESSION_NOT_FOUND)
  }
  announce(removedSessions([sessionHash], reply).sessionHashes)
}
