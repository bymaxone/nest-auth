/**
 * @fileoverview The removal of one stored refresh session, and the checks on what names it.
 *
 * Not exported by the package: a removal announces nothing, so each caller is a revocation that
 * fires `onSessionsRevoked` itself, once, under its own reason.
 *
 * @layer Util
 */

import { revokeSessionAccess } from './session-access'
import { pinned } from './settle'
import { raiseFirst, settleWrites } from './settle-writes'
import { sessionIndexKey } from '../constants/user-keys'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { AuthRedisService } from '../redis/auth-redis.service'
import { integerReply } from '../redis/integer-reply'

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
  redis: AuthRedisService,
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
 * Removes one refresh session, ends its access tokens, and announces the removal.
 *
 * The family id is read before the removal deletes the record, and used only once the removal has
 * proved the account owns the session. A refused access write is raised after `announce`.
 *
 * @throws {@link AuthException} `SESSION_NOT_FOUND` when the session is not owned by the account.
 */
export async function endStoredSession(
  redis: AuthRedisService,
  { hmacKey, jwt }: { hmacKey: string; jwt: { accessExpiresIn: string } },
  session: { userId: string; tenantId: string; sessionHash: string },
  announce: () => void
): Promise<void> {
  assertTenant(session.tenantId)
  assertSessionHash(session.sessionHash)
  const { familyId } = await pinned(redis.readSessionOwner(`rt:${session.sessionHash}`))
  await pinned(removeStoredSession(redis, hmacKey, session))
  const failures = await pinned(
    settleWrites([
      (): Promise<void> => revokeSessionAccess(redis, 'dashboard', familyId, jwt.accessExpiresIn)
    ])
  )
  announce()
  raiseFirst(failures)
}
