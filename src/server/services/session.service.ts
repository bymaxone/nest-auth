import { Inject, Injectable, Logger, Optional } from '@nestjs/common'

import {
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import { sessionIndexKey } from '../constants/user-keys'
import { sha256, timingSafeCompare } from '../crypto/secure-token'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { HookContext, IAuthHooks } from '../interfaces/auth-hooks.interface'
import type { SessionInfo as EmailSessionInfo } from '../interfaces/email-provider.interface'
import type {
  AuthUser,
  IUserRepository,
  SafeAuthUser
} from '../interfaces/user-repository.interface'
import { AuthRedisService } from '../redis/auth-redis.service'
import { describeChannelStatus } from '../utils/describe-error'
import { logSafe } from '../utils/log-safe'

// ---------------------------------------------------------------------------
// Module-level constants
// ---------------------------------------------------------------------------

/** Maximum stored IP length — IPv6 max is 45 characters. Truncated before Redis storage. */
const MAX_IP_LENGTH = 45

/** Regex for a valid SHA-256 hex session hash (64 lowercase hex characters). */
const SESSION_HASH_RE = /^[a-f0-9]{64}$/

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
 * Lua script for atomic session detail rotation.
 *
 * Deletes the old `sd:{oldHash}` detail record and atomically writes the new
 * `sd:{newHash}` record in a single round-trip. This prevents a window where
 * neither key exists between a non-atomic DEL + SET sequence, which would
 * cause `listSessions` to classify the session as stale and clean it up.
 *
 * KEYS[1] = `sd:{oldHash}` (auto-namespaced by AuthRedisService)
 * KEYS[2] = `sd:{newHash}` (auto-namespaced)
 * ARGV[1] = new detail JSON string
 * ARGV[2] = TTL in seconds (string-encoded positive integer)
 *
 * Returns: 1 after the write completes. Callers can assert `result === 1`
 * to detect silent network-level failures during the eval round-trip.
 */
const ROTATE_SESSION_DETAIL_LUA = `
redis.call('DEL', KEYS[1])
redis.call('SET', KEYS[2], ARGV[1], 'EX', ARGV[2])
return 1
`

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/**
 * Rich session metadata for session management endpoints.
 *
 * Returned by session listing operations to present active sessions
 * to the authenticated user. Credential and secret fields are never
 * included — only display-safe device and activity metadata.
 */
export interface SessionInfo {
  /** First 8 characters of `sessionHash` — a short display identifier. */
  id: string
  /** Full SHA-256 hex hash of the original refresh token. */
  sessionHash: string
  /** Human-readable device description parsed from the User-Agent (e.g. "Chrome on macOS"). */
  device: string
  /** IP address from which the session was established. */
  ip: string
  /** Whether this session is the caller's current active session. */
  isCurrent: boolean
  /** Unix timestamp in milliseconds when the session was first created. */
  createdAt: number
  /** Unix timestamp in milliseconds of the most recent activity on this session. */
  lastActivityAt: number
}

// ---------------------------------------------------------------------------
// Private types
// ---------------------------------------------------------------------------

/** Internal detail record persisted in Redis under `sd:{hash}`. */
interface StoredSessionDetail {
  device: string
  ip: string
  createdAt: number
  lastActivityAt: number
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/**
 * Parses a raw User-Agent string into a short human-readable description.
 *
 * Uses only regex — no external libraries. Detects the browser and OS
 * from the most common UA patterns and returns a string of the form
 * "BrowserName on OSName" (e.g. "Chrome on macOS").
 *
 * @param ua - Raw `User-Agent` header value.
 * @returns Human-readable device description.
 */
function parseUserAgent(ua: string): string {
  // --- Browser detection (order matters: Edge > Opera > Chrome > Firefox > Safari) ---
  let browser = 'Unknown Browser'

  if (/Edg\//.test(ua)) {
    browser = 'Edge'
  } else if (/OPR\/|Opera/.test(ua)) {
    browser = 'Opera'
  } else if (/Chrome\//.test(ua)) {
    browser = 'Chrome'
  } else if (/Firefox\//.test(ua)) {
    browser = 'Firefox'
  } else if (/Safari\//.test(ua) && /Version\//.test(ua)) {
    browser = 'Safari'
  }

  // --- OS detection ---
  let os = 'Unknown OS'

  if (/Android/.test(ua)) {
    os = 'Android'
  } else if (/iPhone|iPad|iPod/.test(ua)) {
    os = 'iOS'
  } else if (/Windows/.test(ua)) {
    os = 'Windows'
  } else if (/Macintosh|Mac OS X/.test(ua)) {
    os = 'macOS'
  } else if (/Linux/.test(ua)) {
    os = 'Linux'
  }

  return `${browser} on ${os}`
}

// ---------------------------------------------------------------------------
// Projection helper
// ---------------------------------------------------------------------------

/**
 * Projects a full {@link AuthUser} to a {@link SafeAuthUser} by excluding
 * credential and secret fields.
 */
function toSafeUser(user: AuthUser): SafeAuthUser {
  const { passwordHash: _p, mfaSecret: _s, mfaRecoveryCodes: _r, ...safe } = user
  return safe
}

// ---------------------------------------------------------------------------
// SessionService
// ---------------------------------------------------------------------------

/**
 * Everything {@link SessionService.createSession} needs to record a session.
 *
 * An object rather than positional arguments, and the reason is the subject of this release: four
 * of the five fields are `string`, so any two of them can be swapped without the compiler
 * noticing. `createSession(userId, rawRefreshToken, ip, userAgent)` — the shape before the tenant
 * was threaded through — still type checks against a positional signature that inserted
 * `tenantId` second, and silently records the session under a tenant named by a refresh token.
 * A named field cannot be transposed; at worst it is misspelled, which is a compile error.
 */
export interface CreateSessionParams {
  /** Internal user ID for whom the session is being created. */
  userId: string
  /** Tenant that user belongs to; scopes the session index. */
  tenantId: string
  /** The raw opaque refresh token; hashed before storage. */
  rawRefreshToken: string
  /** Client IP address for the new session. */
  ip: string
  /** Raw `User-Agent` header value, for device detection. */
  userAgent: string
}

/** Everything {@link SessionService.listSessions} needs. See {@link CreateSessionParams}. */
export interface ListSessionsParams {
  /** Internal user ID whose sessions are being listed. */
  userId: string
  /** Tenant that user belongs to; scopes the session index. */
  tenantId: string
  /**
   * SHA-256 hash of the caller's active session, when known; the matching entry comes back with
   * `isCurrent: true`. Optional, which is what made the positional form dangerous — arity did not
   * catch a two-argument call.
   *
   * Written `?: string | undefined` rather than `?: string` because the project runs
   * `exactOptionalPropertyTypes`: under it the two are different types, and a caller forwarding a
   * value it already holds as `string | undefined` — which every controller reading an optional
   * header does — cannot assign to the narrower one.
   */
  currentSessionHash?: string | undefined
}

/**
 * Names one session to revoke, for {@link SessionService.revokeSession} and
 * {@link SessionService.revokeOtherSession}. See {@link CreateSessionParams}.
 */
export interface RevokeSessionParams {
  /** Internal user ID that must own the session. */
  userId: string
  /** Tenant that user belongs to; scopes the session index. */
  tenantId: string
  /** SHA-256 hash of the session being revoked. */
  sessionHash: string
}

/** Everything {@link SessionService.revokeAllExceptCurrent} needs. See {@link CreateSessionParams}. */
export interface RevokeAllExceptCurrentParams {
  /** Internal user ID whose other sessions are ending. */
  userId: string
  /** Tenant that user belongs to; scopes the session index. */
  tenantId: string
  /** SHA-256 hash of the session to KEEP — the caller's own. */
  currentSessionHash: string
}

/**
 * Manages user session lifecycle for @bymax-one/nest-auth.
 *
 * Handles session creation, concurrent session enforcement (FIFO eviction),
 * and per-session detail storage in Redis. Integrates with `IAuthHooks` to
 * fire `onNewSession` and `onSessionEvicted` events for consumer-side alerting.
 *
 * @remarks
 * Session details are stored under `sd:{hash}` with the same TTL as the
 * refresh token. The `sess:{userId}` Redis SET tracks all active `rt:{hash}`
 * members for a user — maintained jointly with `TokenManagerService`.
 *
 * This service is responsible only for session creation and enforcement.
 * Session listing, individual revocation, and bulk-revocation are handled
 * by dedicated session-management services.
 *
 * @layer Service
 */
@Injectable()
export class SessionService {
  private readonly logger = new Logger(SessionService.name)

  constructor(
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions,
    @Inject(BYMAX_AUTH_USER_REPOSITORY) private readonly userRepo: IUserRepository,
    @Inject(BYMAX_AUTH_HOOKS) @Optional() private readonly hooks: IAuthHooks | null,
    @Inject(AuthRedisService) private readonly redis: AuthRedisService
  ) {}

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  /**
   * Refuses a dashboard tenant that names nothing, at the public boundary.
   *
   * Every method on this service takes the tenant as a REQUIRED named field, and all of them are
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
  private assertTenant(tenantId: string): void {
    if (tenantId === '') {
      throw new AuthException(AUTH_ERROR_CODES.VALIDATION, [
        { field: 'tenantId', message: 'tenantId is required to name a session index' }
      ])
    }
  }

  /**
   * Records a new session in Redis and enforces the concurrent session limit.
   *
   * Stores device and activity metadata under `sd:{hash}` with the same TTL
   * as the refresh token. Calls `enforceSessionLimit` to evict the oldest
   * session when the user has exceeded their limit. Fires the `onNewSession`
   * hook (fire-and-forget) after the session is recorded.
   *
   * @remarks
   * **Caller ordering contract:** This method must be called **after**
   * `TokenManagerService.issueTokens` (or equivalent) has already added
   * `rt:{hash}` to the `sess:{userId}` SET in Redis. `enforceSessionLimit`
   * reads that SET to count active sessions, and it uses `newHash` to exclude
   * the just-issued token from eviction candidates. If this method is called
   * before the SET member is committed, the limit check will see one fewer
   * session than actually exists, allowing a permanent extra session.
   *
   * @param params - See {@link CreateSessionParams}.
   * @returns The SHA-256 hash of `rawRefreshToken` used as the session key.
   */
  async createSession({
    userId,
    tenantId,
    rawRefreshToken,
    ip,
    userAgent
  }: CreateSessionParams): Promise<string> {
    this.assertTenant(tenantId)
    const hash = sha256(rawRefreshToken)
    const device = parseUserAgent(userAgent)
    const now = Date.now()
    const ttl = this.options.jwt.refreshExpiresInDays * 86_400

    const detail: StoredSessionDetail = {
      device,
      // Truncate to MAX_IP_LENGTH before storage to guard against oversized
      // attacker-controlled values arriving via X-Forwarded-For.
      ip: ip.slice(0, MAX_IP_LENGTH),
      createdAt: now,
      lastActivityAt: now
    }

    await this.redis.set(`sd:${hash}`, JSON.stringify(detail), ttl)

    await this.enforceSessionLimit(userId, tenantId, hash, ip, userAgent)

    // Fire onNewSession hook — fire-and-forget; errors must not propagate.
    if (this.hooks?.onNewSession) {
      const { onNewSession } = this.hooks
      const minimalSessionInfo: EmailSessionInfo = {
        device,
        ip,
        sessionHash: hash.slice(0, 8)
      }
      const context: HookContext = {
        ip,
        userAgent,
        sanitizedHeaders: {}
      }

      void this.userRepo
        .findById(userId, tenantId)
        .then((user) => {
          if (!user) return
          // Explicit `void` so the inner promise's lifecycle is unambiguous —
          // the .catch() attaches a rejection handler, but neither `return`ing
          // the chain nor leaving it bare reads cleanly. The hook is fire-and-
          // forget by contract; this matches the pattern used elsewhere in the
          // codebase (auth.service afterLogin/afterRegister, mfa.service afterLogin).
          void Promise.resolve(onNewSession(toSafeUser(user), minimalSessionInfo, context)).catch(
            (err: unknown) => {
              this.logger.error(`onNewSession hook threw: ${describeChannelStatus(err)}`)
            }
          )
        })
        .catch((err: unknown) => {
          this.logger.error(`onNewSession hook — findById failed: ${describeChannelStatus(err)}`)
        })
    }

    return hash
  }

  /**
   * Lists all active sessions for a user, enriched with device and activity metadata.
   *
   * Reads all `rt:`-prefixed members from `sess:{userId}`, fetches the
   * corresponding `sd:{hash}` detail records, and marks the caller's own
   * session via `isCurrent`. A member whose detail record is missing, unreadable
   * or malformed is excluded from the result, and removed from the SET
   * asynchronously (fire-and-forget) only if its `rt:` key is also gone — see
   * {@link AuthRedisService.pruneDeadMembers} for why the detail record alone
   * does not settle it.
   *
   * Results are sorted by `createdAt` descending (newest session first).
   *
   * @param params - See {@link ListSessionsParams}.
   * @returns Array of {@link SessionInfo} sorted newest-first.
   */
  async listSessions({
    userId,
    tenantId,
    currentSessionHash
  }: ListSessionsParams): Promise<SessionInfo[]> {
    this.assertTenant(tenantId)
    // Drop the grace members whose pointers have already expired, before reading the index.
    // A rotation adds one per refresh and only a revoke-all ever removed them, so an account
    // that refreshes and never signs out again accumulates them without bound — and this
    // method ships the whole set. Fire-and-forget: a failed prune is a tidy-up that did not
    // happen, not a listing that should fail. See `pruneExpiredGraceMembers`.
    void this.redis
      .pruneExpiredGraceMembers(this.indexKey(userId, tenantId), 'rp:')
      .catch((err: unknown) => {
        this.logger.warn(`listSessions: grace-pointer prune failed: ${describeChannelStatus(err)}`)
      })

    const members = await this.redis.smembers(this.indexKey(userId, tenantId))
    const rtMembers = members.filter((m) => m.startsWith('rt:'))

    const results: SessionInfo[] = []
    const staleKeys: string[] = []

    await Promise.all(
      rtMembers.map(async (member) => {
        const hash = member.slice(3)
        let raw: string | null = null

        try {
          raw = await this.redis.get(`sd:${hash}`)
        } catch {
          // A read that throws is an infrastructure fault, not a stale member — the pruning
          // below treats them alike (both are dropped from the index), and only this line
          // says which one happened, so a Redis outage does not read as a tidy-up.
          this.logger.warn(`listSessions: session detail read failed hash=${hash.slice(0, 8)}`)
          staleKeys.push(member)
          return
        }

        if (raw === null) {
          staleKeys.push(member)
          return
        }

        let detail: StoredSessionDetail

        try {
          const parsed: unknown = JSON.parse(raw)
          const p = parsed as Record<string, unknown>
          if (
            // Stryker disable next-line ConditionalExpression,LogicalOperator: `parsed === null` is subsumed by the adjacent `typeof parsed !== 'object'` clause (typeof null is 'object' but the field reads below reject it identically)
            parsed === null ||
            // Stryker disable next-line ConditionalExpression: equivalent — a non-object
            // parsed value reaches the field reads below as `undefined` on every property,
            // which reject it with the identical outcome
            typeof parsed !== 'object' ||
            typeof p['device'] !== 'string' ||
            typeof p['ip'] !== 'string' ||
            typeof p['createdAt'] !== 'number' ||
            typeof p['lastActivityAt'] !== 'number'
          ) {
            staleKeys.push(member)
            return
          }
          detail = parsed as StoredSessionDetail
        } catch {
          staleKeys.push(member)
          return
        }

        results.push({
          id: hash.slice(0, 8),
          sessionHash: hash,
          device: detail.device,
          ip: detail.ip,
          // '' fallback: timingSafeCompare returns false on length mismatch,
          // so no hash (always 64 chars) will ever match the empty string.
          // Stryker disable next-line StringLiteral: a 64-char session hash never length-matches the fallback sentinel, so timingSafeCompare returns false identically for '' or any other non-matching fallback
          isCurrent: timingSafeCompare(hash, currentSessionHash ?? ''),
          createdAt: detail.createdAt,
          lastActivityAt: detail.lastActivityAt
        })
      })
    )

    // Fire-and-forget: drop the dead members without blocking the response.
    //
    // Candidates, not verdicts. Every branch above reaches this list by way of the `sd:` record
    // — missing, unreadable, or malformed — and none of those facts says the session is gone.
    // The credential is the `rt:` key; a live `rt:` with no `sd:` still opens the account. So
    // `pruneDeadMembers` re-checks each candidate against `EXISTS` and removes only the ones
    // that name nothing, because a member dropped while its `rt:` lives is invisible to
    // `invalidateUserSessions` — the session would then survive "sign out everywhere" and keep
    // rotating, and merely opening this listing would be what orphaned it.
    void this.redis
      .pruneDeadMembers(this.indexKey(userId, tenantId), staleKeys)
      .catch((err: unknown) => {
        this.logger.error(
          `listSessions: failed to prune ${staleKeys.length} dead member(s): ${describeChannelStatus(err)}`
        )
      })

    results.sort((a, b) => b.createdAt - a.createdAt)

    return results
  }

  /**
   * Revokes a single session belonging to the specified user.
   *
   * Verifies ownership via `SISMEMBER` before deleting the refresh token,
   * session detail, and removing the member from the user's session SET.
   * Throws {@link AuthException} with `SESSION_NOT_FOUND` if the session
   * does not belong to the user.
   *
   * @param userId - Internal user ID who owns the session.
   * @param sessionHash - SHA-256 hash of the refresh token identifying the session.
   * @throws {@link AuthException} `SESSION_NOT_FOUND` when the session is not owned by the user.
   */
  async revokeSession({ userId, tenantId, sessionHash }: RevokeSessionParams): Promise<void> {
    this.assertTenant(tenantId)
    this.assertValidSessionHash(sessionHash)

    // Atomic Lua script: ownership check (SISMEMBER) + all deletions in one
    // round-trip to eliminate TOCTOU between the membership check and DEL/SREM.
    const result = await this.redis.eval(
      REVOKE_SESSION_LUA,
      [this.indexKey(userId, tenantId), `rt:${sessionHash}`, `sd:${sessionHash}`],
      [`rt:${sessionHash}`]
    )

    const revoked = typeof result === 'number' ? result : 0

    if (revoked === 0) {
      throw new AuthException(AUTH_ERROR_CODES.SESSION_NOT_FOUND)
    }
  }

  /**
   * Revokes one named session **other than the caller's own**, and cuts the access tokens with
   * it.
   *
   * Distinct from {@link revokeSession}, which is the primitive: deleting the refresh session
   * stops rotation but says nothing about the stateless access token that session's holder is
   * already carrying, and that token keeps working until it expires. Someone who opens their
   * session list and revokes a device does so because they think it is compromised — a decision
   * about *right now*, not about the next fifteen minutes. The same argument
   * {@link revokeAllExceptCurrent} makes in its own JSDoc applies to revoking one.
   *
   * The epoch is the only lever available: a session hash does not name the `jti` of any access
   * token, so there is nothing to blacklist individually. Bumping it ends every access token
   * the account holds, and the user's *other* devices silently re-mint one on their next
   * rotation — they still hold live refresh sessions. The revoked device cannot, which is the
   * point.
   *
   * `logout` deliberately keeps using the primitive: it blacklists its own `jti` by name, and
   * ending one session must not sign the account out of every other device's access token.
   *
   * @param userId - Internal user ID who owns the session.
   * @param sessionHash - SHA-256 hash of the refresh token identifying the session.
   * @throws {@link AuthException} `SESSION_NOT_FOUND` when the session is not owned by the user.
   */
  async revokeOtherSession({ userId, tenantId, sessionHash }: RevokeSessionParams): Promise<void> {
    this.assertTenant(tenantId)
    await this.revokeSession({ userId, tenantId, sessionHash })
    // After the revoke, not before: a failure above leaves the epoch untouched and the
    // operation visibly incomplete, rather than the reverse — every device losing its access
    // token for a session that is in fact still alive.
    await this.redis.bumpUserTokenEpoch(userId, tenantId, 'dashboard')
  }

  /**
   * Revokes all sessions for a user except the caller's current session.
   *
   * Reads all `rt:`-prefixed members from `sess:{userId}` and calls
   * {@link revokeSession} for each session whose hash differs from
   * `currentSessionHash`. The current session is always preserved.
   *
   * The user's token epoch is advanced as part of this, which is what makes the revocation
   * take effect *now* rather than whenever each device's access token happens to expire.
   * Deleting a refresh session stops that device rotating, but its already-issued access token
   * is stateless and keeps verifying for the rest of its lifetime — up to `jwt.accessExpiresIn`
   * of continued access on a device the user just told the system to sign out. Someone who
   * clicks "sign out my other devices" because they think one is compromised is making a
   * statement about right now.
   *
   * The caller's own access token is invalidated too — the epoch is per user, not per session —
   * but the caller is the one party who can recover instantly: their refresh session is
   * deliberately preserved, so the next request refreshes and continues. The revoked devices
   * cannot, having lost the refresh token that would let them. Clients using the library's
   * silent-refresh flow absorb this without the user noticing; a client that does not will see
   * one 401 and must refresh.
   *
   * @param userId - Internal user ID whose other sessions are being revoked.
   * @param currentSessionHash - SHA-256 hash of the session to preserve.
   * @throws {unknown} Propagates any error thrown by `revokeSession` — including
   *   {@link AuthException} with various codes, Redis errors, or other runtime errors.
   */
  async revokeAllExceptCurrent({
    userId,
    tenantId,
    currentSessionHash
  }: RevokeAllExceptCurrentParams): Promise<void> {
    this.assertTenant(tenantId)
    this.assertValidSessionHash(currentSessionHash)

    const members = await this.redis.smembers(this.indexKey(userId, tenantId))
    const rtMembers = members.filter((m) => m.startsWith('rt:'))

    for (const member of rtMembers) {
      const hash = member.slice(3)

      if (timingSafeCompare(hash, currentSessionHash)) continue

      try {
        await this.revokeSession({ userId, tenantId, sessionHash: hash })
      } catch (err: unknown) {
        // SESSION_NOT_FOUND is expected when a concurrent logout already removed
        // this session between our SMEMBERS read and the Lua revocation. Any
        // other error (Redis failure, unexpected exception) is re-thrown.
        if (err instanceof AuthException) {
          const body = err.getResponse() as { error?: { code?: string } }
          if (body.error?.code === AUTH_ERROR_CODES.SESSION_NOT_FOUND) continue
        }
        throw err
      }
    }

    // Every rotation grace pointer the account holds goes too.
    //
    // `revokeSession` only ever deletes `rt:`/`sd:` keys, and the loop above only visits `rt:`
    // members, so a `rp:{predecessor}` pointer survived both. For a *revoked* session that is
    // harmless — the grace branch requires the successor's `rt:` key, which is gone. The gap is
    // the *preserved* session: its predecessor's pointer names a hash that is deliberately
    // still alive, so anyone holding that predecessor token could take the grace branch and
    // mint a brand-new full-lifetime session for the rest of the window. The epoch bump below
    // does not help — a recovered session signs its access token from the current epoch.
    //
    // "Sign out my other devices" is a statement about right now, so no credential minted
    // before this moment may still produce a session. `logout` clears the same pointer for the
    // single token it is handed, for the same reason.
    const gracePointers = members.filter((m) => m.startsWith('rp:'))
    for (const member of gracePointers) {
      await this.redis.del(member)
      await this.redis.srem(this.indexKey(userId, tenantId), member)
    }

    // Last, and only once every refresh session is gone: a bump before the loop would be
    // undone by nothing, but a bump after it means a failure above leaves the epoch untouched
    // rather than logging the user out of a device the loop never got to revoke.
    await this.redis.bumpUserTokenEpoch(userId, tenantId, 'dashboard')
  }

  /**
   * Rotates the session detail record from the old token hash to the new one.
   *
   * Called by `AuthService` immediately after `TokenManagerService.reissueTokens()`
   * successfully issues a new refresh token. Atomically deletes `sd:{oldHash}` and
   * writes `sd:{newHash}` with the original `createdAt` preserved — so the user sees
   * a stable session age across token rotations.
   *
   * The `ip` and `device` fields are refreshed from the current request, reflecting
   * the most recent device and location seen for this session.
   *
   * @remarks
   * The `sd:` keys are display metadata only — they have no effect on authentication.
   * If the old `sd:` record is missing or unparseable (e.g. the session predates
   * `SessionService` or was partially cleaned up), a new record is written with
   * `createdAt = Date.now()`.
   *
   * @param oldHash - SHA-256 hex hash of the old (consumed) refresh token.
   * @param newHash - SHA-256 hex hash of the newly issued refresh token.
   * @param ip - Client IP address from the current request.
   * @param userAgent - Raw `User-Agent` header value from the current request.
   * @throws {@link AuthException} `SESSION_NOT_FOUND` when either hash is not a valid
   *   64-character lowercase hex string.
   */
  async rotateSession(
    oldHash: string,
    newHash: string,
    ip: string,
    userAgent: string
  ): Promise<void> {
    this.assertValidSessionHash(oldHash)
    this.assertValidSessionHash(newHash)

    // Guard against a programming error where the same hash is supplied for both
    // arguments. timingSafeCompare is used because session hashes are derived from
    // secrets (refresh tokens). If this precondition is violated, the Lua DEL+SET
    // on a single key is semantically safe today, but that relies on the current
    // command order — an explicit guard makes the invariant durable.
    if (timingSafeCompare(oldHash, newHash)) {
      return
    }

    const now = Date.now()
    const ttl = this.options.jwt.refreshExpiresInDays * 86_400

    // Read the old detail record outside Lua (Lua cannot parse JSON). Preserve
    // createdAt so that session age is stable across token rotations.
    //
    // @remarks
    // TOCTOU: a concurrent rotation may have already moved sd:{oldHash}
    // before we reach the eval below. This is benign — the concurrently
    // written sd:{newHash} will be overwritten with the same createdAt value
    // since both racing requests read the same sd:{oldHash} before it was gone.
    let createdAt = now
    try {
      const raw = await this.redis.get(`sd:${oldHash}`)
      if (raw !== null) {
        const parsed: unknown = JSON.parse(raw)
        if (
          // Stryker disable next-line ConditionalExpression: defensive `parsed !== null` guard; `'createdAt' in null` would throw and the surrounding try/catch falls back to now(), the same result as the original false branch
          parsed !== null &&
          typeof parsed === 'object' &&
          'createdAt' in parsed &&
          typeof (parsed as Record<string, unknown>)['createdAt'] === 'number'
        ) {
          createdAt = (parsed as Record<string, unknown>)['createdAt'] as number
        }
      }
    } catch {
      // Old detail missing or unparseable — fall back to current timestamp.
    }

    const newDetail: StoredSessionDetail = {
      device: parseUserAgent(userAgent),
      ip: ip.slice(0, MAX_IP_LENGTH),
      createdAt,
      lastActivityAt: now
    }

    // Atomically delete old detail and write new detail to prevent the window
    // where a concurrent listSessions call would find neither key and classify
    // the session as stale, triggering a spurious SREM on the sess: SET.
    await this.redis.eval(
      ROTATE_SESSION_DETAIL_LUA,
      [`sd:${oldHash}`, `sd:${newHash}`],
      [JSON.stringify(newDetail), String(ttl)]
    )
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  /**
   * Asserts that a session hash string is a valid 64-character lowercase hex string.
   *
   * Rejects malformed inputs before they reach Redis to prevent unexpected key
   * construction and to avoid leaking timing information via Redis operations on
   * attacker-controlled key names.
   *
   * @remarks
   * `SESSION_NOT_FOUND` is thrown intentionally (instead of HTTP 400) to prevent
   * callers from enumerating valid hash formats. Callers cannot distinguish between
   * "bad format" and "session does not exist", which is the desired behavior.
   *
   * @param sessionHash - The session hash to validate.
   * @throws {@link AuthException} `SESSION_NOT_FOUND` when the format is invalid.
   */
  private assertValidSessionHash(sessionHash: string): void {
    if (!SESSION_HASH_RE.test(sessionHash)) {
      throw new AuthException(AUTH_ERROR_CODES.SESSION_NOT_FOUND)
    }
  }

  /**
   * The Redis key of this user's session index.
   *
   * Derived rather than interpolated, and tenant-scoped: `IUserRepository.findById` takes a
   * tenant because ids may only be unique within one, so a bare-id index let a revoke aimed at
   * one tenant's user empty another's. The derivation lives in `user-keys.ts` because rust-auth
   * reads the same key from the same contract.
   *
   * @param userId - The account whose sessions the index tracks.
   * @param tenantId - The tenant that account belongs to.
   * @returns The un-namespaced index key.
   */
  private indexKey(userId: string, tenantId: string): string {
    return sessionIndexKey('dashboard', userId, this.options.hmacKey, tenantId)
  }

  /**
   * Enforces the concurrent session limit for a user by evicting the oldest
   * sessions (FIFO) when the limit has been exceeded.
   *
   * Only `rt:`-prefixed members are counted as active sessions — `rp:` grace
   * pointers are excluded from the limit calculation. Sessions with missing or
   * unparseable detail records are treated as the oldest (evicted first).
   *
   * @remarks
   * **TOCTOU caveat:** The SMEMBERS read, sd: lookups, and DEL/SREM operations are
   * not atomic. Under high concurrency two simultaneous logins for the same user
   * may both observe the SET before the other's session is committed, allowing a
   * transient overshoot of 1 extra session per concurrent login pair. A fully atomic
   * A fully atomic Lua implementation is used in `rotateSession`. The practical
   * risk is low for most `defaultMaxSessions` values (≥ 2).
   *
   * @param userId - Internal user ID whose session count is being checked.
   * @param tenantId - The tenant that user belongs to; part of the index key.
   * @param newHash - SHA-256 hash of the newly issued refresh token (excluded from eviction).
   * @param ip - Client IP address (forwarded to the `onSessionEvicted` hook context).
   * @param userAgent - User-Agent string (forwarded to the `onSessionEvicted` hook context).
   */
  private async enforceSessionLimit(
    userId: string,
    tenantId: string,
    newHash: string,
    ip: string,
    userAgent: string
  ): Promise<void> {
    // Awaited here, unlike in `listSessions`: this runs on every login, which makes it the
    // path that actually bounds the index, and the eviction below walks the set it prunes.
    await this.redis.pruneExpiredGraceMembers(this.indexKey(userId, tenantId), 'rp:')

    const members = await this.redis.smembers(this.indexKey(userId, tenantId))

    // Only count active refresh token entries — exclude grace pointers (rp:).
    const rtMembers = members.filter((m) => m.startsWith('rt:'))

    const limit = await this.resolveSessionLimit(userId, tenantId)

    if (rtMembers.length <= limit) return

    // Fetch createdAt for each rt: member to determine eviction order.
    const withTimestamps = await Promise.all(
      rtMembers.map(async (member) => {
        // member is "rt:{hash}" — extract just the hash portion.
        const memberHash = member.slice(3)
        let createdAt = 0

        try {
          const raw = await this.redis.get(`sd:${memberHash}`)
          if (raw !== null) {
            const parsed: unknown = JSON.parse(raw)
            if (
              // Stryker disable next-line ConditionalExpression: defensive `parsed !== null` guard masked by the surrounding try/catch fallback, yielding the same result
              parsed !== null &&
              typeof parsed === 'object' &&
              'createdAt' in parsed &&
              typeof (parsed as Record<string, unknown>)['createdAt'] === 'number'
            ) {
              createdAt = (parsed as StoredSessionDetail).createdAt
            }
          }
        } catch {
          // Parse error — treat as oldest (createdAt = 0).
        }

        return { member, memberHash, createdAt }
      })
    )

    // Sort ascending by createdAt — oldest first.
    withTimestamps.sort((a, b) => a.createdAt - b.createdAt)

    const evictCount = rtMembers.length - limit
    const toEvict = withTimestamps
      .filter((entry) => entry.memberHash !== newHash)
      .slice(0, evictCount)

    const context: HookContext = {
      ip,
      userAgent,
      sanitizedHeaders: {}
    }

    for (const entry of toEvict) {
      try {
        // Best-effort eviction: partial Redis failures leave stale keys that expire via TTL.
        // The new session is already committed at this point — a mid-eviction failure
        // MUST NOT propagate back to createSession callers.
        await this.redis.del(`rt:${entry.memberHash}`)
        await this.redis.srem(this.indexKey(userId, tenantId), entry.member)
        await this.redis.del(`sd:${entry.memberHash}`)
      } catch (err: unknown) {
        this.logger.error(
          `enforceSessionLimit: failed to evict session ${entry.memberHash} ` +
            `for user ${logSafe(userId)}: ${describeChannelStatus(err)}`
        )
        continue
      }

      // Fire onSessionEvicted hook — fire-and-forget; errors must not propagate.
      if (this.hooks?.onSessionEvicted) {
        // Note: entry.memberHash is SHA-256 (not HMAC-SHA-256) of the refresh token.
        void Promise.resolve(this.hooks.onSessionEvicted(userId, entry.memberHash, context)).catch(
          (err: unknown) => {
            this.logger.error(`onSessionEvicted hook threw: ${describeChannelStatus(err)}`)
          }
        )
      }
    }
  }

  /**
   * Resolves the maximum number of concurrent sessions allowed for a user.
   *
   * When `options.sessions.maxSessionsResolver` is configured, it is called with
   * the full user record. Falls back to `options.sessions.defaultMaxSessions` if
   * the resolver is absent, the user cannot be found, the resolver throws, or it answers
   * with something that is not a usable limit.
   *
   * That last case is the one that mattered. The resolver is the host's code and its return
   * value went straight into the eviction arithmetic, where `NaN` — the result of, say,
   * `Number(user.plan.maxSessions)` against a column that is missing — quietly disabled the cap
   * altogether: `length <= NaN` is `false`, so eviction was entered, `length - NaN` is `NaN`,
   * and `slice(0, NaN)` is empty, so nothing was evicted and every call path still reported
   * success. A negative value evicted every other session on each login instead. Only a
   * *thrown* resolver was ever caught.
   *
   * @param userId - Internal user ID to resolve the limit for.
   * @param tenantId - Tenant that user belongs to; scopes the lookup behind the resolver.
   * @returns Maximum allowed concurrent sessions for the given user.
   */
  private async resolveSessionLimit(userId: string, tenantId: string): Promise<number> {
    const { maxSessionsResolver, defaultMaxSessions } = this.options.sessions

    if (!maxSessionsResolver) {
      return defaultMaxSessions
    }

    try {
      const user = await this.userRepo.findById(userId, tenantId)
      if (!user) return defaultMaxSessions
      const resolved = await maxSessionsResolver(user)
      if (!Number.isInteger(resolved) || resolved < 1) {
        this.logger.error(
          `maxSessionsResolver returned ${logSafe(String(resolved))}, which is not a positive whole ` +
            `number of sessions — falling back to defaultMaxSessions. A cap that silently ` +
            `stops applying is worse than one that is merely wrong.`
        )
        return defaultMaxSessions
      }
      return resolved
    } catch (err: unknown) {
      this.logger.error(
        `maxSessionsResolver threw — falling back to defaultMaxSessions: ${describeChannelStatus(err)}`
      )
      return defaultMaxSessions
    }
  }
}
