/**
 * @fileoverview Thin Redis wrapper for authentication state (tokens, sessions, brute-force counters).
 *
 * @layer Service
 */
import { Inject, Injectable } from '@nestjs/common'
import type { Redis } from 'ioredis'

import { BYMAX_AUTH_OPTIONS, BYMAX_AUTH_REDIS_CLIENT } from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import { TOKEN_EPOCH_RETENTION_SECONDS } from '../constants/token-epoch'
import { generateSecureToken, sha256 } from '../crypto/secure-token'
import type { WsTicketSnapshot } from '../interfaces/ws-ticket.interface'

/**
 * Lifetime of a token-epoch key, in seconds.
 *
 * Pinned to the {@link TOKEN_EPOCH_RETENTION_SECONDS} store contract rather than repeating the
 * literal: startup validation rejects a `jwt.accessExpiresIn` longer than that bound, so a bump
 * can never lapse while a pre-bump access token is still presentable. Deriving the TTL from the
 * same constant the validation reads is what keeps the two from drifting apart. A small integer
 * per reset-affected user is negligible.
 */
const EPOCH_TTL_SECONDS = TOKEN_EPOCH_RETENTION_SECONDS

/**
 * Entropy of a freshly-minted WebSocket ticket, in bytes (256-bit, like the opaque refresh
 * token). rust-auth mints the same width, so neither backend issues the weaker ticket.
 */
const WS_TICKET_ENTROPY_BYTES = 32

/** Tag the rotation script prepends to a session recovered from the grace window. */
const GRACE_TAG = 'GRACE:'

/** Tag the rotation script prepends to the family id of a replayed consumed token. */
const REUSED_TAG = 'REUSED:'

/**
 * The key prefixes each identity plane rotates over. The two planes are keyed by ids from
 * different consumer repositories, which may legitimately collide, so every keyspace is
 * separated — sharing one would let a revoke on one plane log the other out.
 */
const REFRESH_PREFIXES = {
  dashboard: {
    live: 'rt',
    grace: 'rp',
    consumed: 'cf',
    family: 'fam',
    index: 'sess',
    detail: 'sd'
  },
  platform: {
    live: 'prt',
    grace: 'prp',
    consumed: 'pcf',
    family: 'pfam',
    index: 'psess',
    detail: 'psd'
  }
} as const

/**
 * Selects the prefix set for an identity plane.
 *
 * Written as an explicit branch rather than an index expression: the two planes are the whole
 * domain, and naming them keeps the lookup out of reach of a computed key.
 *
 * @param kind - The identity plane.
 * @returns That plane's key prefixes.
 */
function prefixesFor(
  kind: 'dashboard' | 'platform'
): (typeof REFRESH_PREFIXES)['dashboard' | 'platform'] {
  return kind === 'platform' ? REFRESH_PREFIXES.platform : REFRESH_PREFIXES.dashboard
}

/**
 * Atomic refresh-token rotation with a grace window and reuse detection.
 *
 * Held byte-identical to rust-auth's `crates/bymax-auth-redis/src/lua/refresh_rotate.lua`
 * so a session written by either backend rotates identically under the other.
 *
 * ```text
 * KEYS[1] = rt:{sha256(old)}   KEYS[2] = rt:{sha256(new)}   KEYS[3] = rp:{sha256(old)}
 * KEYS[4] = cf:{sha256(old)}   KEYS[5] = fam:{family}
 * ARGV[1] = new session JSON   ARGV[2] = refresh TTL (s)    ARGV[3] = grace TTL (s; 0 skips)
 * ARGV[4] = family id ('' = legacy record, skip family work)
 * ARGV[5] = sha256(old)        ARGV[6] = sha256(new)
 * ```
 *
 * The script deliberately never decodes a stored record: every JSON value it touches is
 * returned to the caller and parsed there, by a real parser rather than Lua's `cjson`.
 */
const ROTATE_LUA = `
local old = redis.call('GET', KEYS[1])
if old then
  redis.call('SET', KEYS[2], ARGV[1], 'EX', ARGV[2])
  -- A zero grace window means no grace recovery: skip the pointer rather than issue an
  -- \`EX 0\` SET, which Redis rejects.
  if tonumber(ARGV[3]) > 0 then
    redis.call('SET', KEYS[3], ARGV[1], 'EX', ARGV[3])
  end
  -- Plant the consumed-family marker (it outlives the much shorter grace window) and move the
  -- family membership onto the new hash, so a post-grace replay is detected as a reuse and the
  -- whole lineage stays revocable. A legacy session with no family skips this bookkeeping.
  if ARGV[4] ~= '' then
    redis.call('SET', KEYS[4], ARGV[4], 'EX', ARGV[2])
    redis.call('SREM', KEYS[5], ARGV[5])
    redis.call('SADD', KEYS[5], ARGV[6])
    redis.call('EXPIRE', KEYS[5], ARGV[2])
  end
  redis.call('DEL', KEYS[1])
  return old
end
local grace = redis.call('GET', KEYS[3])
if grace then
  -- The window is single-shot: consume the pointer so one captured token cannot mint a fresh
  -- session on every request for the whole window. It exists to cover the one retry where the
  -- old token was consumed but the client never received the new one.
  redis.call('DEL', KEYS[3])
  return 'GRACE:' .. grace
end
-- Post-grace reuse: the consumed-family marker outlives the grace pointer, so its presence
-- here means this token was validly issued and already rotated — a replay of a consumed token.
local family = redis.call('GET', KEYS[4])
if family then
  return 'REUSED:' .. family
end
return false
`

/**
 * Revokes every live session in a refresh-token family in one transaction.
 *
 * Held byte-identical to rust-auth's `crates/bymax-auth-redis/src/lua/revoke_family.lua`.
 *
 * ```text
 * KEYS[1] = fam:{family} (already namespaced)
 * ARGV[1] = namespace   ARGV[2] = live prefix   ARGV[3] = detail prefix
 * ARGV[4] = the owner's index key, or '' when no member record was readable
 * ```
 *
 * The owner is resolved by the caller rather than decoded here: every member of one family
 * belongs to the same user, and reading one record in the host language keeps the script free
 * of `cjson`. The script still re-reads the membership itself, so a member added between the
 * two steps is revoked too.
 */
const REVOKE_FAMILY_LUA = `
local members = redis.call('SMEMBERS', KEYS[1])
if #members == 0 then
  redis.call('DEL', KEYS[1])
  return 0
end
local ns, rt, sd, sess_key = ARGV[1], ARGV[2], ARGV[3], ARGV[4]
for _, hash in ipairs(members) do
  redis.call('DEL', ns .. ':' .. rt .. ':' .. hash)
  redis.call('DEL', ns .. ':' .. sd .. ':' .. hash)
  if sess_key ~= '' then
    -- The index stores full key suffixes, not bare hashes, so the member to prune is
    -- \`rt:{hash}\` (\`prt:{hash}\` on the platform plane).
    redis.call('SREM', sess_key, rt .. ':' .. hash)
  end
end
redis.call('DEL', KEYS[1])
return #members
`

/** The rotation bundle {@link AuthRedisService.rotateRefreshSession} consumes. */
export interface RefreshRotationParams {
  /** Which identity plane is rotating; selects the whole prefix set. */
  kind: 'dashboard' | 'platform'
  /** SHA-256 of the presented (old) refresh token. */
  oldHash: string
  /** SHA-256 of the freshly minted refresh token. */
  newHash: string
  /** Serialized session record to store under the new hash. */
  newSessionJson: string
  /** Family of the presented session; `''` for a legacy record written before families. */
  familyId: string
  /** Refresh-session lifetime in seconds. */
  refreshTtl: number
  /** Grace-pointer lifetime in seconds; `0` writes no pointer. */
  graceTtl: number
}

/** What {@link AuthRedisService.rotateRefreshSession} found for the presented token. */
export type RefreshRotationOutcome =
  | { kind: 'rotated'; sessionJson: string }
  | { kind: 'grace'; sessionJson: string }
  | { kind: 'reused'; familyId: string }
  | { kind: 'invalid' }

/**
 * Internal Redis service for @bymax-one/nest-auth.
 *
 * Wraps the host-provided ioredis client and automatically prefixes every key
 * with `{namespace}:` to prevent collisions with the host application's own
 * Redis keys. All operations are exposed as typed async methods.
 *
 * @remarks
 * This service is **internal** — it is NOT exported from the public barrel
 * (`src/server/index.ts`). Consumers interact with it indirectly through the
 * higher-level services (BruteForceService, TokenManagerService, etc.).
 *
 * The namespace is taken from `ResolvedOptions.redisNamespace` (defaults to
 * `'auth'`). Example key with namespace `'auth'` and key `'rt:abc'`:
 * → `'auth:rt:abc'`
 */
@Injectable()
export class AuthRedisService {
  private readonly namespace: string

  constructor(
    @Inject(BYMAX_AUTH_REDIS_CLIENT) private readonly redis: Redis,
    @Inject(BYMAX_AUTH_OPTIONS) options: ResolvedOptions
  ) {
    this.namespace = options.redisNamespace
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  /** Returns the fully-qualified Redis key by prepending the configured namespace prefix. */
  private prefix(key: string): string {
    return `${this.namespace}:${key}`
  }

  // ---------------------------------------------------------------------------
  // String operations
  // ---------------------------------------------------------------------------

  /**
   * Gets the string value for a key.
   *
   * @param key - Application key (namespace prefix is applied automatically).
   * @returns The stored string, or `null` if the key does not exist.
   */
  async get(key: string): Promise<string | null> {
    return this.redis.get(this.prefix(key))
  }

  /**
   * Sets a string value, optionally with an expiry.
   *
   * @param key - Application key (namespace prefix is applied automatically).
   * @param value - String value to store.
   * @param ttl - Time-to-live in seconds. When omitted the key never expires.
   */
  async set(key: string, value: string, ttl?: number): Promise<void> {
    if (ttl !== undefined) {
      await this.redis.set(this.prefix(key), value, 'EX', ttl)
    } else {
      await this.redis.set(this.prefix(key), value)
    }
  }

  /**
   * Deletes a key.
   *
   * @param key - Application key (namespace prefix is applied automatically).
   */
  async del(key: string): Promise<void> {
    await this.redis.del(this.prefix(key))
  }

  /**
   * Atomically sets a key with an expiry only if the key does not already exist.
   *
   * Equivalent to `SET key "1" EX ttl NX`. Returns `true` if the key was created
   * (first caller), or `false` if the key already existed (subsequent callers).
   *
   * Use this instead of a GET + SET pair to avoid TOCTOU race conditions, e.g.
   * for cooldown guards where only one concurrent caller should succeed.
   *
   * @param key - Application key (namespace prefix is applied automatically).
   * @param ttl - Time-to-live in seconds.
   * @returns `true` if the key was newly set, `false` if it already existed.
   */
  async setnx(key: string, ttl: number): Promise<boolean> {
    const result = await this.redis.set(this.prefix(key), '1', 'EX', ttl, 'NX')
    return result === 'OK'
  }

  // ---------------------------------------------------------------------------
  // Counter / expiry operations
  // ---------------------------------------------------------------------------

  /**
   * Atomically increments an integer counter and returns the new value.
   *
   * @param key - Application key (namespace prefix is applied automatically).
   * @returns The value of the key after the increment.
   */
  async incr(key: string): Promise<number> {
    return this.redis.incr(this.prefix(key))
  }

  /**
   * Sets a key's time-to-live in seconds.
   *
   * @param key - Application key (namespace prefix is applied automatically).
   * @param ttl - New time-to-live in seconds.
   */
  async expire(key: string, ttl: number): Promise<void> {
    await this.redis.expire(this.prefix(key), ttl)
  }

  /**
   * Returns the remaining time-to-live of a key in seconds.
   *
   * @param key - Application key (namespace prefix is applied automatically).
   * @returns Seconds until expiry, `-1` if no expiry is set, or `-2` if the key
   *   does not exist.
   */
  async ttl(key: string): Promise<number> {
    return this.redis.ttl(this.prefix(key))
  }

  // ---------------------------------------------------------------------------
  // Set operations
  // ---------------------------------------------------------------------------

  /**
   * Adds a member to a Redis Set.
   *
   * @param setKey - Set key (namespace prefix is applied automatically).
   * @param member - Member to add.
   * @returns `1` if the member was added, `0` if it already existed.
   */
  async sadd(setKey: string, member: string): Promise<number> {
    return this.redis.sadd(this.prefix(setKey), member)
  }

  /**
   * Removes a member from a Redis Set.
   *
   * @param setKey - Set key (namespace prefix is applied automatically).
   * @param member - Member to remove.
   * @returns `1` if the member was removed, `0` if it did not exist.
   */
  async srem(setKey: string, member: string): Promise<number> {
    return this.redis.srem(this.prefix(setKey), member)
  }

  /**
   * Returns all members of a Redis Set.
   *
   * @param setKey - Set key (namespace prefix is applied automatically).
   * @returns Array of member strings (empty array if the key does not exist).
   */
  async smembers(setKey: string): Promise<string[]> {
    return this.redis.smembers(this.prefix(setKey))
  }

  /**
   * Tests whether a member belongs to a Redis Set.
   *
   * @param setKey - Set key (namespace prefix is applied automatically).
   * @param member - Member to test.
   * @returns `true` if the member is in the set, `false` otherwise.
   */
  async sismember(setKey: string, member: string): Promise<boolean> {
    const result = await this.redis.sismember(this.prefix(setKey), member)
    return result === 1
  }

  // ---------------------------------------------------------------------------
  // Lua scripting
  // ---------------------------------------------------------------------------

  /**
   * Executes a Lua script via EVAL.
   *
   * @param script - Lua script source.
   * @param keys - Redis keys referenced in the script (automatically prefixed).
   *   Accessible as `KEYS[1]`, `KEYS[2]`, … inside Lua.
   * @param args - Additional arguments. Accessible as `ARGV[1]`, `ARGV[2]`, … in Lua.
   * @returns The script's return value. The concrete type depends on the script —
   *   callers must cast or narrow the result themselves.
   *
   * @remarks
   * The return type is `unknown` rather than `any` to enforce explicit handling
   * at the call site. Use a type assertion or runtime check after calling this method.
   */
  async eval(script: string, keys: string[], args: string[]): Promise<unknown> {
    const prefixedKeys = keys.map((k) => this.prefix(k))
    return this.redis.eval(script, prefixedKeys.length, ...prefixedKeys, ...args)
  }

  // ---------------------------------------------------------------------------
  // Refresh-token rotation and family revocation
  // ---------------------------------------------------------------------------

  /**
   * Atomically rotates a refresh session, plants the reuse-detection bookkeeping, and
   * reports what the presented token actually was.
   *
   * Byte-identical in behaviour to rust-auth's `refresh_rotate.lua`, so both backends can
   * drive the same Redis. In one round trip it:
   *
   * - consumes the live session (`GET` + `DEL`) and writes the new one,
   * - writes the rotation grace pointer, unless the grace window is zero,
   * - plants the consumed-family marker `cf:{oldHash}` and moves the family membership
   *   from the old hash to the new one.
   *
   * Writes happen **before** the old key is deleted. Redis does not roll back a script's
   * earlier writes, so a failing write aborts the script with the old token still intact —
   * the old token is never consumed without the new session being persisted and the
   * consumed marker planted, which is what makes reuse detection crash-safe.
   *
   * @param params - The rotation bundle; see {@link RefreshRotationParams}.
   * @returns What the presented token was: a live session (`rotated`), a replay inside the
   *   grace window (`grace`), a replay of a consumed token past its grace window
   *   (`reused`, carrying the compromised family), or never-issued (`invalid`).
   */
  async rotateRefreshSession(params: RefreshRotationParams): Promise<RefreshRotationOutcome> {
    const p = prefixesFor(params.kind)
    const raw = await this.eval(
      ROTATE_LUA,
      [
        `${p.live}:${params.oldHash}`,
        `${p.live}:${params.newHash}`,
        `${p.grace}:${params.oldHash}`,
        `${p.consumed}:${params.oldHash}`,
        `${p.family}:${params.familyId}`
      ],
      [
        params.newSessionJson,
        String(params.refreshTtl),
        String(params.graceTtl),
        params.familyId,
        params.oldHash,
        params.newHash
      ]
    )
    if (typeof raw !== 'string') return { kind: 'invalid' }
    if (raw.startsWith(GRACE_TAG)) {
      const sessionJson = raw.slice(GRACE_TAG.length)
      const alive = await this.familyIsAlive(sessionJson, p.family)
      return alive ? { kind: 'grace', sessionJson } : { kind: 'invalid' }
    }
    if (raw.startsWith(REUSED_TAG)) {
      return { kind: 'reused', familyId: raw.slice(REUSED_TAG.length) }
    }
    return { kind: 'rotated', sessionJson: raw }
  }

  /**
   * Whether the lineage a recovered grace record belongs to is still alive.
   *
   * A grace pointer can outlive its own lineage: reuse detection revokes the family's live
   * sessions, but a pointer planted by an *earlier* rotation of that same lineage can still be
   * inside its (much shorter) window at that moment — detection only proves the replayed
   * token's own pointer expired, which says nothing about a younger sibling's. Recovering from
   * such a pointer would mint a fresh session carrying the revoked family id and hand the thief
   * back the lineage the revocation just killed.
   *
   * A record written before families existed carries none and recovers as before.
   *
   * @param sessionJson - The record the grace pointer held.
   * @param familyPrefix - The family-index prefix for the plane being rotated.
   * @returns `false` only when the record names a family whose index is gone.
   */
  private async familyIsAlive(sessionJson: string, familyPrefix: string): Promise<boolean> {
    let familyId: unknown
    try {
      familyId = (JSON.parse(sessionJson) as Record<string, unknown>)['familyId']
    } catch {
      // Deliberately swallowed: a malformed record names no family, so there is nothing to
      // check, and it is rejected downstream by the session parser with its own warning.
      // Reporting it as a dead family here would be a misleading theft signal.
    }
    if (typeof familyId !== 'string' || familyId === '') return true
    const present = await this.redis.exists(this.prefix(`${familyPrefix}:${familyId}`))
    return present === 1
  }

  /**
   * Revokes every live session in one refresh-token family, in a single transaction.
   *
   * Called on reuse detection: the whole lineage descending from the compromised login is
   * deleted, forcing each holder to re-authenticate. This is deliberately narrower than
   * {@link invalidateUserSessions} — the OWASP-recommended behaviour is to kill the stolen
   * token's chain, not to log the user's other legitimate devices out.
   *
   * Idempotent: an empty, unknown, or already-cleared family is a no-op.
   *
   * @param familyId - The family id carried by the consumed-token marker.
   * @param kind - Which identity plane the family belongs to. Defaults to `'dashboard'`.
   * @returns The number of family members that were removed.
   */
  async revokeFamily(
    familyId: string,
    kind: 'dashboard' | 'platform' = 'dashboard'
  ): Promise<number> {
    if (familyId === '') return 0
    const p = prefixesFor(kind)
    const members = await this.smembers(`${p.family}:${familyId}`)
    const indexKey = await this.resolveFamilyOwnerIndex(members, p.live, p.index)
    const removed = await this.eval(
      REVOKE_FAMILY_LUA,
      [`${p.family}:${familyId}`],
      [this.namespace, p.live, p.detail, indexKey]
    )
    return typeof removed === 'number' ? removed : 0
  }

  /**
   * Resolves the namespaced index key of the user a family belongs to.
   *
   * Every member of one family descends from the same login, so the first readable record
   * names the owner. Reading it here rather than decoding JSON inside the revocation script
   * keeps the script free of `cjson` and uses a real parser on the stored record.
   *
   * @param members - The family index members (bare session hashes).
   * @param livePrefix - The live-session prefix for the plane (`rt` or `prt`).
   * @param indexPrefix - The session-index prefix for the plane (`sess` or `psess`).
   * @returns The namespaced `sess:`/`psess:` key, or `''` when no member record is readable —
   *   every member may have already expired, in which case there is nothing left to prune.
   */
  private async resolveFamilyOwnerIndex(
    members: string[],
    livePrefix: string,
    indexPrefix: string
  ): Promise<string> {
    for (const hash of members) {
      const record = await this.get(`${livePrefix}:${hash}`)
      if (record === null) continue
      let userId: unknown
      try {
        userId = (JSON.parse(record) as Record<string, unknown>)['userId']
      } catch {
        // Deliberately swallowed: an unreadable member names no owner, and the next member
        // may still name one. The loop's own guard rejects the undefined that leaves here.
      }
      if (typeof userId === 'string' && userId !== '') {
        return this.prefix(`${indexPrefix}:${userId}`)
      }
    }
    return ''
  }

  // ---------------------------------------------------------------------------
  // Atomic compound operations
  // ---------------------------------------------------------------------------

  /**
   * Atomically gets a key's value and deletes it in a single operation.
   *
   * Equivalent to Redis 6.2+ `GETDEL` command. Implemented via Lua for
   * compatibility with older Redis versions (minimum Redis 2.6 for EVAL).
   *
   * @param key - Application key (namespace prefix is applied automatically).
   * @returns The value of the key before deletion, or `null` if it did not exist.
   */
  async getdel(key: string): Promise<string | null> {
    const result = await this.eval(
      `local v = redis.call('GET', KEYS[1]); if v then redis.call('DEL', KEYS[1]) end; return v`,
      [key],
      []
    )
    return typeof result === 'string' ? result : null
  }

  /**
   * Atomically sets a key only if it does not already exist, with a TTL.
   *
   * Equivalent to `SET key value EX ttl NX`. Returns `true` if the key was created
   * (this caller won the race), or `false` if the key already existed.
   *
   * Use this to prevent overwriting an existing value in concurrent scenarios
   * (e.g. idempotent MFA setup where two requests must not generate different secrets).
   *
   * @param key - Application key (namespace prefix is applied automatically).
   * @param value - String value to store.
   * @param ttl - Time-to-live in seconds.
   * @returns `true` if the key was newly set, `false` if it already existed.
   */
  async setIfAbsent(key: string, value: string, ttl: number): Promise<boolean> {
    const result = await this.redis.set(this.prefix(key), value, 'EX', ttl, 'NX')
    return result === 'OK'
  }

  /**
   * Atomically deletes every refresh session belonging to one identity plane.
   *
   * The set members are full key suffixes — `rt:{hash}`/`rp:{hash}` on the dashboard plane,
   * `prt:{hash}`/`prp:{hash}` on the platform plane — so a member names the key to delete
   * outright. Grace pointers are members too, which is what lets a revoke-all also kill a
   * refresh token that was rotated away but is still inside its grace window.
   *
   * Only members carrying one of the two supplied prefixes are touched. That filter is the
   * point: a dashboard user id and a platform admin id come from different repositories and
   * may legitimately collide, and an unfiltered sweep would let revoking one plane log the
   * other out. Members that do not match are left in place, and the SET itself is deleted
   * only once it is empty.
   *
   * The whole sweep is one Lua transaction, closing the race where a concurrent login adds a
   * session between the SMEMBERS read and the delete.
   *
   * @param setKey - The un-namespaced index key (`sess:{id}` or `psess:{id}`).
   * @param livePrefix - Member prefix for live sessions (`rt:` or `prt:`).
   * @param gracePrefix - Member prefix for rotation grace pointers (`rp:` or `prp:`).
   * @param detailPrefix - Key prefix for the per-session detail record (`sd:` or `psd:`).
   */
  private async sweepSessionIndex(
    setKey: string,
    livePrefix: string,
    gracePrefix: string,
    detailPrefix: string
  ): Promise<void> {
    await this.eval(
      `local members = redis.call('SMEMBERS', KEYS[1])
       local ns, live, grace, detail = ARGV[1], ARGV[2], ARGV[3], ARGV[4]
       for _, member in ipairs(members) do
         local isLive = string.sub(member, 1, string.len(live)) == live
         if isLive or string.sub(member, 1, string.len(grace)) == grace then
           redis.call('DEL', ns .. ':' .. member)
           if isLive then
             redis.call('DEL', ns .. ':' .. detail .. string.sub(member, string.len(live) + 1))
           end
           redis.call('SREM', KEYS[1], member)
         end
       end
       if redis.call('SCARD', KEYS[1]) == 0 then
         redis.call('DEL', KEYS[1])
       end`,
      [setKey],
      [this.namespace, livePrefix, gracePrefix, detailPrefix]
    )
  }

  /**
   * Atomically deletes all refresh sessions for a user on the given identity plane.
   *
   * A platform revoke also sweeps the legacy `sess:{id}` index, where platform sessions used
   * to be indexed before they moved to their own `psess:` keyspace. It removes only the
   * `prt:`/`prp:` members from there, so a dashboard user who happens to share the id keeps
   * their sessions. That legacy pass can be dropped once every session predating the move has
   * expired (one refresh lifetime, seven days by default).
   *
   * @param userId - Internal user or admin ID whose sessions will be invalidated.
   * @param kind - Which identity plane to revoke. Defaults to `'dashboard'`.
   */
  async invalidateUserSessions(
    userId: string,
    kind: 'dashboard' | 'platform' = 'dashboard'
  ): Promise<void> {
    if (kind === 'platform') {
      await this.sweepSessionIndex(`psess:${userId}`, 'prt:', 'prp:', 'psd:')
      await this.sweepSessionIndex(`sess:${userId}`, 'prt:', 'prp:', 'psd:')
      return
    }

    await this.sweepSessionIndex(`sess:${userId}`, 'rt:', 'rp:', 'sd:')
  }

  /**
   * Atomically increments a counter and sets a fixed TTL on the **first** increment.
   *
   * Implements a fixed-window rate-limit counter. The TTL is set only when the
   * counter transitions from 0 → 1, so the window starts at the first failure and
   * does NOT reset on subsequent failures. This prevents an attacker from sending
   * one request per `(windowSeconds - 1)` seconds to avoid ever crossing the
   * threshold.
   *
   * @param key - Application key (namespace prefix is applied automatically).
   * @param ttl - Window duration in seconds. Applied only on the first increment.
   * @returns The value of the counter after incrementing.
   */
  async incrWithFixedTtl(key: string, ttl: number): Promise<number> {
    const result = await this.eval(
      `local v = redis.call('INCR', KEYS[1])
       if v == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
       return v`,
      [key],
      [String(ttl)]
    )
    return typeof result === 'number' ? result : 0
  }

  // ---------------------------------------------------------------------------
  // Token epoch (bulk revocation of stateless access tokens)
  // ---------------------------------------------------------------------------

  /**
   * Reads the user's token **epoch** — a per-user generation counter — defaulting to `0`.
   *
   * Access tokens are stateless JWTs: the server does not track their individual `jti`s and
   * cannot enumerate them on a bulk event such as a password reset. Instead every token is
   * stamped with the epoch current at issuance, and a token stamped below the stored epoch is
   * rejected — one write invalidates every outstanding token for that user.
   *
   * The counter replaced an `iat < cutoff` timestamp comparison, which could not separate a
   * token issued in the same second as the reset from one issued just before it, and depended
   * on the token carrying a well-formed `iat` at all.
   *
   * This is a plain read: it never creates the key, so only a user who has actually been
   * bumped carries one.
   *
   * @param userId - Internal user or admin ID to look up.
   * @param kind - Which identity plane to read. Defaults to `'dashboard'`.
   * @returns The stored epoch, or `0` when none is stored or the value is unreadable.
   */
  async getUserTokenEpoch(
    userId: string,
    kind: 'dashboard' | 'platform' = 'dashboard'
  ): Promise<number> {
    const raw = await this.get(`${kind === 'platform' ? 'pep' : 'ep'}:${userId}`)
    // `Number(null)` is 0, which is exactly the "never bumped" default, so an absent key needs
    // no branch of its own. Anything that is not a whole number — a corrupt value, a float —
    // reads as 0 too: comparing a stamped epoch against NaN is always false, which would
    // silently disable bulk revocation for that user. A negative value clamps up for the same
    // reason.
    const parsed = Number(raw)
    return Number.isInteger(parsed) ? Math.max(0, parsed) : 0
  }

  /**
   * Atomically advances the user's token epoch and returns the new value, invalidating every
   * outstanding access token for that user at once.
   *
   * The TTL is deliberately far longer than any access token lives, so a bump stays in force
   * for the whole window a pre-bump token could still be presented. Once it lapses the counter
   * restarts at zero, which is safe: by then every token stamped below it has expired anyway.
   *
   * @param userId - Internal user or admin ID whose outstanding access tokens are revoked.
   * @param kind - Which identity plane to bump. Defaults to `'dashboard'`.
   * @returns The epoch after the increment.
   */
  async bumpUserTokenEpoch(
    userId: string,
    kind: 'dashboard' | 'platform' = 'dashboard'
  ): Promise<number> {
    return this.incrWithFixedTtl(
      `${kind === 'platform' ? 'pep' : 'ep'}:${userId}`,
      EPOCH_TTL_SECONDS
    )
  }

  // ---------------------------------------------------------------------------
  // WebSocket upgrade tickets
  // ---------------------------------------------------------------------------

  /**
   * Mints a single-use WebSocket upgrade ticket holding a verified-identity snapshot.
   *
   * The browser `WebSocket` API cannot set handshake headers, which leaves a browser client
   * with no way to present an `Authorization` header at the upgrade. The alternative most
   * codebases reach for — the access token in the query string — puts a long-lived credential
   * into access logs, browser history and proxy caches. This is the other answer: an opaque,
   * ~30-second, single-use ticket that is worthless the moment it is redeemed.
   *
   * Only `sha256(ticket)` becomes a key, so a Redis dump never yields a usable ticket, and the
   * access token is never echoed into the value — the snapshot carries the identity the socket
   * is authorized as, nothing that could be replayed against the REST surface.
   *
   * @param snapshot - The verified-identity snapshot to bind to the ticket.
   * @param ttlSeconds - Lifetime of the ticket in seconds.
   * @returns The raw ticket to hand to the client — never persisted in this form.
   */
  async mintWsTicket(snapshot: WsTicketSnapshot, ttlSeconds: number): Promise<string> {
    const ticket = generateSecureToken(WS_TICKET_ENTROPY_BYTES)
    await this.set(`wst:${sha256(ticket)}`, JSON.stringify(snapshot), ttlSeconds)
    return ticket
  }

  /**
   * Redeems a WebSocket upgrade ticket, consuming it in the same round trip.
   *
   * `GETDEL` is what makes the ticket single-use: the first redemption wins, and a second
   * presentation of a captured upgrade URL finds nothing. A ticket that is unknown, expired or
   * already redeemed is indistinguishable here by design — all three return `null`.
   *
   * @param ticket - The raw ticket presented at the handshake.
   * @returns The bound snapshot, or `null` when the ticket cannot be redeemed.
   */
  async redeemWsTicket(ticket: string): Promise<WsTicketSnapshot | null> {
    const raw = await this.getdel(`wst:${sha256(ticket)}`)
    if (raw === null) return null
    try {
      const parsed: unknown = JSON.parse(raw)
      return isWsTicketSnapshot(parsed) ? parsed : null
    } catch {
      // A stored value that will not parse is a corrupted record, not a valid ticket. It has
      // already been consumed by the GETDEL above, which is the right outcome either way.
      return null
    }
  }
}

/**
 * Whether an unknown value is a well-formed {@link WsTicketSnapshot}.
 *
 * The record is read back from Redis, which the sibling implementation also writes, so it is
 * parsed defensively rather than cast: a snapshot missing `mfaVerified` would otherwise
 * authorize a socket as MFA-satisfied through an `undefined` that reads as false only by luck
 * of the comparison used downstream.
 *
 * @param value - The parsed JSON read back from the store.
 * @returns `true` when every required field is present and correctly typed.
 */
function isWsTicketSnapshot(value: unknown): value is WsTicketSnapshot {
  if (typeof value !== 'object' || value === null) return false
  const record = value as Record<string, unknown>
  return (
    typeof record['sub'] === 'string' &&
    typeof record['role'] === 'string' &&
    typeof record['status'] === 'string' &&
    typeof record['mfaEnabled'] === 'boolean' &&
    typeof record['mfaVerified'] === 'boolean' &&
    (record['tenantId'] === undefined || typeof record['tenantId'] === 'string')
  )
}
