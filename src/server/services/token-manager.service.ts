import { randomUUID } from 'node:crypto'

import { Inject, Injectable, Logger } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import type { JwtSignOptions } from '@nestjs/jwt'

import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import { generateSecureToken, sha256 } from '../crypto/secure-token'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type {
  AuthResult,
  PlatformAuthResult,
  RotatedTokenResult
} from '../interfaces/auth-result.interface'
import type {
  DashboardJwtPayload,
  MfaTempPayload,
  PlatformJwtPayload
} from '../interfaces/jwt-payload.interface'
import type { SafeAuthPlatformUser } from '../interfaces/platform-user-repository.interface'
import type { SafeAuthUser } from '../interfaces/user-repository.interface'
import { AuthRedisService } from '../redis/auth-redis.service'
import { verifyWithRotation } from '../utils/verify-with-rotation'

/** TTL in seconds for MFA temp tokens (5 minutes). */
const MFA_TEMP_TOKEN_TTL_SECONDS = 300

/**
 * Ceiling on the stored device and IP strings in a session detail record. Both are
 * attacker-controlled request headers, so they are truncated before they reach Redis. 45
 * characters is the longest possible textual IPv6 address (IPv4-mapped form).
 */
const MAX_SESSION_FIELD_LENGTH = 45

/**
 * Session record stored in Redis for each active refresh token.
 */
interface RefreshSession {
  userId: string
  /** Empty string for platform admin sessions (platform admins have no tenant). */
  tenantId: string
  role: string
  device: string
  ip: string
  createdAt: string
  /**
   * The refresh-token **family** (login lineage) this session belongs to.
   *
   * Minted at login and inherited unchanged by every rotation, so all descendants of one
   * login share it. It is the unit of reuse-detection revocation: replaying an
   * already-consumed refresh token past its grace window revokes the whole family, not the
   * user's other legitimate devices.
   *
   * Empty only on the placeholder a replayed token produces, which is never stored. Such a
   * record is never a reuse-revocation target, and the field is omitted from the wire when
   * empty so the stored bytes match what rust-auth writes.
   */
  familyId: string
  /**
   * When the **family** was born — the moment of the login this session descends from, as an
   * ISO-8601 string.
   *
   * Distinct from `createdAt`, which is this session's own creation and is reset on every
   * rotation. Carried unchanged through the lineage so the absolute-lifetime cap has something
   * to measure: without it, a client rotating every fifteen minutes renews its lifetime
   * forever and a session established once never has to be established again.
   *
   * Absent on a record written before the field existed; such a session is simply not capped.
   */
  familyCreatedAt: string
  /**
   * Whether MFA is enabled on the account at the time the session was created.
   *
   * Persisted so that `buildRotatedResult` can propagate the correct value into
   * rotated access tokens. Without this, `mfaEnabled` would be reset to `false`
   * on every rotation, silently disabling `MfaRequiredGuard` for MFA-enabled users
   * after their first token refresh.
   *
   * `mfaVerified` is intentionally NOT stored — it must always be `false` in
   * rotated tokens to force re-authentication through the MFA challenge endpoint.
   */
  mfaEnabled: boolean
}

/**
 * Manages JWT access tokens, opaque refresh tokens, and MFA temp tokens.
 *
 * @remarks
 * This service handles all token issuance and rotation logic:
 * - Access tokens: short-lived JWTs signed with HS256
 * - Refresh tokens: opaque UUID v4 stored as `rt:{sha256(token)}` in Redis
 * - Rotation: atomic Lua script prevents race conditions during token reuse
 * - MFA temp tokens: short-lived JWTs for the MFA challenge flow, consumed on use
 *
 * All Redis keys are prefixed by {@link AuthRedisService} — this service uses
 * application-level key names without the namespace prefix.
 *
 * @layer Service
 */
@Injectable()
export class TokenManagerService {
  private readonly logger = new Logger(TokenManagerService.name)

  constructor(
    private readonly jwtService: JwtService,
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions,
    private readonly redis: AuthRedisService
  ) {}

  // ---------------------------------------------------------------------------
  // Access token
  // ---------------------------------------------------------------------------

  /**
   * Issues a signed JWT access token for a dashboard user.
   *
   * @param payload - JWT claims without `jti`, `iat`, or `exp` (auto-generated).
   * @returns Signed JWT string.
   */
  issueAccess(payload: Omit<DashboardJwtPayload, 'jti' | 'iat' | 'exp'>): string {
    const jti = randomUUID()
    return this.jwtService.sign({ ...payload, jti }, this.accessSignOptions())
  }

  /**
   * Issues a signed JWT access token for a platform administrator.
   *
   * @param payload - JWT claims without `jti`, `iat`, or `exp` (auto-generated).
   * @returns Signed JWT string.
   */
  private issuePlatformAccess(payload: Omit<PlatformJwtPayload, 'jti' | 'iat' | 'exp'>): string {
    const jti = randomUUID()
    return this.jwtService.sign({ ...payload, jti }, this.accessSignOptions())
  }

  /**
   * Builds JwtSignOptions from resolved configuration.
   *
   * The double-cast through `unknown` is required because:
   * 1. `@nestjs/jwt` types `expiresIn` as the branded `StringValue` from `ms`
   *    (not a plain `string`), and
   * 2. `exactOptionalPropertyTypes` rejects `string | undefined` as the value
   *    type of an optional property typed as `StringValue`.
   * At runtime the value is always a valid `ms` string — the cast is safe.
   */
  private accessSignOptions(): JwtSignOptions {
    return {
      expiresIn: this.options.jwt.accessExpiresIn,
      algorithm: this.options.jwt.algorithm
    } as unknown as JwtSignOptions
  }

  // ---------------------------------------------------------------------------
  // Dashboard tokens
  // ---------------------------------------------------------------------------

  /**
   * Issues access + refresh tokens for a successfully authenticated dashboard user.
   *
   * Stores the refresh session in Redis under `rt:{sha256(rawRefreshToken)}` with
   * TTL = `refreshExpiresInDays × 86400` seconds.
   *
   * @param user - Safe user object (credential fields excluded).
   * @param ip - Client IP address (for session audit).
   * @param userAgent - User-Agent header value (for session description).
   * @param overrides - Optional JWT claim overrides. Use `{ mfaVerified: true }` when
   *   issuing tokens after a successful MFA challenge.
   * @returns Full auth result containing access token, raw refresh token, and user.
   */
  async issueTokens(
    user: SafeAuthUser,
    ip: string,
    userAgent: string,
    overrides?: { mfaVerified?: boolean }
  ): Promise<AuthResult> {
    // Stamp the user's current token epoch so a later bump (a password reset) invalidates this
    // token at verification, without the server having to enumerate outstanding tokens.
    const epoch = await this.redis.getUserTokenEpoch(user.id)
    const accessToken = this.issueAccess({
      sub: user.id,
      tenantId: user.tenantId,
      role: user.role,
      type: 'dashboard',
      status: user.status,
      mfaEnabled: user.mfaEnabled,
      mfaVerified: overrides?.mfaVerified ?? false,
      epoch
    })

    const rawRefreshToken = generateSecureToken()
    const tokenHash = sha256(rawRefreshToken)
    const sessionKey = `rt:${tokenHash}`
    // A fresh login opens a new refresh-token family; every rotation inherits this id, so the
    // whole lineage can be revoked together the moment one of its tokens is replayed.
    const familyId = randomUUID()
    const session = this.buildSession(
      user.id,
      user.tenantId,
      user.role,
      ip,
      userAgent,
      user.mfaEnabled,
      familyId
    )
    const ttl = this.options.jwt.refreshExpiresInDays * 86_400

    await this.redis.set(sessionKey, this.serializeSession(session), ttl)
    // Track session in the per-user SET so MFA enable/disable can invalidate all sessions atomically.
    await this.redis.sadd(`sess:${user.id}`, `rt:${tokenHash}`)
    await this.redis.expire(`sess:${user.id}`, ttl)
    // The family index holds bare hashes: it only ever tracks live `rt:` sessions, so the
    // prefix is implied. It carries the refresh TTL so it ages out with what it tracks.
    await this.redis.sadd(`fam:${familyId}`, tokenHash)
    await this.redis.expire(`fam:${familyId}`, ttl)

    return { user, accessToken, rawRefreshToken }
  }

  // ---------------------------------------------------------------------------
  // Platform tokens
  // ---------------------------------------------------------------------------

  /**
   * Issues access + refresh tokens for a successfully authenticated platform admin.
   *
   * Stores the refresh session in Redis under `prt:{sha256(rawRefreshToken)}`.
   *
   * @param admin - Safe platform admin object (credential fields excluded).
   * @param ip - Client IP address.
   * @param userAgent - User-Agent header value.
   * @param overrides - Optional JWT claim overrides. Use `{ mfaVerified: true }` when
   *   issuing tokens after a successful MFA challenge.
   * @returns Platform auth result.
   */
  async issuePlatformTokens(
    admin: SafeAuthPlatformUser,
    ip: string,
    userAgent: string,
    overrides?: { mfaVerified?: boolean }
  ): Promise<PlatformAuthResult> {
    const epoch = await this.redis.getUserTokenEpoch(admin.id, 'platform')
    const accessToken = this.issuePlatformAccess({
      sub: admin.id,
      role: admin.role,
      type: 'platform',
      mfaEnabled: admin.mfaEnabled,
      mfaVerified: overrides?.mfaVerified ?? false,
      epoch
    })

    const rawRefreshToken = generateSecureToken()
    const tokenHash = sha256(rawRefreshToken)
    const sessionKey = `prt:${tokenHash}`
    // A fresh platform login opens its own refresh-token family, indexed under `pfam:`.
    const familyId = randomUUID()
    const session = this.buildSession(
      admin.id,
      '',
      admin.role,
      ip,
      userAgent,
      admin.mfaEnabled,
      familyId
    )
    const ttl = this.options.jwt.refreshExpiresInDays * 86_400

    await this.redis.set(sessionKey, this.serializeSession(session), ttl)
    // Track the session in the platform-only index so MFA enable/disable and logout-all can
    // invalidate every platform session atomically. The platform plane has its own `psess:`
    // keyspace because the two id spaces come from different repositories and may collide:
    // sharing one index let revoking a dashboard user log out the admin with the same id.
    await this.redis.sadd(`psess:${admin.id}`, `prt:${tokenHash}`)
    await this.redis.expire(`psess:${admin.id}`, ttl)
    await this.redis.sadd(`pfam:${familyId}`, tokenHash)
    await this.redis.expire(`pfam:${familyId}`, ttl)
    await this.writePlatformSessionDetail(tokenHash, ip, userAgent, ttl)

    return { admin, accessToken, rawRefreshToken }
  }

  /**
   * Writes the per-session detail record for a platform session under `psd:{hash}`.
   *
   * The dashboard plane gets the equivalent `sd:{hash}` record from {@link SessionService},
   * but platform sessions never had one, so a session listing had nothing to describe them
   * with. The field set and the Unix-millisecond timestamps mirror the dashboard record
   * exactly, so either backend sharing this Redis reads the same shape.
   *
   * @param tokenHash - SHA-256 of the raw refresh token; the key's `{hash}` segment.
   * @param ip - Client IP, truncated before storage against oversized forwarded values.
   * @param userAgent - Raw User-Agent, stored as the device description.
   * @param ttl - Record lifetime in seconds; matches the refresh session it describes.
   */
  private async writePlatformSessionDetail(
    tokenHash: string,
    ip: string,
    userAgent: string,
    ttl: number
  ): Promise<void> {
    const now = Date.now()
    const detail = {
      device: userAgent.slice(0, MAX_SESSION_FIELD_LENGTH),
      ip: ip.slice(0, MAX_SESSION_FIELD_LENGTH),
      createdAt: now,
      lastActivityAt: now
    }
    await this.redis.set(`psd:${tokenHash}`, JSON.stringify(detail), ttl)
  }

  // ---------------------------------------------------------------------------
  // Token rotation
  // ---------------------------------------------------------------------------

  /**
   * Atomically rotates a dashboard refresh token, detecting reuse of a consumed one.
   *
   * One Lua script consumes the live session, writes the new one and the grace pointer, and
   * moves the family bookkeeping — so a crash can never leave a token consumed without its
   * successor and its reuse marker in place. The script reports which of four things the
   * presented token was:
   *
   * - **live** — the normal rotation;
   * - **inside the grace window** — a concurrent retry of a token that was just rotated away,
   *   served with a fresh session and no new grace pointer;
   * - **consumed, past its grace window** — the RFC 6819 theft signal. The whole family (every
   *   live descendant of that login) is revoked and the request is rejected. Deliberately
   *   narrower than the old "revoke every session the user has": a theft no longer logs the
   *   user's other legitimate devices out (the OWASP-recommended behaviour, and what
   *   rust-auth does);
   * - **never issued** — a plain invalid string; nothing is revoked.
   *
   * The live record is read once before the script so the new record can inherit its family
   * (the script needs the family id to plant `cf:`/`fam:`). That read is non-destructive and
   * cannot double-spend: the script re-reads and deletes the old key itself, so a concurrent
   * rotation still finds the key gone and falls to the grace path.
   *
   * @param oldRefresh - The raw refresh token being exchanged.
   * @param ip - Client IP address for session audit.
   * @param userAgent - User-Agent for session description.
   * @returns A {@link RotatedTokenResult} with new tokens and minimal session identity.
   *   **The caller is responsible for fetching the full user record from the
   *   repository if it needs to be included in the HTTP response.**
   * @throws {@link AuthException} with `REFRESH_TOKEN_INVALID` if no valid session found.
   */
  async reissueTokens(
    oldRefresh: string,
    ip: string,
    userAgent: string
  ): Promise<RotatedTokenResult> {
    const oldHash = sha256(oldRefresh)
    const newRawRefresh = generateSecureToken()
    const newHash = sha256(newRawRefresh)

    const refreshTtl = this.options.jwt.refreshExpiresInDays * 86_400
    const graceTtl = this.options.jwt.refreshGraceWindowSeconds

    const seed = await this.readSeedSession(`rt:${oldHash}`, ip, userAgent)
    this.assertWithinAbsoluteLifetime(seed)
    const newSession = this.buildSession(
      seed.userId,
      seed.tenantId,
      seed.role,
      ip,
      userAgent,
      seed.mfaEnabled,
      seed.familyId,
      seed.familyCreatedAt
    )

    const outcome = await this.redis.rotateRefreshSession({
      kind: 'dashboard',
      oldHash,
      newHash,
      newSessionJson: this.serializeSession(newSession),
      familyId: seed.familyId,
      refreshTtl,
      graceTtl
    })

    if (outcome.kind === 'rotated') {
      return this.rotateFromPrimary(
        outcome.sessionJson,
        oldHash,
        newHash,
        newSession,
        newRawRefresh,
        refreshTtl,
        graceTtl
      )
    }
    if (outcome.kind === 'grace') {
      return this.rotateFromGrace(outcome.sessionJson, ip, userAgent, refreshTtl)
    }
    if (outcome.kind === 'reused') {
      this.logger.warn(
        'reissueTokens: reuse of a consumed refresh token detected — revoking the token family'
      )
      await this.redis.revokeFamily(outcome.familyId)
      throw new AuthException(AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID)
    }
    this.logger.warn(
      'reissueTokens: no valid session or grace window found — REFRESH_TOKEN_INVALID'
    )
    throw new AuthException(AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID)
  }

  /**
   * Refuses a rotation once the login it descends from has outlived the absolute cap.
   *
   * `refreshExpiresInDays` bounds a single refresh token, not a session: a client rotating
   * every fifteen minutes renews that lifetime forever, so without this a session established
   * once never has to be established again. The cap measures from the **family's** birth, which
   * is carried unchanged through the lineage.
   *
   * A session with no birth time predates the field and is not capped — it ages out under the
   * refresh lifetime like any other. A cap of `0` disables the check entirely.
   *
   * @param session - The presented session, or the placeholder when the token is not live.
   * @throws {@link AuthException} with `REFRESH_TOKEN_INVALID` once the cap is passed. The
   *   caller cannot distinguish this from any other invalid refresh, which is deliberate: the
   *   remedy is the same (sign in again) and the difference would only tell a holder of a
   *   stolen token how old the account's session is.
   */
  private assertWithinAbsoluteLifetime(session: RefreshSession): void {
    const capDays = this.options.jwt.absoluteSessionLifetimeDays
    if (capDays <= 0) return

    // An absent birth time parses to NaN, so the finite check covers both the family-less
    // record and a malformed value with one guard. Neither is evidence the session is old, and
    // ending a session on a field that cannot be read would be a self-inflicted outage.
    const bornAt = Date.parse(session.familyCreatedAt)
    // Stryker disable next-line ConditionalExpression: equivalent — `NaN > cap` is false, so
    // dropping this guard reaches the same decision by a longer route. It states the intent.
    if (!Number.isFinite(bornAt)) return

    if (Date.now() - bornAt > capDays * 86_400_000) {
      this.logger.warn('rotation refused: the session has outlived the absolute lifetime cap')
      throw new AuthException(AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID)
    }
  }

  /**
   * Reads the presented token's live record to seed the rotated one.
   *
   * The rotation script plants the family bookkeeping in the same step that consumes the old
   * token, so it needs the family id up front — which lives in the old record. When the live
   * key is already gone the rotation can only end in grace/reuse/invalid, none of which store
   * the record being built here, so an empty placeholder is returned rather than failing early.
   *
   * @param sessionKey - The `rt:`/`prt:` key of the presented token.
   * @param ip - Client IP, carried into the placeholder so its every field is the real one.
   * @param userAgent - User-Agent, carried into the placeholder for the same reason.
   * @returns The parsed live record, or an empty-identity placeholder when the key is gone.
   */
  private async readSeedSession(
    sessionKey: string,
    ip: string,
    userAgent: string
  ): Promise<RefreshSession> {
    const json = await this.redis.get(sessionKey)
    if (json === null) {
      // Empty identity, MFA left enforcing, and no family — a placeholder must never be able
      // to plant family bookkeeping or mint a token that clears the MFA gate.
      return this.buildSession('', '', '', ip, userAgent, false, '')
    }
    return this.parseSession(json)
  }

  /**
   * Handles the primary rotation path: the presented token was live and is now consumed.
   *
   * The rotation script already wrote `rt:{new}`, the grace pointer, and the family
   * bookkeeping. What is left is the per-user session index, whose members are full key
   * suffixes: the rotated-away session is pruned, the new session added, and the grace
   * pointer indexed too so a revoke-all can delete it — without that member, a token rotated
   * away moments before "log out everywhere" would still recover a session for the whole
   * grace window.
   */
  private async rotateFromPrimary(
    oldSessionJson: string,
    oldHash: string,
    newHash: string,
    newSession: RefreshSession,
    newRawRefresh: string,
    refreshTtl: number,
    graceTtl: number
  ): Promise<RotatedTokenResult> {
    const old = this.parseSession(oldSessionJson)
    await this.redis.srem(`sess:${old.userId}`, `rt:${oldHash}`)
    await this.redis.sadd(`sess:${old.userId}`, `rt:${newHash}`)
    if (graceTtl > 0) {
      await this.redis.sadd(`sess:${old.userId}`, `rp:${oldHash}`)
    }
    await this.redis.expire(`sess:${old.userId}`, refreshTtl)
    return await this.buildRotatedResult(newSession, newRawRefresh)
  }

  /**
   * Handles the grace-window rotation path: old session gone but grace pointer found.
   *
   * Issues a new session but **does NOT** create another grace pointer. A grace
   * rotation is the terminal operation of one rotation cycle — chaining grace pointers
   * would allow an attacker who captured a refresh token to indefinitely keep a
   * session alive by consuming consecutive grace windows, each one producing a
   * fresh grace pointer.
   *
   * Concurrent legitimate retries are served by the primary `rt:` session; the
   * grace pointer exists only to cover the narrow window in which the old token
   * was already consumed but the client has not yet received the new one.
   *
   * The recovered session keeps its family, and the fresh hash joins the family index, so a
   * session born from a grace recovery stays revocable with the rest of its lineage. The
   * script has already refused the recovery if that family was revoked in the meantime.
   */
  private async rotateFromGrace(
    graceSessionJson: string,
    ip: string,
    userAgent: string,
    refreshTtl: number
  ): Promise<RotatedTokenResult> {
    const graceSession = this.parseSession(graceSessionJson)
    // The cap is measured again here, against the RECOVERED record. The check at the top of
    // `reissueTokens` ran against the seed — and on this path the seed is the placeholder
    // `readSeedSession` returns when the live key is already gone, whose `familyCreatedAt` is
    // `now`, so the cap it applied was `now - now`, i.e. none at all. Without this second
    // check, a lineage that had just passed its absolute cap could still mint a fresh access
    // token and a full-length refresh session by presenting a token inside its grace window:
    // the one path where the cap is easiest to reach is the one where it did not apply.
    this.assertWithinAbsoluteLifetime(graceSession)
    const anotherNewRefresh = generateSecureToken()
    const anotherNewHash = sha256(anotherNewRefresh)
    const anotherSession = this.buildSession(
      graceSession.userId,
      graceSession.tenantId,
      graceSession.role,
      ip,
      userAgent,
      graceSession.mfaEnabled,
      graceSession.familyId,
      graceSession.familyCreatedAt
    )
    await this.redis.set(`rt:${anotherNewHash}`, this.serializeSession(anotherSession), refreshTtl)
    // Deliberately NO `rp:{anotherNewHash}` write — see JSDoc above.
    await this.redis.sadd(`sess:${graceSession.userId}`, `rt:${anotherNewHash}`)
    await this.redis.expire(`sess:${graceSession.userId}`, refreshTtl)
    if (graceSession.familyId !== '') {
      await this.redis.sadd(`fam:${graceSession.familyId}`, anotherNewHash)
      await this.redis.expire(`fam:${graceSession.familyId}`, refreshTtl)
    }
    return await this.buildRotatedResult(anotherSession, anotherNewRefresh)
  }

  /**
   * Parses and validates a Redis session JSON string.
   *
   * Guards against malformed JSON (e.g. from a key collision with another process)
   * and against missing required fields that would produce JWTs with `undefined` claims.
   *
   * @throws {@link AuthException} with `REFRESH_TOKEN_INVALID` if the JSON is invalid
   *   or missing required `userId` / `role` fields.
   */
  private parseSession(json: string): RefreshSession {
    let parsed: unknown
    try {
      parsed = JSON.parse(json)
    } catch {
      this.logger.warn('parseSession: malformed session JSON in Redis')
      throw new AuthException(AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID)
    }
    const rec = parsed as Record<string, unknown>
    if (
      // Stryker disable next-line ConditionalExpression: the object-type clause is redundant: every reachable non-object value also fails the sibling string/sub field checks, so dropping it changes nothing
      typeof parsed !== 'object' ||
      parsed === null ||
      typeof rec['userId'] !== 'string' ||
      typeof rec['role'] !== 'string'
    ) {
      throw new AuthException(AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID)
    }
    // `mfaEnabled` is required, deliberately. Defaulting a missing value to `false` would turn
    // a truncated or corrupt record into a silent second-factor bypass: the gate refuses only a
    // token whose claims say `mfaEnabled && !mfaVerified`, so an absent field reads as "no
    // second factor here" and the rotated token clears every MFA-gated route. Refusing the
    // record costs the holder a login; defaulting it costs the account.
    if (typeof rec['mfaEnabled'] !== 'boolean') {
      throw new AuthException(AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID)
    }
    const mfaEnabled = rec['mfaEnabled']
    // The family, by contrast, is genuinely optional: the placeholder record a replay produces
    // carries none, and the contract omits the key rather than writing an empty string. Absent
    // reads as "no family", which skips the family bookkeeping — a real state, not a missing
    // one.
    const familyId = typeof rec['familyId'] === 'string' ? rec['familyId'] : ''
    // Same for the birth time: no family means no cap to measure from, and the session still
    // ages out under the refresh lifetime like any other.
    const familyCreatedAt = typeof rec['familyCreatedAt'] === 'string' ? rec['familyCreatedAt'] : ''
    return { ...(parsed as RefreshSession), mfaEnabled, familyId, familyCreatedAt }
  }

  /**
   * Serializes a session record for storage, omitting an empty `familyId`.
   *
   * rust-auth skips the field when empty (`skip_serializing_if`), so emitting `"familyId":""`
   * here would make the same session serialize to different bytes on each side and break the
   * shared-Redis contract. A record with no family simply has no key.
   *
   * @param session - The record to store.
   * @returns The JSON string written under an `rt:`/`prt:` key.
   */
  private serializeSession(session: RefreshSession): string {
    if (session.familyId !== '') return JSON.stringify(session)
    const { familyId: _omitted, familyCreatedAt: _alsoOmitted, ...rest } = session
    return JSON.stringify(rest)
  }

  /**
   * Constructs a session record from identity fields and request metadata.
   *
   * @param userId - Internal user ID for whom the session is being created.
   * @param tenantId - Tenant ID scoping the session. Empty string for platform admin sessions.
   * @param role - Role claim to persist in the session record.
   * @param ip - Client IP address for session audit metadata.
   * @param device - Human-readable device description (parsed from User-Agent).
   * @param mfaEnabled - Whether MFA is enabled on the account at session creation time.
   * @param familyId - Login lineage this session belongs to; `''` when it belongs to none.
   */
  private buildSession(
    userId: string,
    tenantId: string,
    role: string,
    ip: string,
    device: string,
    mfaEnabled: boolean,
    familyId: string,
    familyCreatedAt: string = new Date().toISOString()
  ): RefreshSession {
    return {
      userId,
      tenantId,
      role,
      device,
      ip,
      createdAt: new Date().toISOString(),
      mfaEnabled,
      familyId,
      familyCreatedAt
    }
  }

  /**
   * Issues an access token and assembles a {@link RotatedTokenResult} from a session record.
   *
   * @remarks
   * The `status` claim in the issued access token is intentionally empty during
   * rotation — the Redis session does not store full user data. Guards that enforce
   * status checks must read from the user repository or a status cache, not the
   * JWT `status` claim.
   *
   * `mfaVerified` is always `false` after rotation because the Redis session does not
   * persist MFA verification state. A user who authenticated with MFA will lose the
   * `mfaVerified: true` claim on the first token rotation. MFA guards should be aware
   * of this behaviour and direct users through the MFA challenge flow to re-acquire it.
   */
  private async buildRotatedResult(
    session: RefreshSession,
    rawRefreshToken: string
  ): Promise<RotatedTokenResult> {
    // mfaEnabled is propagated from the stored session so MfaRequiredGuard continues
    // to enforce MFA after rotation. mfaVerified is always false — the user must
    // re-complete the MFA challenge after rotation to re-acquire a verified token.
    // The epoch is re-read at rotation time, so a reset that lands mid-session is picked up
    // by the very next rotation rather than being carried over from the old token.
    const epoch = await this.redis.getUserTokenEpoch(session.userId)
    const accessToken = this.issueAccess({
      sub: session.userId,
      tenantId: session.tenantId,
      role: session.role,
      type: 'dashboard',
      status: '',
      mfaEnabled: session.mfaEnabled,
      mfaVerified: false,
      epoch
    })

    return {
      session: { userId: session.userId, tenantId: session.tenantId, role: session.role },
      accessToken,
      rawRefreshToken
    }
  }

  // ---------------------------------------------------------------------------
  // Platform token rotation
  // ---------------------------------------------------------------------------

  /**
   * Atomically rotates a platform admin refresh token.
   * Mirror of {@link reissueTokens} — uses `prt:` (platform refresh) and
   * `prp:` (platform refresh pointer / grace window) key prefixes.
   *
   * @param oldRefresh - The raw platform refresh token being exchanged.
   * @param ip - Client IP address for session audit.
   * @param userAgent - User-Agent for session description.
   * @returns A {@link RotatedTokenResult} with new tokens and minimal session identity.
   * @throws {@link AuthException} with `REFRESH_TOKEN_INVALID` if no valid session found.
   */
  async reissuePlatformTokens(
    oldRefresh: string,
    ip: string,
    userAgent: string
  ): Promise<RotatedTokenResult> {
    const oldHash = sha256(oldRefresh)
    const newRawRefresh = generateSecureToken()
    const newHash = sha256(newRawRefresh)

    const refreshTtl = this.options.jwt.refreshExpiresInDays * 86_400
    const graceTtl = this.options.jwt.refreshGraceWindowSeconds

    const seed = await this.readSeedSession(`prt:${oldHash}`, ip, userAgent)
    this.assertWithinAbsoluteLifetime(seed)
    const newSession = this.buildSession(
      seed.userId,
      '',
      seed.role,
      ip,
      userAgent,
      seed.mfaEnabled,
      seed.familyId,
      seed.familyCreatedAt
    )

    const outcome = await this.redis.rotateRefreshSession({
      kind: 'platform',
      oldHash,
      newHash,
      newSessionJson: this.serializeSession(newSession),
      familyId: seed.familyId,
      refreshTtl,
      graceTtl
    })

    if (outcome.kind === 'rotated') {
      return this.rotatePlatformFromPrimary(
        outcome.sessionJson,
        oldHash,
        newHash,
        newSession,
        ip,
        userAgent,
        newRawRefresh,
        refreshTtl,
        graceTtl
      )
    }
    if (outcome.kind === 'grace') {
      return this.rotatePlatformFromGrace(outcome.sessionJson, oldHash, ip, userAgent, refreshTtl)
    }
    if (outcome.kind === 'reused') {
      // #38 deferred platform reuse detection entirely; the family design closes that gap on
      // both planes at once.
      this.logger.warn(
        'reissuePlatformTokens: reuse of a consumed refresh token detected — revoking the token family'
      )
      await this.redis.revokeFamily(outcome.familyId, 'platform')
      throw new AuthException(AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID)
    }

    this.logger.warn(
      'reissuePlatformTokens: no valid session or grace window found — REFRESH_TOKEN_INVALID'
    )
    throw new AuthException(AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID)
  }

  /**
   * Handles the primary rotation path for platform tokens: old session found in Redis.
   *
   * Writes the new session and a grace pointer (using `oldHash` as the grace key)
   * so that concurrent requests carrying the old token can still succeed within
   * the grace window.
   */
  private async rotatePlatformFromPrimary(
    oldSessionJson: string,
    oldHash: string,
    newHash: string,
    newSession: RefreshSession,
    ip: string,
    userAgent: string,
    newRawRefresh: string,
    refreshTtl: number,
    graceTtl: number
  ): Promise<RotatedTokenResult> {
    const old = this.parseSession(oldSessionJson)

    // The rotated session is indexed under the platform-only `psess:` key — the dashboard
    // `sess:` index is a separate plane and is never touched from here.
    await this.redis.srem(`psess:${old.userId}`, `prt:${oldHash}`)
    await this.redis.sadd(`psess:${old.userId}`, `prt:${newHash}`)
    if (graceTtl > 0) {
      await this.redis.sadd(`psess:${old.userId}`, `prp:${oldHash}`)
    }
    await this.redis.expire(`psess:${old.userId}`, refreshTtl)
    // Move the detail record with the session, so a listing describes the live token rather
    // than a hash that no longer exists.
    await this.redis.del(`psd:${oldHash}`)
    await this.writePlatformSessionDetail(newHash, ip, userAgent, refreshTtl)

    return await this.buildPlatformRotatedResult(newSession, newRawRefresh)
  }

  /**
   * Handles the grace-window rotation path for platform tokens: old session gone but grace pointer found.
   *
   * Issues a new session but **does NOT** create another grace pointer. The grace
   * window is deliberately single-shot — chaining grace pointers would allow an
   * attacker who captured a platform refresh token to indefinitely keep a session
   * alive by consuming consecutive grace windows. See `rotateFromGrace` for the
   * matching dashboard-side semantics.
   */
  private async rotatePlatformFromGrace(
    graceSessionJson: string,
    oldHash: string,
    ip: string,
    userAgent: string,
    refreshTtl: number
  ): Promise<RotatedTokenResult> {
    const graceSession = this.parseSession(graceSessionJson)
    const anotherNewRefresh = generateSecureToken()
    const anotherNewHash = sha256(anotherNewRefresh)
    const anotherSession = this.buildSession(
      graceSession.userId,
      '',
      graceSession.role,
      ip,
      userAgent,
      graceSession.mfaEnabled,
      graceSession.familyId,
      graceSession.familyCreatedAt
    )

    await this.redis.set(`prt:${anotherNewHash}`, this.serializeSession(anotherSession), refreshTtl)
    // Deliberately NO `prp:{anotherNewHash}` write — see JSDoc above.
    // Remove the consumed grace pointer from the per-user SET — the key itself is still live
    // (the script leaves it for its remaining window); the SET entry is what a revoke-all uses.
    await this.redis.srem(`psess:${graceSession.userId}`, `prp:${oldHash}`)
    await this.redis.sadd(`psess:${graceSession.userId}`, `prt:${anotherNewHash}`)
    await this.redis.expire(`psess:${graceSession.userId}`, refreshTtl)
    if (graceSession.familyId !== '') {
      await this.redis.sadd(`pfam:${graceSession.familyId}`, anotherNewHash)
      await this.redis.expire(`pfam:${graceSession.familyId}`, refreshTtl)
    }
    await this.redis.del(`psd:${oldHash}`)
    await this.writePlatformSessionDetail(anotherNewHash, ip, userAgent, refreshTtl)

    return await this.buildPlatformRotatedResult(anotherSession, anotherNewRefresh)
  }

  /**
   * Issues a platform access token and assembles a {@link RotatedTokenResult} from a session record.
   *
   * @remarks
   * `mfaVerified` is always `false` after rotation — same semantics as {@link buildRotatedResult}.
   * Platform admins must re-complete the MFA challenge flow to re-acquire a verified token.
   */
  private async buildPlatformRotatedResult(
    session: RefreshSession,
    rawRefreshToken: string
  ): Promise<RotatedTokenResult> {
    // mfaVerified is always false after rotation (same semantics as buildRotatedResult).
    const epoch = await this.redis.getUserTokenEpoch(session.userId, 'platform')
    const accessToken = this.issuePlatformAccess({
      sub: session.userId,
      role: session.role,
      type: 'platform',
      mfaEnabled: session.mfaEnabled,
      mfaVerified: false,
      epoch
    })

    return {
      session: { userId: session.userId, tenantId: '', role: session.role },
      accessToken,
      rawRefreshToken
    }
  }

  // ---------------------------------------------------------------------------
  // Token decoding (no expiry check)
  // ---------------------------------------------------------------------------

  /**
   * Decodes a JWT without validating its expiration or signature.
   *
   * @internal
   * **WARNING:** This method does NOT verify the token signature or expiry.
   * It must only be used for internal diagnostic purposes (e.g. reading the
   * `sub` claim from an expired token to look up a session for revocation).
   * Never use it to authorize requests — use `JwtService.verify()` in guards.
   *
   * @param token - Raw JWT string.
   * @returns Decoded payload.
   * @throws {@link AuthException} with `TOKEN_INVALID` if the payload is not an
   *   object or lacks required `jti` (string) and `sub` (string) claims.
   */
  /**
   * Verifies an access token's signature under the pinned algorithm while **ignoring its
   * expiry**, returning the payload.
   *
   * Exactly one caller wants this: logout. An access token that expired while the user was
   * away is the normal case there, and refusing the request would leave the refresh session —
   * the long-lived credential logout exists to kill — alive for its whole lifetime. But the
   * signature still has to hold: the payload's `jti` decides which token gets blacklisted, so
   * reading it unverified would let a caller revoke an access token they do not own by naming
   * its id. Retired signing secrets are accepted, as everywhere else.
   *
   * @param token - The raw access token.
   * @returns The verified payload, expiry aside.
   * @throws Whatever the verifier throws when no configured secret accepts the token.
   */
  verifyIgnoringExpiry(token: string): DashboardJwtPayload {
    return verifyWithRotation<DashboardJwtPayload>(this.jwtService, this.options, token, {
      ignoreExpiration: true
    })
  }

  /**
   * The platform twin of {@link verifyIgnoringExpiry}, for the same single caller: logout.
   *
   * An operator who walks away for longer than the access-token lifetime and then signs out is
   * the ordinary case, and refusing them leaves the refresh session — seven days of the
   * highest-privilege identity in the system — alive on a console they believed they had left.
   *
   * @param token - The raw platform access token.
   * @returns The verified payload, expiry aside.
   * @throws Whatever the verifier throws when no configured secret accepts the token.
   */
  verifyPlatformIgnoringExpiry(token: string): PlatformJwtPayload {
    return verifyWithRotation<PlatformJwtPayload>(this.jwtService, this.options, token, {
      ignoreExpiration: true
    })
  }

  decodeToken(token: string): DashboardJwtPayload | PlatformJwtPayload | MfaTempPayload {
    const raw = this.jwtService.decode(token)

    if (
      // Stryker disable next-line ConditionalExpression: the object-type clause is redundant: every reachable non-object value also fails the sibling field checks, so dropping it changes nothing
      typeof raw !== 'object' ||
      raw === null ||
      typeof (raw as Record<string, unknown>)['jti'] !== 'string' ||
      typeof (raw as Record<string, unknown>)['sub'] !== 'string'
    ) {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    return raw as DashboardJwtPayload | PlatformJwtPayload | MfaTempPayload
  }

  // ---------------------------------------------------------------------------
  // MFA temp tokens
  // ---------------------------------------------------------------------------

  /**
   * Issues a short-lived MFA challenge token and stores it in Redis for
   * single-use enforcement.
   *
   * Stores `mfa:{sha256(jti)}` → `userId` in Redis with a 5-minute TTL.
   * The Redis key is derived from the `jti` UUID claim (not the full token) to
   * reduce information disclosure in the Redis keyspace: the `jti` alone reveals
   * only the identifier, not the structured token format.
   *
   * @param userId - The user (or admin) pending MFA completion.
   * @param context - Authentication context: `'dashboard'` or `'platform'`.
   * @returns The signed MFA temp JWT.
   */
  async issueMfaTempToken(userId: string, context: 'dashboard' | 'platform'): Promise<string> {
    const jti = randomUUID()
    const payload: Omit<MfaTempPayload, 'iat' | 'exp'> = {
      jti,
      sub: userId,
      type: 'mfa_challenge',
      context
    }

    const token = this.jwtService.sign(payload, {
      expiresIn: `${MFA_TEMP_TOKEN_TTL_SECONDS}s`,
      algorithm: this.options.jwt.algorithm
    } as unknown as JwtSignOptions)

    await this.redis.set(`mfa:${sha256(jti)}`, userId, MFA_TEMP_TOKEN_TTL_SECONDS)

    // The per-user MFA challenge counter is deliberately NOT reset here. It used to be, on
    // the reasoning that "a fresh login proves renewed possession of the password" — but
    // possession of the password is exactly the attacker's assumed capability in the threat
    // model the second factor exists to cover. Resetting on every temp-token issuance let
    // that attacker loop `login → five wrong codes → login` forever, so the per-account
    // lockout never engaged and the only remaining control was the per-IP rate limit, which
    // a distributed caller sidesteps. The counter is cleared by exactly one event: a
    // SUCCESSFUL challenge (see `MfaService.challenge`), which is the only thing that proves
    // possession of the factor being guessed.

    return token
  }

  /**
   * Verifies a MFA temp token WITHOUT consuming it.
   *
   * Validates the JWT signature and expiry, then performs a Redis `GET`
   * to confirm the entry still exists. The Redis key is NOT removed by
   * this call — the caller must invoke {@link consumeMfaTempToken} with
   * the returned `jti` after successfully validating the TOTP code.
   *
   * **Why verify and consume are split** (v1.0.8+): the previous version
   * used an atomic `GETDEL` here as a TOCTOU defence, but it had a fatal
   * UX side effect: a single mistyped TOTP digit consumed the token, so
   * the user's retry attempt always failed with `MFA_TEMP_TOKEN_INVALID`.
   * Splitting verify from consume lets the MFA service retry within the
   * token's TTL (5 minutes) while keeping the rest of the security model
   * intact:
   *   - The JWT is signed and short-lived, so it cannot be forged.
   *   - The brute-force counter (`bruteForce.recordFailure` keyed on
   *     `challenge:${userId}`) caps how many wrong codes can be tried
   *     under one token before the account is locked.
   *   - The Redis entry's TTL caps the total replay window.
   * The single TOCTOU race that GETDEL prevented (two concurrent
   * successful submissions both completing) collapses into "two valid
   * sessions for the same legitimate user" — a benign duplicate, not a
   * privilege escalation.
   *
   * @param token - The MFA temp JWT issued by {@link issueMfaTempToken}.
   * @returns The `userId`, `context`, and `jti` from the token. Pass the
   *   `jti` to {@link consumeMfaTempToken} after TOTP validation succeeds.
   * @throws {@link AuthException} with `MFA_TEMP_TOKEN_INVALID` if the
   *   Redis entry is missing (already consumed, expired, or never issued).
   * @throws {Error} When JWT signature or expiry validation fails (propagated
   *   directly from `JwtService.verify()` — not wrapped in {@link AuthException}).
   */
  async verifyMfaTempToken(
    token: string
  ): Promise<{ userId: string; context: 'dashboard' | 'platform'; jti: string }> {
    const payload = verifyWithRotation<MfaTempPayload>(this.jwtService, this.options, token)

    // GET (not GETDEL): keep the entry alive so wrong-TOTP attempts can
    // retry under the same token. consumeMfaTempToken deletes it once
    // the caller has confirmed the code is valid.
    const storedUserId = await this.redis.get(`mfa:${sha256(payload.jti)}`)

    if (storedUserId === null) {
      throw new AuthException(AUTH_ERROR_CODES.MFA_TEMP_TOKEN_INVALID)
    }

    // Defence-in-depth: cross-check the Redis-stored userId against the JWT sub claim.
    // In the current threat model this requires a forged JWT (which requires the secret),
    // but an explicit comparison makes the relationship between the two values auditable.
    if (storedUserId !== payload.sub) {
      throw new AuthException(AUTH_ERROR_CODES.MFA_TEMP_TOKEN_INVALID)
    }

    return { userId: payload.sub, context: payload.context, jti: payload.jti }
  }

  /**
   * Atomically consumes a previously-verified MFA temp token.
   *
   * Removes the Redis entry keyed by `mfa:{sha256(jti)}` so the token
   * cannot be reused. Idempotent: a second call (e.g. from a concurrent
   * request that lost a race) is a no-op. Must be called only AFTER
   * the TOTP / recovery code has been validated, otherwise wrong-code
   * retries inside the JWT TTL would surface as `MFA_TEMP_TOKEN_INVALID`
   * instead of `MFA_INVALID_CODE`.
   *
   * @param jti - The `jti` claim returned by {@link verifyMfaTempToken}.
   */
  async consumeMfaTempToken(jti: string): Promise<boolean> {
    return await this.redis.del(`mfa:${sha256(jti)}`)
  }
}
