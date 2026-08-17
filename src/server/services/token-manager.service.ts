import { randomUUID } from 'node:crypto'

import { Inject, Injectable, Logger, Optional } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import type { JwtSignOptions } from '@nestjs/jwt'

import { BYMAX_AUTH_HOOKS, BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import { RECENT_AUTH_TTL_SECONDS, recentAuthKey } from '../constants/recent-auth'
import { sessionIndexKey } from '../constants/user-keys'
import { generateSecureToken, sha256 } from '../crypto/secure-token'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { IAuthHooks } from '../interfaces/auth-hooks.interface'
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
import { describeChannelStatus } from '../utils/describe-error'
import { logSafe } from '../utils/log-safe'
import { ownerFragment } from '../utils/owner-fragment'
import { createEmptyHookContext } from '../utils/sanitize-headers'
import { readStampedEpoch } from '../utils/stamped-epoch'
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
    @Inject(JwtService) private readonly jwtService: JwtService,
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions,
    @Inject(AuthRedisService) private readonly redis: AuthRedisService,
    // Optional, and the only reason this otherwise dependency-light service knows about hooks:
    // reuse detection happens here and nowhere else, and it is the strongest evidence of
    // compromise the library produces. Routing it out through an exception would lose the
    // family id, and losing it would leave a consumer with nothing to correlate against.
    @Inject(BYMAX_AUTH_HOOKS) @Optional() private readonly hooks: IAuthHooks | null
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
      algorithm: this.options.jwt.algorithm,
      ...this.issuerAudience()
    } as unknown as JwtSignOptions
  }

  /**
   * The `iss`/`aud` pair to stamp and to require, or nothing when the deployment configured
   * neither.
   *
   * Spread into both the sign and the verify options so the two can never disagree — a token
   * stamped with an issuer the verifier does not require, or required where none is stamped,
   * is a deployment that rejects its own tokens.
   *
   * Absent by default. With HS256 the verifier can also sign, so audience binding is what
   * stops a token minted for one service being replayed at another that trusts the same
   * secret; it is opt-in because enabling it on one backend of a shared deployment and not the
   * other splits them apart.
   */
  private issuerAudience(): { issuer?: string; audience?: string } {
    // The key is OMITTED rather than set to `undefined`, and that asymmetry with the verifier
    // is load-bearing: `jsonwebtoken` validates sign options by type and throws
    // `"issuer" must be a string` on an explicit `undefined`, while its verify path reads the
    // same value as "do not check". Signing is the side that cares, so this is the side that
    // guards.
    //
    // `resolveOptions` has already dropped an empty value, so the only question left here is
    // present-or-absent.
    const { issuer, audience } = this.options.jwt
    return {
      ...(issuer === undefined ? {} : { issuer }),
      ...(audience === undefined ? {} : { audience })
    }
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
    const epoch = await this.redis.getUserTokenEpoch(user.id, user.tenantId, 'dashboard')
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

    // One atomic step, not five. Loose, this left two windows: a `revoke_all` arriving between
    // the record write and the index `SADD` swept an index the new session was not in yet — so
    // it survived a revocation the user was told had happened — and a dropped connection
    // between the `SADD` and the `EXPIRE` left the index with no TTL at all, permanently.
    // rust-auth has always written this in one `MULTI/EXEC`; see `CREATE_SESSION_LUA`.
    await this.redis.writeNewSession({
      kind: 'dashboard',
      tenantId: user.tenantId,
      tokenHash,
      sessionJson: this.serializeSession(session),
      familyId,
      userId: user.id,
      refreshTtl: ttl
    })

    // Record that a REAL authentication just completed, for the flows that need to know how
    // recently rather than merely whether. Written here and nowhere else: this method is the
    // single point where a dashboard session is born — password login, OAuth callback, MFA
    // challenge completion, invitation acceptance and email verification all reach it — while
    // `reissueTokens` deliberately does not, because a refresh proves possession of a token,
    // not of a credential. That asymmetry is the whole value of the marker: an attacker holding
    // a stolen session can rotate it forever and never make this mark fresh again.
    await this.redis.set(
      recentAuthKey('dashboard', user.id, this.options.hmacKey, user.tenantId),
      '1',
      RECENT_AUTH_TTL_SECONDS
    )

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
    const epoch = await this.redis.getUserTokenEpoch(admin.id, undefined, 'platform')
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

    // Atomic for the same two reasons as the dashboard plane above. The platform plane has its
    // own `psess:` keyspace because the two id spaces come from different repositories and may
    // collide: sharing one index let revoking a dashboard user log out the admin with the
    // same id.
    await this.redis.writeNewSession({
      kind: 'platform',
      tenantId: undefined,
      tokenHash,
      sessionJson: this.serializeSession(session),
      familyId,
      userId: admin.id,
      refreshTtl: ttl
    })
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
    this.assertRotatableTenant(seed)
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
      tenantId: seed.tenantId,
      oldHash,
      newHash,
      newSessionJson: this.serializeSession(newSession),
      familyId: seed.familyId,
      userId: seed.userId,
      refreshTtl,
      graceTtl
    })

    if (outcome.kind === 'rotated') {
      return this.rotateFromPrimary(newSession, newRawRefresh)
    }
    if (outcome.kind === 'grace') {
      return this.rotateFromGrace(outcome.sessionJson, ip, userAgent, refreshTtl)
    }
    if (outcome.kind === 'reused') {
      // Named, on both lines. This is the strongest compromise signal the library produces —
      // a token that was already exchanged has been presented again — and it used to be
      // logged as bare prose, with the account it concerns reaching only a consumer who had
      // configured `onRefreshTokenReuseDetected`. The default hooks are no-ops, so on a
      // default deployment the one unambiguous theft signal was anonymous in the log and
      // nowhere else. An operator reading it could tell that something happened and not to
      // whom (ASVS 16.2.1).
      //
      // Two lines rather than one: the detection is the finding and the revocation is the
      // response to it, and a `revokeFamily` that throws must not take the finding down with
      // it. The owner is only knowable after the revocation, which reads a member record.
      this.logger.warn(
        `reissueTokens: reuse of a consumed refresh token detected — revoking the token family ` +
          `familyId=${logSafe(outcome.familyId)}`
      )
      const { ownerId } = await this.redis.revokeFamily(outcome.familyId)
      this.logger.warn(
        `reissueTokens: token family revoked after reuse detection ` +
          `${ownerFragment(ownerId)} familyId=${logSafe(outcome.familyId)}`
      )
      // The one moment the library can say "this is not a guess about risk": a token that was
      // already exchanged has been presented again, so one of its two holders is not the owner.
      // Emitted after the revocation, so a consumer that reacts by paging someone is reacting
      // to a lineage that is already dead rather than one still being torn down.
      this.emitReuseDetected(ownerId, outcome.familyId)
      throw new AuthException(AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID)
    }
    this.logger.warn(
      'reissueTokens: no valid session or grace window found — REFRESH_TOKEN_INVALID'
    )
    throw new AuthException(AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID)
  }

  /**
   * Emits {@link IAuthHooks.onRefreshTokenReuseDetected}, fire-and-forget.
   *
   * The owner is read from the stored session where it can be — a replay of a token whose live
   * key is already gone leaves nothing to read, and the hook is skipped rather than fired with
   * an empty identity that a consumer would have to guess about.
   */
  private emitReuseDetected(userId: string, familyId: string): void {
    if (!this.hooks?.onRefreshTokenReuseDetected || userId === '') return
    try {
      void Promise.resolve(
        this.hooks.onRefreshTokenReuseDetected({ userId, familyId }, createEmptyHookContext())
      ).catch((err: unknown) => {
        this.logger.error(`onRefreshTokenReuseDetected hook threw: ${describeChannelStatus(err)}`)
      })
    } catch (err: unknown) {
      this.logger.error(
        `onRefreshTokenReuseDetected hook threw synchronously: ${describeChannelStatus(err)}`
      )
    }
  }

  /**
   * Refuses to rotate a dashboard session whose record names no tenant.
   *
   * `parseSession` validates `userId`, `role` and `mfaEnabled` but not `tenantId`, so a record
   * written before the index carried one reaches here with the field absent. Rotating it would do
   * two wrong things at once: write the new session under `dashboard:9:undefined:{userId}`, an
   * index belonging to no tenant and swept by no revoke-all, and mint an access token with no
   * tenant claim — which every dashboard guard then refuses, so the caller gets a session that
   * cannot be used and cannot be revoked.
   *
   * Refusing is the same answer the migration note gives: a pre-upgrade session dies and the user
   * signs in again. That is a cost; rotating into a keyspace nobody sweeps is a hole.
   *
   * The platform plane is exempt — its subject carries no tenant segment by design.
   *
   * @param session - The seed session read from the presented token.
   * @throws {@link AuthException} with `REFRESH_TOKEN_INVALID`, indistinguishable from any other
   *   invalid refresh: the remedy is the same and the difference would only tell a token holder
   *   how old the record is.
   */
  private assertRotatableTenant(session: RefreshSession): void {
    // Only a record that NAMES a user is judged. `readSeedSession` answers a placeholder with an
    // empty identity when the live key is gone, and that placeholder is how the grace-window path
    // is reached — refusing it here would turn every grace recovery into an invalid refresh.
    if (session.userId === '') return
    if (session.tenantId === undefined || session.tenantId === '') {
      throw new AuthException(AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID)
    }
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
   * The rotation script wrote `rt:{new}`, the grace pointer, the family bookkeeping **and**
   * the per-user session index. The index moved inside the script because doing it here left
   * a window between the consume and the SADD in which "log out everywhere" could sweep the
   * index without seeing the session this rotation had just minted — leaving it alive, and
   * rotating, after a revocation the user was told had happened.
   *
   * What is left here is issuing the token pair.
   */
  private async rotateFromPrimary(
    newSession: RefreshSession,
    newRawRefresh: string
  ): Promise<RotatedTokenResult> {
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
    // Re-checked here for the same reason, and it is the same one word of argument: the seed the
    // top-level check saw was the placeholder, whose tenant is empty by construction. The record
    // that actually mints the next session is this one.
    this.assertRotatableTenant(graceSession)
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
    // One atomic step, not four. Written loose, these landed several awaits after the script
    // returned, and a `revoke_all` arriving in that gap swept an index the recovered session
    // was not in yet — so it survived a revocation the user was told had happened, and its
    // access token, signed afterwards, carried the post-bump epoch and verified. See
    // `RECOVER_GRACE_LUA`.
    //
    // Deliberately NO `rp:{anotherNewHash}` write — see JSDoc above.
    const written = await this.redis.writeRecoveredSession({
      kind: 'dashboard',
      tenantId: graceSession.tenantId,
      newHash: anotherNewHash,
      newSessionJson: this.serializeSession(anotherSession),
      familyId: graceSession.familyId,
      userId: graceSession.userId,
      refreshTtl
    })
    if (!written) {
      // The account was swept while this recovery was in flight. The grace pointer is already
      // consumed, so there is nothing left to retry against — which is the right end state:
      // the revocation the sweep performed is what the caller must now obey.
      throw new AuthException(AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID)
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
   * JWT `status` claim. `rust-auth` stamps the same empty string at the same point, with a
   * test pinning it, so this is a shared contract rather than a local shortcut.
   *
   * **What that means for a consumer, which is where the cost lands.** `issueTokens` stamps the
   * account's value at that moment, this path stamps nothing, and `AuthService.refresh` re-stamps
   * it from the account when `role`, `tenantId` or `mfaEnabled` changed — so a session's tokens
   * carry a populated claim, then an empty one, then possibly a populated one again, with no
   * signal a client can read. A derived backend reading `request.user.status` is wrong in both
   * directions: `!== 'active'` refuses everyone whose session refreshed ordinarily, and
   * `=== 'suspended'` refuses nobody, ever.
   *
   * Backfilling it here would be worse than leaving it empty: the claim would become *usually*
   * true, which is the failure mode that survives testing, since status can still change under an
   * unexpired token. The claim cannot be authoritative, so it is not made to look like it — and
   * the empty string is the one state that cannot be mistaken for an answer.
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
    const epoch = await this.redis.getUserTokenEpoch(session.userId, session.tenantId, 'dashboard')
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
      tenantId: undefined,
      oldHash,
      newHash,
      newSessionJson: this.serializeSession(newSession),
      familyId: seed.familyId,
      userId: seed.userId,
      refreshTtl,
      graceTtl
    })

    if (outcome.kind === 'rotated') {
      return this.rotatePlatformFromPrimary(
        oldHash,
        newHash,
        newSession,
        ip,
        userAgent,
        newRawRefresh,
        refreshTtl
      )
    }
    if (outcome.kind === 'grace') {
      return this.rotatePlatformFromGrace(outcome.sessionJson, oldHash, ip, userAgent, refreshTtl)
    }
    if (outcome.kind === 'reused') {
      // #38 deferred platform reuse detection entirely; the family design closes that gap on
      // both planes at once.
      this.logger.warn(
        `reissuePlatformTokens: reuse of a consumed refresh token detected — revoking the ` +
          `token family familyId=${logSafe(outcome.familyId)}`
      )
      const { ownerId } = await this.redis.revokeFamily(outcome.familyId, 'platform')
      // Named for the same reason as the dashboard plane, and more so: this is the
      // highest-privilege identity in the system.
      this.logger.warn(
        `reissuePlatformTokens: token family revoked after reuse detection ` +
          `${ownerFragment(ownerId)} familyId=${logSafe(outcome.familyId)}`
      )
      // Both planes report reuse: an operator watching for account takeover cares about a
      // replayed platform token at least as much as a dashboard one.
      this.emitReuseDetected(ownerId, outcome.familyId)
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
    oldHash: string,
    newHash: string,
    newSession: RefreshSession,
    ip: string,
    userAgent: string,
    newRawRefresh: string,
    refreshTtl: number
  ): Promise<RotatedTokenResult> {
    // The `psess:` index moved inside the rotation script, on this plane as on the other:
    // maintaining it out here left a window in which a concurrent revoke-all could sweep past
    // the session the rotation was minting. What remains is the per-session DETAIL, which the
    // revocation never reaches through — a stale `psd:` costs a row in a session listing, not
    // a session that should have died.
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
    // The same re-check the dashboard twin makes, for the same reason: the pre-script check
    // ran against the seed, and on this path the seed is the placeholder `readSeedSession`
    // returns when the live key is already gone — its `familyCreatedAt` is `now`, so the cap
    // compared `now - now` and applied nothing. Without this, a platform lineage that had just
    // passed its absolute cap could still mint a fresh access token and a full-length refresh
    // session through its grace window. Adding the check to only one plane left the other with
    // the identical hole, on the higher-privilege identity.
    this.assertWithinAbsoluteLifetime(graceSession)
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

    // The platform twin of the dashboard grace write, atomic for the same reason.
    // Deliberately NO `prp:{anotherNewHash}` write — see JSDoc above.
    const written = await this.redis.writeRecoveredSession({
      kind: 'platform',
      tenantId: undefined,
      newHash: anotherNewHash,
      newSessionJson: this.serializeSession(anotherSession),
      familyId: graceSession.familyId,
      userId: graceSession.userId,
      refreshTtl
    })
    if (!written) {
      throw new AuthException(AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID)
    }
    // Remove the consumed grace pointer from the per-user SET — the key itself is still live
    // (the script leaves it for its remaining window); the SET entry is what a revoke-all uses.
    await this.redis.srem(
      sessionIndexKey('platform', graceSession.userId, this.options.hmacKey, undefined),
      `prp:${oldHash}`
    )
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
    const epoch = await this.redis.getUserTokenEpoch(session.userId, undefined, 'platform')
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

  /**
   * Re-signs a rotated platform access token with the authority the administrator holds *now*.
   *
   * The platform twin of the re-stamp the dashboard plane performs inline after its own
   * account re-read. Platform rotation builds its claims from the `prt:` record written at
   * login, so the role and MFA flag it carries are the ones the admin had then, inherited
   * unchanged through every later rotation. Demoting a `super_admin` to `support` therefore had
   * no effect on a live console session: it kept minting tokens carrying the old authority for
   * the refresh token's whole lifetime, and every role check reads that claim — on the
   * highest-privilege identity in the system. The dashboard plane closed this; the platform
   * plane was left with the identical hole.
   *
   * Everything the rotated token already established is kept, including `mfaVerified`: a second
   * factor already cleared on this session must not be silently demanded again. A fresh `jti`,
   * window and epoch are issued — the token this replaces was never handed out.
   *
   * @param claims - The claims of the token rotation just produced.
   * @param role - The administrator's current role.
   * @param mfaEnabled - Whether the administrator currently has a second factor.
   * @returns The re-signed platform access token.
   */
  async reissuePlatformAccessWithAuthority(
    claims: PlatformJwtPayload,
    role: string,
    mfaEnabled: boolean
  ): Promise<string> {
    return this.issuePlatformAccess({
      sub: claims.sub,
      role,
      type: 'platform',
      mfaEnabled,
      mfaVerified: claims.mfaVerified,
      epoch: await this.redis.getUserTokenEpoch(claims.sub, undefined, 'platform')
    })
  }

  // ---------------------------------------------------------------------------
  // Verification that ignores expiry (logout only)
  // ---------------------------------------------------------------------------

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
   * @param tenantId - The tenant the account belongs to, on the dashboard plane only. Stamped
   *   into the token so the challenge resolves the account tenant-scoped rather than by `sub`
   *   alone. Omitted on the platform plane, which has no tenant.
   * @returns The signed MFA temp JWT.
   */
  async issueMfaTempToken(
    userId: string,
    context: 'dashboard' | 'platform',
    tenantId?: string
  ): Promise<string> {
    const jti = randomUUID()
    const payload: Omit<MfaTempPayload, 'iat' | 'exp'> = {
      jti,
      sub: userId,
      type: 'mfa_challenge',
      context,
      // Present only on the dashboard plane; a platform token carries no tenant claim, exactly
      // as the platform arm of every other MFA key stays tenant-free.
      ...(tenantId !== undefined ? { tenantId } : {}),
      // Stamped so the challenge token dies with the rest of the account's credentials. See
      // the claim's own documentation for what it was surviving.
      epoch: await this.redis.getUserTokenEpoch(userId, tenantId, context)
    }

    const token = this.jwtService.sign(payload, {
      expiresIn: `${MFA_TEMP_TOKEN_TTL_SECONDS}s`,
      algorithm: this.options.jwt.algorithm,
      // The challenge token is stamped and checked like every other: it grants no resource
      // access on its own, but it is still a token this backend minted, and a verifier that
      // exempted one shape would be a verifier an attacker aims at.
      ...this.issuerAudience()
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
   * @throws {@link AuthException} with `MFA_TEMP_TOKEN_INVALID` for every way the token can be
   *   unusable — a bad signature, an expired one, a shape no secret accepts, or a missing Redis
   *   entry (already consumed, expired, or never issued).
   */
  async verifyMfaTempToken(token: string): Promise<{
    userId: string
    context: 'dashboard' | 'platform'
    jti: string
    tenantId?: string
  }> {
    // The verifier's own error is wrapped rather than propagated. It used to travel out of here
    // unchanged, and since nothing above catches it, a malformed `mfaTempToken` — from the body
    // or from the `mfa_temp_token` cookie an OAuth callback plants — answered **500
    // `auth.internal`** instead of 401. Three consequences, none of them visible from a unit
    // test that only ever passed this a token it had just minted:
    //
    //   - an attacker-controlled input produced a 5xx, which is free noise in an operator's
    //     error budget and hides the 500s that mean something;
    //   - `MfaController` clears the temp cookie only for an `AuthException` it recognises, so
    //     a browser holding a malformed cookie was never told to drop it and retried the same
    //     dead value on every attempt;
    //   - rust-auth maps the same failure to `MfaTempTokenInvalid`
    //     (`token_manager.rs`, `verify_rotating(...).map_err(|_| AuthError::MfaTempTokenInvalid)`),
    //     so the two backends answered one request differently.
    //
    // Every other failure below already answers `MFA_TEMP_TOKEN_INVALID`; this makes the
    // verification failure say the same thing, which is also all a caller may be told.
    let payload: MfaTempPayload
    try {
      payload = verifyWithRotation<MfaTempPayload>(this.jwtService, this.options, token)
    } catch {
      throw new AuthException(AUTH_ERROR_CODES.MFA_TEMP_TOKEN_INVALID)
    }

    // Plane/tenant binding is mandatory and mutually exclusive: a dashboard challenge MUST carry
    // the tenant it was issued for; a platform challenge MUST NOT. A missing or misplaced claim is
    // an invalid token, never a fallback to the tenant-blind lookup — that lookup is exactly the
    // path an attacker would reach by dropping the field, so it is refused rather than degraded to.
    // (RFC 8725 §3.9/§3.12; ASVS 6.6.2 — the out-of-band token must be bound to its originating
    // request.) A token minted before the claim existed is refused, and the user redoes login.
    // Blank counts as missing. `''` passes `!== undefined` and then names `dashboard:0::{userId}`,
    // an epoch nobody has ever bumped — so the revocation gate below would read 0 and accept a
    // challenge that a password or MFA reset had revoked. That is the tenant-blind lookup this
    // comment refuses, reached through the one shape the check did not cover.
    if (
      (payload.context === 'dashboard' && (payload.tenantId ?? '') === '') ||
      (payload.context === 'platform' && payload.tenantId !== undefined)
    ) {
      throw new AuthException(AUTH_ERROR_CODES.MFA_TEMP_TOKEN_INVALID)
    }

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

    // The same bulk-revocation gate the access-token guards apply, on the plane the challenge
    // was issued for. A password reset bumps the epoch and kills every access token, but
    // nothing deleted an outstanding `mfa:` record — so a challenge token minted before the
    // reset stayed redeemable for its whole TTL, and completing it handed back a full session
    // under the new epoch. The reset is supposed to end everything the old credential could
    // still reach, and this was the one credential it did not reach.
    //
    // The check lives here rather than in `MfaService.challenge` so every caller of the temp
    // token inherits it.
    if (
      readStampedEpoch(payload) <
      (await this.redis.getUserTokenEpoch(payload.sub, payload.tenantId, payload.context))
    ) {
      throw new AuthException(AUTH_ERROR_CODES.MFA_TEMP_TOKEN_INVALID)
    }

    return {
      userId: payload.sub,
      context: payload.context,
      jti: payload.jti,
      // Absent on a platform token and on a dashboard token minted before this claim existed;
      // the challenge falls back to the pre-tenant lookup in that case.
      ...(payload.tenantId !== undefined ? { tenantId: payload.tenantId } : {})
    }
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
