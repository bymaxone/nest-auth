import { randomUUID } from 'node:crypto'

import { Inject, Injectable } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import type { JwtSignOptions } from '@nestjs/jwt'

import { BYMAX_AUTH_OPTIONS } from '../bymax-one-nest-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import { sha256 } from '../crypto/secure-token'
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

/** TTL in seconds for MFA temp tokens (5 minutes). */
const MFA_TEMP_TOKEN_TTL_SECONDS = 300

/**
 * Lua script for atomic refresh-token rotation.
 *
 * Atomically reads the old session and deletes the old key.
 * The new session and grace-window pointer are written by TypeScript AFTER
 * parsing the real user data from the returned old session JSON. This prevents
 * a window where the new session key holds a hollow placeholder record.
 *
 * KEYS[1] = old session key (`rt:{sha256(oldRefresh)}` — namespaced by AuthRedisService)
 *
 * Returns the old session JSON string, or nil if the old key does not exist.
 * The old key is deleted atomically, preventing double-use of the old token.
 */
const ROTATE_LUA = `
local old_session = redis.call('GET', KEYS[1])
if not old_session then
  return nil
end
redis.call('DEL', KEYS[1])
return old_session
`

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
 * - MFA temp tokens: short-lived JWTs for the MFA challenge step, consumed on use
 *
 * All Redis keys are prefixed by {@link AuthRedisService} — this service uses
 * application-level key names without the namespace prefix.
 */
@Injectable()
export class TokenManagerService {
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
    const accessToken = this.issueAccess({
      sub: user.id,
      tenantId: user.tenantId,
      role: user.role,
      type: 'dashboard',
      status: user.status,
      mfaEnabled: user.mfaEnabled,
      mfaVerified: overrides?.mfaVerified ?? false
    })

    const rawRefreshToken = randomUUID()
    const tokenHash = sha256(rawRefreshToken)
    const sessionKey = `rt:${tokenHash}`
    const session = this.buildSession(
      user.id,
      user.tenantId,
      user.role,
      ip,
      userAgent,
      user.mfaEnabled
    )
    const ttl = this.options.jwt.refreshExpiresInDays * 86_400

    await this.redis.set(sessionKey, JSON.stringify(session), ttl)
    // Track session in the per-user SET so MFA enable/disable can invalidate all sessions atomically.
    await this.redis.sadd(`sess:${user.id}`, `rt:${tokenHash}`)
    await this.redis.expire(`sess:${user.id}`, ttl)

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
    const accessToken = this.issuePlatformAccess({
      sub: admin.id,
      role: admin.role,
      type: 'platform',
      mfaEnabled: admin.mfaEnabled,
      mfaVerified: overrides?.mfaVerified ?? false
    })

    const rawRefreshToken = randomUUID()
    const tokenHash = sha256(rawRefreshToken)
    const sessionKey = `prt:${tokenHash}`
    const session = this.buildSession(admin.id, '', admin.role, ip, userAgent, admin.mfaEnabled)
    const ttl = this.options.jwt.refreshExpiresInDays * 86_400

    await this.redis.set(sessionKey, JSON.stringify(session), ttl)
    // Track session in the per-user SET so MFA enable/disable can invalidate all sessions atomically.
    await this.redis.sadd(`sess:${admin.id}`, `prt:${tokenHash}`)
    await this.redis.expire(`sess:${admin.id}`, ttl)

    return { admin, accessToken, rawRefreshToken }
  }

  // ---------------------------------------------------------------------------
  // Token rotation
  // ---------------------------------------------------------------------------

  /**
   * Atomically rotates a dashboard refresh token.
   *
   * Uses a Lua script to atomically read and delete the old session key, returning
   * the old session JSON. TypeScript then writes the new session and grace pointer
   * with the real user data — no hollow placeholder is ever stored in Redis.
   *
   * If the old session is not found, atomically checks and consumes the grace-window
   * pointer (`rp:{sha256(old)}`). The grace pointer is deleted on first use
   * (GETDEL) to prevent unlimited reuse of an already-rotated token. After
   * consuming the grace pointer, a new grace pointer is written for the newly
   * issued token to maintain symmetric rotation behavior.
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
    const newRawRefresh = randomUUID()
    const newHash = sha256(newRawRefresh)

    const refreshTtl = this.options.jwt.refreshExpiresInDays * 86_400
    const graceTtl = this.options.jwt.refreshGraceWindowSeconds

    const oldSessionKey = `rt:${oldHash}`
    const newSessionKey = `rt:${newHash}`
    const graceKey = `rp:${oldHash}`

    // Atomically read old session and delete it. No data is written to Redis here —
    // the new session is written AFTER we parse the real user data from the old session.
    const oldSessionJson = (await this.redis.eval(ROTATE_LUA, [oldSessionKey], [])) as string | null

    if (oldSessionJson !== null) {
      return this.rotateFromPrimary(
        oldSessionJson,
        oldHash,
        ip,
        userAgent,
        newRawRefresh,
        newSessionKey,
        graceKey,
        refreshTtl,
        graceTtl
      )
    }

    // Grace window: atomically consume the pointer (GETDEL prevents unlimited reuse).
    const graceSessionJson = await this.redis.getdel(graceKey)
    if (graceSessionJson !== null) {
      return this.rotateFromGrace(graceSessionJson, ip, userAgent, refreshTtl, graceTtl)
    }

    throw new AuthException(AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID)
  }

  /**
   * Handles the primary rotation path: old session found in Redis.
   *
   * Writes the new session and a grace pointer (using `oldHash` as the grace key)
   * so that concurrent requests carrying the old token can still succeed within
   * the grace window.
   */
  private async rotateFromPrimary(
    oldSessionJson: string,
    oldHash: string,
    ip: string,
    userAgent: string,
    newRawRefresh: string,
    newSessionKey: string,
    graceKey: string,
    refreshTtl: number,
    graceTtl: number
  ): Promise<RotatedTokenResult> {
    const old = this.parseSession(oldSessionJson)
    const newHash = sha256(newRawRefresh)
    const newSession = this.buildSession(
      old.userId,
      old.tenantId,
      old.role,
      ip,
      userAgent,
      old.mfaEnabled
    )
    await this.redis.set(newSessionKey, JSON.stringify(newSession), refreshTtl)
    await this.redis.set(graceKey, JSON.stringify(newSession), graceTtl)
    // Update the per-user session SET: remove the rotated-away session, add the new session
    // AND the grace pointer so that invalidateUserSessions can delete both on logout/MFA change.
    await this.redis.srem(`sess:${old.userId}`, `rt:${oldHash}`)
    await this.redis.sadd(`sess:${old.userId}`, `rt:${newHash}`)
    await this.redis.sadd(`sess:${old.userId}`, graceKey)
    await this.redis.expire(`sess:${old.userId}`, refreshTtl)
    return this.buildRotatedResult(newSession, newRawRefresh)
  }

  /**
   * Handles the grace-window rotation path: old session gone but grace pointer found.
   *
   * Issues a new token pair and writes both a new session key and a new grace pointer
   * for the newly issued token, mirroring the symmetry of the primary rotation path.
   */
  private async rotateFromGrace(
    graceSessionJson: string,
    ip: string,
    userAgent: string,
    refreshTtl: number,
    graceTtl: number
  ): Promise<RotatedTokenResult> {
    const graceSession = this.parseSession(graceSessionJson)
    const anotherNewRefresh = randomUUID()
    const anotherNewHash = sha256(anotherNewRefresh)
    const anotherSession = this.buildSession(
      graceSession.userId,
      graceSession.tenantId,
      graceSession.role,
      ip,
      userAgent,
      graceSession.mfaEnabled
    )
    await this.redis.set(`rt:${anotherNewHash}`, JSON.stringify(anotherSession), refreshTtl)
    await this.redis.set(`rp:${anotherNewHash}`, JSON.stringify(anotherSession), graceTtl)
    // Add new session AND its grace pointer to the per-user SET so that
    // invalidateUserSessions deletes both keys on logout or MFA state change.
    await this.redis.sadd(`sess:${graceSession.userId}`, `rt:${anotherNewHash}`)
    await this.redis.sadd(`sess:${graceSession.userId}`, `rp:${anotherNewHash}`)
    await this.redis.expire(`sess:${graceSession.userId}`, refreshTtl)
    return this.buildRotatedResult(anotherSession, anotherNewRefresh)
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
      throw new AuthException(AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID)
    }
    const rec = parsed as Record<string, unknown>
    if (
      typeof parsed !== 'object' ||
      parsed === null ||
      typeof rec['userId'] !== 'string' ||
      typeof rec['role'] !== 'string'
    ) {
      throw new AuthException(AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID)
    }
    // Older sessions written before `mfaEnabled` was added to RefreshSession will
    // have an absent key. Default to false so rotation is safe for legacy sessions.
    if (typeof rec['mfaEnabled'] !== 'boolean') {
      rec['mfaEnabled'] = false
    }
    return parsed as RefreshSession
  }

  /** Constructs a session record from identity fields and request metadata. */
  private buildSession(
    userId: string,
    tenantId: string,
    role: string,
    ip: string,
    device: string,
    mfaEnabled: boolean
  ): RefreshSession {
    return { userId, tenantId, role, device, ip, createdAt: new Date().toISOString(), mfaEnabled }
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
  private buildRotatedResult(session: RefreshSession, rawRefreshToken: string): RotatedTokenResult {
    // mfaEnabled is propagated from the stored session so MfaRequiredGuard continues
    // to enforce MFA after rotation. mfaVerified is always false — the user must
    // re-complete the MFA challenge after rotation to re-acquire a verified token.
    const accessToken = this.issueAccess({
      sub: session.userId,
      tenantId: session.tenantId,
      role: session.role,
      type: 'dashboard',
      status: '',
      mfaEnabled: session.mfaEnabled,
      mfaVerified: false
    })

    return {
      session: { userId: session.userId, tenantId: session.tenantId, role: session.role },
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
  decodeToken(token: string): DashboardJwtPayload | PlatformJwtPayload | MfaTempPayload {
    const raw = this.jwtService.decode(token)

    if (
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

    return token
  }

  /**
   * Verifies a MFA temp token and atomically consumes it (single-use).
   *
   * Validates the JWT signature and expiry, then atomically gets and deletes the
   * Redis entry keyed by `mfa:{sha256(jti)}`. The atomic GETDEL prevents a
   * time-of-check/time-of-use race where two concurrent requests with the same
   * token could both pass the existence check before either deletes the key.
   *
   * @param token - The MFA temp JWT issued by {@link issueMfaTempToken}.
   * @returns The `userId` and `context` extracted from the token.
   * @throws {@link AuthException} with `MFA_TEMP_TOKEN_INVALID` if the token is
   *   missing from Redis (already consumed, expired, or revoked).
   * @throws If the JWT signature or expiry is invalid (propagated from JwtService).
   */
  async verifyMfaTempToken(
    token: string
  ): Promise<{ userId: string; context: 'dashboard' | 'platform' }> {
    const payload = this.jwtService.verify<MfaTempPayload>(token, {
      algorithms: [this.options.jwt.algorithm]
    })

    // Atomic GET+DEL prevents TOCTOU: two concurrent requests cannot both consume the token.
    const storedUserId = await this.redis.getdel(`mfa:${sha256(payload.jti)}`)

    if (storedUserId === null) {
      throw new AuthException(AUTH_ERROR_CODES.MFA_TEMP_TOKEN_INVALID)
    }

    // Defence-in-depth: cross-check the Redis-stored userId against the JWT sub claim.
    // In the current threat model this requires a forged JWT (which requires the secret),
    // but an explicit comparison makes the relationship between the two values auditable.
    if (storedUserId !== payload.sub) {
      throw new AuthException(AUTH_ERROR_CODES.MFA_TEMP_TOKEN_INVALID)
    }

    return { userId: payload.sub, context: payload.context }
  }
}
