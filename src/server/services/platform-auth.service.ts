import { Inject, Injectable, Logger } from '@nestjs/common'

import { BYMAX_AUTH_OPTIONS, BYMAX_AUTH_PLATFORM_USER_REPOSITORY } from '../bymax-auth.constants'
import { BruteForceService } from './brute-force.service'
import { PasswordService } from './password.service'
import { TokenManagerService } from './token-manager.service'
import type { ResolvedOptions } from '../config/resolved-options'
import { hmacSha256, sha256 } from '../crypto/secure-token'
import type { PlatformLoginDto } from '../dto/platform-login.dto'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type {
  MfaChallengeResult,
  PlatformAuthResult,
  RotatedTokenResult
} from '../interfaces/auth-result.interface'
import type {
  IPlatformUserRepository,
  SafeAuthPlatformUser
} from '../interfaces/platform-user-repository.interface'
import { AuthRedisService } from '../redis/auth-redis.service'
import { maskEmail } from '../utils/mask-email'

/**
 * Core authentication service for platform administrators.
 *
 * Orchestrates login, logout, token refresh, and session revocation for the
 * operator/super-admin layer. Platform admins are not tenant-scoped — they
 * authenticate against the global `IPlatformUserRepository`.
 *
 * All brute-force tracking uses an HMAC-SHA-256 identifier derived from the email
 * so that no PII appears in Redis keys and the identifier cannot be reversed via
 * dictionary lookup.
 *
 * @remarks
 * Platform refresh tokens are stored under `prt:{sha256(token)}` in Redis.
 * The `sess:{userId}` SET tracks all active session keys for a given admin,
 * enabling full-session revocation via {@link revokeAllPlatformSessions}.
 */
@Injectable()
export class PlatformAuthService {
  private readonly logger = new Logger(PlatformAuthService.name)

  constructor(
    @Inject(BYMAX_AUTH_PLATFORM_USER_REPOSITORY)
    private readonly platformUserRepo: IPlatformUserRepository,
    private readonly passwordService: PasswordService,
    private readonly tokenManager: TokenManagerService,
    private readonly bruteForce: BruteForceService,
    private readonly redis: AuthRedisService,
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions
  ) {}

  // ---------------------------------------------------------------------------
  // Login
  // ---------------------------------------------------------------------------

  /**
   * Authenticates a platform administrator with email and password.
   *
   * Returns either a full {@link PlatformAuthResult} or a {@link MfaChallengeResult}
   * when the admin has MFA enabled.
   *
   * @param dto - Login credentials (email + password).
   * @param ip - Client IP address (for session audit and brute-force tracking).
   * @param userAgent - User-Agent header value (for session description).
   * @returns Auth result or MFA challenge prompt.
   * @throws {@link AuthException} with `ACCOUNT_LOCKED` (429) when brute-force limit reached.
   * @throws {@link AuthException} with `INVALID_CREDENTIALS` on bad email/password.
   */
  async login(
    dto: PlatformLoginDto,
    ip: string,
    userAgent: string
  ): Promise<PlatformAuthResult | MfaChallengeResult> {
    // HMAC-SHA-256 of 'platform:' + email prevents PII in Redis keys and blocks
    // rainbow-table reversal. The JWT secret is the HMAC key so the identifier
    // is specific to this deployment (same email → different hash on each instance
    // with a different secret).
    const bfIdentifier = hmacSha256('platform:' + dto.email, this.options.jwt.secret)

    const locked = await this.bruteForce.isLockedOut(bfIdentifier)
    if (locked) {
      this.logger.warn(`login: account locked email=${maskEmail(dto.email)}`)
      const retryAfterSeconds = await this.bruteForce.getRemainingLockoutSeconds(bfIdentifier)
      throw new AuthException(AUTH_ERROR_CODES.ACCOUNT_LOCKED, 429, { retryAfterSeconds })
    }

    const admin = await this.platformUserRepo.findByEmail(dto.email)
    if (!admin) {
      await this.bruteForce.recordFailure(bfIdentifier)
      this.logger.warn(`login: invalid credentials email=${maskEmail(dto.email)}`)
      throw new AuthException(AUTH_ERROR_CODES.INVALID_CREDENTIALS)
    }

    const passwordMatch = await this.passwordService.compare(dto.password, admin.passwordHash)
    if (!passwordMatch) {
      await this.bruteForce.recordFailure(bfIdentifier)
      this.logger.warn(`login: invalid credentials email=${maskEmail(dto.email)}`)
      throw new AuthException(AUTH_ERROR_CODES.INVALID_CREDENTIALS)
    }

    await this.bruteForce.resetFailures(bfIdentifier)

    // MFA challenge path: issue a short-lived temp token and stop here.
    if (admin.mfaEnabled) {
      const mfaTempToken = await this.tokenManager.issueMfaTempToken(admin.id, 'platform')
      this.logger.log(`login: MFA challenge issued adminId=${admin.id}`)
      return { mfaRequired: true, mfaTempToken }
    }

    // Destructure credential fields before issuing tokens.
    const {
      passwordHash: _passwordHash,
      mfaSecret: _mfaSecret,
      mfaRecoveryCodes: _mfaRecoveryCodes,
      ...safeAdmin
    } = admin

    const result = await this.tokenManager.issuePlatformTokens(safeAdmin, ip, userAgent)
    this.logger.log(`login: success adminId=${admin.id}`)

    // Fire-and-forget: a slow or failing DB update must not block the auth response.
    void this.platformUserRepo.updateLastLogin(admin.id).catch((err: unknown) => {
      this.logger.error('updateLastLogin failed', err)
    })

    return result
  }

  // ---------------------------------------------------------------------------
  // Logout
  // ---------------------------------------------------------------------------

  /**
   * Logs out a platform administrator by revoking the access token JTI and
   * deleting the associated platform refresh session from Redis.
   *
   * @param userId - The authenticated admin's ID (from the verified JWT `sub` claim).
   * @param jti - The JWT ID claim (`jti`) from the access token (for revocation blacklist).
   * @param exp - The expiry Unix timestamp from the access token (for TTL calculation).
   * @param rawRefreshToken - The raw opaque platform refresh token.
   */
  async logout(userId: string, jti: string, exp: number, rawRefreshToken: string): Promise<void> {
    this.logger.log(`logout: adminId=${userId}`)
    const remainingTtl = Math.max(0, exp - Math.floor(Date.now() / 1000))
    if (remainingTtl > 0) {
      await this.redis.set('rv:' + jti, '1', remainingTtl)
    }

    const tokenHash = sha256(rawRefreshToken)
    // Delete the primary session key and its grace pointer (if it exists from the
    // last rotation). Both are tracked in the per-user sess: SET so both must be
    // removed from the SET to keep it accurate for future invalidateUserSessions calls.
    await this.redis.del('prt:' + tokenHash)
    await this.redis.del('prp:' + tokenHash)
    await this.redis.srem('sess:' + userId, 'prt:' + tokenHash)
    await this.redis.srem('sess:' + userId, 'prp:' + tokenHash)
  }

  // ---------------------------------------------------------------------------
  // Refresh
  // ---------------------------------------------------------------------------

  /**
   * Rotates a platform administrator's refresh token.
   *
   * Delegates to {@link TokenManagerService.reissuePlatformTokens}. Callers that
   * need the full admin record in the HTTP response must fetch it from the
   * repository using the returned `session.userId`.
   *
   * @param rawRefreshToken - The raw opaque platform refresh token from the client.
   * @param ip - Client IP address.
   * @param userAgent - User-Agent header value.
   * @returns New tokens and minimal session identity.
   * @throws {@link AuthException} with `REFRESH_TOKEN_INVALID` if the token is invalid or expired.
   */
  async refresh(
    rawRefreshToken: string,
    ip: string,
    userAgent: string
  ): Promise<RotatedTokenResult> {
    return this.tokenManager.reissuePlatformTokens(rawRefreshToken, ip, userAgent)
  }

  // ---------------------------------------------------------------------------
  // GetMe
  // ---------------------------------------------------------------------------

  /**
   * Retrieves the full safe platform admin record for the currently authenticated admin.
   *
   * @param userId - Subject claim from the verified platform JWT.
   * @returns Safe admin object (credential fields excluded).
   * @throws {@link AuthException} with `TOKEN_INVALID` if the admin no longer exists.
   */
  async getMe(userId: string): Promise<SafeAuthPlatformUser> {
    const admin = await this.platformUserRepo.findById(userId)
    if (!admin) {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    const {
      passwordHash: _passwordHash,
      mfaSecret: _mfaSecret,
      mfaRecoveryCodes: _mfaRecoveryCodes,
      ...safeAdmin
    } = admin

    return safeAdmin
  }

  // ---------------------------------------------------------------------------
  // Session revocation
  // ---------------------------------------------------------------------------

  /**
   * Revokes all active platform sessions for the given admin.
   *
   * Delegates to {@link AuthRedisService.invalidateUserSessions} which uses an atomic
   * Lua script to read the `sess:{userId}` SET, delete all session and grace-pointer
   * keys, and remove the SET itself in a single Redis round-trip. This prevents the
   * TOCTOU race that would arise from a non-atomic SMEMBERS + loop + DEL approach.
   *
   * @param userId - The platform admin's internal ID.
   */
  async revokeAllPlatformSessions(userId: string): Promise<void> {
    await this.redis.invalidateUserSessions(userId)
  }
}
