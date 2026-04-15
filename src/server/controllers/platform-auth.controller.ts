import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UseGuards,
  UsePipes,
  ValidationPipe
} from '@nestjs/common'
import { Throttle } from '@nestjs/throttler'
import type { Request } from 'express'

import { AUTH_THROTTLE_CONFIGS } from '../constants/throttle-configs'
import { CurrentUser } from '../decorators/current-user.decorator'
import { Public } from '../decorators/public.decorator'
import { MfaChallengeDto } from '../dto/mfa-challenge.dto'
import { PlatformLoginDto } from '../dto/platform-login.dto'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { JwtPlatformGuard } from '../guards/jwt-platform.guard'
import type {
  AuthResult,
  MfaChallengeResult,
  PlatformAuthResult
} from '../interfaces/auth-result.interface'
import type { PlatformJwtPayload } from '../interfaces/jwt-payload.interface'
import type { SafeAuthPlatformUser } from '../interfaces/platform-user-repository.interface'
import { MfaService } from '../services/mfa.service'
import { PlatformAuthService } from '../services/platform-auth.service'
import type { PlatformBearerAuthResponse } from '../services/token-delivery.service'
import { TokenDeliveryService } from '../services/token-delivery.service'

// ---------------------------------------------------------------------------
// Type guard
// ---------------------------------------------------------------------------

/**
 * Narrows an `AuthResult | PlatformAuthResult` union to `PlatformAuthResult`.
 *
 * Uses the `admin` property as the discriminant — `PlatformAuthResult` carries
 * `admin` while `AuthResult` carries `user`. Required to safely handle the return
 * type of `MfaService.challenge()` which may return either result type depending
 * on the context embedded in the MFA temp token.
 */
function isPlatformResult(result: AuthResult | PlatformAuthResult): result is PlatformAuthResult {
  return 'admin' in result
}

// ---------------------------------------------------------------------------
// PlatformAuthController
// ---------------------------------------------------------------------------

/**
 * Authentication controller for platform administrators.
 *
 * Thin controller — validates input, delegates to {@link PlatformAuthService} or
 * {@link MfaService}, and serialises the response. All business logic lives in
 * the service layer.
 *
 * Platform sessions are always bearer-mode: tokens are returned in the response body
 * rather than as cookies. Platform admin dashboards are not browser sessions and do
 * not benefit from HttpOnly cookie delivery. Token extraction uses
 * {@link TokenDeliveryService.extractPlatformRefreshToken} and
 * {@link TokenDeliveryService.extractPlatformAccessToken} which always read from the
 * bearer header and request body respectively, bypassing the module-level
 * `tokenDelivery` mode configuration.
 *
 * Route prefix (`platform`) is relative — the consuming application applies a global
 * prefix (e.g. `/auth`) via `RouterModule` or `setGlobalPrefix`, producing final
 * routes such as `/auth/platform/login`.
 *
 * @remarks
 * **Known limitation — no PlatformUserStatusGuard:**
 * There is currently no guard that re-validates the admin's status on every request.
 * If an admin account is suspended after login, the issued JWT remains valid until it
 * expires naturally. Mitigation: the hosting application should call
 * `PlatformAuthService.revokeAllPlatformSessions(userId)` when suspending an admin
 * to invalidate all active refresh sessions. Active access tokens will expire on
 * their own schedule (default 15 minutes). Note that the `DELETE /platform/sessions`
 * endpoint can be used as an out-of-band revocation path if the admin's access token
 * is still valid at the time of suspension.
 */
@Controller('platform')
@UsePipes(new ValidationPipe({ whitelist: true }))
export class PlatformAuthController {
  constructor(
    private readonly platformAuthService: PlatformAuthService,
    private readonly mfaService: MfaService,
    private readonly tokenDelivery: TokenDeliveryService
  ) {}

  // ---------------------------------------------------------------------------
  // POST /platform/login
  // ---------------------------------------------------------------------------

  /**
   * Authenticates a platform administrator with email and password.
   *
   * Returns a {@link PlatformBearerAuthResponse} on success, or a
   * {@link MfaChallengeResult} when the admin has MFA enabled. In the MFA case
   * the caller must exchange the `mfaTempToken` at `POST /platform/mfa/challenge`.
   *
   * @param dto - Login credentials (email + password).
   * @param req - Incoming request (provides IP and User-Agent for session tracking).
   */
  @Public()
  @Throttle(AUTH_THROTTLE_CONFIGS.platformLogin)
  @HttpCode(HttpStatus.OK)
  @Post('login')
  async login(
    @Body() dto: PlatformLoginDto,
    @Req() req: Request
  ): Promise<PlatformBearerAuthResponse | MfaChallengeResult> {
    const ip = req.ip ?? ''
    // Truncate User-Agent to 512 chars — the value is stored in the Redis session record
    // (device field). Unbounded storage is a minor memory amplification vector.
    const userAgent = String(req.headers['user-agent'] ?? '').slice(0, 512)
    const result = await this.platformAuthService.login(dto, ip, userAgent)

    // MFA challenge path: return the temp token for the client to exchange.
    if ('mfaRequired' in result && result.mfaRequired) {
      return result
    }

    return this.tokenDelivery.deliverPlatformAuthResponse(result as PlatformAuthResult)
  }

  // ---------------------------------------------------------------------------
  // POST /platform/mfa/challenge
  // ---------------------------------------------------------------------------

  /**
   * Completes a platform administrator MFA challenge.
   *
   * Exchanges a short-lived `mfaTempToken` (issued at login) and a TOTP code for
   * full platform auth tokens. The `context: 'platform'` in the temp token directs
   * {@link MfaService.challenge} to issue a {@link PlatformAuthResult}.
   *
   * Explicitly guards against cross-context token abuse: if a dashboard-context MFA
   * temp token is submitted here, the response will contain an `AuthResult` (not a
   * `PlatformAuthResult`). The `isPlatformResult` check detects this and throws
   * `PLATFORM_AUTH_REQUIRED` rather than silently returning a dashboard-scoped token
   * as if it were a platform auth response.
   *
   * @param dto - Contains the MFA temp token and the TOTP (or recovery) code.
   * @param req - Incoming request (provides IP and User-Agent for brute-force tracking).
   * @throws `PLATFORM_AUTH_REQUIRED` when the submitted MFA token has `context='dashboard'`.
   */
  @Public()
  @Throttle(AUTH_THROTTLE_CONFIGS.mfaChallenge)
  @HttpCode(HttpStatus.OK)
  @Post('mfa/challenge')
  async mfaChallenge(
    @Body() dto: MfaChallengeDto,
    @Req() req: Request
  ): Promise<PlatformBearerAuthResponse> {
    const ip = req.ip ?? ''
    // Truncate User-Agent to 512 chars (same reason as login).
    const userAgent = String(req.headers['user-agent'] ?? '').slice(0, 512)
    const result = await this.mfaService.challenge(dto.mfaTempToken, dto.code, ip, userAgent)

    // Guard against cross-context token abuse: reject if the temp token had context='dashboard'.
    // MfaService returns AuthResult (with 'user') for dashboard context and PlatformAuthResult
    // (with 'admin') for platform context. The isPlatformResult discriminant detects the mismatch.
    if (!isPlatformResult(result)) {
      throw new AuthException(AUTH_ERROR_CODES.PLATFORM_AUTH_REQUIRED)
    }

    return this.tokenDelivery.deliverPlatformAuthResponse(result)
  }

  // ---------------------------------------------------------------------------
  // GET /platform/me
  // ---------------------------------------------------------------------------

  /**
   * Returns the safe record for the currently authenticated platform administrator.
   *
   * @param user - JWT payload from the verified platform access token.
   */
  @UseGuards(JwtPlatformGuard)
  @Get('me')
  async me(@CurrentUser() user: PlatformJwtPayload): Promise<SafeAuthPlatformUser> {
    return this.platformAuthService.getMe(user.sub)
  }

  // ---------------------------------------------------------------------------
  // POST /platform/logout
  // ---------------------------------------------------------------------------

  /**
   * Logs out the authenticated platform administrator.
   *
   * Blacklists the access token JTI, deletes the platform refresh session, and
   * removes the session entry from the per-admin tracking SET. The access token
   * remains valid until its natural expiry (no server-side invalidation for JWTs
   * beyond the blacklist check in {@link JwtPlatformGuard}).
   *
   * Uses {@link TokenDeliveryService.extractPlatformRefreshToken} which always reads
   * `req.body.refreshToken` regardless of the module-level `tokenDelivery` setting,
   * ensuring correct behaviour when the library is configured in `'cookie'` mode for
   * dashboard users.
   *
   * @param user - JWT payload from the verified platform access token.
   * @param req - Incoming request (used to extract the raw refresh token from the body).
   */
  @UseGuards(JwtPlatformGuard)
  @HttpCode(HttpStatus.NO_CONTENT)
  @Post('logout')
  async logout(@CurrentUser() user: PlatformJwtPayload, @Req() req: Request): Promise<void> {
    // Always reads from req.body — platform sessions never use cookie delivery.
    const rawRefreshToken = this.tokenDelivery.extractPlatformRefreshToken(req) ?? ''
    await this.platformAuthService.logout(user.sub, user.jti, user.exp, rawRefreshToken)
  }

  // ---------------------------------------------------------------------------
  // POST /platform/refresh
  // ---------------------------------------------------------------------------

  /**
   * Rotates a platform administrator's refresh token and issues new auth tokens.
   *
   * Fetches the full admin record from the service layer after rotation to include
   * it in the response body. This endpoint is public because the platform refresh
   * token is the credential being validated — no access token guard is applied.
   *
   * Uses {@link TokenDeliveryService.extractPlatformRefreshToken} which always reads
   * `req.body.refreshToken` regardless of the module-level `tokenDelivery` setting.
   *
   * @param req - Incoming request (used to extract the refresh token, IP, and User-Agent).
   */
  @Public()
  @Throttle(AUTH_THROTTLE_CONFIGS.refresh)
  @HttpCode(HttpStatus.OK)
  @Post('refresh')
  async refresh(@Req() req: Request): Promise<PlatformBearerAuthResponse> {
    // Always reads from req.body — platform sessions never use cookie delivery.
    const rawRefreshToken = this.tokenDelivery.extractPlatformRefreshToken(req) ?? ''
    const ip = req.ip ?? ''
    // Truncate User-Agent to 512 chars (same reason as login).
    const userAgent = String(req.headers['user-agent'] ?? '').slice(0, 512)

    const rotated = await this.platformAuthService.refresh(rawRefreshToken, ip, userAgent)
    const admin = await this.platformAuthService.getMe(rotated.session.userId)

    return this.tokenDelivery.deliverPlatformAuthResponse({
      admin,
      accessToken: rotated.accessToken,
      rawRefreshToken: rotated.rawRefreshToken
    })
  }

  // ---------------------------------------------------------------------------
  // DELETE /platform/sessions
  // ---------------------------------------------------------------------------

  /**
   * Revokes all active platform sessions for the authenticated administrator.
   *
   * Uses an atomic Lua script to delete all refresh session keys (primary `prt:`
   * keys and grace-pointer `prp:` keys) tracked in the `sess:{userId}` Redis SET.
   *
   * @param user - JWT payload from the verified platform access token.
   *
   * @remarks
   * **Known limitation — no PlatformUserStatusGuard:**
   * Calling this endpoint is the recommended mitigation when an admin account must be
   * disabled mid-session. The hosting application should call this endpoint (or invoke
   * `PlatformAuthService.revokeAllPlatformSessions` directly) when suspending a
   * platform admin, since no guard re-validates status on every request.
   */
  @UseGuards(JwtPlatformGuard)
  @Throttle(AUTH_THROTTLE_CONFIGS.revokeAllSessions)
  @HttpCode(HttpStatus.NO_CONTENT)
  @Delete('sessions')
  async revokeSessions(@CurrentUser() user: PlatformJwtPayload): Promise<void> {
    await this.platformAuthService.revokeAllPlatformSessions(user.sub)
  }
}
