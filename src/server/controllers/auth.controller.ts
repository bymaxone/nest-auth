import {
  Inject,
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
  UseGuards,
  UsePipes,
  UseInterceptors
} from '@nestjs/common'
import { Throttle } from '@nestjs/throttler'
import type { Request, Response } from 'express'

import { AUTH_THROTTLE_CONFIGS } from '../constants/throttle-configs'
import { AuthRateLimit } from '../decorators/auth-rate-limit.decorator'
import { CurrentUser } from '../decorators/current-user.decorator'
import { Public } from '../decorators/public.decorator'
import { LoginDto } from '../dto/login.dto'
import { RegisterDto } from '../dto/register.dto'
import { ResendVerificationDto } from '../dto/resend-verification.dto'
import { VerifyEmailDto } from '../dto/verify-email.dto'
import { AuthRateLimitGuard } from '../guards/auth-rate-limit.guard'
import { JwtAuthGuard } from '../guards/jwt-auth.guard'
import { TrustedOriginGuard } from '../guards/trusted-origin.guard'
import { UserStatusGuard } from '../guards/user-status.guard'
import { NoStoreInterceptor } from '../interceptors/no-store.interceptor'
import type { AuthResult, MfaChallengeResult } from '../interfaces/auth-result.interface'
import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface'
import type { SafeAuthUser } from '../interfaces/user-repository.interface'
import { createAuthValidationPipe } from '../pipes/auth-validation.pipe'
import { AuthService } from '../services/auth.service'
import type {
  BearerAuthResponse,
  BothAuthResponse,
  CookieAuthResponse
} from '../services/token-delivery.service'
import { TokenDeliveryService } from '../services/token-delivery.service'
import { WsTicketService } from '../services/ws-ticket.service'

/**
 * Narrows `AuthResult | MfaChallengeResult` to `MfaChallengeResult` using the
 * literal `mfaRequired: true` discriminant. Extracted as a named type guard so
 * the compiler narrows the `else` branch to `AuthResult` without resorting to a
 * raw `as AuthResult` cast — `in` alone does not fully eliminate the MFA arm
 * under the union's structural overlap.
 */
function isMfaChallenge(result: AuthResult | MfaChallengeResult): result is MfaChallengeResult {
  return 'mfaRequired' in result && result.mfaRequired === true
}

// ---------------------------------------------------------------------------
// AuthController
// ---------------------------------------------------------------------------

/**
 * Core authentication controller for dashboard (tenant) users.
 *
 * Thin controller — validates input, delegates to {@link AuthService}, and
 * delivers the response via {@link TokenDeliveryService}. All business logic
 * lives in the service layer.
 *
 * Route prefix is applied by the consuming application's `RouterModule` or
 * NestJS global prefix — this controller uses no explicit path prefix.
 *
 * @layer Controller
 */
@UseInterceptors(NoStoreInterceptor)
@Controller()
@UseGuards(TrustedOriginGuard, AuthRateLimitGuard)
@UsePipes(createAuthValidationPipe())
export class AuthController {
  constructor(
    @Inject(AuthService) private readonly authService: AuthService,
    @Inject(TokenDeliveryService) private readonly tokenDelivery: TokenDeliveryService,
    @Inject(WsTicketService) private readonly wsTicketService: WsTicketService
  ) {}

  /**
   * Registers a new dashboard user and issues auth tokens.
   *
   * @param dto - Registration payload.
   * @param req - Incoming request (used for tenantId resolution and hooks).
   * @param res - Response object (passthrough — used to set cookies).
   * @returns Auth response with tokens delivered per the configured token-delivery mode.
   */
  @Public()
  @Throttle(AUTH_THROTTLE_CONFIGS.register)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.register)
  @Post('register')
  async register(
    @Body() dto: RegisterDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<CookieAuthResponse | BearerAuthResponse | BothAuthResponse> {
    const result = await this.authService.register(dto, req)
    return this.tokenDelivery.deliverAuthResponse(res, result, req)
  }

  /**
   * Authenticates a dashboard user with email and password.
   *
   * Returns either an auth response or a `MfaChallengeResult` when MFA is enabled.
   *
   * @param dto - Login credentials.
   * @param req - Incoming request.
   * @param res - Response object (passthrough — used to set cookies).
   * @returns Auth response, or a {@link MfaChallengeResult} when MFA verification is required.
   */
  @Public()
  @Throttle(AUTH_THROTTLE_CONFIGS.login)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.login)
  @HttpCode(HttpStatus.OK)
  @Post('login')
  async login(
    @Body() dto: LoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<CookieAuthResponse | BearerAuthResponse | BothAuthResponse | MfaChallengeResult> {
    const result = await this.authService.login(dto, req)

    // Discriminate MFA challenge via the literal boolean `mfaRequired` field.
    if (isMfaChallenge(result)) {
      return result
    }

    return this.tokenDelivery.deliverAuthResponse(res, result, req)
  }

  /**
   * Logs out the caller by revoking their refresh session and clearing the auth cookies.
   *
   * Deliberately **not** behind the access-token guard. The common case is a user returning
   * after the 15-minute access token expired and clicking "sign out" — under the guard that
   * request answered 401, so `logout` never ran and the refresh session stayed live for its
   * full seven days on a device the user had just told the system to sign out. The refresh
   * token is the credential that authorizes this, and the service reads the session's owner
   * from the stored record rather than from the access token's claims.
   *
   * Always 204: a caller presenting a token for an already-gone session gets their cookies
   * cleared and learns nothing about whether a session existed.
   *
   * @param req - Incoming request (used to extract tokens).
   * @param res - Response object (passthrough — used to clear cookies).
   */
  @Public()
  @Throttle(AUTH_THROTTLE_CONFIGS.logout)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.logout)
  @HttpCode(HttpStatus.NO_CONTENT)
  @Post('logout')
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response): Promise<void> {
    const accessToken = this.tokenDelivery.extractAccessToken(req) ?? ''
    const rawRefreshToken = this.tokenDelivery.extractRefreshToken(req) ?? ''
    await this.authService.logout(accessToken, rawRefreshToken)
    this.tokenDelivery.clearAuthSession(res, req)
  }

  /**
   * Rotates the refresh token and issues new auth tokens.
   *
   * Fetches the full user record from the service layer after rotation to
   * include it in the response body (required by `deliverRefreshResponse`).
   *
   * @param req - Incoming request (used to extract the refresh token and IP).
   * @param res - Response object (passthrough — used to set cookies).
   * @returns New auth response with rotated tokens.
   */
  @Public()
  @Throttle(AUTH_THROTTLE_CONFIGS.refresh)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.refresh)
  @HttpCode(HttpStatus.OK)
  @Post('refresh')
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<CookieAuthResponse | BearerAuthResponse | BothAuthResponse> {
    const rawRefreshToken = this.tokenDelivery.extractRefreshToken(req) ?? ''
    const ip = req.ip ?? ''
    const userAgent = String(req.headers['user-agent'] ?? '')

    // `refresh` re-reads the account to re-apply the status gate, and hands the record back so
    // this does not pay a second repository read to build the body.
    const rotated = await this.authService.refresh(rawRefreshToken, ip, userAgent)

    const authResult: AuthResult = {
      user: rotated.user,
      accessToken: rotated.accessToken,
      rawRefreshToken: rotated.rawRefreshToken
    }

    return this.tokenDelivery.deliverRefreshResponse(res, authResult, req)
  }

  /**
   * Returns the safe user record for the currently authenticated user.
   *
   * `JwtAuthGuard` alone, deliberately without `UserStatusGuard`: this is the one
   * dashboard read a not-yet-verified — or suspended — session must still reach, so a
   * client can fetch who it is and render the "verify your email" or "account
   * suspended" state instead of being locked out with no way to learn why. The safe
   * record exposes no privileged data and drives no action; every route that DOES act
   * (MFA management, invitations, password change, ws-ticket) composes `UserStatusGuard`
   * and so refuses an unverified or blocked account. The account's own `status` and
   * `emailVerified` fields are in the returned record for the client to branch on.
   *
   * @param user - JWT payload from the verified access token.
   */
  @UseGuards(JwtAuthGuard)
  @Get('me')
  async me(@CurrentUser() user: DashboardJwtPayload): Promise<SafeAuthUser> {
    return this.authService.getMe(user.sub)
  }

  /**
   * Mints a single-use ticket for authenticating a WebSocket upgrade.
   *
   * The browser `WebSocket` API cannot set handshake headers, so a browser client cannot send
   * `Authorization: Bearer <token>` at the upgrade. Putting the access token in the query
   * string instead writes a long-lived credential into access logs, browser history and proxy
   * caches — which is why {@link WsJwtGuard} refuses it. The ticket is the supported path: it
   * is opaque, lives ~30 seconds, and is consumed by the first redemption.
   *
   * The guard stack is the point. `UserStatusGuard` re-checks the account is in good standing:
   * a token stays valid for its whole lifetime, and an account suspended in the meantime must
   * not still be able to open a socket. The second-factor check lives in the service rather
   * than in `MfaRequiredGuard`, which is only registered when MFA is configured — a route that
   * named it would fail to resolve on a deployment without MFA, and this endpoint has to work
   * on both. The rule applied is the guard's, unchanged. rust-auth composes the identical
   * three checks.
   *
   * @param user - JWT payload from the verified access token.
   * @returns The raw ticket and its lifetime in seconds.
   */
  @UseGuards(JwtAuthGuard, UserStatusGuard)
  @Throttle(AUTH_THROTTLE_CONFIGS.wsTicket)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.wsTicket)
  @Post('ws-ticket')
  @HttpCode(HttpStatus.OK)
  async wsTicket(
    @CurrentUser() user: DashboardJwtPayload
  ): Promise<{ ticket: string; expiresIn: number }> {
    return this.wsTicketService.issue(user)
  }

  /**
   * Verifies the user's email address using a one-time password.
   *
   * @param dto - Verification payload: tenantId, email, and OTP. The user is
   *   resolved server-side from `(tenantId, email)` — no userId is accepted
   *   from the caller.
   */
  @Public()
  @Throttle(AUTH_THROTTLE_CONFIGS.verifyEmail)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.verifyEmail)
  @HttpCode(HttpStatus.NO_CONTENT)
  @Post('verify-email')
  async verifyEmail(@Body() dto: VerifyEmailDto, @Req() req: Request): Promise<void> {
    await this.authService.verifyEmail(dto.tenantId, dto.email, dto.otp, req)
  }

  /**
   * Resends an email verification OTP with an atomic cooldown.
   *
   * Always returns 204 — the response never reveals whether the email exists.
   *
   * @param dto - Payload: tenantId and email.
   */
  @Public()
  @Throttle(AUTH_THROTTLE_CONFIGS.resendVerification)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.resendVerification)
  @HttpCode(HttpStatus.NO_CONTENT)
  @Post('resend-verification')
  async resendVerification(@Body() dto: ResendVerificationDto, @Req() req: Request): Promise<void> {
    await this.authService.resendVerificationEmail(dto.tenantId, dto.email, req)
  }
}
