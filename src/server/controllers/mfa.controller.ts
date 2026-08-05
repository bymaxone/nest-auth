import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Inject,
  Post,
  Req,
  Res,
  UseGuards,
  UsePipes,
  UseInterceptors
} from '@nestjs/common'
import { Throttle } from '@nestjs/throttler'
import type { Request, Response } from 'express'

import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import { MFA_TEMP_COOKIE_NAME } from '../constants/mfa-temp-cookie'
import { AUTH_THROTTLE_CONFIGS } from '../constants/throttle-configs'
import { AuthRateLimit } from '../decorators/auth-rate-limit.decorator'
import { CurrentUser } from '../decorators/current-user.decorator'
import { Public } from '../decorators/public.decorator'
import { SkipMfa } from '../decorators/skip-mfa.decorator'
import { MfaChallengeDto } from '../dto/mfa-challenge.dto'
import { MfaDisableDto } from '../dto/mfa-disable.dto'
import { MfaRegenerateRecoveryCodesDto } from '../dto/mfa-regenerate-recovery-codes.dto'
import { MfaSetupDto } from '../dto/mfa-setup.dto'
import { MfaVerifyDto } from '../dto/mfa-verify.dto'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRateLimitGuard } from '../guards/auth-rate-limit.guard'
import { JwtAuthGuard } from '../guards/jwt-auth.guard'
import { TrustedOriginGuard } from '../guards/trusted-origin.guard'
import { NoStoreInterceptor } from '../interceptors/no-store.interceptor'
import type { AuthResult, PlatformAuthResult } from '../interfaces/auth-result.interface'
import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface'
import { createAuthValidationPipe } from '../pipes/auth-validation.pipe'
import type { MfaSetupResult } from '../services/mfa.service'
import { MfaService } from '../services/mfa.service'
import type {
  BearerAuthResponse,
  BothAuthResponse,
  CookieAuthResponse,
  PlatformBearerAuthResponse
} from '../services/token-delivery.service'
import { TokenDeliveryService } from '../services/token-delivery.service'

// ---------------------------------------------------------------------------
// Type guard
// ---------------------------------------------------------------------------

/**
 * Narrows an `AuthResult | PlatformAuthResult` union to `PlatformAuthResult`.
 *
 * Uses the `admin` property as the discriminant — `PlatformAuthResult` carries
 * `admin` while `AuthResult` carries `user`.
 */
function isPlatformResult(result: AuthResult | PlatformAuthResult): result is PlatformAuthResult {
  return 'admin' in result
}

/**
 * Reads the `mfa_temp_token` value from a request's parsed cookie jar.
 *
 * Returns `undefined` when the cookie is absent or carries a non-string value
 * (defence-in-depth against custom cookie parsers).
 *
 * @remarks
 * Uses destructuring with the literal cookie name rather than the
 * `MFA_TEMP_COOKIE_NAME` constant in a computed-property access to keep the
 * `security/detect-object-injection` lint rule satisfied without a
 * suppression. The literal MUST stay in sync with `MFA_TEMP_COOKIE_NAME`
 * — `mfa.controller.spec.ts` pins the equality so a future rename
 * surfaces as a test failure rather than as a silent cookie miss.
 */
function readMfaTempCookie(req: Request): string | undefined {
  const cookies = req.cookies as { mfa_temp_token?: unknown } | undefined
  if (cookies === undefined) return undefined
  const { mfa_temp_token: value } = cookies
  return typeof value === 'string' && value.length > 0 ? value : undefined
}

/**
 * True when the thrown error indicates the MFA temp token is no longer
 * usable (`MFA_TEMP_TOKEN_INVALID`) — i.e., a retry under the same
 * cookie can never succeed.
 *
 * Used by the challenge controller to decide whether to clear the
 * `mfa_temp_token` cookie on failure. `MFA_INVALID_CODE`, `ACCOUNT_LOCKED`,
 * and other failures leave the cookie in place so the user can retry
 * (or wait out the lockout) under the same JWT — see the v1.0.8 split
 * of verify/consume in `TokenManagerService` for the rationale.
 *
 * The `instanceof AuthException` check guarantees the response shape:
 * `AuthException`'s constructor invariantly calls `super(...)` with
 * `{ error: { code, message, details } }` (see `auth-exception.ts`),
 * so the cast on `getResponse()` is safe — the only un-narrowable case
 * (`getResponse()` returning a string) is unreachable for this class.
 */
function isTokenInvalidException(err: unknown): boolean {
  if (!(err instanceof AuthException)) return false
  const body = err.getResponse() as { error: { code: string } }
  return body.error.code === AUTH_ERROR_CODES.MFA_TEMP_TOKEN_INVALID
}

// ---------------------------------------------------------------------------
// MfaController
// ---------------------------------------------------------------------------

/**
 * MFA controller — setup, enable, challenge, and disable flows.
 *
 * All business logic lives in {@link MfaService}. This controller validates
 * input, delegates to the service, and delivers the response.
 *
 * Route prefix (`/mfa`) is relative — the consuming application applies
 * a global prefix (e.g. `/auth`) via `RouterModule` or `setGlobalPrefix`.
 *
 * @layer Controller
 */
@UseInterceptors(NoStoreInterceptor)
@Controller('mfa')
@UseGuards(TrustedOriginGuard, AuthRateLimitGuard)
@UsePipes(createAuthValidationPipe({ forbidUnknownValues: true }))
export class MfaController {
  constructor(
    @Inject(MfaService) private readonly mfaService: MfaService,
    @Inject(TokenDeliveryService) private readonly tokenDelivery: TokenDeliveryService,
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions
  ) {}

  /**
   * Clears the `mfa_temp_token` HttpOnly cookie planted by the OAuth
   * callback. Centralised so the success and clear-on-dead-token branches
   * of {@link challenge} share one source of truth for the cookie's
   * attributes (path, httpOnly, secure, sameSite) — diverging them would
   * silently break the cookie removal in some browsers.
   *
   * Clearing policy (v1.0.8+) enforced by {@link challenge}:
   *
   *   - SUCCESS → clear (JWT consumed by {@link MfaService.challenge}).
   *   - `MFA_TEMP_TOKEN_INVALID` → clear (token forged / expired / unknown —
   *     retry under the same cookie can never succeed).
   *   - `MFA_INVALID_CODE`, `ACCOUNT_LOCKED`, transient errors → KEEP
   *     (token is still alive in Redis because `TokenManagerService` splits
   *     verify and consume; the user can retry inside the 5-minute TTL).
   *
   * The brute-force counter on {@link MfaService.challenge} still caps
   * how many wrong codes can be tried under one token before the account
   * is locked, so the keep-on-failure policy does not weaken the threat
   * model.
   *
   * @param res - Express response in passthrough mode.
   */
  private clearMfaTempCookie(res: Response): void {
    res.clearCookie(MFA_TEMP_COOKIE_NAME, {
      path: this.options.cookies.mfaTempCookiePath,
      httpOnly: true,
      secure: this.options.secureCookies,
      sameSite: this.options.cookies.sameSite
    })
  }

  /**
   * Initiates the MFA setup flow for the authenticated user.
   *
   * Returns a TOTP secret, QR code URI, and plain-text recovery codes.
   * The recovery codes are shown once and must be saved by the user.
   * Idempotent: repeated calls within the 10-minute setup window return
   * the same secret.
   *
   * @param user - JWT payload of the authenticated user.
   * @throws `MFA_ALREADY_ENABLED` if MFA is already active on the account.
   */
  @UseGuards(JwtAuthGuard)
  @Throttle(AUTH_THROTTLE_CONFIGS.mfaSetup)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.mfaSetup)
  @Post('setup')
  async setup(
    @CurrentUser() user: DashboardJwtPayload,
    @Body() dto: MfaSetupDto
  ): Promise<MfaSetupResult> {
    return this.mfaService.setup(user.sub, 'dashboard', dto.password)
  }

  /**
   * Verifies the first TOTP code and permanently enables MFA on the account.
   *
   * After a successful call, all existing refresh sessions are invalidated
   * so the user must re-authenticate through the MFA challenge endpoint.
   *
   * @param user - JWT payload of the authenticated user.
   * @param dto - Contains the 6-digit TOTP code from the authenticator app.
   * @param req - Incoming request (provides IP and User-Agent for hooks).
   * @throws `MFA_SETUP_REQUIRED` if no pending setup data is found in Redis.
   * @throws `MFA_INVALID_CODE` if the submitted TOTP code is invalid.
   */
  @UseGuards(JwtAuthGuard)
  @Throttle(AUTH_THROTTLE_CONFIGS.mfaVerifyEnable)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.mfaVerifyEnable)
  @HttpCode(HttpStatus.NO_CONTENT)
  @Post('verify-enable')
  async verifyEnable(
    @CurrentUser() user: DashboardJwtPayload,
    @Body() dto: MfaVerifyDto,
    @Req() req: Request
  ): Promise<void> {
    const ip = req.ip ?? ''
    const userAgent = String(req.headers['user-agent'] ?? '')
    await this.mfaService.verifyAndEnable(user.sub, dto.code, ip, userAgent)
  }

  /**
   * Exchanges a valid MFA temp token + TOTP or recovery code for full auth tokens.
   *
   * This endpoint is public — it is called with the short-lived temp token
   * issued after a successful password login OR after the OAuth callback when
   * the resolved user has MFA enabled. `@SkipMfa()` ensures that
   * `MfaRequiredGuard` does not block this route when applied globally.
   *
   * The temp token is read from `dto.mfaTempToken` (password-login flow / SPA
   * OAuth flow that copies the cookie into sessionStorage) OR from the
   * HttpOnly `mfa_temp_token` cookie (browser-driven OAuth flow). When both
   * are present, the body value wins — that matches the historical contract
   * for the password-login path. When the cookie is consumed, it is cleared
   * on the response so the temp token is not left around if the user closes
   * the tab mid-challenge.
   *
   * Returns either a standard auth response (dashboard) or a
   * {@link PlatformChallengeResponse} for platform admin sessions (cookie
   * delivery is not applied for the platform context — tokens are in the body).
   *
   * @param dto - Contains the optional MFA temp token and the TOTP / recovery code.
   * @param req - Incoming request (provides IP, User-Agent, and cookie context).
   * @param res - Response object in passthrough mode (used for cookie delivery).
   * @throws `MFA_TEMP_TOKEN_INVALID` if no token is supplied (neither body nor cookie),
   *   the token is invalid, or it has already been consumed.
   * @throws `ACCOUNT_LOCKED` if the brute-force threshold has been reached.
   * @throws `MFA_INVALID_CODE` if the submitted code is incorrect.
   */
  @Public()
  @SkipMfa()
  @Throttle(AUTH_THROTTLE_CONFIGS.mfaChallenge)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.mfaChallenge)
  @HttpCode(HttpStatus.OK)
  @Post('challenge')
  async challenge(
    @Body() dto: MfaChallengeDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<
    CookieAuthResponse | BearerAuthResponse | BothAuthResponse | PlatformBearerAuthResponse
  > {
    const ip = req.ip ?? ''
    const userAgent = String(req.headers['user-agent'] ?? '')
    // Prefer the body value (back-compat with the existing sessionStorage flow);
    // fall back to the HttpOnly cookie planted by the OAuth callback.
    const cookieToken = readMfaTempCookie(req)
    const mfaTempToken = dto.mfaTempToken ?? cookieToken
    if (mfaTempToken === undefined || mfaTempToken.length === 0) {
      throw new AuthException(AUTH_ERROR_CODES.MFA_TEMP_TOKEN_INVALID)
    }

    // Cookie clearing policy lives on `clearMfaTempCookie` JSDoc.
    let result: AuthResult | PlatformAuthResult
    try {
      result = await this.mfaService.challenge(mfaTempToken, dto.code, ip, userAgent)
    } catch (err) {
      if (cookieToken !== undefined && isTokenInvalidException(err)) {
        this.clearMfaTempCookie(res)
      }
      throw err
    }
    if (cookieToken !== undefined) {
      this.clearMfaTempCookie(res)
    }

    // Discriminate by result shape: PlatformAuthResult carries `admin`, AuthResult carries `user`.
    // Platform tokens are returned via deliverPlatformAuthResponse — cookie delivery does not apply
    // to platform sessions. Using the shared method keeps the response shape in sync with
    // PlatformAuthController so the two sites never diverge.
    if (isPlatformResult(result)) {
      return this.tokenDelivery.deliverPlatformAuthResponse(result)
    }

    return this.tokenDelivery.deliverAuthResponse(res, result, req)
  }

  /**
   * Disables MFA on the authenticated user's account.
   *
   * Requires a valid TOTP code (recovery codes are not accepted by design).
   * All existing refresh sessions are invalidated after disabling, ensuring
   * subsequent token rotations reflect the updated `mfaEnabled: false` state.
   *
   * @param user - JWT payload of the authenticated user.
   * @param dto - Contains the 6-digit TOTP code confirming the action.
   * @param req - Incoming request (provides IP and User-Agent for hooks).
   * @throws `MFA_NOT_ENABLED` if MFA is not currently active on the account.
   * @throws `ACCOUNT_LOCKED` if the brute-force threshold has been reached.
   * @throws `MFA_INVALID_CODE` if the submitted TOTP code is incorrect.
   */
  @UseGuards(JwtAuthGuard)
  @Throttle(AUTH_THROTTLE_CONFIGS.mfaDisable)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.mfaDisable)
  @HttpCode(HttpStatus.NO_CONTENT)
  @Post('disable')
  async disable(
    @CurrentUser() user: DashboardJwtPayload,
    @Body() dto: MfaDisableDto,
    @Req() req: Request
  ): Promise<void> {
    const ip = req.ip ?? ''
    const userAgent = String(req.headers['user-agent'] ?? '')
    // Always the dashboard plane: `JwtAuthGuard` runs `assertTokenType(payload, 'dashboard')`,
    // so a platform token cannot reach this controller at all. The platform surface has its
    // own — `PlatformMfaController` — and the branch that used to read the plane off the
    // payload here could never take its other arm.
    await this.mfaService.disable(user.sub, dto.code, ip, userAgent, 'dashboard')
  }

  /**
   * Regenerates the user's MFA recovery codes after verifying a current TOTP code.
   *
   * Requires a valid TOTP code (recovery codes are not accepted by design — see
   * {@link MfaRegenerateRecoveryCodesDto} for the rationale). The freshly
   * generated plain-text codes are returned in the response body and are shown
   * once. Only a keyed HMAC-SHA-256 of each is persisted.
   *
   * Shares the disable throttle config because the security posture is identical
   * (authenticated, TOTP-gated, MFA-affecting state change).
   *
   * @param user - JWT payload of the authenticated user.
   * @param dto - Contains the 6-digit TOTP code confirming the action.
   * @param req - Incoming request (provides IP and User-Agent for hooks).
   * @throws `MFA_NOT_ENABLED` if MFA is not currently active on the account.
   * @throws `ACCOUNT_LOCKED` if the brute-force threshold has been reached.
   * @throws `MFA_INVALID_CODE` if the submitted TOTP code is incorrect.
   * @returns The fresh plain-text recovery codes, one-time display.
   */
  @UseGuards(JwtAuthGuard)
  @Throttle(AUTH_THROTTLE_CONFIGS.mfaDisable)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.mfaDisable)
  @HttpCode(HttpStatus.OK)
  @Post('recovery-codes')
  async regenerateRecoveryCodes(
    @CurrentUser() user: DashboardJwtPayload,
    @Body() dto: MfaRegenerateRecoveryCodesDto,
    @Req() req: Request
  ): Promise<{ recoveryCodes: string[] }> {
    const ip = req.ip ?? ''
    const userAgent = String(req.headers['user-agent'] ?? '')
    // See `disable`: this controller is dashboard-only by its guard.
    return this.mfaService.regenerateRecoveryCodes(user.sub, dto.code, ip, userAgent, 'dashboard')
  }
}
