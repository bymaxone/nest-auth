import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
  UseGuards,
  UsePipes,
  ValidationPipe
} from '@nestjs/common'
import { Throttle } from '@nestjs/throttler'
import type { Request, Response } from 'express'

import { AUTH_THROTTLE_CONFIGS } from '../constants/throttle-configs'
import { CurrentUser } from '../decorators/current-user.decorator'
import { Public } from '../decorators/public.decorator'
import { SkipMfa } from '../decorators/skip-mfa.decorator'
import { MfaChallengeDto } from '../dto/mfa-challenge.dto'
import { MfaDisableDto } from '../dto/mfa-disable.dto'
import { MfaVerifyDto } from '../dto/mfa-verify.dto'
import { JwtAuthGuard } from '../guards/jwt-auth.guard'
import type { AuthResult, PlatformAuthResult } from '../interfaces/auth-result.interface'
import type { DashboardJwtPayload, PlatformJwtPayload } from '../interfaces/jwt-payload.interface'
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
 */
@Controller('mfa')
@UsePipes(
  new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, forbidUnknownValues: true })
)
export class MfaController {
  constructor(
    private readonly mfaService: MfaService,
    private readonly tokenDelivery: TokenDeliveryService
  ) {}

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
  @Post('setup')
  async setup(@CurrentUser() user: DashboardJwtPayload): Promise<MfaSetupResult> {
    return this.mfaService.setup(user.sub)
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
   * issued after a successful password login. `@SkipMfa()` ensures that
   * `MfaRequiredGuard` does not block this route when applied globally.
   *
   * Returns either a standard auth response (dashboard) or a
   * {@link PlatformChallengeResponse} for platform admin sessions (cookie
   * delivery is not applied for the platform context — tokens are in the body).
   *
   * @param dto - Contains the MFA temp token and the TOTP or recovery code.
   * @param req - Incoming request (provides IP, User-Agent, and cookie context).
   * @param res - Response object in passthrough mode (used for cookie delivery).
   * @throws `MFA_TEMP_TOKEN_INVALID` if the token is invalid or already consumed.
   * @throws `ACCOUNT_LOCKED` if the brute-force threshold has been reached.
   * @throws `MFA_INVALID_CODE` if the submitted code is incorrect.
   */
  @Public()
  @SkipMfa()
  @Throttle(AUTH_THROTTLE_CONFIGS.mfaChallenge)
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
    const result = await this.mfaService.challenge(dto.mfaTempToken, dto.code, ip, userAgent)

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
  @HttpCode(HttpStatus.NO_CONTENT)
  @Post('disable')
  async disable(
    @CurrentUser() user: DashboardJwtPayload | PlatformJwtPayload,
    @Body() dto: MfaDisableDto,
    @Req() req: Request
  ): Promise<void> {
    const ip = req.ip ?? ''
    const userAgent = String(req.headers['user-agent'] ?? '')
    const context = user.type === 'platform' ? 'platform' : 'dashboard'
    await this.mfaService.disable(user.sub, dto.code, ip, userAgent, context)
  }
}
