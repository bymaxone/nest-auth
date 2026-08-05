import {
  Inject,
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UseGuards,
  UsePipes,
  UseInterceptors
} from '@nestjs/common'
import { Throttle } from '@nestjs/throttler'
import type { Request } from 'express'

import { AUTH_THROTTLE_CONFIGS } from '../constants/throttle-configs'
import { AuthRateLimit } from '../decorators/auth-rate-limit.decorator'
import { CurrentUser } from '../decorators/current-user.decorator'
import { MfaDisableDto } from '../dto/mfa-disable.dto'
import { MfaRegenerateRecoveryCodesDto } from '../dto/mfa-regenerate-recovery-codes.dto'
import { MfaSetupDto } from '../dto/mfa-setup.dto'
import { MfaVerifyDto } from '../dto/mfa-verify.dto'
import { AuthRateLimitGuard } from '../guards/auth-rate-limit.guard'
import { JwtPlatformGuard } from '../guards/jwt-platform.guard'
import { TrustedOriginGuard } from '../guards/trusted-origin.guard'
import { NoStoreInterceptor } from '../interceptors/no-store.interceptor'
import type { PlatformJwtPayload } from '../interfaces/jwt-payload.interface'
import { createAuthValidationPipe } from '../pipes/auth-validation.pipe'
import type { MfaSetupResult } from '../services/mfa.service'
import { MfaService } from '../services/mfa.service'

// ---------------------------------------------------------------------------
// PlatformMfaController
// ---------------------------------------------------------------------------

/**
 * Platform admin MFA controller — setup, enable, disable, and recovery-code
 * regeneration flows mirrored from the dashboard `MfaController` but bound to
 * the platform user repository and protected by {@link JwtPlatformGuard}.
 *
 * The dashboard `MfaController` already handles the MFA challenge flow for
 * both contexts (the temp token carries the discriminant). Only enrolment,
 * disable, and recovery-code rotation needed a dedicated platform surface —
 * those routes operate against a known authenticated identity rather than
 * exchanging a temp token, so they must use a guard that validates the
 * `type: 'platform'` JWT claim.
 *
 * All business logic lives in {@link MfaService} with the `'platform'`
 * context flag, which routes persistence through the platform user
 * repository instead of the tenant user repository.
 *
 * Route prefix (`/platform/mfa`) is relative — the consuming application
 * applies a global prefix (e.g. `/auth`) via `RouterModule` or
 * `setGlobalPrefix`, producing final routes such as `/auth/platform/mfa/setup`.
 *
 * @remarks
 * The challenge endpoint `POST /platform/mfa/challenge` lives on
 * {@link PlatformAuthController} (it is the post-login exchange endpoint, not an
 * authenticated MFA management action).
 *
 * @layer Controller
 */
@UseInterceptors(NoStoreInterceptor)
@Controller('platform/mfa')
@UseGuards(TrustedOriginGuard, AuthRateLimitGuard)
@UsePipes(createAuthValidationPipe({ forbidUnknownValues: true }))
export class PlatformMfaController {
  constructor(@Inject(MfaService) private readonly mfaService: MfaService) {}

  /**
   * Initiates the MFA setup flow for the authenticated platform administrator.
   *
   * Returns a TOTP secret, QR code URI, and plain-text recovery codes (shown once).
   * Idempotent within the 10-minute setup window — repeated calls return the
   * same payload until the user completes or abandons the flow.
   *
   * @param user - JWT payload of the authenticated platform admin.
   * @throws `MFA_ALREADY_ENABLED` if MFA is already active on the account.
   */
  @UseGuards(JwtPlatformGuard)
  @Throttle(AUTH_THROTTLE_CONFIGS.mfaSetup)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.mfaSetup)
  @Post('setup')
  async setup(
    @CurrentUser() user: PlatformJwtPayload,
    @Body() dto: MfaSetupDto
  ): Promise<MfaSetupResult> {
    return this.mfaService.setup(user.sub, 'platform', dto.password)
  }

  /**
   * Verifies the first TOTP code and permanently enables MFA on the platform
   * admin's account.
   *
   * After a successful call, all existing refresh sessions are invalidated so
   * the admin must re-authenticate through the MFA challenge endpoint.
   *
   * @param user - JWT payload of the authenticated platform admin.
   * @param dto - Contains the 6-digit TOTP code from the authenticator app.
   * @param req - Incoming request (provides IP and User-Agent for hooks).
   * @throws `MFA_SETUP_REQUIRED` if no pending setup data is found in Redis.
   * @throws `MFA_INVALID_CODE` if the submitted TOTP code is invalid.
   */
  @UseGuards(JwtPlatformGuard)
  @Throttle(AUTH_THROTTLE_CONFIGS.mfaVerifyEnable)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.mfaVerifyEnable)
  @HttpCode(HttpStatus.NO_CONTENT)
  @Post('verify-enable')
  async verifyEnable(
    @CurrentUser() user: PlatformJwtPayload,
    @Body() dto: MfaVerifyDto,
    @Req() req: Request
  ): Promise<void> {
    const ip = req.ip ?? ''
    const userAgent = String(req.headers['user-agent'] ?? '')
    await this.mfaService.verifyAndEnable(user.sub, dto.code, ip, userAgent, 'platform')
  }

  /**
   * Disables MFA on the authenticated platform admin's account.
   *
   * Requires a valid TOTP code (recovery codes are not accepted by design).
   * All existing refresh sessions are invalidated after disabling.
   *
   * @param user - JWT payload of the authenticated platform admin.
   * @param dto - Contains the 6-digit TOTP code confirming the action.
   * @param req - Incoming request (provides IP and User-Agent for hooks).
   * @throws `MFA_NOT_ENABLED` if MFA is not currently active on the account.
   * @throws `ACCOUNT_LOCKED` if the brute-force threshold has been reached.
   * @throws `MFA_INVALID_CODE` if the submitted TOTP code is incorrect.
   */
  @UseGuards(JwtPlatformGuard)
  @Throttle(AUTH_THROTTLE_CONFIGS.mfaDisable)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.mfaDisable)
  @HttpCode(HttpStatus.NO_CONTENT)
  @Post('disable')
  async disable(
    @CurrentUser() user: PlatformJwtPayload,
    @Body() dto: MfaDisableDto,
    @Req() req: Request
  ): Promise<void> {
    const ip = req.ip ?? ''
    const userAgent = String(req.headers['user-agent'] ?? '')
    await this.mfaService.disable(user.sub, dto.code, ip, userAgent, 'platform')
  }

  /**
   * Regenerates the platform admin's MFA recovery codes.
   *
   * Requires a valid TOTP code (recovery codes are not accepted by design).
   * Returns the fresh plain-text codes once — only a keyed HMAC-SHA-256 of each
   * is persisted.
   *
   * @param user - JWT payload of the authenticated platform admin.
   * @param dto - Contains the 6-digit TOTP code confirming the action.
   * @param req - Incoming request (provides IP and User-Agent for hooks).
   * @throws `MFA_NOT_ENABLED` if MFA is not currently active on the account.
   * @throws `ACCOUNT_LOCKED` if the brute-force threshold has been reached.
   * @throws `MFA_INVALID_CODE` if the submitted TOTP code is incorrect.
   * @returns The fresh plain-text recovery codes, one-time display.
   */
  @UseGuards(JwtPlatformGuard)
  @Throttle(AUTH_THROTTLE_CONFIGS.mfaDisable)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.mfaDisable)
  @HttpCode(HttpStatus.OK)
  @Post('recovery-codes')
  async regenerateRecoveryCodes(
    @CurrentUser() user: PlatformJwtPayload,
    @Body() dto: MfaRegenerateRecoveryCodesDto,
    @Req() req: Request
  ): Promise<{ recoveryCodes: string[] }> {
    const ip = req.ip ?? ''
    const userAgent = String(req.headers['user-agent'] ?? '')
    return this.mfaService.regenerateRecoveryCodes(user.sub, dto.code, ip, userAgent, 'platform')
  }
}
