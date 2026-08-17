import {
  Inject,
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  UsePipes,
  UseGuards,
  UseInterceptors,
  Req
} from '@nestjs/common'
import { Throttle } from '@nestjs/throttler'
import type { Request } from 'express'

import { AUTH_THROTTLE_CONFIGS } from '../constants/throttle-configs'
import { AuthRateLimit } from '../decorators/auth-rate-limit.decorator'
import { Authenticated } from '../decorators/authenticated.decorator'
import { CurrentUser } from '../decorators/current-user.decorator'
import { Public } from '../decorators/public.decorator'
import { ChangePasswordDto } from '../dto/change-password.dto'
import { ForgotPasswordDto } from '../dto/forgot-password.dto'
import { ResendOtpDto } from '../dto/resend-otp.dto'
import { ResetPasswordDto } from '../dto/reset-password.dto'
import { VerifyOtpDto } from '../dto/verify-otp.dto'
import { AuthRateLimitGuard } from '../guards/auth-rate-limit.guard'
import { JwtAuthGuard } from '../guards/jwt-auth.guard'
import { TrustedOriginGuard } from '../guards/trusted-origin.guard'
import { UserStatusGuard } from '../guards/user-status.guard'
import { NoStoreInterceptor } from '../interceptors/no-store.interceptor'
import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface'
import { createAuthValidationPipe } from '../pipes/auth-validation.pipe'
import { PasswordResetService } from '../services/password-reset.service'
import { TokenDeliveryService } from '../services/token-delivery.service'

// ---------------------------------------------------------------------------
// PasswordResetController
// ---------------------------------------------------------------------------

/**
 * Password controller — the four recovery endpoints are public (unauthenticated); the
 * change endpoint is not.
 *
 * Exposes the full password lifecycle:
 *
 * - `POST /password/forgot-password` — initiates a reset (sends token or OTP)
 * - `POST /password/reset-password`  — applies the new password (token, OTP, or verifiedToken)
 * - `POST /password/verify-otp`      — validates the OTP and issues a short-lived `verifiedToken`
 * - `POST /password/resend-otp`      — re-sends the password-reset OTP (60-second cooldown)
 * - `POST /password/change`          — **authenticated**: rotates the password by proving the
 *   current one, which is the flow ASVS v5 §6.2.2 and §6.2.3 require at Level 1
 *
 * The four recovery endpoints return `200 OK` (or `204 No Content` for no-body responses) to
 * prevent response-code differences from leaking user-existence information.
 * Anti-enumeration timing normalization is applied inside {@link PasswordResetService}.
 *
 * Route prefix (`/password`) is relative — the consuming application applies a global
 * prefix (e.g. `/auth`) via `RouterModule` or `setGlobalPrefix`.
 *
 * @layer Controller
 */
@Public()
@UseInterceptors(NoStoreInterceptor)
@Controller('password')
@UseGuards(TrustedOriginGuard, AuthRateLimitGuard)
@UsePipes(createAuthValidationPipe())
export class PasswordResetController {
  constructor(
    @Inject(PasswordResetService) private readonly passwordResetService: PasswordResetService,
    @Inject(TokenDeliveryService) private readonly tokenDelivery: TokenDeliveryService
  ) {}

  // ---------------------------------------------------------------------------
  // POST /password/forgot-password
  // ---------------------------------------------------------------------------

  /**
   * Initiates a password reset for the given email address.
   *
   * Sends a reset token or OTP to the user's email if the account exists and
   * is eligible. Always returns `200 OK` regardless of outcome (anti-enumeration).
   *
   * @param dto - Validated DTO with `email` and `tenantId`.
   */
  @Throttle(AUTH_THROTTLE_CONFIGS.forgotPassword)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.forgotPassword)
  @HttpCode(HttpStatus.OK)
  @Post('forgot-password')
  async forgotPassword(@Body() dto: ForgotPasswordDto, @Req() req: Request): Promise<void> {
    await this.passwordResetService.initiateReset(dto, req)
  }

  // ---------------------------------------------------------------------------
  // POST /password/reset-password
  // ---------------------------------------------------------------------------

  /**
   * Applies a new password using a verified proof (token, OTP, or verifiedToken).
   *
   * Exactly one of `dto.token`, `dto.otp`, or `dto.verifiedToken` must be present.
   * The proof is consumed on success (single-use). All active sessions are
   * invalidated after the password is updated.
   *
   * @param dto - Validated DTO with `email`, `newPassword`, `tenantId`, and one proof field.
   * @throws {@link AuthException} `PASSWORD_RESET_TOKEN_INVALID` on invalid proof.
   * @throws {@link AuthException} `OTP_INVALID` — for a wrong code, a missing record, and
   *   an exhausted attempt ceiling alike
   *   for OTP-path failures.
   */
  @Throttle(AUTH_THROTTLE_CONFIGS.resetPassword)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.resetPassword)
  @HttpCode(HttpStatus.NO_CONTENT)
  @Post('reset-password')
  async resetPassword(@Body() dto: ResetPasswordDto, @Req() req: Request): Promise<void> {
    await this.passwordResetService.resetPassword(dto, req)
  }

  // ---------------------------------------------------------------------------
  // POST /password/change
  // ---------------------------------------------------------------------------

  /**
   * Changes the password of the authenticated account, proving identity with the current one.
   *
   * The recovery endpoints above answer to anyone who can read the account's mailbox. This one
   * answers only to someone who holds a live session **and** knows the password — which is the
   * point: a session alone is not proof of identity, and without this route a user who wants to
   * rotate a credential they already know has to go through the anonymous recovery flow, while
   * an attacker holding a stolen session cannot be raced out of the account by the owner
   * changing it.
   *
   * Every other session is ended on success and the token epoch is bumped, so already-issued
   * access tokens die with them (ASVS v5 §7.4.3). The caller's own session survives when the
   * request carries its refresh token, so the device that made the change stays signed in.
   *
   * @param user - JWT payload from the verified access token — the subject is never taken
   *   from the body.
   * @param dto - Validated current and new password.
   * @param req - Incoming request, read for the caller's refresh token.
   * @throws {@link AuthException} `INVALID_CREDENTIALS` when the current password is wrong or
   *   the account has no local password to change.
   * @throws {@link AuthException} `PASSWORD_COMPROMISED` when the breach checker refuses the
   *   new password.
   */
  @Authenticated()
  @UseGuards(JwtAuthGuard, UserStatusGuard)
  @Throttle(AUTH_THROTTLE_CONFIGS.changePassword)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.changePassword)
  @HttpCode(HttpStatus.NO_CONTENT)
  @Post('change')
  async changePassword(
    @CurrentUser() user: DashboardJwtPayload,
    @Body() dto: ChangePasswordDto,
    @Req() req: Request
  ): Promise<void> {
    const currentRefreshToken = this.tokenDelivery.extractRefreshToken(req)
    await this.passwordResetService.changePassword(
      user.sub,
      user.tenantId,
      dto,
      currentRefreshToken
    )
  }

  // ---------------------------------------------------------------------------
  // POST /password/verify-otp
  // ---------------------------------------------------------------------------

  /**
   * Verifies the password-reset OTP and exchanges it for a short-lived `verifiedToken`.
   *
   * The returned `verifiedToken` (64-char hex) can be submitted via
   * `POST /password/reset-password` with `{ verifiedToken }` within 5 minutes.
   * The OTP is consumed on success (single-use).
   *
   * @param dto - Validated DTO with `email`, `tenantId`, and `otp`.
   * @returns Object containing the `verifiedToken` to pass to `reset-password`.
   * @throws {@link AuthException} `OTP_INVALID` for every failure — a wrong code, a record
   *   that is not in Redis, and an exhausted attempt ceiling are indistinguishable.
   * @throws {@link AuthException} `OTP_INVALID` when the OTP does not match.
   */
  @Throttle(AUTH_THROTTLE_CONFIGS.verifyOtp)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.verifyOtp)
  @HttpCode(HttpStatus.OK)
  @Post('verify-otp')
  async verifyOtp(
    @Body() dto: VerifyOtpDto,
    @Req() req: Request
  ): Promise<{ verifiedToken: string }> {
    const verifiedToken = await this.passwordResetService.verifyOtp(dto, req)
    return { verifiedToken }
  }

  // ---------------------------------------------------------------------------
  // POST /password/resend-otp
  // ---------------------------------------------------------------------------

  /**
   * Re-sends the password-reset OTP for the given email address.
   *
   * Subject to a 60-second atomic cooldown per `(tenantId, email)` pair.
   * Always returns `200 OK` regardless of outcome (anti-enumeration).
   *
   * @param dto - Validated DTO with `email` and `tenantId`.
   */
  @Throttle(AUTH_THROTTLE_CONFIGS.resendPasswordOtp)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.resendPasswordOtp)
  @HttpCode(HttpStatus.OK)
  @Post('resend-otp')
  async resendOtp(@Body() dto: ResendOtpDto, @Req() req: Request): Promise<void> {
    await this.passwordResetService.resendOtp(dto, req)
  }
}
