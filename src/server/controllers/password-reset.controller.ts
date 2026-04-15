import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  UsePipes,
  ValidationPipe
} from '@nestjs/common'
import { Throttle } from '@nestjs/throttler'

import { AUTH_THROTTLE_CONFIGS } from '../constants/throttle-configs'
import { Public } from '../decorators/public.decorator'
import { ForgotPasswordDto } from '../dto/forgot-password.dto'
import { ResendOtpDto } from '../dto/resend-otp.dto'
import { ResetPasswordDto } from '../dto/reset-password.dto'
import { VerifyOtpDto } from '../dto/verify-otp.dto'
import { PasswordResetService } from '../services/password-reset.service'

// ---------------------------------------------------------------------------
// PasswordResetController
// ---------------------------------------------------------------------------

/**
 * Password-reset controller — all four endpoints are public (unauthenticated).
 *
 * Exposes the full password reset lifecycle:
 *
 * - `POST /password/forgot-password` — initiates a reset (sends token or OTP)
 * - `POST /password/reset-password`  — applies the new password (token, OTP, or verifiedToken)
 * - `POST /password/verify-otp`      — validates the OTP and issues a short-lived `verifiedToken`
 * - `POST /password/resend-otp`      — re-sends the password-reset OTP (60-second cooldown)
 *
 * All endpoints return `200 OK` (or `204 No Content` for no-body responses) to
 * prevent response-code differences from leaking user-existence information.
 * Anti-enumeration timing normalization is applied inside {@link PasswordResetService}.
 *
 * Route prefix (`/password`) is relative — the consuming application applies a global
 * prefix (e.g. `/auth`) via `RouterModule` or `setGlobalPrefix`.
 */
@Public()
@Controller('password')
@UsePipes(new ValidationPipe({ whitelist: true }))
export class PasswordResetController {
  constructor(private readonly passwordResetService: PasswordResetService) {}

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
  @HttpCode(HttpStatus.OK)
  @Post('forgot-password')
  async forgotPassword(@Body() dto: ForgotPasswordDto): Promise<void> {
    await this.passwordResetService.initiateReset(dto)
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
   * @throws {@link AuthException} `OTP_INVALID` / `OTP_EXPIRED` / `OTP_MAX_ATTEMPTS`
   *   for OTP-path failures.
   */
  @Throttle(AUTH_THROTTLE_CONFIGS.resetPassword)
  @HttpCode(HttpStatus.NO_CONTENT)
  @Post('reset-password')
  async resetPassword(@Body() dto: ResetPasswordDto): Promise<void> {
    await this.passwordResetService.resetPassword(dto)
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
   * @throws {@link AuthException} `OTP_EXPIRED` when the OTP is not in Redis.
   * @throws {@link AuthException} `OTP_MAX_ATTEMPTS` when the attempt limit is reached.
   * @throws {@link AuthException} `OTP_INVALID` when the OTP does not match.
   */
  @Throttle(AUTH_THROTTLE_CONFIGS.verifyOtp)
  @HttpCode(HttpStatus.OK)
  @Post('verify-otp')
  async verifyOtp(@Body() dto: VerifyOtpDto): Promise<{ verifiedToken: string }> {
    const verifiedToken = await this.passwordResetService.verifyOtp(dto)
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
  @HttpCode(HttpStatus.OK)
  @Post('resend-otp')
  async resendOtp(@Body() dto: ResendOtpDto): Promise<void> {
    await this.passwordResetService.resendOtp(dto)
  }
}
