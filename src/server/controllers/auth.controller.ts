import {
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
  ValidationPipe
} from '@nestjs/common'
import { Throttle } from '@nestjs/throttler'
import { IsEmail, IsNotEmpty, IsString } from 'class-validator'
import type { Request, Response } from 'express'

import { AUTH_THROTTLE_CONFIGS } from '../constants/throttle-configs'
import { CurrentUser } from '../decorators/current-user.decorator'
import { Public } from '../decorators/public.decorator'
import { LoginDto } from '../dto/login.dto'
import { RegisterDto } from '../dto/register.dto'
import { JwtAuthGuard } from '../guards/jwt-auth.guard'
import type { AuthResult, MfaChallengeResult } from '../interfaces/auth-result.interface'
import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface'
import type { SafeAuthUser } from '../interfaces/user-repository.interface'
import { AuthService } from '../services/auth.service'
import type {
  BearerAuthResponse,
  BothAuthResponse,
  CookieAuthResponse
} from '../services/token-delivery.service'
import { TokenDeliveryService } from '../services/token-delivery.service'

// ---------------------------------------------------------------------------
// Inline request body DTOs — scoped to auth endpoints not covered by Phase 2 DTOs
// ---------------------------------------------------------------------------

class VerifyEmailBody {
  @IsString() @IsNotEmpty() tenantId!: string

  @IsEmail() email!: string

  /**
   * User ID from the verification link sent by email.
   * The OTP is the primary security mechanism — the userId is used only after
   * the OTP is validated, so spoofing this field without the correct OTP has no effect.
   */
  @IsString() @IsNotEmpty() userId!: string

  @IsString() @IsNotEmpty() otp!: string
}

class ResendVerificationBody {
  @IsString() @IsNotEmpty() tenantId!: string

  @IsEmail() email!: string
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
 */
@Controller()
@UsePipes(new ValidationPipe({ whitelist: true }))
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly tokenDelivery: TokenDeliveryService
  ) {}

  /**
   * Registers a new dashboard user and issues auth tokens.
   *
   * @param dto - Registration payload.
   * @param req - Incoming request (used for tenantId resolution and hooks).
   * @param res - Response object (passthrough — used to set cookies).
   */
  @Public()
  @Throttle(AUTH_THROTTLE_CONFIGS.register)
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
   */
  @Public()
  @Throttle(AUTH_THROTTLE_CONFIGS.login)
  @HttpCode(HttpStatus.OK)
  @Post('login')
  async login(
    @Body() dto: LoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<CookieAuthResponse | BearerAuthResponse | BothAuthResponse | MfaChallengeResult> {
    const result = await this.authService.login(dto, req)

    // Discriminate MFA challenge via the literal boolean `mfaRequired` field.
    if ('mfaRequired' in result && result.mfaRequired) {
      return result
    }

    return this.tokenDelivery.deliverAuthResponse(res, result as AuthResult, req)
  }

  /**
   * Logs out the authenticated user by revoking tokens and clearing the session.
   *
   * @param user - JWT payload from the verified access token.
   * @param req - Incoming request (used to extract tokens).
   * @param res - Response object (passthrough — used to clear cookies).
   */
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.NO_CONTENT)
  @Post('logout')
  async logout(
    @CurrentUser() user: DashboardJwtPayload,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<void> {
    const accessToken = this.tokenDelivery.extractAccessToken(req) ?? ''
    const rawRefreshToken = this.tokenDelivery.extractRefreshToken(req) ?? ''
    await this.authService.logout(accessToken, rawRefreshToken, user.sub)
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
   */
  @Public()
  @Throttle(AUTH_THROTTLE_CONFIGS.refresh)
  @HttpCode(HttpStatus.OK)
  @Post('refresh')
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<CookieAuthResponse | BearerAuthResponse | BothAuthResponse> {
    const rawRefreshToken = this.tokenDelivery.extractRefreshToken(req) ?? ''
    const ip = req.ip ?? ''
    const userAgent = String(req.headers['user-agent'] ?? '')

    const rotated = await this.authService.refresh(rawRefreshToken, ip, userAgent)
    const user = await this.authService.getMe(rotated.session.userId)

    const authResult: AuthResult = {
      user,
      accessToken: rotated.accessToken,
      rawRefreshToken: rotated.rawRefreshToken
    }

    return this.tokenDelivery.deliverRefreshResponse(res, authResult, req)
  }

  /**
   * Returns the safe user record for the currently authenticated user.
   *
   * @param user - JWT payload from the verified access token.
   */
  @UseGuards(JwtAuthGuard)
  @Get('me')
  async me(@CurrentUser() user: DashboardJwtPayload): Promise<SafeAuthUser> {
    return this.authService.getMe(user.sub)
  }

  /**
   * Verifies the user's email address using a one-time password.
   *
   * @param body - Verification payload: tenantId, email, userId, and OTP.
   */
  @Public()
  @Throttle(AUTH_THROTTLE_CONFIGS.verifyEmail)
  @HttpCode(HttpStatus.NO_CONTENT)
  @Post('verify-email')
  async verifyEmail(@Body() body: VerifyEmailBody): Promise<void> {
    await this.authService.verifyEmail(body.tenantId, body.email, body.userId, body.otp)
  }

  /**
   * Resends an email verification OTP with an atomic cooldown.
   *
   * Always returns 204 — the response never reveals whether the email exists.
   *
   * @param body - Payload: tenantId and email.
   */
  @Public()
  @Throttle(AUTH_THROTTLE_CONFIGS.resendVerification)
  @HttpCode(HttpStatus.NO_CONTENT)
  @Post('resend-verification')
  async resendVerification(@Body() body: ResendVerificationBody): Promise<void> {
    await this.authService.resendVerificationEmail(body.tenantId, body.email)
  }
}
