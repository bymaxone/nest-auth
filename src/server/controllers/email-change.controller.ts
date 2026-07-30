import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
  UseInterceptors,
  UsePipes,
  ValidationPipe
} from '@nestjs/common'
import { Throttle } from '@nestjs/throttler'

import { AUTH_THROTTLE_CONFIGS } from '../constants/throttle-configs'
import { AuthRateLimit } from '../decorators/auth-rate-limit.decorator'
import { CurrentUser } from '../decorators/current-user.decorator'
import { Public } from '../decorators/public.decorator'
import { ChangeEmailDto } from '../dto/change-email.dto'
import { ConfirmEmailChangeDto } from '../dto/confirm-email-change.dto'
import { AuthRateLimitGuard } from '../guards/auth-rate-limit.guard'
import { JwtAuthGuard } from '../guards/jwt-auth.guard'
import { TrustedOriginGuard } from '../guards/trusted-origin.guard'
import { UserStatusGuard } from '../guards/user-status.guard'
import { NoStoreInterceptor } from '../interceptors/no-store.interceptor'
import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface'
import { EmailChangeService } from '../services/email-change.service'

// ---------------------------------------------------------------------------
// EmailChangeController
// ---------------------------------------------------------------------------

/**
 * Controller for changing the address on an account.
 *
 * Two endpoints, and the split is the security property:
 *
 * - `POST /email/change`         — authenticated, re-proves the password, mails a token to
 *   the **new** address. Nothing about the account changes here.
 * - `POST /email/change/confirm` — public, consumes that token. Public because the person
 *   holding it is proving control of a mailbox, not of a session — requiring a login here
 *   would break the case the flow exists to serve, where someone confirms from the device
 *   their new mail is on.
 *
 * @remarks
 * Route prefix (`/email`) is relative — the consuming application applies a global prefix
 * (e.g. `/auth`) via `RouterModule` or `setGlobalPrefix`.
 *
 * @layer Controller
 */
@UseInterceptors(NoStoreInterceptor)
@Controller('email')
@UseGuards(TrustedOriginGuard, AuthRateLimitGuard)
@UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
export class EmailChangeController {
  constructor(private readonly emailChangeService: EmailChangeService) {}

  // ---------------------------------------------------------------------------
  // POST /email/change
  // ---------------------------------------------------------------------------

  /**
   * Requests an address change for the authenticated caller.
   *
   * The account comes from the verified JWT — never from the body. A payload that could name
   * a user would let anyone holding any session move any account's recovery address.
   *
   * Answers `204` and nothing else: whether a verification went out is not something the
   * response should carry, because the failure modes it would describe (the address is taken,
   * the password was wrong) are already reported as errors, and anything beyond that would be
   * describing the state of an account to whoever is holding its token.
   *
   * @param dto - The new address and the current password.
   * @param user - Verified JWT payload from the access token.
   */
  // `UserStatusGuard` alongside the JWT guard, for the same reason minting an invitation
  // carries it: a suspended account holding a live access token must not be able to move the
  // credential its recovery depends on.
  @UseGuards(JwtAuthGuard, UserStatusGuard)
  @Throttle(AUTH_THROTTLE_CONFIGS.emailChangeRequest)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.emailChangeRequest)
  @HttpCode(HttpStatus.NO_CONTENT)
  @Post('change')
  async requestChange(
    @Body() dto: ChangeEmailDto,
    @CurrentUser() user: DashboardJwtPayload
  ): Promise<void> {
    await this.emailChangeService.requestChange(user.sub, dto)
  }

  // ---------------------------------------------------------------------------
  // POST /email/change/confirm
  // ---------------------------------------------------------------------------

  /**
   * Confirms an address change with the token mailed to the new address.
   *
   * Public and rate-limited. Guessing is bounded by the token being 256 bits of entropy
   * looked up by its SHA-256 — a wrong value reveals nothing and reaches no record.
   *
   * @param dto - The single-use token.
   */
  @Public()
  @Throttle(AUTH_THROTTLE_CONFIGS.emailChangeConfirm)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.emailChangeConfirm)
  @HttpCode(HttpStatus.NO_CONTENT)
  @Post('change/confirm')
  async confirmChange(@Body() dto: ConfirmEmailChangeDto): Promise<void> {
    await this.emailChangeService.confirmChange(dto)
  }
}
