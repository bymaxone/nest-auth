import {
  Inject,
  Body,
  Controller,
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
import { AcceptInvitationDto } from '../dto/accept-invitation.dto'
import { CreateInvitationDto } from '../dto/create-invitation.dto'
import { RevokeInvitationDto } from '../dto/revoke-invitation.dto'
import { AuthRateLimitGuard } from '../guards/auth-rate-limit.guard'
import { JwtAuthGuard } from '../guards/jwt-auth.guard'
import { TrustedOriginGuard } from '../guards/trusted-origin.guard'
import { UserStatusGuard } from '../guards/user-status.guard'
import { NoStoreInterceptor } from '../interceptors/no-store.interceptor'
import type { AuthResult } from '../interfaces/auth-result.interface'
import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface'
import { createAuthValidationPipe } from '../pipes/auth-validation.pipe'
import { InvitationService } from '../services/invitation.service'
import type {
  BearerAuthResponse,
  BothAuthResponse,
  CookieAuthResponse
} from '../services/token-delivery.service'
import { TokenDeliveryService } from '../services/token-delivery.service'

// ---------------------------------------------------------------------------
// InvitationController
// ---------------------------------------------------------------------------

/**
 * Controller for tenant invitation flows.
 *
 * Exposes two endpoints:
 *
 * - `POST /invitations`        — authenticated invite (requires JwtAuthGuard).
 *   The `tenantId` is always extracted from the caller's JWT — never from the request body —
 *   to prevent tenant spoofing.
 *
 * - `POST /invitations/accept` — public accept endpoint, rate-limited to prevent
 *   brute-force token guessing.
 *
 * @remarks
 * Route prefix (`/invitations`) is relative — the consuming application applies
 * a global prefix (e.g. `/auth`) via `RouterModule` or `setGlobalPrefix`.
 *
 * @layer Controller
 */
@UseInterceptors(NoStoreInterceptor)
@Controller('invitations')
@UseGuards(TrustedOriginGuard, AuthRateLimitGuard)
@UsePipes(createAuthValidationPipe())
export class InvitationController {
  constructor(
    @Inject(InvitationService) private readonly invitationService: InvitationService,
    @Inject(TokenDeliveryService) private readonly tokenDelivery: TokenDeliveryService
  ) {}

  // ---------------------------------------------------------------------------
  // POST /invitations
  // ---------------------------------------------------------------------------

  /**
   * Creates an invitation for a new user to join the caller's tenant.
   *
   * The `tenantId` is extracted from the verified JWT payload — it is never read
   * from `dto` to prevent an authenticated attacker from inviting into a different
   * tenant by supplying a spoofed `tenantId` in the body.
   *
   * @param dto - Validated invitation payload (email, role, optional tenantName).
   * @param user - Verified JWT payload from the access token.
   */
  // `UserStatusGuard` alongside the JWT guard: minting an invitation delegates the caller's
  // authority, and a suspended admin still holding a live access token must not be able to
  // delegate what they no longer have. Without it there is a window of one access-token
  // lifetime after a suspension in which the account can still hand out roles.
  @UseGuards(JwtAuthGuard, UserStatusGuard)
  @Throttle(AUTH_THROTTLE_CONFIGS.invitationCreate)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.invitationCreate)
  @HttpCode(HttpStatus.NO_CONTENT)
  @Post()
  async invite(
    @Body() dto: CreateInvitationDto,
    @CurrentUser() user: DashboardJwtPayload
  ): Promise<void> {
    // tenantId comes from the JWT — not from the DTO body — to prevent tenant spoofing.
    await this.invitationService.invite(
      user.sub,
      dto.email,
      dto.role,
      user.tenantId,
      dto.tenantName
    )
  }

  // ---------------------------------------------------------------------------
  // POST /invitations/revoke
  // ---------------------------------------------------------------------------

  /**
   * Withdraws a pending invitation before it is accepted.
   *
   * An invitation provisions an account, at a role, inside a tenant, to whoever holds the
   * link — a credential in every sense, and until now one the library could mint but never
   * take back. A link sent to the wrong address stayed redeemable for its whole TTL.
   *
   * Answers `204` whether or not there was anything to withdraw. The caller asked for an
   * end state and gets it; reporting the difference would turn this into an oracle for
   * "does this address have a pending invitation".
   *
   * @param dto - Validated payload naming the invited address.
   * @param user - Verified JWT payload from the access token.
   */
  // Same guards as minting one: withdrawing an invitation is an authority decision, and a
  // suspended admin holding a live access token must not be making it either.
  @UseGuards(JwtAuthGuard, UserStatusGuard)
  @Throttle(AUTH_THROTTLE_CONFIGS.invitationRevoke)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.invitationRevoke)
  @HttpCode(HttpStatus.NO_CONTENT)
  @Post('revoke')
  async revoke(
    @Body() dto: RevokeInvitationDto,
    @CurrentUser() user: DashboardJwtPayload
  ): Promise<void> {
    // tenantId comes from the JWT — not from the DTO body — to prevent tenant spoofing.
    await this.invitationService.revokeInvitation(user.sub, dto.email, user.tenantId)
  }

  // ---------------------------------------------------------------------------
  // POST /invitations/accept
  // ---------------------------------------------------------------------------

  /**
   * Accepts a pending invitation, creates the new user account, and issues tokens.
   *
   * This endpoint is public and rate-limited. Token brute-forcing is mitigated by
   * the SHA-256 key lookup (wrong token never reveals stored data) and the per-IP
   * throttle applied by `AUTH_THROTTLE_CONFIGS.invitationAccept`.
   *
   * @param dto - Validated acceptance payload (token, name, password).
   * @param req - Incoming request (IP + User-Agent for session creation).
   * @param res - Response object (passthrough — used to set auth cookies).
   * @returns Auth response with tokens delivered per the configured `tokenDelivery` mode.
   */
  @Public()
  @Throttle(AUTH_THROTTLE_CONFIGS.invitationAccept)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.invitationAccept)
  @HttpCode(HttpStatus.CREATED)
  @Post('accept')
  async accept(
    @Body() dto: AcceptInvitationDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<CookieAuthResponse | BearerAuthResponse | BothAuthResponse> {
    const ip = req.ip ?? ''
    const userAgent = String(req.headers['user-agent'] ?? '')
    const headers = req.headers as Record<string, string | string[] | undefined>
    const result: AuthResult = await this.invitationService.acceptInvitation(
      dto,
      ip,
      userAgent,
      headers
    )
    return this.tokenDelivery.deliverAuthResponse(res, result, req)
  }
}
