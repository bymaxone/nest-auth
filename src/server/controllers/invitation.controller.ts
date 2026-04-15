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
import { AcceptInvitationDto } from '../dto/accept-invitation.dto'
import { CreateInvitationDto } from '../dto/create-invitation.dto'
import { JwtAuthGuard } from '../guards/jwt-auth.guard'
import type { AuthResult } from '../interfaces/auth-result.interface'
import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface'
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
 */
@Controller('invitations')
@UsePipes(new ValidationPipe({ whitelist: true }))
export class InvitationController {
  constructor(
    private readonly invitationService: InvitationService,
    private readonly tokenDelivery: TokenDeliveryService
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
  @UseGuards(JwtAuthGuard)
  @Throttle(AUTH_THROTTLE_CONFIGS.invitationCreate)
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
