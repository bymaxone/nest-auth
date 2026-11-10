/**
 * @fileoverview `WorkspaceInvitationController`: invite, list, resend, revoke and preview, behind
 * `controllers.workspaceInvitations`.
 *
 * @layer Controller
 */

import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Inject,
  Post,
  Query,
  Req,
  Res,
  UseGuards,
  UseInterceptors,
  UsePipes
} from '@nestjs/common'
import { Throttle } from '@nestjs/throttler'
import type { Request, Response } from 'express'

import { AUTH_THROTTLE_CONFIGS } from '../constants/throttle-configs'
import { AuthRateLimit } from '../decorators/auth-rate-limit.decorator'
import { CurrentUser } from '../decorators/current-user.decorator'
import { CurrentWorkspace } from '../decorators/current-workspace.decorator'
import type { CurrentWorkspaceContext } from '../decorators/current-workspace.decorator'
import { Public } from '../decorators/public.decorator'
import { WorkspacePermission } from '../decorators/workspace-permission.decorator'
import { AcceptWorkspaceInvitationSignupDto } from '../dto/accept-workspace-invitation-signup.dto'
import { AcceptWorkspaceInvitationDto } from '../dto/accept-workspace-invitation.dto'
import { InviteToWorkspaceDto } from '../dto/invite-to-workspace.dto'
import { PreviewWorkspaceInvitationDto } from '../dto/preview-workspace-invitation.dto'
import { WorkspaceInvitationEmailDto } from '../dto/workspace-invitation-email.dto'
import { WorkspacePageQueryDto } from '../dto/workspace-page-query.dto'
import { AuthRateLimitGuard } from '../guards/auth-rate-limit.guard'
import { JwtAuthGuard } from '../guards/jwt-auth.guard'
import { RequestEncodingGuard } from '../guards/request-encoding.guard'
import { TrustedOriginGuard } from '../guards/trusted-origin.guard'
import { UserStatusGuard } from '../guards/user-status.guard'
import { WorkspaceGuard } from '../guards/workspace.guard'
import { NoStoreInterceptor } from '../interceptors/no-store.interceptor'
import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface'
import type { WorkspaceInvitationPreview } from '../interfaces/workspace-invitation.interface'
import type { WorkspaceRef } from '../interfaces/workspace-repository.interface'
import { createAuthValidationPipe } from '../pipes/auth-validation.pipe'
import type {
  BearerAuthResponse,
  BothAuthResponse,
  CookieAuthResponse
} from '../services/token-delivery.service'
import { TokenDeliveryService } from '../services/token-delivery.service'
import { WorkspaceInvitationAcceptService } from '../services/workspace-invitation-accept.service'
import type { AcceptedInvitation } from '../services/workspace-invitation-accept.service'
import { WorkspaceInvitationService } from '../services/workspace-invitation.service'
import { resolveClientAddress } from '../utils/client-address'
import { dashboardHookContext } from '../utils/request-hook-context'
import type { InvitationPage } from '../utils/workspace-invitation-page'

/**
 * Controller for inviting people into a workspace.
 *
 * Every route but the preview needs a verified dashboard access token and passes
 * {@link WorkspaceGuard}, which checks the caller's membership and the permission the route
 * declares. The preview is public: it answers what a token is for, and every token that cannot be
 * previewed gets the same answer.
 *
 * @remarks
 * Route prefix (`/workspaces`) is relative — the consuming application applies a global prefix.
 * Registered only with `controllers.workspaceInvitations: true`.
 *
 * @layer Controller
 */
@UseInterceptors(NoStoreInterceptor)
@Controller('workspaces')
@UseGuards(RequestEncodingGuard, TrustedOriginGuard, AuthRateLimitGuard)
@UsePipes(createAuthValidationPipe())
export class WorkspaceInvitationController {
  constructor(
    @Inject(WorkspaceInvitationService) private readonly invitations: WorkspaceInvitationService,
    @Inject(WorkspaceInvitationAcceptService)
    private readonly accepts: WorkspaceInvitationAcceptService,
    @Inject(TokenDeliveryService) private readonly tokenDelivery: TokenDeliveryService
  ) {}

  /**
   * Invites an address to the workspace, or resends to one already invited.
   *
   * @param workspace - The access the guard resolved.
   * @param user - Verified JWT payload from the access token.
   * @param dto - The invitee and the role.
   * @param req - Incoming request, for the hook context.
   */
  @UseGuards(JwtAuthGuard, UserStatusGuard, WorkspaceGuard)
  @WorkspacePermission('manageMembers')
  @Throttle(AUTH_THROTTLE_CONFIGS.workspaceInvite)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.workspaceInvite)
  @HttpCode(HttpStatus.NO_CONTENT)
  @Post(':workspaceId/invitations')
  async invite(
    @CurrentWorkspace() workspace: CurrentWorkspaceContext,
    @CurrentUser() user: DashboardJwtPayload,
    @Body() dto: InviteToWorkspaceDto,
    @Req() req: Request
  ): Promise<void> {
    await this.invitations.invite(
      refOf(workspace),
      actorOf(workspace),
      dto.email,
      dto.role,
      dashboardHookContext(req, user)
    )
  }

  /**
   * Lists the workspace's pending invitations, oldest first.
   *
   * @param workspace - The access the guard resolved.
   * @param query - The cursor and page size.
   * @returns One page.
   */
  @UseGuards(JwtAuthGuard, UserStatusGuard, WorkspaceGuard)
  @WorkspacePermission('manageMembers')
  @Throttle(AUTH_THROTTLE_CONFIGS.workspaceInvitations)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.workspaceInvitations)
  @Get(':workspaceId/invitations')
  async list(
    @CurrentWorkspace() workspace: CurrentWorkspaceContext,
    @Query() query: WorkspacePageQueryDto
  ): Promise<InvitationPage> {
    return this.invitations.list(refOf(workspace), pageOf(query))
  }

  /**
   * Sends a pending invitation again under a new token.
   *
   * @param workspace - The access the guard resolved.
   * @param user - Verified JWT payload from the access token.
   * @param dto - The invitee.
   * @param req - Incoming request, for the hook context.
   */
  @UseGuards(JwtAuthGuard, UserStatusGuard, WorkspaceGuard)
  @WorkspacePermission('manageMembers')
  @Throttle(AUTH_THROTTLE_CONFIGS.workspaceInvitationResend)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.workspaceInvitationResend)
  @HttpCode(HttpStatus.NO_CONTENT)
  @Post(':workspaceId/invitations/resend')
  async resend(
    @CurrentWorkspace() workspace: CurrentWorkspaceContext,
    @CurrentUser() user: DashboardJwtPayload,
    @Body() dto: WorkspaceInvitationEmailDto,
    @Req() req: Request
  ): Promise<void> {
    await this.invitations.resend(
      refOf(workspace),
      actorOf(workspace),
      dto.email,
      dashboardHookContext(req, user)
    )
  }

  /**
   * Withdraws a pending invitation.
   *
   * @param workspace - The access the guard resolved.
   * @param user - Verified JWT payload from the access token.
   * @param dto - The invitee.
   * @param req - Incoming request, for the hook context.
   */
  @UseGuards(JwtAuthGuard, UserStatusGuard, WorkspaceGuard)
  @WorkspacePermission('manageMembers')
  @Throttle(AUTH_THROTTLE_CONFIGS.workspaceInvitationRevoke)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.workspaceInvitationRevoke)
  @HttpCode(HttpStatus.NO_CONTENT)
  @Post(':workspaceId/invitations/revoke')
  async revoke(
    @CurrentWorkspace() workspace: CurrentWorkspaceContext,
    @CurrentUser() user: DashboardJwtPayload,
    @Body() dto: WorkspaceInvitationEmailDto,
    @Req() req: Request
  ): Promise<void> {
    await this.invitations.revoke(
      refOf(workspace),
      actorOf(workspace),
      dto.email,
      dashboardHookContext(req, user)
    )
  }

  /**
   * Tells a token holder what the token is for, without signing in.
   *
   * @param dto - The token.
   * @returns The workspace, the inviter, the role, the masked address and whether an account exists.
   * @throws {AuthException} `auth.invalid_invitation_token` for every token that cannot be
   *   previewed, whatever the reason.
   */
  @Public()
  @Throttle(AUTH_THROTTLE_CONFIGS.workspaceInvitationPreview)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.workspaceInvitationPreview)
  @HttpCode(HttpStatus.OK)
  @Post('invitations/preview')
  async preview(@Body() dto: PreviewWorkspaceInvitationDto): Promise<WorkspaceInvitationPreview> {
    return this.invitations.preview(dto.token)
  }

  /**
   * Accepts an invitation as the signed-in account it was addressed to.
   *
   * @param user - Verified JWT payload from the access token.
   * @param dto - The token.
   * @param req - Incoming request, for the hook context.
   * @returns The workspace the caller joined and the role they hold there.
   * @throws {AuthException} `auth.invalid_invitation_token` for any token that cannot be honoured;
   *   `auth.invitation_email_mismatch` or `auth.email_not_verified` for a caller the invitation
   *   is not addressed to, with the token left unspent.
   */
  @UseGuards(JwtAuthGuard, UserStatusGuard)
  @Throttle(AUTH_THROTTLE_CONFIGS.workspaceInvitationAccept)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.workspaceInvitationAccept)
  @HttpCode(HttpStatus.OK)
  @Post('invitations/accept')
  async accept(
    @CurrentUser() user: DashboardJwtPayload,
    @Body() dto: AcceptWorkspaceInvitationDto,
    @Req() req: Request
  ): Promise<AcceptedInvitation> {
    return this.accepts.accept(user, dto.token, dashboardHookContext(req, user))
  }

  /**
   * Accepts an invitation by creating the account it was addressed to, and signs that account in.
   *
   * @param dto - The token and the new account's name and password.
   * @param req - Incoming request, for the session and the hook.
   * @param res - Response, for the cookies the delivery mode sets.
   * @returns The session in the configured delivery mode, with the workspace joined and the role.
   * @throws {AuthException} `auth.invalid_invitation_token`; `auth.email_already_exists` when the
   *   address already has an account, which then accepts by signing in; and the password policy.
   */
  @Public()
  @Throttle(AUTH_THROTTLE_CONFIGS.workspaceInvitationAcceptSignup)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.workspaceInvitationAcceptSignup)
  @HttpCode(HttpStatus.CREATED)
  @Post('invitations/accept-signup')
  async acceptSignup(
    @Body() dto: AcceptWorkspaceInvitationSignupDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<(CookieAuthResponse | BearerAuthResponse | BothAuthResponse) & AcceptedInvitation> {
    const request = {
      ip: resolveClientAddress(req),
      userAgent: String(req.headers['user-agent'] ?? ''),
      headers: req.headers as Record<string, string | string[] | undefined>
    }
    const { result, accepted } = await this.accepts.acceptSignup(dto, request)
    return { ...this.tokenDelivery.deliverAuthResponse(res, result, req), ...accepted }
  }
}

/** Reads the page parameters a request carried; each is present only when the request gave one. */
function pageOf(query: WorkspacePageQueryDto): { cursor?: string; limit?: number } {
  return {
    ...(query.cursor === undefined ? {} : { cursor: query.cursor }),
    ...(query.limit === undefined ? {} : { limit: Number(query.limit) })
  }
}

/** The key of the workspace the guard admitted the caller to. */
function refOf(workspace: CurrentWorkspaceContext): WorkspaceRef {
  return { tenantId: workspace.tenantId, workspaceId: workspace.workspaceId }
}

/** The acting member as the guard resolved them. */
function actorOf(workspace: CurrentWorkspaceContext): { userId: string; role: string } {
  return { userId: workspace.userId, role: workspace.role }
}
