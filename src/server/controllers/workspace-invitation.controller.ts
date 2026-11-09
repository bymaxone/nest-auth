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
  UseGuards,
  UseInterceptors,
  UsePipes
} from '@nestjs/common'
import { Throttle } from '@nestjs/throttler'
import type { Request } from 'express'

import { AUTH_THROTTLE_CONFIGS } from '../constants/throttle-configs'
import { AuthRateLimit } from '../decorators/auth-rate-limit.decorator'
import { CurrentUser } from '../decorators/current-user.decorator'
import { CurrentWorkspace } from '../decorators/current-workspace.decorator'
import type { CurrentWorkspaceContext } from '../decorators/current-workspace.decorator'
import { Public } from '../decorators/public.decorator'
import { WorkspacePermission } from '../decorators/workspace-permission.decorator'
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
import { WorkspaceInvitationService } from '../services/workspace-invitation.service'
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
    @Inject(WorkspaceInvitationService) private readonly invitations: WorkspaceInvitationService
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
