import {
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
import { ANY_WORKSPACE_MEMBER } from '../constants/workspace-roles'
import { AuthRateLimit } from '../decorators/auth-rate-limit.decorator'
import { CurrentUser } from '../decorators/current-user.decorator'
import { CurrentWorkspace } from '../decorators/current-workspace.decorator'
import type { CurrentWorkspaceContext } from '../decorators/current-workspace.decorator'
import { RequestEncoding } from '../decorators/request-encoding.decorator'
import { WorkspacePermission } from '../decorators/workspace-permission.decorator'
import { WorkspaceRoles } from '../decorators/workspace-roles.decorator'
import { WorkspacePageQueryDto } from '../dto/workspace-page-query.dto'
import { AuthRateLimitGuard } from '../guards/auth-rate-limit.guard'
import { JwtAuthGuard } from '../guards/jwt-auth.guard'
import { RequestEncodingGuard } from '../guards/request-encoding.guard'
import { TrustedOriginGuard } from '../guards/trusted-origin.guard'
import { UserStatusGuard } from '../guards/user-status.guard'
import { WorkspaceGuard } from '../guards/workspace.guard'
import { NoStoreInterceptor } from '../interceptors/no-store.interceptor'
import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface'
import type { WorkspaceRef } from '../interfaces/workspace-repository.interface'
import { createAuthValidationPipe } from '../pipes/auth-validation.pipe'
import { MembershipService } from '../services/membership.service'
import { WorkspaceService } from '../services/workspace.service'
import { dashboardHookContext } from '../utils/request-hook-context'
import {
  toAccessResponse,
  toMembersResponse,
  toMyWorkspacesResponse
} from '../utils/workspace-views'
import type {
  MembersResponse,
  MyWorkspacesResponse,
  WorkspaceAccessResponse
} from '../utils/workspace-views'

// ---------------------------------------------------------------------------
// WorkspaceController
// ---------------------------------------------------------------------------

/**
 * Controller for the workspaces a signed-in identity belongs to: who they are in each, and who
 * else belongs to the ones they may see.
 *
 * Every route needs a verified dashboard access token. A route under `:workspaceId` is also behind
 * {@link WorkspaceGuard}, which checks the caller's active membership in that workspace and the
 * roles the route declares; the workspace a request acts in is always the path segment, never the
 * body, a query or a remembered default. The two lists answer only the caller's own data: their
 * memberships, or the members of a workspace the guard admitted them to, so neither enumerates.
 *
 * @remarks
 * Route prefix (`/workspaces`) is relative — the consuming application applies a global prefix
 * (e.g. `/auth`) via `RouterModule` or `setGlobalPrefix`. Registered only with
 * `controllers.workspaces: true`.
 *
 * @layer Controller
 */
@UseInterceptors(NoStoreInterceptor)
@Controller('workspaces')
// One decorator, in the order every other controller uses: the rate limiter runs before the token
// is verified, so a flood of bad tokens is metered.
@UseGuards(
  RequestEncodingGuard,
  TrustedOriginGuard,
  AuthRateLimitGuard,
  JwtAuthGuard,
  UserStatusGuard
)
@UsePipes(createAuthValidationPipe())
export class WorkspaceController {
  constructor(
    @Inject(WorkspaceService) private readonly workspaces: WorkspaceService,
    @Inject(MembershipService) private readonly memberships: MembershipService
  ) {}

  // ---------------------------------------------------------------------------
  // GET /workspaces
  // ---------------------------------------------------------------------------

  /**
   * Lists the caller's own active memberships and the workspace they last switched to.
   *
   * Only the caller's memberships are ever listed: the tenant and the member come from the token,
   * and the cursor only says where the next page starts.
   *
   * @param user - Verified JWT payload from the access token.
   * @param query - The cursor and page size.
   * @returns One page, and the last active workspace id, `null` when none is recorded.
   */
  @Throttle(AUTH_THROTTLE_CONFIGS.workspaceList)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.workspaceList)
  @Get()
  async list(
    @CurrentUser() user: DashboardJwtPayload,
    @Query() query: WorkspacePageQueryDto
  ): Promise<MyWorkspacesResponse> {
    return toMyWorkspacesResponse(
      await this.memberships.listMine(user.tenantId, user.sub, pageOf(query))
    )
  }

  // ---------------------------------------------------------------------------
  // GET /workspaces/:workspaceId/access
  // ---------------------------------------------------------------------------

  /**
   * Reads a workspace and the caller's role in it, for server-side rendering and clients.
   *
   * @param workspace - The access the guard resolved.
   * @returns The workspace and the caller's role.
   */
  @UseGuards(WorkspaceGuard)
  @WorkspaceRoles(ANY_WORKSPACE_MEMBER)
  @Throttle(AUTH_THROTTLE_CONFIGS.workspaceAccess)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.workspaceAccess)
  @Get(':workspaceId/access')
  async access(
    @CurrentWorkspace() workspace: CurrentWorkspaceContext
  ): Promise<WorkspaceAccessResponse> {
    return toAccessResponse(await this.workspaces.getAccess(refOf(workspace), workspace.userId))
  }

  // ---------------------------------------------------------------------------
  // POST /workspaces/:workspaceId/switch
  // ---------------------------------------------------------------------------

  /**
   * Records the workspace as the caller's last active one and reports the switch.
   *
   * Nothing about the session changes: the token carries no workspace.
   *
   * @param workspace - The access the guard resolved.
   * @param user - Verified JWT payload from the access token.
   * @param req - Incoming request, for the hook context.
   */
  @UseGuards(WorkspaceGuard)
  @WorkspaceRoles(ANY_WORKSPACE_MEMBER)
  @Throttle(AUTH_THROTTLE_CONFIGS.workspaceSwitch)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.workspaceSwitch)
  @HttpCode(HttpStatus.NO_CONTENT)
  @RequestEncoding('when-body')
  @Post(':workspaceId/switch')
  async switchTo(
    @CurrentWorkspace() workspace: CurrentWorkspaceContext,
    @CurrentUser() user: DashboardJwtPayload,
    @Req() req: Request
  ): Promise<void> {
    await this.workspaces.switchTo(
      refOf(workspace),
      workspace.userId,
      dashboardHookContext(req, user)
    )
  }

  // ---------------------------------------------------------------------------
  // GET /workspaces/:workspaceId/members
  // ---------------------------------------------------------------------------

  /**
   * Lists the members of a workspace, in every membership status.
   *
   * Reached only by a caller the guard admitted to this workspace with a role that
   * `workspaces.permissions.viewMembers` accepts; the cursor says where the next page starts and
   * never which workspace is listed.
   *
   * @param workspace - The access the guard resolved.
   * @param query - The cursor and page size.
   * @returns One page of members.
   */
  @UseGuards(WorkspaceGuard)
  @WorkspacePermission('viewMembers')
  @Throttle(AUTH_THROTTLE_CONFIGS.workspaceMembers)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.workspaceMembers)
  @Get(':workspaceId/members')
  async members(
    @CurrentWorkspace() workspace: CurrentWorkspaceContext,
    @Query() query: WorkspacePageQueryDto
  ): Promise<MembersResponse> {
    return toMembersResponse(await this.memberships.listMembers(refOf(workspace), pageOf(query)))
  }
}

/**
 * Reads the page parameters a request carried.
 *
 * @param query - The validated query.
 * @returns The cursor and size, each present only when the request gave one.
 */
function pageOf(query: WorkspacePageQueryDto): { cursor?: string; limit?: number } {
  return {
    ...(query.cursor === undefined ? {} : { cursor: query.cursor }),
    ...(query.limit === undefined ? {} : { limit: Number(query.limit) })
  }
}

/**
 * The key of the workspace the guard admitted the caller to.
 *
 * Only the two halves of the key go to a service: the caller and their role stay out of what a
 * repository or an event receives.
 *
 * @param workspace - The access the guard resolved.
 * @returns The tenant and workspace.
 */
function refOf(workspace: CurrentWorkspaceContext): WorkspaceRef {
  return { tenantId: workspace.tenantId, workspaceId: workspace.workspaceId }
}
