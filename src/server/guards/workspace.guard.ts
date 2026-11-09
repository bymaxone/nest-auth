/**
 * @fileoverview `WorkspaceGuard`: lets a request through only for a workspace it names explicitly,
 * in which the caller is an active member holding an accepted role.
 *
 * @layer Guard
 */

import { Inject, Injectable } from '@nestjs/common'
import type { CanActivate, ExecutionContext } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import type { Request } from 'express'

import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import type { ResolvedWorkspaceOptions } from '../config/workspace-options'
import { ANY_WORKSPACE_MEMBER } from '../constants/workspace-roles'
import type { WorkspaceRequest } from '../decorators/current-workspace.decorator'
import { WORKSPACE_ROLES_KEY } from '../decorators/workspace-roles.decorator'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface'
import { WorkspaceAccessService } from '../services/workspace-access.service'
import { resolveRequestWorkspace } from '../utils/resolve-request-workspace'
import { hasRole } from '../utils/roles.util'

type GuardedRequest = Request & WorkspaceRequest & { user?: DashboardJwtPayload }

/** What a route may declare: role names and the any-member marker. */
type AcceptedRole = string | typeof ANY_WORKSPACE_MEMBER

/**
 * Authorizes a request in the workspace it names.
 *
 * Run it after `JwtAuthGuard` and `UserStatusGuard`. In order it:
 *
 * 1. refuses a route that declares no `@WorkspaceRoles(...)`, with `403 auth.forbidden`, before any
 *    lookup, so a forgotten decorator closes the route rather than opening it;
 * 2. refuses anything but a verified dashboard token. A platform token is refused outright: there
 *    is no implicit bypass for platform operators;
 * 3. resolves the workspace from the route or the host's resolver (never the body, never a
 *    remembered default);
 * 4. resolves the caller's membership with the tenant taken from the token. A workspace that does
 *    not exist, one that is not active and one the caller does not belong to all answer
 *    `404 auth.workspace_not_found`, so the answer reveals nothing about which workspaces exist;
 * 5. checks the role through `workspaces.roles.hierarchy`, answering `403
 *    auth.insufficient_workspace_role` when it is below what the route declares;
 * 6. attaches the access to `request.workspace` for `@CurrentWorkspace()`.
 */
@Injectable()
export class WorkspaceGuard implements CanActivate {
  private readonly group: ResolvedWorkspaceOptions

  constructor(
    @Inject(Reflector) private readonly reflector: Reflector,
    @Inject(WorkspaceAccessService) private readonly access: WorkspaceAccessService,
    @Inject(BYMAX_AUTH_OPTIONS) options: ResolvedOptions
  ) {
    if (options.workspaces === undefined) {
      throw new Error('[BymaxAuthModule] WorkspaceGuard needs workspaces.enabled.')
    }
    this.group = options.workspaces
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const accepted = this.declaredRoles(context)
    const request = context.switchToHttp().getRequest<GuardedRequest>()
    const user = request.user
    if (user?.type !== 'dashboard' || !hasText(user.sub) || !hasText(user.tenantId)) {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    const workspaceId = resolveRequestWorkspace(request, this.group.resolveRequestWorkspace)
    const member = await this.access.resolveMembership({
      tenantId: user.tenantId,
      workspaceId,
      userId: user.sub
    })
    if (member === null) throw new AuthException(AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND)
    if (!this.accepts(accepted, member.role)) {
      throw new AuthException(AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE)
    }

    request.workspace = { ...member }
    return true
  }

  private declaredRoles(context: ExecutionContext): AcceptedRole[] {
    const roles = this.reflector.getAllAndOverride<AcceptedRole[] | undefined>(
      WORKSPACE_ROLES_KEY,
      [context.getHandler(), context.getClass()]
    )
    if (roles === undefined || roles.length === 0) {
      throw new AuthException(AUTH_ERROR_CODES.FORBIDDEN)
    }
    return roles
  }

  private accepts(accepted: AcceptedRole[], role: string): boolean {
    const { hierarchy } = this.group.roles
    return accepted.some(
      (required) =>
        required === ANY_WORKSPACE_MEMBER ||
        (typeof required === 'string' && hasRole(role, required, hierarchy))
    )
  }
}

/**
 * Whether a token claim is a non-blank string.
 *
 * @param value - The claim.
 * @returns `true` for a string with a visible character.
 */
function hasText(value: unknown): value is string {
  return typeof value === 'string' && value.trim() !== ''
}
