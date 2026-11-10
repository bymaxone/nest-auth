/**
 * @fileoverview Reads what a route or a message handler declares about the workspace roles it
 * accepts, for every guard that admits a caller to a workspace.
 *
 * @layer Utility
 */

import type { ExecutionContext } from '@nestjs/common'
import type { Reflector } from '@nestjs/core'

import type { ResolvedWorkspaceOptions } from '../config/workspace-options'
import { ALLOW_PENDING_WORKSPACE_KEY } from '../decorators/allow-pending-workspace.decorator'
import {
  WORKSPACE_PERMISSION_KEY,
  type WorkspaceAction
} from '../decorators/workspace-permission.decorator'
import { WORKSPACE_ROLES_KEY } from '../decorators/workspace-roles.decorator'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { WorkspaceRoleList } from '../interfaces/workspace-options.interface'

/**
 * Whether the handler or its class carries `@AllowPendingWorkspace()`.
 *
 * @param reflector - Nest's reflector.
 * @param context - The execution context.
 */
export function admitsPendingWorkspace(reflector: Reflector, context: ExecutionContext): boolean {
  return (
    reflector.getAllAndOverride<boolean | undefined>(ALLOW_PENDING_WORKSPACE_KEY, [
      context.getHandler(),
      context.getClass()
    ]) === true
  )
}

/**
 * The roles a target accepts: those it declares, or those configured for the action it declares.
 * The handler's declaration replaces the class's; a target that declares both is undeclared.
 *
 * @param reflector - Nest's reflector.
 * @param context - The execution context.
 * @param permissions - The resolved `workspaces.permissions`.
 * @returns The accepted roles.
 * @throws {AuthException} `auth.forbidden` for a target that declares none, so a forgotten
 *   decorator closes the surface rather than opening it.
 */
export function declaredWorkspaceRoles(
  reflector: Reflector,
  context: ExecutionContext,
  permissions: ResolvedWorkspaceOptions['permissions']
): WorkspaceRoleList {
  for (const target of [context.getHandler(), context.getClass()]) {
    const roles = reflector.get<WorkspaceRoleList | undefined>(WORKSPACE_ROLES_KEY, target)
    const action = reflector.get<WorkspaceAction | undefined>(WORKSPACE_PERMISSION_KEY, target)
    if (roles !== undefined && action !== undefined) break
    const declared = action === undefined ? roles : permittedRoles(permissions, action)
    if (declared !== undefined && declared.length > 0) return [...declared]
    if (declared !== undefined) break
  }
  throw new AuthException(AUTH_ERROR_CODES.FORBIDDEN)
}

/**
 * The roles configured for an action.
 *
 * @param permissions - The resolved `workspaces.permissions`.
 * @param action - The action a route declared.
 * @returns The roles that may perform it.
 */
function permittedRoles(
  permissions: ResolvedWorkspaceOptions['permissions'],
  action: WorkspaceAction
): WorkspaceRoleList {
  switch (action) {
    case 'manageWorkspace':
      return permissions.manageWorkspace
    case 'deleteWorkspace':
      return permissions.deleteWorkspace
    case 'manageMembers':
      return permissions.manageMembers
    case 'viewMembers':
      return permissions.viewMembers
  }
}
