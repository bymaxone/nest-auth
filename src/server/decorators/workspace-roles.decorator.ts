/**
 * @fileoverview `@WorkspaceRoles(...)`: the workspace roles a route accepts.
 *
 * @layer Decorator
 */

import { SetMetadata } from '@nestjs/common'

import type { ANY_WORKSPACE_MEMBER } from '../constants/workspace-roles'

/** Metadata key under which {@link WorkspaceRoles} stores the accepted roles. */
export const WORKSPACE_ROLES_KEY = 'workspaceRoles'

/**
 * Declares which roles may call a route, judged in the workspace the request names.
 *
 * A role is matched through `workspaces.roles.hierarchy`, so a role that includes another passes
 * wherever the included one does. `ANY_WORKSPACE_MEMBER` accepts every active member.
 *
 * `WorkspaceGuard` refuses a route that carries no declaration, and an empty list counts as none:
 * a guard that waved an undeclared route through would turn a forgotten decorator into open access.
 *
 * @param roles - The accepted roles, or the any-member marker.
 * @returns A method and class decorator.
 */
export const WorkspaceRoles = (
  ...roles: Array<string | typeof ANY_WORKSPACE_MEMBER>
): MethodDecorator & ClassDecorator => SetMetadata(WORKSPACE_ROLES_KEY, roles)
