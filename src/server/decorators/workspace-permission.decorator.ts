/**
 * @fileoverview `@WorkspacePermission(action)`: a route accepts the roles `workspaces.permissions`
 * names for an action.
 *
 * @layer Decorator
 */

import { SetMetadata } from '@nestjs/common'

import type { WorkspacePermissionOptions } from '../interfaces/workspace-options.interface'

/** Metadata key under which {@link WorkspacePermission} stores the action. */
export const WORKSPACE_PERMISSION_KEY = 'workspacePermission'

/** A workspace-level action whose roles the host configures in `workspaces.permissions`. */
export type WorkspaceAction = keyof WorkspacePermissionOptions

/**
 * Declares that a route accepts the roles configured for an action, judged in the workspace the
 * request names.
 *
 * The roles are read from `workspaces.permissions` when the request arrives, so a host that
 * changes who may manage members changes every route that declares that action. It is the
 * alternative to `@WorkspaceRoles(...)`: one target declares one of the two, and a target that
 * declares both is refused as undeclared, because the guard cannot know which one was meant.
 *
 * @param action - The action the route performs.
 * @returns A method and class decorator.
 */
export const WorkspacePermission = (action: WorkspaceAction): MethodDecorator & ClassDecorator =>
  SetMetadata(WORKSPACE_PERMISSION_KEY, action)
