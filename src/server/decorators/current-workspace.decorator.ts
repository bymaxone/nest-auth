/**
 * @fileoverview `@CurrentWorkspace()`: the workspace and role `WorkspaceGuard` resolved for the
 * request.
 *
 * @layer Decorator
 */

import { createParamDecorator } from '@nestjs/common'
import type { ExecutionContext } from '@nestjs/common'

/** The access `WorkspaceGuard` resolved for a request. */
export interface CurrentWorkspaceContext {
  /** The tenant, taken from the verified token. */
  tenantId: string
  /** The workspace the request named, checked against the caller's active membership. */
  workspaceId: string
  /** The caller. */
  userId: string
  /** The caller's role in that workspace. */
  role: string
}

/** A request after `WorkspaceGuard` ran. */
export interface WorkspaceRequest {
  workspace?: CurrentWorkspaceContext
}

/**
 * Injects the workspace access the guard resolved.
 *
 * A service takes its workspace from here and never from a DTO or a query: the guard is the only
 * place that checked the caller may act in it. Throws when the route runs without
 * `WorkspaceGuard`, since an id read from anywhere else would be unchecked.
 */
export const CurrentWorkspace = createParamDecorator(
  (_data: unknown, context: ExecutionContext): CurrentWorkspaceContext => {
    const { workspace } = context.switchToHttp().getRequest<WorkspaceRequest>()
    if (workspace === undefined) {
      throw new Error('@CurrentWorkspace() needs WorkspaceGuard on the route.')
    }
    return workspace
  }
)
