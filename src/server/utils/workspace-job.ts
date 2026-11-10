/**
 * @fileoverview Stamps the context a queued job carries.
 *
 * @layer Utility
 */

import type { CurrentWorkspaceContext } from '../decorators/current-workspace.decorator'
import type { WorkspaceJobContext } from '../interfaces/workspace-job-context.interface'

/**
 * Builds the context to put on a job from the workspace a guarded request resolved.
 *
 * @param workspace - What `@CurrentWorkspace()` returned.
 * @returns The tenant, the workspace and the account, and nothing else: the role is deliberately
 *   not carried, because the worker asks again what the account may do now.
 */
export function stampJobContext(workspace: CurrentWorkspaceContext): WorkspaceJobContext {
  return {
    tenantId: workspace.tenantId,
    workspaceId: workspace.workspaceId,
    actorUserId: workspace.userId
  }
}
