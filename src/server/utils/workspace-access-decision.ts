/**
 * @fileoverview The one decision every surface makes about a resolved workspace access: a route's
 * guard, a stream's verification and a socket's per-message check refuse in the same order with
 * the same answers, because they all call this.
 *
 * @layer Utility
 */

import { hasRole } from './roles.util'
import { ANY_WORKSPACE_MEMBER } from '../constants/workspace-roles'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { WorkspaceAccessRefusal } from '../errors/workspace-access-refusal'
import type { WorkspaceRoleList } from '../interfaces/workspace-options.interface'
import type { ResolvedWorkspaceMember, WorkspaceAccess } from '../services/workspace-access.service'

/** Whether `role` satisfies at least one of the accepted roles. */
export function acceptsWorkspaceRole(
  accepted: WorkspaceRoleList,
  role: string,
  hierarchy: Record<string, string[]>
): boolean {
  return accepted.some((required) => {
    if (required === ANY_WORKSPACE_MEMBER) return true
    return hasRole(role, required, hierarchy)
  })
}

/**
 * Turns a resolved access into the member it admits, or refuses it.
 *
 * The order is fixed: a caller who is not an active member of an active workspace, or who is a
 * member of one pending deletion without owning it, gets the identical `workspace_not_found`,
 * decided from the rows already read; the owner of a workspace pending deletion gets
 * `workspace_pending_deletion` unless the surface admits it; and only then is the role judged. The
 * disclosure rule lives in the resolution itself, which reports a pending workspace to its owner
 * only, so nothing here can tell a non-owner more.
 *
 * @param access - What {@link WorkspaceAccessService.resolveAccess} returned.
 * @param accepted - The roles the surface accepts.
 * @param hierarchy - The configured role hierarchy.
 * @param allowPending - Whether the owner of a workspace pending deletion is admitted.
 * @returns The member, with the role they hold.
 * @throws {WorkspaceAccessRefusal} `auth.workspace_not_found`, `auth.workspace_pending_deletion` or
 *   `auth.insufficient_workspace_role`.
 */
export function assertWorkspaceAccess(
  access: WorkspaceAccess,
  accepted: WorkspaceRoleList,
  hierarchy: Record<string, string[]>,
  allowPending: boolean
): ResolvedWorkspaceMember {
  if (access.kind === 'denied') {
    throw new WorkspaceAccessRefusal(
      AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND,
      access.pendingDeletion === true ? 'pending_deletion' : 'not_member'
    )
  }
  if (access.kind === 'pending_deletion' && !allowPending) {
    throw new WorkspaceAccessRefusal(
      AUTH_ERROR_CODES.WORKSPACE_PENDING_DELETION,
      'pending_deletion'
    )
  }
  if (!acceptsWorkspaceRole(accepted, access.member.role, hierarchy)) {
    throw new WorkspaceAccessRefusal(
      AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE,
      'insufficient_role'
    )
  }
  return access.member
}
