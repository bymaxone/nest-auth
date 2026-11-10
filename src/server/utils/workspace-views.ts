/**
 * @fileoverview The wire shapes of the workspace read routes.
 *
 * What the ports return carries the tenant and every column the host stores; a route answers only
 * what the caller needs, with dates as ISO strings. The tenant is the caller's own and is not
 * repeated.
 *
 * @layer Util
 */

import type {
  AuthMembership,
  MembershipWithWorkspace
} from '../interfaces/membership-repository.interface'
import type { AuthWorkspace } from '../interfaces/workspace-repository.interface'
import type { MyWorkspaces } from '../services/membership.service'
import type { WorkspaceAccessView } from '../services/workspace.service'

/** A workspace as a route answers it. */
export interface WorkspaceView {
  id: string
  name: string
  status: AuthWorkspace['status']
  createdAt: string
  /** When a scheduled deletion becomes final, `null` when none is scheduled. */
  deletionScheduledAt: string | null
}

/** The workspace a caller reached and their role in it. */
export interface WorkspaceAccessResponse {
  workspace: WorkspaceView
  role: string
}

/** One page of the caller's own memberships. */
export interface MyWorkspacesResponse {
  items: WorkspaceAccessResponse[]
  nextCursor: string | null
  lastActiveWorkspaceId: string | null
}

/** One member of a workspace. */
export interface MemberView {
  userId: string
  role: string
  status: AuthMembership['status']
  invitedByUserId: string | null
  createdAt: string
}

/** One page of a workspace's members. */
export interface MembersResponse {
  items: MemberView[]
  nextCursor: string | null
}

/**
 * Shapes a workspace.
 *
 * @param workspace - The workspace as the port returned it.
 * @returns The wire shape.
 */
export function toWorkspaceView(workspace: AuthWorkspace): WorkspaceView {
  return {
    id: workspace.id,
    name: workspace.name,
    status: workspace.status,
    createdAt: workspace.createdAt.toISOString(),
    deletionScheduledAt: workspace.deletionScheduledAt?.toISOString() ?? null
  }
}

/**
 * Shapes the workspace a caller reached and their role.
 *
 * @param view - What the service returned.
 * @returns The wire shape.
 */
export function toAccessResponse(view: WorkspaceAccessView): WorkspaceAccessResponse {
  return { workspace: toWorkspaceView(view.workspace), role: view.role }
}

/**
 * Shapes a page of the caller's own memberships.
 *
 * @param page - What the service returned.
 * @returns The wire shape.
 */
export function toMyWorkspacesResponse(page: MyWorkspaces): MyWorkspacesResponse {
  return {
    items: page.items.map((item: MembershipWithWorkspace) => ({
      workspace: toWorkspaceView(item.workspace),
      role: item.role
    })),
    nextCursor: page.nextCursor,
    lastActiveWorkspaceId: page.lastActiveWorkspaceId
  }
}

/**
 * Shapes one member of a workspace.
 *
 * @param member - The membership as the port returned it.
 * @returns The wire shape.
 */
export function toMemberView(member: AuthMembership): MemberView {
  return {
    userId: member.userId,
    role: member.role,
    status: member.status,
    invitedByUserId: member.invitedByUserId,
    createdAt: member.createdAt.toISOString()
  }
}

/**
 * Shapes a page of a workspace's members.
 *
 * @param page - What the service returned.
 * @returns The wire shape.
 */
export function toMembersResponse(page: {
  items: AuthMembership[]
  nextCursor: string | null
}): MembersResponse {
  return {
    items: page.items.map(toMemberView),
    nextCursor: page.nextCursor
  }
}
