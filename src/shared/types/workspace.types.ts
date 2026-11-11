/**
 * Workspace shapes as the server answers them, for the client, React and Next.js entry points.
 *
 * Each type mirrors a view the server builds, key for key; a spec on the server side compares them,
 * so a field added on one side only is a red test and not a runtime surprise. A role is a plain
 * string: the hierarchy that gives roles their meaning is the host's configuration and is not
 * shipped to the browser.
 */

/** The lifecycle state of a workspace. */
export type WorkspaceStatusClient = 'active' | 'pending_deletion' | 'suspended' | 'deleted'

/** The state of one membership. */
export type MembershipStatusClient = 'active' | 'suspended'

/** A workspace. */
export interface WorkspaceClient {
  id: string
  name: string
  status: WorkspaceStatusClient
  /** ISO-8601 instant. */
  createdAt: string
  /** When a scheduled deletion becomes final, `null` when none is scheduled. */
  deletionScheduledAt: string | null
}

/** A workspace and the caller's role in it. */
export interface WorkspaceAccessClient {
  workspace: WorkspaceClient
  role: string
}

/** One page of the caller's own workspaces. */
export interface WorkspaceListResult {
  items: WorkspaceAccessClient[]
  /** The cursor of the next page, `null` on the last one. */
  nextCursor: string | null
  /** The workspace the caller last switched to, `null` when none. */
  lastActiveWorkspaceId: string | null
}

/** A member of a workspace. */
export interface WorkspaceMemberClient {
  userId: string
  role: string
  status: MembershipStatusClient
  invitedByUserId: string | null
  /** ISO-8601 instant. */
  createdAt: string
}

/** One page of a workspace's members. */
export interface WorkspaceMemberPage {
  items: WorkspaceMemberClient[]
  nextCursor: string | null
}

/** A pending invitation to a workspace. */
export interface WorkspaceInvitationClient {
  email: string
  role: string
  inviterUserId: string
  /** ISO-8601 instant. */
  createdAt: string
  /** ISO-8601 instant. */
  expiresAt: string
  resendCount: number
}

/** One page of a workspace's pending invitations. */
export interface WorkspaceInvitationPage {
  items: WorkspaceInvitationClient[]
  nextCursor: string | null
}

interface InvitationPreviewBase {
  workspaceName: string
  role: string
  /** The invited address with its local part masked. */
  maskedEmail: string
  /** Whether the invited address already has an account, so the page offers sign-in or sign-up. */
  accountExists: boolean
}

/** What a member invitation is for. */
export interface MemberInvitationPreviewClient extends InvitationPreviewBase {
  kind: 'member'
  inviterName: string
}

/** What the invitation that creates a workspace's first owner is for. */
export interface BootstrapInvitationPreviewClient extends InvitationPreviewBase {
  kind: 'bootstrap'
}

/** What an invitation token is for, without signing in. */
export type WorkspaceInvitationPreview =
  MemberInvitationPreviewClient | BootstrapInvitationPreviewClient

/** Where an accepted invitation put the caller. */
export interface AcceptedWorkspaceInvitation {
  workspaceId: string
  role: string
}

/** The page parameters of a list. */
export interface WorkspacePageParams {
  cursor?: string
  /** A positive whole number; the server clamps it to its own bounds. */
  limit?: number
}
