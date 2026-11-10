/**
 * @fileoverview Which source file writes each workspace Redis prefix the wire contract declares.
 *
 * @layer Test
 */

/** The prefixes of the workspace-membership cache and of workspace invitations, by contract name. */
export const WORKSPACE_PREFIX_SOURCES: Readonly<Record<string, string>> = {
  workspaceVersion: 'constants/workspace-keys.ts',
  membershipVersion: 'constants/workspace-keys.ts',
  membershipCache: 'constants/workspace-keys.ts',
  workspaceInvitation: 'constants/workspace-invitation-keys.ts',
  workspaceInvitationIndex: 'constants/workspace-invitation-keys.ts',
  workspaceInvitationSet: 'constants/workspace-invitation-keys.ts',
  workspaceInvitationInviterRate: 'constants/workspace-invitation-keys.ts'
}
