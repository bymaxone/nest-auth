/**
 * @fileoverview The workspace invitation data the email provider specs hand to the provider.
 *
 * @layer Test
 */

import type { WorkspaceInviteData } from '../../interfaces/email-provider.interface'

/** An invitation to join a workspace that exists. */
export const WORKSPACE_INVITE: WorkspaceInviteData = {
  inviterName: 'Ada',
  workspaceName: 'Platform',
  role: 'admin',
  inviteToken: 'b'.repeat(64),
  expiresAt: new Date('2026-12-31T23:59:59.000Z'),
  accountExists: true,
  kind: 'member'
}

/** A platform invitation to own a workspace that does not exist yet. */
export const BOOTSTRAP_INVITE: WorkspaceInviteData = {
  ...WORKSPACE_INVITE,
  role: 'owner',
  kind: 'bootstrap'
}
