/**
 * @fileoverview The stored record of a workspace invitation and the shapes the invitation routes
 * answer with.
 *
 * @layer Interface
 */

/**
 * What Redis holds under `winv:{sha256(token)}`. The record is shared with rust-auth through
 * `conformance/wire-contract.json`.
 */
export interface StoredWorkspaceInvitation {
  /** The invited address, trimmed and lowercased. */
  email: string
  /** The workspace role the invitation grants. */
  role: string
  /** The tenant the workspace lives in. */
  tenantId: string
  /** The workspace the invitee joins. */
  workspaceId: string
  /** The member who issued the current token. */
  inviterUserId: string
  /** When the current token was issued, as an ISO-8601 instant. */
  createdAt: string
  /** How many times the invitation has been resent. */
  resendCount: number
}

/** One pending invitation as the list route shows it. The token is never part of it. */
export interface WorkspaceInvitationView {
  /** The invited address. */
  email: string
  /** The role the invitation grants. */
  role: string
  /** The member who issued the current token. */
  inviterUserId: string
  /** When the current token was issued. */
  createdAt: string
  /** When the current token stops being valid. */
  expiresAt: string
  /** How many times it has been resent. */
  resendCount: number
}

/** What a holder of a token may learn about it before signing in. */
export interface WorkspaceInvitationPreview {
  /** The workspace the invitation is for. */
  workspaceName: string
  /** The display name of the member who invited. */
  inviterName: string
  /** The role the invitation grants. */
  role: string
  /** The invited address with its local part masked. */
  maskedEmail: string
  /** Whether an account already exists for the address. */
  accountExists: boolean
}
