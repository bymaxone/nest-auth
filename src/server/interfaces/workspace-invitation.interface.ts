/**
 * @fileoverview The stored record of a workspace invitation and the shapes the invitation routes
 * answer with.
 *
 * @layer Interface
 */

/** The fields both kinds of stored invitation carry. */
interface InvitationRecordBase {
  /** The invited address, trimmed and lowercased. */
  email: string
  /** The workspace role the invitation grants. */
  role: string
  /** The tenant the workspace lives in. */
  tenantId: string
  /** The workspace the invitee joins, or the id the workspace will be created with. */
  workspaceId: string
  /** When the current token was issued, as an ISO-8601 instant. */
  createdAt: string
  /** How many times the invitation has been resent. */
  resendCount: number
}

/** An invitation a workspace member issued, to join a workspace that exists. */
export interface MemberInvitationRecord extends InvitationRecordBase {
  /** Discriminator. */
  kind: 'member'
  /** The member who issued the current token. */
  inviterUserId: string
}

/**
 * An invitation the platform issued, for the invitee to own a workspace that does not exist until
 * they accept. It carries no inviter, and its role is the owner role.
 */
export interface BootstrapInvitationRecord extends InvitationRecordBase {
  /** Discriminator. */
  kind: 'bootstrap'
  /** The name the workspace is created with, in the form the create route stores it. */
  workspaceName: string
}

/**
 * What Redis holds under `winv:{sha256(token)}`. The record is shared with rust-auth through
 * `conformance/wire-contract.json`; any other combination of fields is not a record.
 */
export type StoredWorkspaceInvitation = MemberInvitationRecord | BootstrapInvitationRecord

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

/** The fields of a preview that every kind of invitation shows. */
interface InvitationPreviewBase {
  /** The workspace the invitation is for. */
  workspaceName: string
  /** The role the invitation grants. */
  role: string
  /** The invited address with its local part masked. */
  maskedEmail: string
  /** Whether an account already exists for the address. */
  accountExists: boolean
}

/** What a holder of a member invitation may learn about it before signing in. */
export interface MemberInvitationPreview extends InvitationPreviewBase {
  /** Discriminator, the same as the record's. */
  kind: 'member'
  /** The display name of the member who invited. */
  inviterName: string
}

/** What a holder of a platform bootstrap invitation may learn about it: it has no inviter. */
export interface BootstrapInvitationPreview extends InvitationPreviewBase {
  /** Discriminator, the same as the record's. */
  kind: 'bootstrap'
}

/** What a holder of a token may learn about it before signing in. */
export type WorkspaceInvitationPreview = MemberInvitationPreview | BootstrapInvitationPreview
