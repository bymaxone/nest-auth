/**
 * @fileoverview The audit event every workspace or membership change hands to its repository, and
 * to the `onWorkspaceEvent` hook after the change commits.
 *
 * @layer Interface
 */

/**
 * The fields every workspace audit event carries.
 *
 * `actorUserId` is `null` for a change no signed-in user made: a scheduled purge, or the platform
 * bootstrap that creates the first workspace. It is never a placeholder id, so a consumer reading
 * the audit trail cannot mistake the system for a user.
 */
interface WorkspaceAuditBase {
  /** The tenant the workspace lives in. */
  tenantId: string
  /** The workspace the event is about. */
  workspaceId: string
  /** The user who made the change, or `null` when none did. */
  actorUserId: string | null
  /** When the change was decided, as an ISO-8601 instant. */
  at: string
}

/**
 * One audited change to a workspace or one of its memberships.
 *
 * Every mutating repository method receives the event for its own change in an `audit` field and
 * must persist it in the SAME transaction as the change, so the audit row cannot be missing for a
 * change that happened or present for one that did not. After the write commits, the library fans
 * the event out to a hook; that fan-out is best-effort and can be lost if the process dies between
 * the commit and the call, which is why the persisted row is the record.
 *
 * `access.denied` and `workspace.switched` are the exceptions: neither rides on a repository write
 * that takes an `audit` field (a refused request writes nothing, and switching only remembers the
 * last workspace), so they go to the hook only.
 */
export type WorkspaceAuditEvent =
  | (WorkspaceAuditBase & {
      type:
        | 'workspace.created'
        | 'workspace.renamed'
        | 'workspace.deletion_scheduled'
        | 'workspace.restored'
        | 'workspace.deleted'
    })
  | (WorkspaceAuditBase & {
      type: 'member.invited' | 'invitation.resent' | 'invitation.revoked'
      /** The invited address, trimmed and lowercased. */
      email: string
      /** The role the invitation carries. */
      role: string
    })
  | (WorkspaceAuditBase & {
      type: 'invitation.accepted'
      /** The invited address, trimmed and lowercased. */
      email: string
      /** The role the invitation carries. */
      role: string
      /** The user the acceptance added to the workspace. */
      userId: string
      /**
       * Set, on the hook event only, when the invitation record could not be spent as expected
       * because a revoke or a resend had already moved it. The membership exists either way.
       */
      lostConsumeRace?: true
    })
  | (WorkspaceAuditBase & {
      type: 'member.role_changed'
      /** The member whose role changed. */
      userId: string
      /** The role before the change. */
      from: string
      /** The role after the change. */
      to: string
    })
  | (WorkspaceAuditBase & {
      type: 'member.removed' | 'member.left' | 'workspace.switched'
      /** The member the event is about. */
      userId: string
    })
  | (WorkspaceAuditBase & {
      type: 'ownership.transferred'
      /** The owner who handed ownership over. */
      fromUserId: string
      /** The member who took it. */
      toUserId: string
    })
  | (WorkspaceAuditBase & {
      type: 'access.denied'
      /** The account that was refused; the same value as `actorUserId`. */
      userId: string
      /** The surface that refused: a route, a stream's verification or a socket message. */
      surface: 'http' | 'verifier' | 'ws'
      /**
       * The code the caller was answered with. The host receives the event and the caller never
       * does, so it also gets {@link reason}, which the answer deliberately does not carry.
       */
      code:
        | 'auth.workspace_not_found'
        | 'auth.workspace_pending_deletion'
        | 'auth.insufficient_workspace_role'
      /**
       * Why the decision refused, for the host to tell two incidents apart: an account probing
       * workspaces it does not belong to (`not_member`) and a member reaching above its role
       * (`insufficient_role`). `not_member` also covers a workspace that does not exist, because
       * the resolution does not tell the two apart. `pending_deletion` is any active member of a
       * workspace pending deletion on a surface that does not admit it: the owner, and also a
       * non-owner, who is answered `auth.workspace_not_found` like a stranger, so `code` and
       * `reason` differ exactly where the caller is not told.
       */
      reason: 'not_member' | 'insufficient_role' | 'pending_deletion'
      /**
       * Denials since the last event for this account that were counted and not emitted, because
       * the account exceeded `workspaces.accessDeniedEvents.max` inside a window. Zero when none.
       */
      suppressedCount: number
    })
