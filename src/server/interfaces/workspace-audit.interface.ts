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
      /** Why the guard refused. */
      reason: 'not_member' | 'insufficient_role'
    })
