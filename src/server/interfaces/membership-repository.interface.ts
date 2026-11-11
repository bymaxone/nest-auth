/**
 * @fileoverview The membership port: who belongs to which workspace with which role, and the
 * writes that change it, including the owner-protecting ones the library cannot make atomic itself.
 *
 * @layer Interface
 */

import type { ActingMember } from './acting-member.interface'
import type { WorkspaceAuditEvent } from './workspace-audit.interface'
import type { AuthWorkspace, WorkspaceRef } from './workspace-repository.interface'

/**
 * Names one member of a workspace. ALL THREE parts are always required: the tenant and workspace
 * halves scope the workspace, and the user id is unique only within the tenant.
 */
export interface MembershipRef extends WorkspaceRef {
  /** The member. */
  userId: string
}

/** Whether a membership grants access. Only `'active'` does; any other value reads as "not a member". */
export type MembershipStatus = 'active' | 'suspended'

/** A membership as the port returns it. */
export interface AuthMembership {
  /** The tenant of the workspace. */
  tenantId: string
  /** The workspace the member belongs to. */
  workspaceId: string
  /** The member. */
  userId: string
  /** The member's role in this workspace, one of the configured hierarchy's roles. */
  role: string
  /** Whether the membership grants access. */
  status: MembershipStatus
  /** The user who invited the member, or `null` for a creator or a system-made membership. */
  invitedByUserId: string | null
  /** When the membership was created. */
  createdAt: Date
  /** When it last changed. */
  updatedAt: Date
}

/** A membership with its workspace, as listed for the member. */
export interface MembershipWithWorkspace extends AuthMembership {
  /** The workspace the membership is in. */
  workspace: AuthWorkspace
}

/** One page of a keyset-paginated list. */
export interface MembershipPage<T> {
  /** The rows of this page. */
  items: T[]
  /** The cursor for the next page, or `null` on the last one. */
  nextCursor: string | null
}

/** Input to {@link IMembershipRepository.listForUser}. */
export interface ListMembershipsForUserParams {
  /** The tenant the member belongs to. */
  tenantId: string
  /** The member whose memberships are listed. */
  userId: string
  /** The `nextCursor` of the previous page, or absent for the first. */
  cursor?: string
  /** Page size. */
  limit: number
}

/** Input to {@link IMembershipRepository.listForWorkspace}. */
export interface ListMembershipsForWorkspaceParams extends WorkspaceRef {
  /** The `nextCursor` of the previous page, or absent for the first. */
  cursor?: string
  /** Page size. */
  limit: number
}

/** Input to {@link IMembershipRepository.create}. */
export interface CreateMembershipParams extends MembershipRef {
  /** The role to grant. */
  role: string
  /** The inviter, or `null` when none. */
  invitedByUserId: string | null
  /** The event for this change, to persist in the same transaction. */
  audit: WorkspaceAuditEvent
}

/** Outcome of {@link IMembershipRepository.create}. */
export type CreateMembershipResult = 'ok' | 'already_member' | 'workspace_not_found'

/** Input to {@link IMembershipRepository.changeRole}. */
export interface ChangeMembershipRoleParams extends MembershipRef {
  /** The role to set. */
  role: string
  /** The role the member held when the library judged the change; the write applies only while it still does. */
  expectedRole: string
  /** The actor whose role authorized the change; see {@link IMembershipRepository.changeRole}. */
  actor: ActingMember
  /** The role that owns a workspace, so the last-owner rule can be decided with the write. */
  ownerRole: string
  /** The `member.role_changed` event, to persist in the same transaction. */
  audit: WorkspaceAuditEvent
}

/** Input to {@link IMembershipRepository.remove}. */
export interface RemoveMembershipParams extends MembershipRef {
  /**
   * The role the member held when the library judged the removal; the write applies only while it
   * still does. Absent when a member leaves, since nobody's role authorized it.
   */
  expectedRole?: string
  /** The actor whose role authorized the removal; absent when a member leaves. */
  actor?: ActingMember
  /** The role that owns a workspace, so the last-owner rule can be decided with the write. */
  ownerRole: string
  /** The `member.removed` or `member.left` event, to persist in the same transaction. */
  audit: WorkspaceAuditEvent
}

/** Input to {@link IMembershipRepository.transferOwnership}. */
export interface TransferOwnershipParams extends WorkspaceRef {
  /** The current owner handing over. */
  fromUserId: string
  /** The member who becomes an owner; must already be an active member. */
  toUserId: string
  /** The role that owns a workspace. */
  ownerRole: string
  /** The role `fromUserId` takes afterwards, or `null` to keep them an owner alongside the new one. */
  demoteFromTo: string | null
  /** The `ownership.transferred` event, to persist in the same transaction. */
  audit: WorkspaceAuditEvent
}

/** Input to {@link IMembershipRepository.countOwned}. */
export interface CountOwnedParams {
  /** The tenant the member belongs to. */
  tenantId: string
  /** The member. */
  userId: string
  /** The role that owns a workspace. */
  ownerRole: string
}

/** Input to {@link IMembershipRepository.listSoleOwned}. */
export interface ListSoleOwnedParams extends CountOwnedParams {
  /** The `nextCursor` of the previous page, or absent for the first. */
  cursor?: string
  /** Page size. */
  limit: number
}

/** Input to {@link IMembershipRepository.getLastActiveWorkspaceId}. */
export interface LastActiveWorkspaceRef {
  /** The tenant the member belongs to. */
  tenantId: string
  /** The member. */
  userId: string
}

/** Input to {@link IMembershipRepository.setLastActiveWorkspaceId}. */
export interface SetLastActiveWorkspaceParams extends LastActiveWorkspaceRef {
  /** The workspace to remember. */
  workspaceId: string
}

/**
 * Outcome of a write that must keep at least one active owner.
 *
 * - `'ok'`: applied.
 * - `'not_found'`: no such membership (`transferOwnership` states what it means there).
 * - `'last_owner'`: the change would leave the workspace with no active member holding `ownerRole`.
 */
export type GuardedWriteResult = 'ok' | 'not_found' | 'last_owner'

/**
 * Outcome of a write that an actor's role authorized: {@link GuardedWriteResult} plus
 * `'actor_changed'`, answered when the actor no longer holds the role the call was judged against.
 */
export type MemberChangeResult = GuardedWriteResult | 'actor_changed'

/** Outcome of {@link IMembershipRepository.transferOwnership}. */
export type TransferOwnershipResult = GuardedWriteResult | 'target_not_member'

/**
 * The event persisted for each membership {@link IMembershipRepository.removeAllForUser} deletes.
 * The repository stores one `member.removed` event per removed membership, naming that
 * membership's workspace, and nothing else is added to it.
 */
export interface AccountRemovalAudit {
  type: 'member.removed'
  /** The tenant of the account. */
  tenantId: string
  /** Who authorized the removal: the member themselves, an administrator, or `null` for a job. */
  actorUserId: string | null
  /** The account whose memberships are removed. */
  userId: string
  /** When the removal was decided, as an ISO-8601 string. */
  at: string
}

/** Input to {@link IMembershipRepository.removeAllForUser}. */
export interface RemoveAllMembershipsParams {
  /** The tenant of the account. */
  tenantId: string
  /** The account whose memberships are removed. */
  userId: string
  /** The role that owns a workspace, so the last-owner rule can be decided with the write. */
  ownerRole: string
  /** The event to persist for each membership removed. */
  audit: AccountRemovalAudit
}

/** One membership an account removal deleted. */
export interface RemovedMembership {
  /** The workspace the membership was in. */
  workspaceId: string
  /** The role the account held there. */
  role: string
}

/** Outcome of {@link IMembershipRepository.removeAllForUser}. */
export type RemoveAllMembershipsResult =
  { result: 'ok'; removed: RemovedMembership[] } | { result: 'last_owner'; workspaceIds: string[] }

/**
 * The membership port a host implements.
 *
 * Every method carries the full key of what it names, and every mutating one receives the audit
 * event for its change and persists it in the same transaction. A result other than `'ok'` means
 * nothing was written: no change and no audit row, so a refused write leaves no trace of an event
 * that did not happen. The audit event a call receives names the same tenant, workspace and member
 * as the key of that call, and is stored as given. Reads the library uses to decide
 * access must come from the primary or be read-your-writes: a replica that lags a removal would
 * cache the removed member as present under the new cache version.
 */
export interface IMembershipRepository {
  /**
   * Reads one membership. Return it in any status: the library decides access.
   *
   * @param ref - The workspace's tenant and id and the member.
   * @returns The membership, or `null` when none matches ALL parts of the key.
   */
  find(ref: MembershipRef): Promise<AuthMembership | null>

  /**
   * Lists a member's memberships with their workspaces, for the workspace picker.
   *
   * Returns only ACTIVE memberships of ACTIVE workspaces, ordered by membership creation instant
   * and then workspace id, ascending. The cursor is opaque to the library and valid only for the
   * same tenant and member; a malformed cursor, or one issued for another query, restarts from the
   * first page and never widens the scope. The library bounds `limit` to 1 through 100.
   *
   * @param params - The tenant, member and page.
   * @returns One page.
   */
  listForUser(
    params: ListMembershipsForUserParams
  ): Promise<MembershipPage<MembershipWithWorkspace>>

  /**
   * Lists the members of a workspace, in every membership status so an administrator can see a
   * suspended member.
   *
   * Ordered by membership creation instant and then user id, ascending. The cursor is opaque to
   * the library and valid only for the same workspace; a malformed cursor, or one issued for
   * another query, restarts from the first page and never widens the scope. The library bounds
   * `limit` to 1 through 100.
   *
   * @param params - The workspace key and page.
   * @returns One page.
   */
  listForWorkspace(
    params: ListMembershipsForWorkspaceParams
  ): Promise<MembershipPage<AuthMembership>>

  /**
   * Adds a member, persisting `audit` in the same transaction.
   *
   * @param params - The membership key, role, inviter and audit event.
   * @returns `'already_member'` when the user already belongs to the workspace in any status,
   *   `'workspace_not_found'` when the workspace does not exist.
   */
  create(params: CreateMembershipParams): Promise<CreateMembershipResult>

  /**
   * Changes a member's role, persisting `audit` in the same transaction.
   *
   * MUST refuse with `'last_owner'` when the change would leave the workspace with no active member
   * holding `ownerRole`. The check and the write happen in ONE transaction (for example
   * `SELECT ... FOR UPDATE` on the workspace's owner rows): two owners demoting each other at the
   * same moment is the race this rule exists for, and the library cannot hold a database
   * transaction. The library pre-checks only to return a friendlier error; this result decides.
   *
   * The same transaction MUST also hold the two roles the library judged the change against, because
   * it read them before the write and either may have changed since:
   *
   * - the actor still holds `actor.expectedRole` as an active member, else answer `'actor_changed'`;
   * - the member still holds `expectedRole`, else answer `'not_found'`.
   *
   * ```sql
   * BEGIN;
   * -- 1. lock the actor's row and the member's row together, in one fixed order, so two members
   * --    acting on each other cannot deadlock and neither role can change before the commit
   * SELECT user_id, role, status FROM memberships
   *  WHERE tenant_id = $tenant AND workspace_id = $workspace AND user_id IN ($actor, $member)
   *  ORDER BY user_id
   *  FOR UPDATE;
   * -- 2. the actor row missing, inactive or not holding $actorRole: ROLLBACK, answer 'actor_changed'
   * --    the member row missing, inactive or not holding $expectedRole: ROLLBACK, answer 'not_found'
   * UPDATE memberships SET role = $role, updated_at = now()
   *  WHERE tenant_id = $tenant AND workspace_id = $workspace AND user_id = $member
   *    AND role = $expectedRole AND status = 'active';
   * -- 3. the last-owner check, the audit insert, then COMMIT
   * ```
   *
   * A host that ignores both keeps the check-then-write window: a role changed between the library's
   * read and this call goes unseen. Nothing is written for any result other than `'ok'`.
   *
   * @param params - The membership key, new role, the roles judged, owner role and audit event.
   */
  changeRole(params: ChangeMembershipRoleParams): Promise<MemberChangeResult>

  /**
   * Removes a member, persisting `audit` in the same transaction. The same atomic last-owner rule
   * as {@link changeRole} applies, and so does its pair of role conditions when `expectedRole` and
   * `actor` are given: the actor must still hold `actor.expectedRole` (`'actor_changed'` otherwise)
   * and the member must still hold `expectedRole` (`'not_found'` otherwise), both in this
   * transaction. A member leaving passes neither, since no role authorized it.
   *
   * @param params - The membership key, the roles judged, owner role and audit event.
   */
  remove(params: RemoveMembershipParams): Promise<MemberChangeResult>

  /**
   * Removes every membership of an account, in every membership status and in every workspace
   * status, persisting one `audit` event per removed membership in the same transaction.
   *
   * For the host that is about to delete or anonymise a user. `listForUser` shows only active
   * memberships of active workspaces, so only the repository can find the rest.
   *
   * The last-owner rule is decided inside the transaction: when the account is the only active
   * `ownerRole` holder of a workspace that is not `pending_deletion` or `deleted`, nothing is
   * removed, no audit row is written and the answer names those workspaces. A workspace pending
   * deletion does not block: no one can finalize it early, and its owner must not wait out the
   * grace period to delete their account. Removing the owner's membership there means the
   * workspace can no longer be restored, and it is deleted when its grace period ends.
   *
   * @param params - The tenant, the account, the owner role and the event template.
   * @returns The removed memberships, or `'last_owner'` with the ids of the workspaces that block.
   */
  removeAllForUser(params: RemoveAllMembershipsParams): Promise<RemoveAllMembershipsResult>

  /**
   * Hands ownership from one member to another in one transaction, persisting `audit` with it.
   *
   * `fromUserId` must be an active member holding `ownerRole`, and `toUserId` an active member; the
   * target takes `ownerRole`, and the previous owner takes `demoteFromTo` when it is set.
   *
   * @param params - The workspace key, both members, owner role, the previous owner's new role and
   *   the audit event.
   * @returns `'not_found'` when the workspace or the `fromUserId` membership does not exist or is
   *   not an active owner, `'target_not_member'` when `toUserId` is not an active member.
   */
  transferOwnership(params: TransferOwnershipParams): Promise<TransferOwnershipResult>

  /**
   * Counts the workspaces a member owns, for the per-user cap.
   *
   * Counts the workspaces in which the member is an ACTIVE `ownerRole` holder and that are not
   * `deleted`, so one pending deletion still counts. Read from the primary, like every read the
   * library decides on.
   *
   * @param params - The tenant, member and owner role.
   * @returns How many.
   */
  countOwned(params: CountOwnedParams): Promise<number>

  /**
   * Lists the workspaces whose ONLY active `ownerRole` holder is this member, so a host can block or
   * route an account deletion that would orphan them.
   *
   * Excludes `deleted` workspaces. Ordered by workspace creation instant and then workspace id,
   * ascending. The cursor is opaque to the library and valid only for the same tenant and member; a
   * malformed cursor, or one issued for another query, restarts from the first page and never widens
   * the scope. The library bounds `limit` to 1 through 100.
   *
   * @param params - The tenant, member, owner role and page.
   * @returns One page of workspaces.
   */
  listSoleOwned(params: ListSoleOwnedParams): Promise<MembershipPage<AuthWorkspace>>

  /**
   * Optional: the workspace this member last switched to, for the post-sign-in landing.
   *
   * @param ref - The tenant and member.
   * @returns The workspace id, or `null` when none was recorded.
   */
  getLastActiveWorkspaceId?(ref: LastActiveWorkspaceRef): Promise<string | null>

  /**
   * Optional: remembers the workspace this member last switched to.
   *
   * @param params - The tenant, member and workspace.
   */
  setLastActiveWorkspaceId?(params: SetLastActiveWorkspaceParams): Promise<void>
}
