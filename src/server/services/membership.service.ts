/**
 * @fileoverview The membership side of the workspace lifecycle: listings, role changes, removal,
 * leaving and ownership transfer.
 *
 * @layer Service
 */

import { Inject, Injectable } from '@nestjs/common'

import { BYMAX_AUTH_MEMBERSHIP_REPOSITORY, BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import { WorkspaceAccessService } from './workspace-access.service'
import { WorkspaceEventsService } from './workspace-events.service'
import type { ResolvedOptions } from '../config/resolved-options'
import type { ResolvedWorkspaceOptions } from '../config/workspace-options'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { HookContext } from '../interfaces/auth-hooks.interface'
import type {
  AuthMembership,
  GuardedWriteResult,
  IMembershipRepository,
  MembershipPage,
  MembershipWithWorkspace
} from '../interfaces/membership-repository.interface'
import type { WorkspaceAuditEvent } from '../interfaces/workspace-audit.interface'
import type { AuthWorkspace, WorkspaceRef } from '../interfaces/workspace-repository.interface'
import { hasRole } from '../utils/roles.util'

/** The most rows one page may hold. */
const MAX_PAGE_SIZE = 100

/** Rows per page when the caller names none. */
const DEFAULT_PAGE_SIZE = 20

/** The audit events a removal produces: an administrator removing a member, or a member leaving. */
type MemberRemovalEvent = WorkspaceAuditEvent & { type: 'member.removed' | 'member.left' }

/** Who is making a change: their id, and the role they hold in the workspace. */
export interface WorkspaceActor {
  userId: string
  role: string
}

/** A member's workspaces, and the one they last switched to. */
export interface MyWorkspaces extends MembershipPage<MembershipWithWorkspace> {
  lastActiveWorkspaceId: string | null
}

/**
 * Brings a requested page size into the range the ports accept.
 *
 * @param limit - What the caller asked for.
 * @returns A whole number from 1 to 100; the default when none was asked.
 */
function pageSize(limit: number | undefined): number {
  if (limit === undefined || !Number.isInteger(limit)) return DEFAULT_PAGE_SIZE
  return Math.min(Math.max(limit, 1), MAX_PAGE_SIZE)
}

/**
 * Changes who belongs to a workspace and what they may do there.
 *
 * Every write is made by the repository together with its audit event, and the last-owner rule is
 * decided there, in the same transaction as the write. A successful write bumps the affected
 * members' cache versions, so a change takes effect on their next request, and a bump that fails
 * surfaces as an error. The hook is told afterwards.
 *
 * The role ceiling. The owner role may grant, change and remove any role, other owners included
 * (the repository still refuses to leave a workspace with none). Every other role acts only
 * STRICTLY below itself: it may grant a role it includes, never its own, and may change or remove a
 * member whose role it includes, never a peer holding the same role and never anyone above. A member
 * therefore cannot change their own role (leaving is its own action), and an editor cannot make
 * another editor or remove one.
 */
@Injectable()
export class MembershipService {
  private readonly group: ResolvedWorkspaceOptions

  constructor(
    @Inject(BYMAX_AUTH_MEMBERSHIP_REPOSITORY) private readonly memberships: IMembershipRepository,
    @Inject(WorkspaceAccessService) private readonly access: WorkspaceAccessService,
    @Inject(WorkspaceEventsService) private readonly events: WorkspaceEventsService,
    @Inject(BYMAX_AUTH_OPTIONS) options: ResolvedOptions
  ) {
    if (options.workspaces === undefined) {
      throw new Error('[BymaxAuthModule] MembershipService needs workspaces.enabled.')
    }
    this.group = options.workspaces
  }

  /**
   * Lists the caller's own active memberships with their workspaces, and the workspace they last
   * switched to.
   *
   * @param tenantId - The caller's tenant.
   * @param userId - The caller; only their own memberships are ever listed.
   * @param page - The cursor and size.
   * @returns One page and the last-used workspace id, `null` when none is recorded.
   */
  async listMine(
    tenantId: string,
    userId: string,
    page: { cursor?: string; limit?: number } = {}
  ): Promise<MyWorkspaces> {
    const listed = await this.memberships.listForUser({
      tenantId,
      userId,
      ...(page.cursor === undefined ? {} : { cursor: page.cursor }),
      limit: pageSize(page.limit)
    })
    const lastActiveWorkspaceId =
      (await this.memberships.getLastActiveWorkspaceId?.({ tenantId, userId })) ?? null
    return { ...listed, lastActiveWorkspaceId }
  }

  /**
   * Lists a workspace's members, in every membership status.
   *
   * @param ref - The workspace.
   * @param page - The cursor and size.
   * @returns One page.
   */
  listMembers(
    ref: WorkspaceRef,
    page: { cursor?: string; limit?: number } = {}
  ): Promise<MembershipPage<AuthMembership>> {
    return this.memberships.listForWorkspace({
      ...ref,
      ...(page.cursor === undefined ? {} : { cursor: page.cursor }),
      limit: pageSize(page.limit)
    })
  }

  /**
   * Lists the workspaces a member alone owns, so a host can block or route an account deletion
   * that would orphan them.
   *
   * @param tenantId - The member's tenant.
   * @param userId - The member.
   * @param page - The cursor and size.
   * @returns One page of workspaces.
   */
  listSoleOwnedWorkspaces(
    tenantId: string,
    userId: string,
    page: { cursor?: string; limit?: number } = {}
  ): Promise<MembershipPage<AuthWorkspace>> {
    return this.memberships.listSoleOwned({
      tenantId,
      userId,
      ownerRole: this.group.roles.ownerRole,
      ...(page.cursor === undefined ? {} : { cursor: page.cursor }),
      limit: pageSize(page.limit)
    })
  }

  /**
   * Changes a member's role.
   *
   * @param ref - The workspace.
   * @param userId - The member whose role changes.
   * @param role - The role to give.
   * @param actor - Who changes it, with the role they hold.
   * @param context - Request metadata for the hook.
   * @throws {AuthException} `auth.validation` for a role outside the hierarchy,
   *   `auth.insufficient_workspace_role` when the actor would grant or change above their own role,
   *   `auth.workspace_not_found` for a member who is not active, `auth.last_owner` when it would
   *   leave the workspace without an owner.
   */
  async changeRole(
    ref: WorkspaceRef,
    userId: string,
    role: string,
    actor: WorkspaceActor,
    context: HookContext
  ): Promise<void> {
    const { hierarchy, ownerRole } = this.group.roles
    if (!Object.hasOwn(hierarchy, role)) {
      throw new AuthException(AUTH_ERROR_CODES.VALIDATION, [
        { field: 'role', message: 'role must be one of the workspace roles' }
      ])
    }
    if (!this.outranks(actor.role, role)) {
      throw new AuthException(AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE)
    }
    const target = await this.activeMember(ref, userId, actor)
    if (target.role === role) return

    const event = {
      type: 'member.role_changed' as const,
      ...ref,
      actorUserId: actor.userId,
      userId,
      from: target.role,
      to: role,
      at: now()
    }
    const result = await this.memberships.changeRole({
      ...ref,
      userId,
      role,
      ownerRole,
      audit: event
    })
    await this.settle(result, ref, [userId])
    this.events.emit(event, context)
  }

  /**
   * Removes a member from a workspace.
   *
   * @param ref - The workspace.
   * @param userId - The member to remove.
   * @param actor - Who removes them, with the role they hold.
   * @param context - Request metadata for the hook.
   * @throws {AuthException} `auth.insufficient_workspace_role` when the member holds a role above
   *   the actor's, `auth.workspace_not_found` for a member who is not active, `auth.last_owner`
   *   when it would leave the workspace without an owner.
   */
  async remove(
    ref: WorkspaceRef,
    userId: string,
    actor: WorkspaceActor,
    context: HookContext
  ): Promise<void> {
    await this.activeMember(ref, userId, actor)
    const event = {
      type: 'member.removed' as const,
      ...ref,
      actorUserId: actor.userId,
      userId,
      at: now()
    }
    await this.removeWith(ref, userId, event, context)
  }

  /**
   * Lets a member leave a workspace.
   *
   * @param ref - The workspace.
   * @param userId - The member leaving.
   * @param context - Request metadata for the hook.
   * @throws {AuthException} `auth.last_owner` when they are the last owner: they must transfer
   *   ownership or delete the workspace first.
   */
  async leave(ref: WorkspaceRef, userId: string, context: HookContext): Promise<void> {
    const event = { type: 'member.left' as const, ...ref, actorUserId: userId, userId, at: now() }
    await this.removeWith(ref, userId, event, context)
  }

  /**
   * Hands ownership to another active member in one atomic step.
   *
   * Only an owner can hand it over. The repository decides the rest in one transaction: the giver
   * must still be an active owner, the receiver must be an active member of THIS workspace in this
   * tenant, and the giver's demotion is part of the same write, so there is never a moment with no
   * owner or with the giver demoted and the receiver not yet promoted.
   *
   * @param ref - The workspace.
   * @param actor - The owner handing it over, with the role they hold.
   * @param toUserId - The active member who becomes an owner.
   * @param demoteFromTo - The role the previous owner takes, or `null` to keep both as owners.
   * @param context - Request metadata for the hook.
   * @throws {AuthException} `auth.insufficient_workspace_role` when the actor is not an owner,
   *   `auth.validation` for a role outside the hierarchy, the owner role, a transfer to oneself or
   *   to a member who is not active in this workspace, `auth.workspace_not_found` when the giver is
   *   no longer an active owner.
   */
  async transferOwnership(
    ref: WorkspaceRef,
    actor: WorkspaceActor,
    toUserId: string,
    demoteFromTo: string | null,
    context: HookContext
  ): Promise<void> {
    const { hierarchy, ownerRole } = this.group.roles
    const fromUserId = actor.userId
    if (actor.role !== ownerRole) {
      throw new AuthException(AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE)
    }
    if (fromUserId === toUserId) throw invalid('userId', 'ownership cannot be handed to oneself')
    if (
      demoteFromTo !== null &&
      (!Object.hasOwn(hierarchy, demoteFromTo) || demoteFromTo === ownerRole)
    ) {
      throw invalid(
        'demoteSelfTo',
        'demoteSelfTo must be a workspace role other than the owner role'
      )
    }
    const event = {
      type: 'ownership.transferred' as const,
      ...ref,
      actorUserId: fromUserId,
      fromUserId,
      toUserId,
      at: now()
    }
    const result = await this.memberships.transferOwnership({
      ...ref,
      fromUserId,
      toUserId,
      ownerRole,
      demoteFromTo,
      audit: event
    })
    if (result === 'target_not_member') throw invalid('userId', 'userId must be an active member')
    await this.settle(result, ref, [fromUserId, toUserId])
    this.events.emit(event, context)
  }

  /** Reads an active member and refuses an actor who would act on a role above their own. */
  private async activeMember(
    ref: WorkspaceRef,
    userId: string,
    actor: WorkspaceActor
  ): Promise<AuthMembership> {
    const member = await this.memberships.find({ ...ref, userId })
    if (member?.status !== 'active') throw new AuthException(AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND)
    if (!this.outranks(actor.role, member.role)) {
      throw new AuthException(AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE)
    }
    return member
  }

  /**
   * Whether an actor's role may act on another role: the owner role on any role, every other role
   * only on a role it includes and does not itself hold.
   */
  private outranks(actorRole: string, otherRole: string): boolean {
    const { hierarchy, ownerRole } = this.group.roles
    return (
      actorRole === ownerRole ||
      (actorRole !== otherRole && hasRole(actorRole, otherRole, hierarchy))
    )
  }

  private async removeWith(
    ref: WorkspaceRef,
    userId: string,
    event: MemberRemovalEvent,
    context: HookContext
  ): Promise<void> {
    const result = await this.memberships.remove({
      ...ref,
      userId,
      ownerRole: this.group.roles.ownerRole,
      audit: event
    })
    await this.settle(result, ref, [userId])
    this.events.emit(event, context)
  }

  /**
   * Turns a guarded write's outcome into an error, or ends the affected members' cached access.
   * A bump that fails throws, so the change is never reported as done.
   */
  private async settle(
    result: GuardedWriteResult,
    ref: WorkspaceRef,
    userIds: string[]
  ): Promise<void> {
    if (result === 'not_found') throw new AuthException(AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND)
    if (result === 'last_owner') throw new AuthException(AUTH_ERROR_CODES.LAST_OWNER)
    for (const userId of userIds) {
      await this.access.invalidateMembership({ ...ref, userId })
    }
  }
}

/** The current instant as an ISO-8601 string, the form audit events carry. */
function now(): string {
  return new Date().toISOString()
}

/**
 * Builds the `400` for a bad field.
 *
 * @param field - The field name.
 * @param message - What is wrong.
 * @returns The exception to throw.
 */
function invalid(field: string, message: string): AuthException {
  return new AuthException(AUTH_ERROR_CODES.VALIDATION, [{ field, message }])
}
