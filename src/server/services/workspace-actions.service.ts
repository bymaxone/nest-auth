/**
 * @fileoverview The workspace operations a route runs as a sequence: each one orders its checks and
 * its write, so the controller only delegates.
 *
 * @layer Service
 */

import { Inject, Injectable } from '@nestjs/common'

import { MembershipService } from './membership.service'
import { WorkspaceCallerService } from './workspace-caller.service'
import { WorkspaceService } from './workspace.service'
import type { WorkspaceActor } from '../interfaces/acting-member.interface'
import type { HookContext } from '../interfaces/auth-hooks.interface'
import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface'
import type { AuthMembership } from '../interfaces/membership-repository.interface'
import type { AuthWorkspace, WorkspaceRef } from '../interfaces/workspace-repository.interface'

/** The verified token of the caller: who they are and the tenant they belong to. */
type Caller = Pick<DashboardJwtPayload, 'sub' | 'tenantId'>

/** What a hand-over of ownership names: the receiver, the role the giver keeps, and the giver's proof. */
export interface HandOver {
  /** The member who becomes an owner. */
  toUserId: string
  /** The role the giver keeps, or `null` to keep both as owners. */
  keeps: string | null
  /** The giver's password, if they submitted one. */
  password: string | undefined
}

/**
 * Runs the workspace operations that need more than one step.
 *
 * Each method fixes the order of its steps, which is part of what it guarantees: a caller is
 * re-proved only after the guard has decided they may act, and before the write.
 */
@Injectable()
export class WorkspaceActionsService {
  constructor(
    @Inject(WorkspaceService) private readonly workspaces: WorkspaceService,
    @Inject(MembershipService) private readonly memberships: MembershipService,
    @Inject(WorkspaceCallerService) private readonly callers: WorkspaceCallerService
  ) {}

  /**
   * Creates a workspace owned by the caller.
   *
   * @param caller - The verified token's subject and tenant.
   * @param name - The requested name.
   * @param context - Request metadata for the hooks.
   * @returns The created workspace.
   * @throws {AuthException} `auth.token_invalid` when the account no longer exists, then whatever
   *   {@link WorkspaceService.create} refuses.
   */
  async create(caller: Caller, name: string, context: HookContext): Promise<AuthWorkspace> {
    return this.workspaces.create(await this.callers.load(caller), { name }, context)
  }

  /**
   * Renames a workspace and reads it back.
   *
   * @param ref - The workspace.
   * @param actor - Who renames it, with the role the guard resolved for them.
   * @param name - The new name.
   * @param context - Request metadata for the hook.
   * @returns The workspace as it now reads.
   */
  async rename(
    ref: WorkspaceRef,
    actor: WorkspaceActor,
    name: string,
    context: HookContext
  ): Promise<AuthWorkspace> {
    await this.workspaces.rename(ref, name, actor, context)
    return (await this.workspaces.getAccess(ref, actor.userId)).workspace
  }

  /**
   * Re-proves the caller, then schedules the workspace's deletion.
   *
   * Nothing is looked up or spent for a caller the guard has not admitted: this runs after it. An
   * account that fails the proof schedules nothing.
   *
   * @param ref - The workspace.
   * @param actor - Who deletes it, with the role the guard resolved for them.
   * @param caller - The verified token's subject and tenant, whose proof is checked.
   * @param password - The password the caller submitted, if any.
   * @param context - Request metadata for the hook.
   * @throws {AuthException} The re-proof's refusals, then whatever
   *   {@link WorkspaceService.scheduleDeletion} refuses.
   */
  async scheduleDeletion(
    ref: WorkspaceRef,
    actor: WorkspaceActor,
    caller: Caller,
    password: string | undefined,
    context: HookContext
  ): Promise<void> {
    await this.callers.reauthenticate(caller, password)
    await this.workspaces.scheduleDeletion(ref, actor, context)
  }

  /**
   * Changes a member's role and reads the membership back.
   *
   * @param ref - The workspace.
   * @param userId - The member whose role changes.
   * @param role - The role to give.
   * @param actor - Who changes it, with the role the guard resolved for them.
   * @param context - Request metadata for the hook.
   * @returns The membership as it now stands.
   */
  async changeRole(
    ref: WorkspaceRef,
    userId: string,
    role: string,
    actor: WorkspaceActor,
    context: HookContext
  ): Promise<AuthMembership> {
    await this.memberships.changeRole(ref, userId, role, actor, context)
    return this.memberships.getMember(ref, userId)
  }

  /**
   * Hands ownership to another member, running the checks from cheapest to costliest.
   *
   * Everything the request alone decides (only an owner may hand it over, not to oneself, the role
   * the giver keeps must exist) is checked first, so a caller who cannot succeed cannot spend a key
   * derivation or a lockout attempt. Then the caller is re-proved, then the write is made.
   *
   * @param ref - The workspace.
   * @param actor - The member handing ownership over, with the role the guard resolved for them.
   * @param caller - The verified token's subject and tenant, whose proof is checked.
   * @param handOver - The receiver, the role the giver keeps and the giver's password.
   * @param context - Request metadata for the hook.
   * @throws {AuthException} The local checks' refusals, the re-proof's refusals, then whatever
   *   {@link MembershipService.transferOwnership} refuses.
   */
  async transferOwnership(
    ref: WorkspaceRef,
    actor: WorkspaceActor,
    caller: Caller,
    handOver: HandOver,
    context: HookContext
  ): Promise<void> {
    this.memberships.assertMayTransfer(actor, handOver.toUserId, handOver.keeps)
    await this.callers.reauthenticate(caller, handOver.password)
    await this.memberships.transferOwnership(ref, actor, handOver.toUserId, handOver.keeps, context)
  }
}
