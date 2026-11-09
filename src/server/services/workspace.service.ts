/**
 * @fileoverview The workspace lifecycle: create, rename, schedule and finalize deletion, restore,
 * switch and read the caller's access.
 *
 * @layer Service
 */

import { randomUUID } from 'node:crypto'

import { Inject, Injectable } from '@nestjs/common'

import {
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_MEMBERSHIP_REPOSITORY,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_WORKSPACE_REPOSITORY
} from '../bymax-auth.constants'
import { WorkspaceAccessService } from './workspace-access.service'
import type { ResolvedWorkspaceMember } from './workspace-access.service'
import { WorkspaceEventsService } from './workspace-events.service'
import type { ResolvedOptions } from '../config/resolved-options'
import type { ResolvedWorkspaceOptions } from '../config/workspace-options'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { HookContext, IAuthHooks } from '../interfaces/auth-hooks.interface'
import type { IMembershipRepository } from '../interfaces/membership-repository.interface'
import type { SafeAuthUser } from '../interfaces/user-repository.interface'
import type {
  AuthWorkspace,
  IWorkspaceRepository,
  UpdateWorkspaceStatusResult,
  WorkspaceRef
} from '../interfaces/workspace-repository.interface'
import { normalizeWorkspaceName } from '../utils/workspace-name'

const DAY_MS = 86_400_000

/** What scheduling a deletion produced. */
export interface ScheduledDeletion {
  /** `deleted` when the grace period is `0` and the workspace was finalized at once. */
  status: 'pending_deletion' | 'deleted'
  /** When the deletion becomes final, or `null` when it already is. */
  deletionScheduledAt: Date | null
}

/** Why {@link WorkspaceService.finalizeDeletion} did not finalize. */
export type FinalizeResult = 'deleted' | 'not_found' | 'not_pending' | 'not_due'

/** A workspace and the caller's role in it. */
export interface WorkspaceAccessView {
  workspace: AuthWorkspace
  role: string
}

/**
 * Owns the life of a workspace.
 *
 * Every change is written by the repository together with its audit event, in one transaction. The
 * service then ends the access the change affects by bumping the cache version, and only after that
 * hands the event to the host's hook, so a failed bump surfaces as an error and a change is never
 * reported as done while stale access could still be served.
 */
@Injectable()
export class WorkspaceService {
  private readonly group: ResolvedWorkspaceOptions

  constructor(
    @Inject(BYMAX_AUTH_WORKSPACE_REPOSITORY) private readonly workspaces: IWorkspaceRepository,
    @Inject(BYMAX_AUTH_MEMBERSHIP_REPOSITORY) private readonly memberships: IMembershipRepository,
    @Inject(WorkspaceAccessService) private readonly access: WorkspaceAccessService,
    @Inject(WorkspaceEventsService) private readonly events: WorkspaceEventsService,
    @Inject(BYMAX_AUTH_HOOKS) private readonly hooks: IAuthHooks,
    @Inject(BYMAX_AUTH_OPTIONS) options: ResolvedOptions
  ) {
    if (options.workspaces === undefined) {
      throw new Error('[BymaxAuthModule] WorkspaceService needs workspaces.enabled.')
    }
    this.group = options.workspaces
  }

  /**
   * Creates a workspace owned by the caller.
   *
   * Checks, in order, `workspaces.allowCreate`, the per-user limit and `beforeWorkspaceCreate`,
   * then writes the workspace and the owner membership atomically. The limit check here is
   * advisory under concurrency; the repository receives the limit and may enforce it exactly.
   *
   * @param user - The identity creating it; the workspace lives in its tenant.
   * @param data - The requested name.
   * @param context - Request metadata for the hooks.
   * @returns The created workspace.
   * @throws {AuthException} `auth.validation` for a bad name, `auth.forbidden` when creation is
   *   not allowed, `auth.workspace_limit_reached` at the limit.
   */
  async create(
    user: SafeAuthUser,
    data: { name: unknown },
    context: HookContext
  ): Promise<AuthWorkspace> {
    const name = normalizeWorkspaceName(data.name)
    await this.assertMayCreate(user, name, context)

    const ref = { tenantId: user.tenantId, workspaceId: randomUUID() }
    const event = { type: 'workspace.created' as const, ...ref, actorUserId: user.id, at: now() }
    const created = await this.workspaces.createWithOwner({
      ...ref,
      name,
      ownerUserId: user.id,
      ownerRole: this.group.roles.ownerRole,
      maxWorkspacesPerUser: this.group.maxWorkspacesPerUser,
      audit: event
    })
    if (created.status === 'limit_reached') {
      throw new AuthException(AUTH_ERROR_CODES.WORKSPACE_LIMIT_REACHED)
    }
    this.events.emit(event, context)
    return created.workspace
  }

  /**
   * Renames a workspace.
   *
   * @param ref - The workspace.
   * @param rawName - The new name.
   * @param actorUserId - Who renames it.
   * @param context - Request metadata for the hook.
   * @throws {AuthException} `auth.validation` for a bad name, `auth.workspace_not_found` when the
   *   workspace does not exist.
   */
  async rename(
    ref: WorkspaceRef,
    rawName: unknown,
    actorUserId: string,
    context: HookContext
  ): Promise<void> {
    const name = normalizeWorkspaceName(rawName)
    const event = { type: 'workspace.renamed' as const, ...ref, actorUserId, at: now() }
    if (!(await this.workspaces.rename({ ...ref, name, audit: event }))) {
      throw new AuthException(AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND)
    }
    this.events.emit(event, context)
  }

  /**
   * Schedules a workspace for deletion, ending every member's access at once.
   *
   * With `workspaces.deletionGraceDays` of `0` the workspace is deleted immediately instead.
   *
   * @param ref - The workspace.
   * @param actorUserId - Who deletes it.
   * @param context - Request metadata for the hook.
   * @returns The resulting status and when the deletion becomes final.
   * @throws {AuthException} `auth.workspace_not_found`, or `auth.workspace_pending_deletion` when
   *   it was already scheduled.
   */
  async scheduleDeletion(
    ref: WorkspaceRef,
    actorUserId: string,
    context: HookContext
  ): Promise<ScheduledDeletion> {
    const days = this.group.deletionGraceDays
    const at = now()
    const immediate = days === 0
    const scheduledAt = immediate ? null : new Date(Date.parse(at) + days * DAY_MS)
    const event = immediate
      ? ({ type: 'workspace.deleted', ...ref, actorUserId, at } as const)
      : ({ type: 'workspace.deletion_scheduled', ...ref, actorUserId, at } as const)

    const result = await this.workspaces.updateStatus({
      ...ref,
      status: immediate ? 'deleted' : 'pending_deletion',
      expectedStatus: 'active',
      deletionScheduledAt: scheduledAt,
      audit: event
    })
    await this.settle(result, ref)
    this.events.emit(event, context)
    return { status: immediate ? 'deleted' : 'pending_deletion', deletionScheduledAt: scheduledAt }
  }

  /**
   * Undoes a scheduled deletion while the grace period has not elapsed.
   *
   * @param ref - The workspace.
   * @param actorUserId - Who restores it.
   * @param context - Request metadata for the hook.
   * @throws {AuthException} `auth.workspace_not_found` when the workspace is not pending deletion
   *   or its grace period is over.
   */
  async restore(ref: WorkspaceRef, actorUserId: string, context: HookContext): Promise<void> {
    const workspace = await this.workspaces.findById(ref)
    const due = workspace?.deletionScheduledAt
    if (workspace?.status !== 'pending_deletion' || (due != null && due.getTime() <= Date.now())) {
      throw new AuthException(AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND)
    }
    const event = { type: 'workspace.restored' as const, ...ref, actorUserId, at: now() }
    const result = await this.workspaces.updateStatus({
      ...ref,
      status: 'active',
      expectedStatus: 'pending_deletion',
      deletionScheduledAt: null,
      audit: event
    })
    await this.settle(result, ref)
    this.events.emit(event, context)
  }

  /**
   * Marks a workspace deleted once its grace period is over. A host job calls it; purging the
   * workspace's data is the host's work.
   *
   * @param ref - The workspace.
   * @param context - Request metadata for the hook; the job has none, so a minimal one is used.
   * @returns `deleted`, or why nothing changed.
   */
  async finalizeDeletion(ref: WorkspaceRef, context?: HookContext): Promise<FinalizeResult> {
    const workspace = await this.workspaces.findById(ref)
    if (workspace === null) return 'not_found'
    if (workspace.status !== 'pending_deletion') return 'not_pending'
    if (
      workspace.deletionScheduledAt !== null &&
      workspace.deletionScheduledAt.getTime() > Date.now()
    ) {
      return 'not_due'
    }
    const event = { type: 'workspace.deleted' as const, ...ref, actorUserId: null, at: now() }
    const result = await this.workspaces.updateStatus({
      ...ref,
      status: 'deleted',
      expectedStatus: 'pending_deletion',
      deletionScheduledAt: null,
      audit: event
    })
    await this.settle(result, ref)
    this.events.emit(event, context ?? systemContext(ref.tenantId))
    return 'deleted'
  }

  /**
   * Records the workspace a member switched to and reports the switch.
   *
   * Nothing about the session changes: the token carries no workspace.
   *
   * @param ref - The workspace.
   * @param userId - The member.
   * @param context - Request metadata for the hook.
   * @returns The member's access.
   * @throws {AuthException} `auth.workspace_not_found` when the caller is not an active member.
   */
  async switchTo(
    ref: WorkspaceRef,
    userId: string,
    context: HookContext
  ): Promise<ResolvedWorkspaceMember> {
    const member = await this.access.resolveMembership({ ...ref, userId })
    if (member === null) throw new AuthException(AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND)
    await this.memberships.setLastActiveWorkspaceId?.({
      tenantId: ref.tenantId,
      userId,
      workspaceId: ref.workspaceId
    })
    this.events.emit(
      { type: 'workspace.switched', ...ref, actorUserId: userId, userId, at: now() },
      context
    )
    return member
  }

  /**
   * Reads a workspace and the caller's role in it.
   *
   * @param ref - The workspace.
   * @param userId - The caller.
   * @returns The workspace and the caller's role.
   * @throws {AuthException} `auth.workspace_not_found` when the caller is not an active member.
   */
  async getAccess(ref: WorkspaceRef, userId: string): Promise<WorkspaceAccessView> {
    const member = await this.access.resolveMembership({ ...ref, userId })
    const workspace = member === null ? null : await this.workspaces.findById(ref)
    if (member === null || workspace === null) {
      throw new AuthException(AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND)
    }
    return { workspace, role: member.role }
  }

  private async assertMayCreate(
    user: SafeAuthUser,
    name: string,
    context: HookContext
  ): Promise<void> {
    const { allowCreate, maxWorkspacesPerUser } = this.group
    const allowed = typeof allowCreate === 'function' ? await allowCreate(user) : allowCreate
    if (!allowed) throw new AuthException(AUTH_ERROR_CODES.FORBIDDEN)

    if (maxWorkspacesPerUser > 0) {
      const owned = await this.memberships.countOwned({
        tenantId: user.tenantId,
        userId: user.id,
        ownerRole: this.group.roles.ownerRole
      })
      if (owned >= maxWorkspacesPerUser) {
        throw new AuthException(AUTH_ERROR_CODES.WORKSPACE_LIMIT_REACHED)
      }
    }

    const verdict = await this.hooks.beforeWorkspaceCreate?.(user, { name }, context)
    if (verdict !== undefined && !verdict.allowed) {
      throw new AuthException(AUTH_ERROR_CODES.FORBIDDEN, [
        { field: 'name', message: verdict.reason ?? 'Workspace creation was refused' }
      ])
    }
  }

  /**
   * Turns a status write's outcome into an error, or ends every member's access to the workspace.
   *
   * A refused write throws; a successful one bumps the workspace version so no cached answer
   * outlives the change. A bump that fails throws too: the change is never reported as done.
   */
  private async settle(result: UpdateWorkspaceStatusResult, ref: WorkspaceRef): Promise<void> {
    if (result === 'not_found') throw new AuthException(AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND)
    if (result === 'status_conflict') {
      const current = await this.workspaces.findById(ref)
      throw new AuthException(
        current?.status === 'pending_deletion'
          ? AUTH_ERROR_CODES.WORKSPACE_PENDING_DELETION
          : AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND
      )
    }
    await this.access.invalidateWorkspace(ref)
  }
}

/** The current instant as an ISO-8601 string, the form audit events carry. */
function now(): string {
  return new Date().toISOString()
}

/**
 * A hook context for a change no request made, such as a scheduled purge.
 *
 * @param tenantId - The tenant the workspace lives in.
 * @returns A context with no address, agent or headers.
 */
function systemContext(tenantId: string): HookContext {
  return { plane: 'dashboard', tenantId, ip: '', userAgent: '', sanitizedHeaders: {} }
}
