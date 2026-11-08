/**
 * @fileoverview The workspace port: the record of a workspace inside a tenant, and the writes that
 * create it, rename it and move it through its lifecycle.
 *
 * @layer Interface
 */

import type { WorkspaceAuditEvent } from './workspace-audit.interface'

/**
 * Names a workspace. BOTH halves are always required: a workspace id is unique only inside its
 * tenant, so an id on its own can name a homonym in another tenant. A method that takes anything
 * less than this cannot scope the row it reads or writes.
 */
export interface WorkspaceRef {
  /** The tenant the workspace lives in. */
  tenantId: string
  /** The workspace, unique within `tenantId`. */
  workspaceId: string
}

/**
 * Where a workspace is in its life. Only `'active'` grants access: any other value reads as "not a
 * member" to every caller, so a workspace nobody can reach and one that does not exist look alike.
 *
 * - `'pending_deletion'`: scheduled for removal; only the owner can restore it, within the grace.
 * - `'suspended'`: held by the host (a billing or abuse decision); the library never sets it.
 * - `'deleted'`: finalized. The row may remain for audit; the host purges the data.
 */
export type WorkspaceStatus = 'active' | 'pending_deletion' | 'suspended' | 'deleted'

/** A workspace as the port returns it. */
export interface AuthWorkspace {
  /** Unique within `tenantId`. */
  id: string
  /** The tenant the workspace lives in. */
  tenantId: string
  /** Display name. */
  name: string
  /** Lifecycle state. */
  status: WorkspaceStatus
  /** When the workspace was created. */
  createdAt: Date
  /** When a scheduled deletion becomes final, or `null` when none is scheduled. */
  deletionScheduledAt: Date | null
}

/** Input to {@link IWorkspaceRepository.createWithOwner}. */
export interface CreateWorkspaceWithOwnerParams extends WorkspaceRef {
  /** Display name. */
  name: string
  /** The creator, who becomes a member holding `ownerRole`. */
  ownerUserId: string
  /** The role that makes the creator the owner. */
  ownerRole: string
  /**
   * The `workspace.created` event, to persist in the same transaction. Its `tenantId` and
   * `workspaceId` equal the key in this same object; the library fills the event in completely.
   */
  audit: WorkspaceAuditEvent
}

/** Input to {@link IWorkspaceRepository.rename}. */
export interface RenameWorkspaceParams extends WorkspaceRef {
  /** The new display name. */
  name: string
  /** The `workspace.renamed` event, to persist in the same transaction. */
  audit: WorkspaceAuditEvent
}

/** Input to {@link IWorkspaceRepository.updateStatus}. */
export interface UpdateWorkspaceStatusParams extends WorkspaceRef {
  /** The state to move to. */
  status: WorkspaceStatus
  /**
   * The state the caller read. The write applies only while the workspace is still in it, so a
   * restore cannot overwrite a finalize that landed first.
   */
  expectedStatus: WorkspaceStatus
  /** The scheduled-deletion instant to store, or `null` to clear it. */
  deletionScheduledAt: Date | null
  /** The event for this transition, to persist in the same transaction. */
  audit: WorkspaceAuditEvent
}

/** Outcome of {@link IWorkspaceRepository.updateStatus}. */
export type UpdateWorkspaceStatusResult = 'ok' | 'not_found' | 'status_conflict'

/**
 * The workspace port a host implements.
 *
 * Every method carries both halves of the workspace key. Every mutating method receives the audit
 * event for its change and persists it in the same transaction; a result other than success means
 * nothing was written, the audit row included. The audit event a call receives names the same
 * tenant and workspace as the key of that call, and is stored as given.
 */
export interface IWorkspaceRepository {
  /**
   * Creates the workspace and the creator's owner membership atomically, persisting `audit` in the
   * same transaction. The library generates the workspace id and passes it in the key, so the
   * audit event is complete before the write; store it as given.
   *
   * @param params - The workspace key, name, creator and audit event.
   * @returns The created workspace, `active`.
   */
  createWithOwner(params: CreateWorkspaceWithOwnerParams): Promise<AuthWorkspace>

  /**
   * Reads one workspace. Return a workspace in any status: the library decides access.
   *
   * @param ref - The workspace's tenant and id.
   * @returns The workspace, or `null` when none matches BOTH halves of the key.
   */
  findById(ref: WorkspaceRef): Promise<AuthWorkspace | null>

  /**
   * Renames a workspace, persisting `audit` in the same transaction.
   *
   * @param params - The workspace key, the new name and the audit event.
   * @returns `false` when no such workspace exists; nothing is written then.
   */
  rename(params: RenameWorkspaceParams): Promise<boolean>

  /**
   * Moves a workspace to another status, persisting `audit` in the same transaction.
   *
   * Compare-and-set: it applies only while the stored status equals `expectedStatus`, decided in
   * the same statement as the write.
   *
   * @param params - The workspace key, the target and expected statuses, the deletion instant and
   *   the audit event.
   * @returns `'ok'` when applied, `'not_found'` for no such workspace, `'status_conflict'` when the
   *   stored status differs from `expectedStatus`. Nothing is written for either refusal.
   */
  updateStatus(params: UpdateWorkspaceStatusParams): Promise<UpdateWorkspaceStatusResult>
}
