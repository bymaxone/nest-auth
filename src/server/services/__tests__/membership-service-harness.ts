/**
 * @fileoverview Shared harness of the membership service specs: the service over stubbed
 * repositories, cache and events.
 *
 * @layer Test
 */

import { WORKSPACE_REF, workspaceOptions } from './workspace-service-harness'
import type { AuthException } from '../../errors/auth-exception'
import type { WorkspaceActor } from '../../interfaces/acting-member.interface'
import type {
  AuthMembership,
  IMembershipRepository
} from '../../interfaces/membership-repository.interface'
import { MembershipService } from '../membership.service'
import type { WorkspaceAccessService } from '../workspace-access.service'
import type { WorkspaceEventsService } from '../workspace-events.service'

/** The refusal text for an owner role kept after a hand-over. */
export const DEMOTE_MESSAGE = 'demoteSelfTo must be a workspace role other than the owner role'
/** The owner acting on the workspace. */
export const OWNER: WorkspaceActor = { userId: 'owner-1', role: 'owner' }
/** An editor acting on the workspace. */
export const EDITOR: WorkspaceActor = { userId: 'editor-1', role: 'editor' }

/**
 * A membership of the workspace.
 *
 * @param userId - The member.
 * @param role - The role they hold.
 * @param status - Their status; active by default.
 */
export function member(
  userId: string,
  role: string,
  status: AuthMembership['status'] = 'active'
): AuthMembership {
  return {
    ...WORKSPACE_REF,
    userId,
    role,
    status,
    invitedByUserId: null,
    createdAt: new Date(0),
    updatedAt: new Date(0)
  }
}

/** The service over stubbed repositories, cache and events. */
export interface Harness {
  service: MembershipService
  memberships: Record<string, jest.Mock>
  access: { invalidateMembership: jest.Mock }
  events: { emit: jest.Mock }
}

/**
 * The service over stubbed repositories, cache and events.
 *
 * @param withLastActive - Whether the repository supports the last-active workspace.
 */
export function build(withLastActive = true): Harness {
  const memberships: Record<string, jest.Mock> = {
    find: jest.fn(),
    listForUser: jest.fn().mockResolvedValue({ items: [], nextCursor: null }),
    listForWorkspace: jest.fn().mockResolvedValue({ items: [], nextCursor: null }),
    listSoleOwned: jest.fn().mockResolvedValue({ items: [], nextCursor: null }),
    changeRole: jest.fn().mockResolvedValue('ok'),
    remove: jest.fn().mockResolvedValue('ok'),
    transferOwnership: jest.fn().mockResolvedValue('ok'),
    removeAllForUser: jest.fn().mockResolvedValue({ result: 'ok', removed: [] }),
    ...(withLastActive ? { getLastActiveWorkspaceId: jest.fn().mockResolvedValue('w9') } : {})
  }
  const access = { invalidateMembership: jest.fn().mockResolvedValue(undefined) }
  const events = { emit: jest.fn() }
  const service = new MembershipService(
    memberships as Partial<IMembershipRepository> as IMembershipRepository,
    access as Partial<WorkspaceAccessService> as WorkspaceAccessService,
    events as Partial<WorkspaceEventsService> as WorkspaceEventsService,
    workspaceOptions()
  )
  return { service, memberships, access, events }
}

/** The error code an operation fails with, or `'ok'`. */
export async function code(promise: Promise<unknown>): Promise<string> {
  try {
    await promise
  } catch (error) {
    return ((error as AuthException).getResponse() as { error: { code: string } }).error.code
  }
  return 'ok'
}

/** The `details` an operation's validation error carries, or `undefined` when it does not fail. */
export async function detailsOf(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise
  } catch (error) {
    return ((error as AuthException).getResponse() as { error: { details: unknown } }).error.details
  }
  return undefined
}
