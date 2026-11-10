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

export const DEMOTE_MESSAGE = 'demoteSelfTo must be a workspace role other than the owner role'
export const OWNER: WorkspaceActor = { userId: 'owner-1', role: 'owner' }
export const EDITOR: WorkspaceActor = { userId: 'editor-1', role: 'editor' }

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

export interface Harness {
  service: MembershipService
  memberships: Record<string, jest.Mock>
  access: { invalidateMembership: jest.Mock }
  events: { emit: jest.Mock }
}

export function build(withLastActive = true): Harness {
  const memberships: Record<string, jest.Mock> = {
    find: jest.fn(),
    listForUser: jest.fn().mockResolvedValue({ items: [], nextCursor: null }),
    listForWorkspace: jest.fn().mockResolvedValue({ items: [], nextCursor: null }),
    listSoleOwned: jest.fn().mockResolvedValue({ items: [], nextCursor: null }),
    changeRole: jest.fn().mockResolvedValue('ok'),
    remove: jest.fn().mockResolvedValue('ok'),
    transferOwnership: jest.fn().mockResolvedValue('ok'),
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
