/**
 * @fileoverview The grace period of a workspace read through the guarded repository: a deadline that is not a time
 * (an Invalid Date, or a Proxy whose `getTime` answers garbage) is refused, so a workspace is never deleted or restored
 * on a date that compares false with every instant.
 *
 * @layer Test
 */

import { AuthException } from '../errors/auth-exception'
import type { IAuthHooks } from '../interfaces/auth-hooks.interface'
import type { IMembershipRepository } from '../interfaces/membership-repository.interface'
import type { IWorkspaceRepository } from '../interfaces/workspace-repository.interface'
import { guardRepository } from '../utils/host-read'
import { WORKSPACE_REPOSITORY_CONTRACT } from '../utils/repository-contracts'
import {
  CONTEXT,
  WORKSPACE_REF,
  workspaceOptions,
  workspaceRow
} from './__tests__/workspace-service-harness'
import { WorkspaceService } from './workspace.service'

/** A Proxy of a date whose `getTime` answers `answer`. */
const timeAs = (answer: unknown): Date =>
  new Proxy(new Date(0), {
    get: (target, key) => {
      if (key === 'getTime') return () => answer
      const member: unknown = Reflect.get(target, key, target)
      return typeof member === 'function' ? member.bind(target) : member
    }
  })

/** A service over a guarded repository whose workspace is pending deletion, due at `due`. */
function build(due: Date): { service: WorkspaceService; updateStatus: jest.Mock } {
  const updateStatus = jest.fn().mockResolvedValue('ok')
  const host = {
    findById: async (): Promise<unknown> =>
      workspaceRow({ status: 'pending_deletion', deletionScheduledAt: due }),
    updateStatus,
    rename: jest.fn(),
    createWithOwner: jest.fn()
  }
  const service = new WorkspaceService(
    guardRepository(
      host as Partial<IWorkspaceRepository>,
      WORKSPACE_REPOSITORY_CONTRACT
    ) as IWorkspaceRepository,
    { countOwned: jest.fn() } as Partial<IMembershipRepository> as IMembershipRepository,
    { invalidateWorkspace: jest.fn() } as never,
    { emit: jest.fn() } as never,
    {} as IAuthHooks,
    workspaceOptions()
  )
  return { service, updateStatus }
}

describe('a workspace whose deadline is not a time', () => {
  // Scenario: the deadline of a workspace pending deletion is not a time, however the host spells it. Expected:
  // finalizing and restoring end in the internal error and nothing is written. Why: `due.getTime() > now` is false for
  // a NaN, which would make the deadline look over: the workspace would be deleted, or restored past its grace period.
  it.each([
    ['a real Invalid Date', (): Date => new Date(Number.NaN)],
    ['a Proxy answering NaN', (): Date => timeAs(Number.NaN)],
    ['a Proxy answering a string', (): Date => timeAs('x')],
    ['a Proxy answering an infinity', (): Date => timeAs(Number.POSITIVE_INFINITY)]
  ])('neither finalizes nor restores it for %s', async (_name, make) => {
    const { service, updateStatus } = build(make())
    const actor = { userId: 'u1', role: 'owner' } as never

    await expect(service.finalizeDeletion(WORKSPACE_REF)).rejects.toBeInstanceOf(AuthException)
    await expect(service.restore(WORKSPACE_REF, actor, CONTEXT)).rejects.toBeInstanceOf(
      AuthException
    )
    expect(updateStatus).not.toHaveBeenCalled()
  })
})
