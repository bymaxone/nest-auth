/**
 * @fileoverview A `beforeWorkspaceCreate` that FAILS rather than refuses: nothing is created and
 * the failure is not turned into the refusal a hook returns. The contract's counterpart sentence:
 * "A `beforeWorkspaceCreate` that fails without refusing creates nothing and answers 500
 * `auth.internal`; the failure's text is not in the response."
 *
 * @layer Test
 */

import type { IAuthHooks } from '../interfaces/auth-hooks.interface'
import type { IMembershipRepository } from '../interfaces/membership-repository.interface'
import type { SafeAuthUser } from '../interfaces/user-repository.interface'
import type { IWorkspaceRepository } from '../interfaces/workspace-repository.interface'
import { CONTEXT, workspaceOptions } from './__tests__/workspace-service-harness'
import type { WorkspaceAccessService } from './workspace-access.service'
import type { WorkspaceEventsService } from './workspace-events.service'
import { WorkspaceService } from './workspace.service'

const USER = { id: 'u1', tenantId: 't1', email: 'a@b.c' } as SafeAuthUser

describe('WorkspaceService.create when beforeWorkspaceCreate fails', () => {
  // Scenario: the host's hook throws. Expected: the very error it threw reaches the caller, which
  // the exception filter answers as `500 auth.internal` without its text, and the repository is
  // never asked to create the workspace, so the failure refuses instead of admitting.
  it('creates nothing and raises the failure untouched', async () => {
    const failure = new Error('billing backend password=hunter2 unreachable')
    const createWithOwner = jest.fn()
    const service = new WorkspaceService(
      { createWithOwner } as Partial<IWorkspaceRepository> as IWorkspaceRepository,
      {
        countOwned: jest.fn().mockResolvedValue(0)
      } as Partial<IMembershipRepository> as IMembershipRepository,
      {} as WorkspaceAccessService,
      { emit: jest.fn() } as Partial<WorkspaceEventsService> as WorkspaceEventsService,
      {
        beforeWorkspaceCreate: jest.fn().mockRejectedValue(failure)
      } as Partial<IAuthHooks> as IAuthHooks,
      workspaceOptions({})
    )

    await expect(service.create(USER, { name: 'A' }, CONTEXT)).rejects.toBe(failure)

    expect(createWithOwner).not.toHaveBeenCalled()
  })
})
