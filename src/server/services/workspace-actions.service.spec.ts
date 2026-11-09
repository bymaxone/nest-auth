/**
 * @fileoverview Tests for `WorkspaceActionsService`: the order of the steps each operation runs.
 *
 * @layer Test
 */

import type { HookContext } from '../interfaces/auth-hooks.interface'
import type { AuthWorkspace } from '../interfaces/workspace-repository.interface'
import { WorkspaceActionsService } from './workspace-actions.service'
import type { WorkspaceCallerService } from './workspace-caller.service'
import type { WorkspaceService } from './workspace.service'

const CALLER = { sub: 'u1', tenantId: 't1' }
const REF = { tenantId: 't1', workspaceId: 'w1' }
const ACTOR = { userId: 'u1', role: 'owner' }
const CONTEXT = { plane: 'dashboard' } as HookContext
const WORKSPACE = { id: 'w1', name: 'Acme' } as AuthWorkspace

function build(): {
  service: WorkspaceActionsService
  workspaces: Record<'create' | 'rename' | 'getAccess' | 'scheduleDeletion', jest.Mock>
  callers: Record<'load' | 'reauthenticate', jest.Mock>
  order: string[]
} {
  const order: string[] = []
  const workspaces = {
    create: jest.fn().mockResolvedValue(WORKSPACE),
    rename: jest.fn().mockImplementation(async () => void order.push('rename')),
    getAccess: jest.fn().mockImplementation(async () => {
      order.push('read')
      return { workspace: WORKSPACE, role: 'owner' }
    }),
    scheduleDeletion: jest.fn().mockImplementation(async () => void order.push('schedule'))
  }
  const callers = {
    load: jest.fn().mockResolvedValue({ id: 'u1', tenantId: 't1' }),
    reauthenticate: jest.fn().mockImplementation(async () => void order.push('reauthenticate'))
  }
  return {
    service: new WorkspaceActionsService(
      workspaces as Partial<WorkspaceService> as WorkspaceService,
      callers as Partial<WorkspaceCallerService> as WorkspaceCallerService
    ),
    workspaces,
    callers,
    order
  }
}

describe('WorkspaceActionsService', () => {
  it('creates the workspace for the account the token names', async () => {
    const { service, workspaces, callers } = build()

    await expect(service.create(CALLER, 'Acme', CONTEXT)).resolves.toBe(WORKSPACE)

    expect(callers.load).toHaveBeenCalledWith(CALLER)
    expect(workspaces.create).toHaveBeenCalledWith(
      { id: 'u1', tenantId: 't1' },
      { name: 'Acme' },
      CONTEXT
    )
  })

  it('creates nothing when the account no longer exists', async () => {
    const { service, workspaces, callers } = build()
    callers.load.mockRejectedValue(new Error('token invalid'))

    await expect(service.create(CALLER, 'Acme', CONTEXT)).rejects.toThrow('token invalid')
    expect(workspaces.create).not.toHaveBeenCalled()
  })

  it('renames, then reads the workspace back for the actor', async () => {
    const { service, workspaces, order } = build()

    await expect(service.rename(REF, ACTOR, 'New', CONTEXT)).resolves.toBe(WORKSPACE)

    expect(workspaces.rename).toHaveBeenCalledWith(REF, 'New', ACTOR, CONTEXT)
    expect(workspaces.getAccess).toHaveBeenCalledWith(REF, 'u1')
    expect(order).toEqual(['rename', 'read'])
  })

  it('reads nothing back when the rename is refused', async () => {
    const { service, workspaces } = build()
    workspaces.rename.mockRejectedValue(new Error('forbidden'))

    await expect(service.rename(REF, ACTOR, 'New', CONTEXT)).rejects.toThrow('forbidden')
    expect(workspaces.getAccess).not.toHaveBeenCalled()
  })

  it('re-proves the caller first, then schedules the deletion', async () => {
    const { service, workspaces, callers, order } = build()

    await service.scheduleDeletion(REF, ACTOR, CALLER, 'pw', CONTEXT)

    expect(callers.reauthenticate).toHaveBeenCalledWith(CALLER, 'pw')
    expect(workspaces.scheduleDeletion).toHaveBeenCalledWith(REF, ACTOR, CONTEXT)
    expect(order).toEqual(['reauthenticate', 'schedule'])
  })

  it('schedules nothing when the re-proof fails', async () => {
    const { service, workspaces, callers } = build()
    callers.reauthenticate.mockRejectedValue(new Error('invalid credentials'))

    await expect(service.scheduleDeletion(REF, ACTOR, CALLER, undefined, CONTEXT)).rejects.toThrow(
      'invalid credentials'
    )
    expect(workspaces.scheduleDeletion).not.toHaveBeenCalled()
  })
})
