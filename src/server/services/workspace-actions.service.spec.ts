/**
 * @fileoverview Tests for `WorkspaceActionsService`: the order of the steps each operation runs.
 *
 * @layer Test
 */

import type { HookContext } from '../interfaces/auth-hooks.interface'
import type { AuthMembership } from '../interfaces/membership-repository.interface'
import type { AuthWorkspace } from '../interfaces/workspace-repository.interface'
import type { MembershipService } from './membership.service'
import { WorkspaceActionsService } from './workspace-actions.service'
import type { WorkspaceCallerService } from './workspace-caller.service'
import type { WorkspaceService } from './workspace.service'

const CALLER = { sub: 'u1', tenantId: 't1' }
const REF = { tenantId: 't1', workspaceId: 'w1' }
const ACTOR = { userId: 'u1', role: 'owner' }
const CONTEXT = { plane: 'dashboard' } as HookContext
const WORKSPACE: AuthWorkspace = {
  id: 'w1',
  tenantId: 't1',
  name: 'Acme',
  status: 'active',
  createdAt: new Date(0),
  deletionScheduledAt: null
}
const MEMBER: AuthMembership = {
  tenantId: 't1',
  workspaceId: 'w1',
  userId: 'u2',
  role: 'editor',
  status: 'active',
  invitedByUserId: null,
  createdAt: new Date(0),
  updatedAt: new Date(0)
}

function build(): {
  service: WorkspaceActionsService
  workspaces: Record<'create' | 'rename' | 'getAccess' | 'scheduleDeletion', jest.Mock>
  callers: Record<'load' | 'reauthenticate', jest.Mock>
  memberships: Record<
    'changeRole' | 'getMember' | 'assertMayTransfer' | 'assertTransferTarget' | 'transferOwnership',
    jest.Mock
  >
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
  const memberships = {
    changeRole: jest.fn().mockImplementation(async () => void order.push('change')),
    getMember: jest.fn().mockImplementation(async () => {
      order.push('read member')
      return MEMBER
    }),
    assertMayTransfer: jest.fn().mockImplementation(() => void order.push('check')),
    assertTransferTarget: jest.fn().mockImplementation(async () => void order.push('target')),
    transferOwnership: jest.fn().mockImplementation(async () => void order.push('transfer'))
  }
  return {
    service: new WorkspaceActionsService(
      workspaces as Partial<WorkspaceService> as WorkspaceService,
      memberships as Partial<MembershipService> as MembershipService,
      callers as Partial<WorkspaceCallerService> as WorkspaceCallerService
    ),
    workspaces,
    callers,
    memberships,
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

  it('changes a role, then reads the membership back', async () => {
    const { service, memberships, order } = build()

    await expect(service.changeRole(REF, 'u2', 'editor', ACTOR, CONTEXT)).resolves.toBe(MEMBER)

    expect(memberships.changeRole).toHaveBeenCalledWith(REF, 'u2', 'editor', ACTOR, CONTEXT)
    expect(memberships.getMember).toHaveBeenCalledWith(REF, 'u2')
    expect(order).toEqual(['change', 'read member'])
  })

  it('reads no membership back when the change is refused', async () => {
    const { service, memberships } = build()
    memberships.changeRole.mockRejectedValue(new Error('last owner'))

    await expect(service.changeRole(REF, 'u2', 'viewer', ACTOR, CONTEXT)).rejects.toThrow(
      'last owner'
    )
    expect(memberships.getMember).not.toHaveBeenCalled()
  })

  describe('transferOwnership', () => {
    const HAND_OVER = { toUserId: 'u2', keeps: 'editor', password: 'pw' }

    it('checks the request locally, then the receiver, then re-proves the caller, then hands ownership over', async () => {
      const { service, memberships, callers, order } = build()

      await service.transferOwnership(REF, ACTOR, CALLER, HAND_OVER, CONTEXT)

      expect(memberships.assertMayTransfer).toHaveBeenCalledWith(ACTOR, 'u2', 'editor')
      expect(callers.reauthenticate).toHaveBeenCalledWith(CALLER, 'pw')
      expect(memberships.transferOwnership).toHaveBeenCalledWith(
        REF,
        ACTOR,
        'u2',
        'editor',
        CONTEXT
      )
      expect(memberships.assertTransferTarget).toHaveBeenCalledWith(REF, 'u2')
      expect(order).toEqual(['check', 'target', 'reauthenticate', 'transfer'])
    })

    it('never re-proves a caller the local check refuses, and writes nothing', async () => {
      const { service, memberships, callers } = build()
      memberships.assertMayTransfer.mockImplementation(() => {
        throw new Error('not an owner')
      })

      await expect(
        service.transferOwnership(REF, ACTOR, CALLER, { ...HAND_OVER, keeps: null }, CONTEXT)
      ).rejects.toThrow('not an owner')

      expect(callers.reauthenticate).not.toHaveBeenCalled()
      expect(memberships.transferOwnership).not.toHaveBeenCalled()
    })

    it('never re-proves a caller whose receiver is not an active member, and writes nothing', async () => {
      const { service, memberships, callers } = build()
      memberships.assertTransferTarget.mockRejectedValue(new Error('not an active member'))

      await expect(
        service.transferOwnership(REF, ACTOR, CALLER, HAND_OVER, CONTEXT)
      ).rejects.toThrow('not an active member')

      expect(callers.reauthenticate).not.toHaveBeenCalled()
      expect(memberships.transferOwnership).not.toHaveBeenCalled()
    })

    it('writes nothing when the re-proof fails', async () => {
      const { service, memberships, callers } = build()
      callers.reauthenticate.mockRejectedValue(new Error('invalid credentials'))

      await expect(
        service.transferOwnership(REF, ACTOR, CALLER, HAND_OVER, CONTEXT)
      ).rejects.toThrow('invalid credentials')
      expect(memberships.transferOwnership).not.toHaveBeenCalled()
    })
  })
})
