/**
 * @fileoverview Tests for `WorkspaceController`: what each handler asks of the services, and what
 * it leaves out. The routes themselves are driven over HTTP in
 * `test/e2e/workspace-http-read.e2e-spec.ts`.
 *
 * @layer Test
 */

import type { Request } from 'express'

import type { CurrentWorkspaceContext } from '../decorators/current-workspace.decorator'
import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface'
import type { MembershipService } from '../services/membership.service'
import type { WorkspaceActionsService } from '../services/workspace-actions.service'
import type { WorkspaceService } from '../services/workspace.service'
import { WorkspaceController } from './workspace.controller'

const USER = { sub: 'u1', tenantId: 't1' } as DashboardJwtPayload
const ACCESS: CurrentWorkspaceContext = {
  tenantId: 't1',
  workspaceId: 'w1',
  userId: 'u1',
  role: 'editor'
}
const REF = { tenantId: 't1', workspaceId: 'w1' }
const REQUEST = {
  headers: { 'user-agent': 'jest' },
  socket: { remoteAddress: '203.0.113.9' },
  ip: '203.0.113.9'
} as Partial<Request> as Request
const WORKSPACE = {
  id: 'w1',
  tenantId: 't1',
  name: 'Acme',
  status: 'active' as const,
  createdAt: new Date(0),
  deletionScheduledAt: null
}

function build(): {
  controller: WorkspaceController
  workspaces: {
    getAccess: jest.Mock
    switchTo: jest.Mock
    create: jest.Mock
    rename: jest.Mock
    scheduleDeletion: jest.Mock
    restore: jest.Mock
  }
  memberships: { listMine: jest.Mock; listMembers: jest.Mock; remove: jest.Mock; leave: jest.Mock }
  actions: {
    create: jest.Mock
    rename: jest.Mock
    scheduleDeletion: jest.Mock
    changeRole: jest.Mock
    transferOwnership: jest.Mock
  }
} {
  const workspaces = {
    getAccess: jest.fn(),
    switchTo: jest.fn(),
    create: jest.fn(),
    rename: jest.fn(),
    scheduleDeletion: jest.fn(),
    restore: jest.fn()
  }
  const memberships = {
    listMine: jest.fn(),
    listMembers: jest.fn(),
    remove: jest.fn(),
    leave: jest.fn()
  }
  const actions = {
    create: jest.fn(),
    rename: jest.fn(),
    scheduleDeletion: jest.fn(),
    changeRole: jest.fn(),
    transferOwnership: jest.fn()
  }
  return {
    controller: new WorkspaceController(
      workspaces as Partial<WorkspaceService> as WorkspaceService,
      memberships as Partial<MembershipService> as MembershipService,
      actions as Partial<WorkspaceActionsService> as WorkspaceActionsService
    ),
    workspaces,
    memberships,
    actions
  }
}

describe('WorkspaceController', () => {
  describe('list', () => {
    it('lists the caller own memberships, from the token, with the page parameters it was given', async () => {
      const { controller, memberships } = build()
      memberships.listMine.mockResolvedValue({
        items: [],
        nextCursor: null,
        lastActiveWorkspaceId: null
      })

      await controller.list(USER, { cursor: 'c1', limit: '25' })

      expect(memberships.listMine).toHaveBeenCalledWith('t1', 'u1', { cursor: 'c1', limit: 25 })
    })

    it('passes no page parameter the request did not carry', async () => {
      const { controller, memberships } = build()
      memberships.listMine.mockResolvedValue({
        items: [],
        nextCursor: null,
        lastActiveWorkspaceId: null
      })

      await controller.list(USER, {})

      expect(Object.keys(memberships.listMine.mock.calls[0]?.[2] as object)).toEqual([])
    })
  })

  describe('access', () => {
    it('asks for the workspace by its key alone, for the caller, and shapes the answer', async () => {
      const { controller, workspaces } = build()
      workspaces.getAccess.mockResolvedValue({ workspace: WORKSPACE, role: 'editor' })

      const result = await controller.access(ACCESS)

      expect(workspaces.getAccess).toHaveBeenCalledWith(REF, 'u1')
      expect(result).toEqual({
        workspace: {
          id: 'w1',
          name: 'Acme',
          status: 'active',
          createdAt: '1970-01-01T00:00:00.000Z',
          deletionScheduledAt: null
        },
        role: 'editor'
      })
    })
  })

  describe('switchTo', () => {
    it('switches by the workspace key alone, with a dashboard hook context', async () => {
      const { controller, workspaces } = build()
      const request = {
        headers: { 'user-agent': 'jest' },
        socket: { remoteAddress: '203.0.113.9' },
        ip: '203.0.113.9'
      } as Partial<Request> as Request

      await controller.switchTo(ACCESS, USER, request)

      expect(workspaces.switchTo).toHaveBeenCalledWith(
        REF,
        'u1',
        expect.objectContaining({ plane: 'dashboard', userId: 'u1', tenantId: 't1' })
      )
    })
  })

  describe('members', () => {
    it('lists the members of the guarded workspace, by its key alone, with the page parameters', async () => {
      const { controller, memberships } = build()
      memberships.listMembers.mockResolvedValue({ items: [], nextCursor: null })

      await controller.members(ACCESS, { cursor: 'c2', limit: '5' })

      expect(memberships.listMembers).toHaveBeenCalledWith(REF, { cursor: 'c2', limit: 5 })
    })

    it('passes no page parameter the request did not carry', async () => {
      const { controller, memberships } = build()
      memberships.listMembers.mockResolvedValue({ items: [], nextCursor: null })

      await controller.members(ACCESS, {})

      expect(Object.keys(memberships.listMembers.mock.calls[0]?.[1] as object)).toEqual([])
    })
  })

  describe('create', () => {
    it('delegates the creation for the token, with the name and a dashboard context, and shapes the workspace', async () => {
      const { controller, actions } = build()
      actions.create.mockResolvedValue(WORKSPACE)

      const result = await controller.create(USER, { name: 'Acme' }, REQUEST)

      expect(actions.create).toHaveBeenCalledWith(
        USER,
        'Acme',
        expect.objectContaining({ plane: 'dashboard', userId: 'u1', tenantId: 't1' })
      )
      expect(result).toMatchObject({ id: 'w1', name: 'Acme', status: 'active' })
    })
  })

  describe('rename', () => {
    it('delegates by the workspace key and the judged actor, and shapes the workspace it returns', async () => {
      const { controller, actions } = build()
      actions.rename.mockResolvedValue({ ...WORKSPACE, name: 'New' })

      const result = await controller.rename(ACCESS, USER, { name: 'New' }, REQUEST)

      expect(actions.rename).toHaveBeenCalledWith(
        REF,
        { userId: 'u1', role: 'editor' },
        'New',
        expect.objectContaining({ plane: 'dashboard' })
      )
      expect(result).toMatchObject({ id: 'w1', name: 'New' })
    })
  })

  describe('scheduleDeletion', () => {
    it('delegates by the workspace key, the judged actor, the token and the submitted password', async () => {
      const { controller, actions } = build()

      await controller.scheduleDeletion(ACCESS, USER, { password: 'pw' }, REQUEST)

      expect(actions.scheduleDeletion).toHaveBeenCalledWith(
        REF,
        { userId: 'u1', role: 'editor' },
        USER,
        'pw',
        expect.objectContaining({ plane: 'dashboard' })
      )
    })
  })

  describe('restore', () => {
    it('restores by the workspace key and the judged actor', async () => {
      const { controller, workspaces } = build()

      await controller.restore(ACCESS, USER, REQUEST)

      expect(workspaces.restore).toHaveBeenCalledWith(
        REF,
        { userId: 'u1', role: 'editor' },
        expect.objectContaining({ plane: 'dashboard' })
      )
    })
  })

  describe('member routes', () => {
    const PARAMS = { workspaceId: 'w1', userId: 'u2' }
    const MEMBER = {
      userId: 'u2',
      role: 'editor',
      status: 'active' as const,
      invitedByUserId: null,
      createdAt: new Date(0)
    }

    it('delegates a role change and shapes the membership it returns', async () => {
      const { controller, actions } = build()
      actions.changeRole.mockResolvedValue(MEMBER)

      const result = await controller.changeRole(ACCESS, USER, PARAMS, { role: 'editor' }, REQUEST)

      expect(actions.changeRole).toHaveBeenCalledWith(
        REF,
        'u2',
        'editor',
        { userId: 'u1', role: 'editor' },
        expect.objectContaining({ plane: 'dashboard' })
      )
      expect(result).toEqual({
        userId: 'u2',
        role: 'editor',
        status: 'active',
        invitedByUserId: null,
        createdAt: '1970-01-01T00:00:00.000Z'
      })
    })

    it('removes the member named in the path by the workspace key and the judged actor', async () => {
      const { controller, memberships } = build()

      await controller.removeMember(ACCESS, USER, PARAMS, REQUEST)

      expect(memberships.remove).toHaveBeenCalledWith(
        REF,
        'u2',
        { userId: 'u1', role: 'editor' },
        expect.objectContaining({ plane: 'dashboard' })
      )
    })

    it('lets the caller leave, as themselves', async () => {
      const { controller, memberships } = build()

      await controller.leave(ACCESS, USER, REQUEST)

      expect(memberships.leave).toHaveBeenCalledWith(
        REF,
        'u1',
        expect.objectContaining({ plane: 'dashboard' })
      )
    })

    it('delegates a hand-over with the receiver, the role the giver keeps and the proof', async () => {
      const { controller, actions } = build()

      await controller.transferOwnership(
        ACCESS,
        USER,
        { userId: 'u2', demoteSelfTo: 'editor', password: 'pw' },
        REQUEST
      )
      await controller.transferOwnership(ACCESS, USER, { userId: 'u3' }, REQUEST)

      expect(actions.transferOwnership).toHaveBeenNthCalledWith(
        1,
        REF,
        { userId: 'u1', role: 'editor' },
        USER,
        { toUserId: 'u2', keeps: 'editor', password: 'pw' },
        expect.objectContaining({ plane: 'dashboard' })
      )
      expect(actions.transferOwnership).toHaveBeenNthCalledWith(
        2,
        REF,
        { userId: 'u1', role: 'editor' },
        USER,
        { toUserId: 'u3', keeps: null, password: undefined },
        expect.objectContaining({ plane: 'dashboard' })
      )
    })
  })
})
