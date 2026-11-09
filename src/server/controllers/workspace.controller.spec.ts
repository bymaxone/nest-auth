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
import type { WorkspaceCallerService } from '../services/workspace-caller.service'
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
} as unknown as Request
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
  memberships: { listMine: jest.Mock; listMembers: jest.Mock }
  callers: { load: jest.Mock; reauthenticate: jest.Mock }
} {
  const workspaces = {
    getAccess: jest.fn(),
    switchTo: jest.fn(),
    create: jest.fn(),
    rename: jest.fn(),
    scheduleDeletion: jest.fn(),
    restore: jest.fn()
  }
  const memberships = { listMine: jest.fn(), listMembers: jest.fn() }
  const callers = { load: jest.fn(), reauthenticate: jest.fn() }
  return {
    controller: new WorkspaceController(
      workspaces as Partial<WorkspaceService> as WorkspaceService,
      memberships as Partial<MembershipService> as MembershipService,
      callers as Partial<WorkspaceCallerService> as WorkspaceCallerService
    ),
    workspaces,
    memberships,
    callers
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
      } as unknown as Request

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
    it('creates the workspace for the account the token names, with the name and a dashboard context', async () => {
      const { controller, workspaces, callers } = build()
      const account = { id: 'u1', tenantId: 't1', email: 'a@b.c' }
      callers.load.mockResolvedValue(account)
      workspaces.create.mockResolvedValue(WORKSPACE)

      const result = await controller.create(USER, { name: 'Acme' }, REQUEST)

      expect(callers.load).toHaveBeenCalledWith(USER)
      expect(workspaces.create).toHaveBeenCalledWith(
        account,
        { name: 'Acme' },
        expect.objectContaining({ plane: 'dashboard', userId: 'u1', tenantId: 't1' })
      )
      expect(result).toMatchObject({ id: 'w1', name: 'Acme', status: 'active' })
    })
  })

  describe('rename', () => {
    it('renames by the workspace key and the judged actor, then answers the workspace as it reads', async () => {
      const { controller, workspaces } = build()
      workspaces.getAccess.mockResolvedValue({
        workspace: { ...WORKSPACE, name: 'New' },
        role: 'editor'
      })

      const result = await controller.rename(ACCESS, USER, { name: 'New' }, REQUEST)

      expect(workspaces.rename).toHaveBeenCalledWith(
        REF,
        'New',
        { userId: 'u1', role: 'editor' },
        expect.objectContaining({ plane: 'dashboard' })
      )
      expect(workspaces.getAccess).toHaveBeenCalledWith(REF, 'u1')
      expect(result).toMatchObject({ id: 'w1', name: 'New' })
    })
  })

  describe('scheduleDeletion', () => {
    it('re-proves the caller first, then schedules by the key and the judged actor', async () => {
      const { controller, workspaces, callers } = build()
      const order: string[] = []
      callers.reauthenticate.mockImplementation(async () => void order.push('reauthenticate'))
      workspaces.scheduleDeletion.mockImplementation(async () => void order.push('schedule'))

      await controller.scheduleDeletion(ACCESS, USER, { password: 'pw' }, REQUEST)

      expect(callers.reauthenticate).toHaveBeenCalledWith(USER, 'pw')
      expect(workspaces.scheduleDeletion).toHaveBeenCalledWith(
        REF,
        { userId: 'u1', role: 'editor' },
        expect.objectContaining({ plane: 'dashboard' })
      )
      expect(order).toEqual(['reauthenticate', 'schedule'])
    })

    it('schedules nothing when the re-proof fails', async () => {
      const { controller, workspaces, callers } = build()
      callers.reauthenticate.mockRejectedValue(new Error('invalid'))

      await expect(
        controller.scheduleDeletion(ACCESS, USER, { password: 'bad' }, REQUEST)
      ).rejects.toThrow('invalid')
      expect(workspaces.scheduleDeletion).not.toHaveBeenCalled()
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
})
