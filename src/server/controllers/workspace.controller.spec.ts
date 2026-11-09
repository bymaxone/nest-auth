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
  workspaces: { getAccess: jest.Mock; switchTo: jest.Mock }
  memberships: { listMine: jest.Mock; listMembers: jest.Mock }
} {
  const workspaces = { getAccess: jest.fn(), switchTo: jest.fn() }
  const memberships = { listMine: jest.fn(), listMembers: jest.fn() }
  return {
    controller: new WorkspaceController(
      workspaces as Partial<WorkspaceService> as WorkspaceService,
      memberships as Partial<MembershipService> as MembershipService
    ),
    workspaces,
    memberships
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

      expect(memberships.listMine).toHaveBeenCalledWith('t1', 'u1', {})
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

      expect(memberships.listMembers).toHaveBeenCalledWith(REF, {})
    })
  })
})
