/**
 * @fileoverview Tests for `WorkspaceInvitationController`: what each handler asks of the service,
 * and what it leaves out. The routes themselves are driven over HTTP in
 * `test/e2e/workspace-http-invitations.e2e-spec.ts`.
 *
 * @layer Test
 */

import type { Request } from 'express'

import type { CurrentWorkspaceContext } from '../decorators/current-workspace.decorator'
import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface'
import type { WorkspaceInvitationService } from '../services/workspace-invitation.service'
import { WorkspaceInvitationController } from './workspace-invitation.controller'

const USER = { sub: 'u1', tenantId: 't1' } as DashboardJwtPayload
const ACCESS: CurrentWorkspaceContext = {
  tenantId: 't1',
  workspaceId: 'w1',
  userId: 'u1',
  role: 'editor'
}
const REF = { tenantId: 't1', workspaceId: 'w1' }
const ACTOR = { userId: 'u1', role: 'editor' }
const REQUEST = {
  headers: { 'user-agent': 'jest' },
  socket: { remoteAddress: '203.0.113.9' },
  ip: '203.0.113.9'
} as Partial<Request> as Request

function build(): {
  controller: WorkspaceInvitationController
  invitations: Record<'invite' | 'list' | 'resend' | 'revoke' | 'preview', jest.Mock>
} {
  const invitations = {
    invite: jest.fn(),
    list: jest.fn(),
    resend: jest.fn(),
    revoke: jest.fn(),
    preview: jest.fn()
  }
  return {
    controller: new WorkspaceInvitationController(
      invitations as Partial<WorkspaceInvitationService> as WorkspaceInvitationService
    ),
    invitations
  }
}

describe('WorkspaceInvitationController', () => {
  it('invites to the workspace the guard admitted, as the member it resolved', async () => {
    const { controller, invitations } = build()

    await controller.invite(ACCESS, USER, { email: 'a@example.com', role: 'viewer' }, REQUEST)

    expect(invitations.invite).toHaveBeenCalledWith(REF, ACTOR, 'a@example.com', 'viewer', {
      plane: 'dashboard',
      tenantId: 't1',
      userId: 'u1',
      ip: '203.0.113.9',
      userAgent: 'jest',
      sanitizedHeaders: { 'user-agent': 'jest' }
    })
  })

  it('answers nothing from an invitation, a resend or a revoke', async () => {
    const { controller } = build()

    await expect(
      controller.invite(ACCESS, USER, { email: 'a@example.com', role: 'viewer' }, REQUEST)
    ).resolves.toBeUndefined()
    await expect(
      controller.resend(ACCESS, USER, { email: 'a@example.com' }, REQUEST)
    ).resolves.toBeUndefined()
    await expect(
      controller.revoke(ACCESS, USER, { email: 'a@example.com' }, REQUEST)
    ).resolves.toBeUndefined()
  })

  it.each([['resend'], ['revoke']] as const)(
    '%ss the address it was given, for the member the guard resolved',
    async (method) => {
      const { controller, invitations } = build()

      await controller[method](ACCESS, USER, { email: 'a@example.com' }, REQUEST)

      expect(invitations[method]).toHaveBeenCalledWith(
        REF,
        ACTOR,
        'a@example.com',
        expect.objectContaining({ tenantId: 't1' })
      )
    }
  )

  it('lists with the cursor and size it was given', async () => {
    const { controller, invitations } = build()
    invitations.list.mockResolvedValue({ items: [], nextCursor: null })

    const page = await controller.list(ACCESS, { cursor: 'c1', limit: '25' })

    expect(page).toEqual({ items: [], nextCursor: null })
    expect(invitations.list).toHaveBeenCalledWith(REF, { cursor: 'c1', limit: 25 })
  })

  it('passes no page parameter the request did not carry', async () => {
    const { controller, invitations } = build()
    invitations.list.mockResolvedValue({ items: [], nextCursor: null })

    await controller.list(ACCESS, {})

    expect(Object.keys(invitations.list.mock.calls[0][1] as object)).toEqual([])
  })

  it('previews the token it was given and answers what the service answered', async () => {
    const { controller, invitations } = build()
    invitations.preview.mockResolvedValue({ workspaceName: 'Acme' })

    const answer = await controller.preview({ token: 'f'.repeat(64) })

    expect(answer).toEqual({ workspaceName: 'Acme' })
    expect(invitations.preview).toHaveBeenCalledWith('f'.repeat(64))
  })
})
