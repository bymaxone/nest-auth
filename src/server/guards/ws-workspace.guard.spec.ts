/**
 * @fileoverview Tests for `WsWorkspaceGuard`: a socket message admitted to the workspace it names,
 * with the route guard's declarations, access resolution and refusals.
 *
 * @layer Test
 */

import type { ExecutionContext } from '@nestjs/common'
import { Reflector } from '@nestjs/core'

import { WsWorkspaceGuard } from './ws-workspace.guard'
import { resolveOptions } from '../config/resolved-options'
import { ANY_WORKSPACE_MEMBER } from '../constants/workspace-roles'
import { AllowPendingWorkspace } from '../decorators/allow-pending-workspace.decorator'
import { WorkspacePermission } from '../decorators/workspace-permission.decorator'
import { WorkspaceRoles } from '../decorators/workspace-roles.decorator'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import type { AuthException } from '../errors/auth-exception'
import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'
import { WorkspaceAccessService } from '../services/workspace-access.service'
import type { WorkspaceDeniedEventsService } from '../services/workspace-denied-events.service'
import { workspaceOfMessage } from '../utils/ws-message-workspace'

/** Lets the decision through untouched: the emitter has its own specs. */
const DENIED = {
  admit: (_denied: unknown, decide: () => unknown) => decide()
} as Partial<WorkspaceDeniedEventsService> as WorkspaceDeniedEventsService

const SECRET = 'xY9!kL2@mN5#pQ8$rS1%tU4^vW7&zA0B'

/** Module options with workspaces enabled and the given extra workspace settings. */
function options(extra: Record<string, unknown> = {}): BymaxAuthModuleOptions {
  return {
    jwt: { secret: SECRET },
    roles: { hierarchy: { ADMIN: [] } },
    rateLimit: { clientIpSource: 'peer' },
    workspaces: {
      enabled: true,
      roles: {
        hierarchy: { owner: ['editor', 'viewer'], editor: ['viewer'], viewer: [] },
        ownerRole: 'owner'
      },
      ...extra
    }
  }
}

class Gateway {
  @WorkspaceRoles('editor')
  edit(): void {}

  @WorkspaceRoles(ANY_WORKSPACE_MEMBER)
  read(): void {}

  @WorkspaceRoles('owner')
  @AllowPendingWorkspace()
  own(): void {}

  @WorkspacePermission('viewMembers')
  members(): void {}

  undeclared(): void {}
}

const IDENTITY = { sub: 'u1', tenantId: 't1' }

/** A WS execution context for a handler, with the client's data and the message. */
function contextFor(
  handler: keyof Gateway,
  client: { data: Record<string, unknown> },
  message: unknown
): ExecutionContext {
  return Object.assign({} as ExecutionContext, {
    getHandler: () => Gateway.prototype[handler],
    getClass: () => Gateway,
    switchToWs: () => ({ getClient: () => client, getData: () => message })
  })
}

/** A guard over a stubbed access resolution. */
function build(access: jest.Mock, extra: Record<string, unknown> = {}): WsWorkspaceGuard {
  const service = { resolveAccess: access } as Partial<WorkspaceAccessService>
  return new WsWorkspaceGuard(
    new Reflector(),
    service as WorkspaceAccessService,
    resolveOptions(options(extra)),
    DENIED
  )
}

const member = (
  role: string
): {
  kind: 'member'
  member: { tenantId: string; workspaceId: string; userId: string; role: string }
} => ({
  kind: 'member',
  member: { tenantId: 't1', workspaceId: 'w1', userId: 'u1', role }
})

/** The code a promise rejects with, or `undefined` when it resolves. */
async function code(promise: Promise<unknown>): Promise<string | undefined> {
  try {
    await promise
  } catch (error) {
    return ((error as AuthException).getResponse() as { error: { code: string } }).error.code
  }
  return undefined
}

describe('WsWorkspaceGuard', () => {
  it('admits a member with an accepted role and keeps the membership with the message', async () => {
    const access = jest.fn().mockResolvedValue(member('editor'))
    const client = { data: { user: IDENTITY } as Record<string, unknown> }
    const message = { workspaceId: 'w1' }

    await expect(build(access).canActivate(contextFor('edit', client, message))).resolves.toBe(true)

    expect(workspaceOfMessage(message)).toEqual({
      tenantId: 't1',
      workspaceId: 'w1',
      userId: 'u1',
      role: 'editor'
    })
    expect(client.data).not.toHaveProperty('workspace')
    expect(access).toHaveBeenCalledWith({ tenantId: 't1', workspaceId: 'w1', userId: 'u1' })
  })

  // Two messages overlap on one socket: the owner-only one for A finishes last, the viewer one for B
  // first. A slot on the connection would hold A when either handler read it afterwards; each message
  // keeps its own.
  it('keeps overlapping messages on one socket apart', async () => {
    const access = jest.fn(async (ref: { workspaceId: string }) => {
      await new Promise((resolve) => setTimeout(resolve, ref.workspaceId === 'A' ? 20 : 1))
      return member(ref.workspaceId === 'A' ? 'owner' : 'viewer')
    })
    const guard = build(access)
    const client = { data: { user: IDENTITY } }
    const a = { workspaceId: 'A' }
    const b = { workspaceId: 'B' }

    await Promise.all([
      guard.canActivate(contextFor('own', client, a)),
      guard.canActivate(contextFor('read', client, b))
    ])

    expect(workspaceOfMessage(a)).toMatchObject({ role: 'owner' })
    expect(workspaceOfMessage(b)).toMatchObject({ role: 'viewer' })
    expect(client.data).not.toHaveProperty('workspace')
  })

  it('takes the tenant and the account from the verified identity, never from the message', async () => {
    const access = jest.fn().mockResolvedValue(member('viewer'))
    const client = { data: { user: IDENTITY } }

    await build(access).canActivate(
      contextFor('read', client, { workspaceId: 'w1', tenantId: 'other', userId: 'other' })
    )

    expect(access).toHaveBeenCalledWith({ tenantId: 't1', workspaceId: 'w1', userId: 'u1' })
  })

  it('judges every message again, so a member removed between two is refused on the second', async () => {
    const access = jest
      .fn()
      .mockResolvedValueOnce(member('viewer'))
      .mockResolvedValueOnce({ kind: 'denied' })
    const guard = build(access)
    const client = { data: { user: IDENTITY } }

    await guard.canActivate(contextFor('read', client, { workspaceId: 'w1' }))

    expect(await code(guard.canActivate(contextFor('read', client, { workspaceId: 'w1' })))).toBe(
      AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND
    )
  })

  it('reads the workspace through the host resolver, which receives the message body only', async () => {
    const access = jest.fn().mockResolvedValue(member('viewer'))
    const resolveWsWorkspace = jest.fn((message: unknown) => (message as { room: string }).room)
    const client = {
      data: { user: IDENTITY },
      handshake: { headers: { 'x-workspace-id': 'evil' } }
    }

    await build(access, { resolveWsWorkspace }).canActivate(
      contextFor('read', client, { room: 'w9', workspaceId: 'ignored' })
    )

    expect(resolveWsWorkspace).toHaveBeenCalledWith({ room: 'w9', workspaceId: 'ignored' })
    expect(resolveWsWorkspace.mock.calls[0]).toHaveLength(1)
    expect(access).toHaveBeenCalledWith(expect.objectContaining({ workspaceId: 'w9' }))
  })

  it('never reads the workspace from a header or the handshake', async () => {
    const access = jest.fn()
    const client = {
      data: { user: IDENTITY },
      handshake: { headers: { 'x-workspace-id': 'w1' }, query: { workspaceId: 'w1' } }
    }

    expect(await code(build(access).canActivate(contextFor('read', client, {})))).toBe(
      AUTH_ERROR_CODES.VALIDATION
    )
    expect(access).not.toHaveBeenCalled()
  })

  it.each([
    ["a workspace that does not exist or is not the caller's", { kind: 'denied' }],
    ['a workspace pending deletion the caller does not own', { kind: 'denied' }]
  ])('answers the identical workspace_not_found for %s', async (_name, resolved) => {
    const access = jest.fn().mockResolvedValue(resolved)

    expect(
      await code(
        build(access).canActivate(
          contextFor('read', { data: { user: IDENTITY } }, { workspaceId: 'w1' })
        )
      )
    ).toBe(AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND)
  })

  it('tells the owner of a pending workspace, unless the handler admits pending ones', async () => {
    const pending = { kind: 'pending_deletion', member: member('owner').member }
    const access = jest.fn().mockResolvedValue(pending)
    const client = { data: { user: IDENTITY } }

    expect(
      await code(build(access).canActivate(contextFor('members', client, { workspaceId: 'w1' })))
    ).toBe(AUTH_ERROR_CODES.WORKSPACE_PENDING_DELETION)
    await expect(
      build(access).canActivate(contextFor('own', client, { workspaceId: 'w1' }))
    ).resolves.toBe(true)
  })

  it('refuses a role below what the handler declares, and honours a declared permission', async () => {
    const access = jest.fn().mockResolvedValue(member('viewer'))
    const client = { data: { user: IDENTITY } }

    expect(
      await code(build(access).canActivate(contextFor('edit', client, { workspaceId: 'w1' })))
    ).toBe(AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE)
    await expect(
      build(access).canActivate(contextFor('members', client, { workspaceId: 'w1' }))
    ).resolves.toBe(true)
  })

  it('refuses a handler that declares nothing before it looks at anything else', async () => {
    const access = jest.fn()

    expect(await code(build(access).canActivate(contextFor('undeclared', { data: {} }, {})))).toBe(
      AUTH_ERROR_CODES.FORBIDDEN
    )
    expect(access).not.toHaveBeenCalled()
  })

  it.each([
    ['no user', {}],
    ['a user without a tenant', { user: { sub: 'u1' } }],
    ['a user with a blank subject', { user: { sub: '  ', tenantId: 't1' } }]
  ])('refuses a connection with %s as token_invalid, before any lookup', async (_name, data) => {
    const access = jest.fn()

    expect(
      await code(build(access).canActivate(contextFor('read', { data }, { workspaceId: 'w1' })))
    ).toBe(AUTH_ERROR_CODES.TOKEN_INVALID)
    expect(access).not.toHaveBeenCalled()
  })

  it.each([
    ['blank', '   '],
    ['over the bound', 'w'.repeat(129)],
    ['holding a control character', 'w\u0000'],
    ['a number', 5],
    ['absent', undefined]
  ])('refuses an id that is %s as a validation error naming workspaceId', async (_n, id) => {
    const access = jest.fn()
    const guard = build(access)

    const error = await guard
      .canActivate(contextFor('read', { data: { user: IDENTITY } }, { workspaceId: id }))
      .catch((e: unknown) => e as AuthException)

    expect((error as AuthException).getResponse()).toMatchObject({
      error: { code: AUTH_ERROR_CODES.VALIDATION, details: [{ field: 'workspaceId' }] }
    })
    expect(access).not.toHaveBeenCalled()
  })

  it('treats a null message as naming no workspace, not as a crash', async () => {
    const access = jest.fn()

    expect(
      await code(build(access).canActivate(contextFor('read', { data: { user: IDENTITY } }, null)))
    ).toBe(AUTH_ERROR_CODES.VALIDATION)
  })

  it('treats a message that is not an object as naming no workspace', async () => {
    const access = jest.fn()

    expect(
      await code(build(access).canActivate(contextFor('read', { data: { user: IDENTITY } }, 'w1')))
    ).toBe(AUTH_ERROR_CODES.VALIDATION)
  })

  // The disclosure rule is decided from the rows already read, so a stream reveals nothing the
  // route hides: through the real access resolution, a non-owner member of a workspace pending
  // deletion gets the not-found a stranger gets, and only the owner is told.
  it('discloses a workspace pending deletion to its owner only, through the real resolution', async () => {
    const workspaces = { findById: jest.fn().mockResolvedValue({ status: 'pending_deletion' }) }
    const memberships = { find: jest.fn() }
    const resolved = resolveOptions(options({ membershipCacheTtlSeconds: 0 }))
    const service = new WorkspaceAccessService(
      {} as never,
      workspaces as never,
      memberships as never,
      resolved
    )
    const guard = new WsWorkspaceGuard(new Reflector(), service, resolved, DENIED)
    const client = { data: { user: IDENTITY } }
    const message = { workspaceId: 'w1' }

    memberships.find.mockResolvedValue({ role: 'editor', status: 'active' })
    const nonOwner = await code(guard.canActivate(contextFor('members', client, message)))
    memberships.find.mockResolvedValue(null)
    const stranger = await code(guard.canActivate(contextFor('members', client, message)))
    memberships.find.mockResolvedValue({ role: 'owner', status: 'active' })
    const owner = await code(guard.canActivate(contextFor('members', client, message)))

    expect(nonOwner).toBe(AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND)
    expect(stranger).toBe(nonOwner)
    expect(owner).toBe(AUTH_ERROR_CODES.WORKSPACE_PENDING_DELETION)
  })

  it('refuses to be built without workspaces', () => {
    const plain = resolveOptions({
      jwt: { secret: SECRET },
      roles: { hierarchy: { ADMIN: [] } },
      rateLimit: { clientIpSource: 'peer' }
    })

    expect(
      () => new WsWorkspaceGuard(new Reflector(), {} as WorkspaceAccessService, plain, DENIED)
    ).toThrow('WsWorkspaceGuard needs workspaces.enabled')
  })
})
