/**
 * @fileoverview The route guard and the socket guard report a refusal to the `access.denied`
 * emitter with the surface they are, the account and tenant of the verified identity, and the
 * workspace they validated, and never alter the decision. Kept apart from the guards' own specs,
 * which are near the size limit.
 *
 * @layer Test
 */

import type { ExecutionContext } from '@nestjs/common'
import { Reflector } from '@nestjs/core'

import { WorkspaceGuard } from './workspace.guard'
import { WsWorkspaceGuard } from './ws-workspace.guard'
import type { ResolvedOptions } from '../config/resolved-options'
import { resolveWorkspaceOptions } from '../config/workspace-options'
import { WorkspaceRoles } from '../decorators/workspace-roles.decorator'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'
import type { WorkspaceAccessService } from '../services/workspace-access.service'
import type { WorkspaceDeniedEventsService } from '../services/workspace-denied-events.service'

class Handlers {
  @WorkspaceRoles('editor')
  edit(): void {}
}

const GROUP = resolveWorkspaceOptions({
  workspaces: {
    enabled: true,
    roles: { hierarchy: { owner: ['editor'], editor: [] }, ownerRole: 'owner' }
  }
} as Partial<BymaxAuthModuleOptions> as BymaxAuthModuleOptions)

if (GROUP === undefined) throw new Error('the workspace group did not resolve')

const OPTIONS = Object.assign({} as ResolvedOptions, { workspaces: GROUP })

function harness(access: unknown) {
  const admit = jest.fn((_denied: unknown, decide: () => unknown) => decide())
  return {
    admit,
    denied: { admit } as Partial<WorkspaceDeniedEventsService> as WorkspaceDeniedEventsService,
    service: {
      resolveAccess: jest.fn().mockResolvedValue(access)
    } as Partial<WorkspaceAccessService> as WorkspaceAccessService
  }
}

const handler = Handlers.prototype.edit

function httpContext(): ExecutionContext {
  const request = {
    headers: {},
    params: { workspaceId: 'w1' },
    user: { type: 'dashboard', sub: 'u1', tenantId: 't1', role: 'MEMBER', jti: 'j' }
  }
  return {
    getHandler: () => handler,
    getClass: () => Handlers,
    switchToHttp: () => ({ getRequest: () => request })
  } as never
}

function wsContext(): ExecutionContext {
  const client = { data: { user: { sub: 'u1', tenantId: 't1' } } }
  return {
    getHandler: () => handler,
    getClass: () => Handlers,
    switchToWs: () => ({ getClient: () => client, getData: () => ({ workspaceId: 'w1' }) })
  } as never
}

describe('access.denied from the workspace guards', () => {
  it('reports a refused route as the http surface and still refuses', async () => {
    const h = harness({ kind: 'denied' })
    const guard = new WorkspaceGuard(new Reflector(), h.service, OPTIONS, h.denied)

    await expect(guard.canActivate(httpContext())).rejects.toMatchObject({
      response: { error: { code: AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND } }
    })

    expect(h.admit).toHaveBeenCalledTimes(1)
    expect(h.admit.mock.calls[0]?.[0]).toEqual({
      tenantId: 't1',
      userId: 'u1',
      workspaceId: 'w1',
      surface: 'http'
    })
  })

  it('reports a refused message as the ws surface and still refuses', async () => {
    const h = harness({ kind: 'denied' })
    const guard = new WsWorkspaceGuard(new Reflector(), h.service, OPTIONS, h.denied)

    await expect(guard.canActivate(wsContext())).rejects.toBeInstanceOf(AuthException)

    expect(h.admit.mock.calls[0]?.[0]).toEqual({
      tenantId: 't1',
      userId: 'u1',
      workspaceId: 'w1',
      surface: 'ws'
    })
  })

  it('admits through the emitter without a report for a member', async () => {
    const member = { tenantId: 't1', workspaceId: 'w1', userId: 'u1', role: 'editor' }
    const h = harness({ kind: 'member', member })

    await expect(
      new WorkspaceGuard(new Reflector(), h.service, OPTIONS, h.denied).canActivate(httpContext())
    ).resolves.toBe(true)
    await expect(
      new WsWorkspaceGuard(new Reflector(), h.service, OPTIONS, h.denied).canActivate(wsContext())
    ).resolves.toBe(true)
  })

  it('does not reach the emitter for a request refused before the decision', async () => {
    const h = harness({ kind: 'denied' })
    const guard = new WorkspaceGuard(new Reflector(), h.service, OPTIONS, h.denied)
    const context = httpContext()
    ;(context.switchToHttp().getRequest() as { params: unknown }).params = {}

    await expect(guard.canActivate(context)).rejects.toBeInstanceOf(AuthException)

    expect(h.admit).not.toHaveBeenCalled()
  })
})
