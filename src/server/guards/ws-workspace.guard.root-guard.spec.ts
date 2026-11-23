/**
 * @fileoverview The WebSocket workspace guard checks the built-ins its decision is made with after the lookup of the access that it
 * waits for, so a replacement made during the lookup is refused before the message is admitted to the workspace.
 *
 * @layer Test
 */

import type { ExecutionContext } from '@nestjs/common'
import { Reflector } from '@nestjs/core'

import { resolveOptions } from '../config/resolved-options'
import { WorkspaceRoles } from '../decorators/workspace-roles.decorator'
import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'
import type { WorkspaceAccessService } from '../services/workspace-access.service'
import type { WorkspaceDeniedEventsService } from '../services/workspace-denied-events.service'
import { WsWorkspaceGuard } from './ws-workspace.guard'

// The test's own copies: the window below replaces a built-in, so nothing inside it may call a live one.
const define = Object.defineProperty
const getOwn = Object.getOwnPropertyDescriptor

const SECRET = 'xY9!kL2@mN5#pQ8$rS1%tU4^vW7&zA0B'
const OPTIONS = {
  jwt: { secret: SECRET },
  roles: { hierarchy: { ADMIN: [] } },
  rateLimit: { clientIpSource: 'peer' },
  workspaces: {
    enabled: true,
    roles: { hierarchy: { owner: ['editor'], editor: [] }, ownerRole: 'owner' }
  }
} as BymaxAuthModuleOptions
const DENIED = {
  admit: (_ref: unknown, decide: () => unknown) => decide()
} as unknown as WorkspaceDeniedEventsService

class Gateway {
  @WorkspaceRoles('editor')
  edit(): void {}
}

function context(): ExecutionContext {
  const client = { data: { user: { sub: 'u1', tenantId: 't1' } } }
  return {
    getHandler: () => Gateway.prototype.edit,
    getClass: () => Gateway,
    switchToWs: () => ({ getClient: () => client, getData: () => ({ workspaceId: 'w1' }) })
  } as unknown as ExecutionContext
}

/** The status of the refusal, `true` for an admission, or `undefined` for any other failure. */
async function outcome(access: () => Promise<unknown>): Promise<number | true | undefined> {
  const service = { resolveAccess: access } as unknown as WorkspaceAccessService
  const guard = new WsWorkspaceGuard(new Reflector(), service, resolveOptions(OPTIONS), DENIED)
  try {
    return (await guard.canActivate(context())) ? true : undefined
  } catch (error) {
    return (error as { getStatus?: () => number }).getStatus?.()
  }
}

const member = {
  kind: 'member',
  member: { tenantId: 't1', workspaceId: 'w1', userId: 'u1', role: 'owner' }
}

describe('WsWorkspaceGuard while a built-in is replaced', () => {
  // Scenario: a member with the role, nothing replaced. Expected: admitted. Why: the control for the row below.
  it('admits a member with nothing replaced', async () => {
    await expect(outcome(async () => member)).resolves.toBe(true)
  })

  // Scenario: the access lookup replaces `Set.prototype.has` while it is awaited and then answers a member. Expected: the library's
  // refusal. Why: the membership and the role are decided after the lookup, with the built-ins as it left them.
  it('is refused when a built-in is replaced during the access lookup', async () => {
    let restore = (): void => undefined
    let result: number | true | undefined
    try {
      result = await outcome(async () => {
        await Promise.resolve()
        const held = getOwn(Set.prototype, 'has') as PropertyDescriptor
        define(Set.prototype, 'has', { ...held, value: () => true })
        restore = (): void => void define(Set.prototype, 'has', held)
        return member
      })
    } finally {
      restore()
    }

    expect(result).toBe(500)
  })
})
