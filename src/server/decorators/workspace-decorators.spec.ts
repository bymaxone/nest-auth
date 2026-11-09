/**
 * @fileoverview Tests for `@WorkspaceRoles` and `@CurrentWorkspace`.
 *
 * @layer Test
 */

import { ROUTE_ARGS_METADATA } from '@nestjs/common/constants'

import { ANY_WORKSPACE_MEMBER } from '../constants/workspace-roles'
import {
  ALLOW_PENDING_WORKSPACE_KEY,
  AllowPendingWorkspace
} from './allow-pending-workspace.decorator'
import { CurrentWorkspace } from './current-workspace.decorator'
import type { CurrentWorkspaceContext } from './current-workspace.decorator'
import { WORKSPACE_ROLES_KEY, WorkspaceRoles } from './workspace-roles.decorator'

describe('WorkspaceRoles', () => {
  it('keeps its metadata under a key of its own', () => {
    expect(WORKSPACE_ROLES_KEY).toBe('workspaceRoles')
  })

  class Controller {
    @WorkspaceRoles('owner', ANY_WORKSPACE_MEMBER)
    handler(): void {}
  }

  it('stores the declared roles on the handler', () => {
    const stored: unknown = Reflect.getMetadata(WORKSPACE_ROLES_KEY, Controller.prototype.handler)

    expect(stored).toEqual(['owner', ANY_WORKSPACE_MEMBER])
  })

  it('stores them on a class when applied there', () => {
    @WorkspaceRoles('editor')
    class Decorated {}

    expect(Reflect.getMetadata(WORKSPACE_ROLES_KEY, Decorated)).toEqual(['editor'])
  })
})

describe('CurrentWorkspace', () => {
  /** Runs the decorator's factory against a request. */
  function resolve(request: unknown): CurrentWorkspaceContext {
    class Host {
      handler(@CurrentWorkspace() _workspace: CurrentWorkspaceContext): void {}
    }
    const args = Reflect.getMetadata(ROUTE_ARGS_METADATA, Host, 'handler') as Record<
      string,
      { factory: (data: unknown, ctx: unknown) => CurrentWorkspaceContext }
    >
    const [entry] = Object.values(args)
    const context = { switchToHttp: () => ({ getRequest: () => request }) }
    return (entry as NonNullable<typeof entry>).factory(undefined, context)
  }

  it('returns the access the guard attached', () => {
    const workspace = { tenantId: 't1', workspaceId: 'w1', userId: 'u1', role: 'owner' }

    expect(resolve({ workspace })).toBe(workspace)
  })

  it('throws when the route ran without the guard', () => {
    expect(() => resolve({})).toThrow('@CurrentWorkspace() needs WorkspaceGuard on the route.')
  })
})

describe('AllowPendingWorkspace', () => {
  it('marks a handler under a key of its own', () => {
    class Host {
      @AllowPendingWorkspace()
      restore(): void {}
    }

    expect(ALLOW_PENDING_WORKSPACE_KEY).toBe('allowPendingWorkspace')
    expect(Reflect.getMetadata(ALLOW_PENDING_WORKSPACE_KEY, Host.prototype.restore)).toBe(true)
  })

  it('marks a class when applied there', () => {
    @AllowPendingWorkspace()
    class Whole {}

    expect(Reflect.getMetadata(ALLOW_PENDING_WORKSPACE_KEY, Whole)).toBe(true)
  })
})
