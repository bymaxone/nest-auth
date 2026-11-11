/**
 * @fileoverview Tests for `WorkspaceGuard` with `@WorkspacePermission(...)`: the roles come from
 * `workspaces.permissions`, a handler's declaration replaces the class's, and a target that
 * declares both a permission and roles is refused.
 *
 * @layer Test
 */

import type { ExecutionContext } from '@nestjs/common'
import type { HttpArgumentsHost } from '@nestjs/common/interfaces'
import { Reflector } from '@nestjs/core'

import { resolveOptions } from '../config/resolved-options'
import { ANY_WORKSPACE_MEMBER } from '../constants/workspace-roles'
import { WorkspacePermission } from '../decorators/workspace-permission.decorator'
import { WorkspaceRoles } from '../decorators/workspace-roles.decorator'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { WorkspaceOptions } from '../interfaces/workspace-options.interface'
import type {
  ResolvedWorkspaceMember,
  WorkspaceAccessService
} from '../services/workspace-access.service'
import type { WorkspaceDeniedEventsService } from '../services/workspace-denied-events.service'
import { WorkspaceGuard } from './workspace.guard'

/** Lets the decision through untouched: the emitter has its own specs. */
const DENIED = {
  admit: (_denied: unknown, decide: () => unknown) => decide()
} as Partial<WorkspaceDeniedEventsService> as WorkspaceDeniedEventsService

const HIERARCHY = { owner: ['editor', 'viewer'], editor: ['viewer'], viewer: [] }

class Routes {
  @WorkspacePermission('manageWorkspace')
  rename(): void {}

  @WorkspacePermission('deleteWorkspace')
  remove(): void {}

  @WorkspacePermission('manageMembers')
  members(): void {}

  @WorkspacePermission('viewMembers')
  list(): void {}

  @WorkspacePermission('manageMembers')
  @WorkspaceRoles('viewer')
  both(): void {}
}

@WorkspacePermission('manageMembers')
class ClassPermission {
  inherit(): void {}

  @WorkspaceRoles('viewer')
  override(): void {}
}

@WorkspaceRoles('viewer')
class ClassRoles {
  @WorkspacePermission('manageMembers')
  override(): void {}

  @WorkspaceRoles()
  emptied(): void {}
}

function guardFor(
  permissions: WorkspaceOptions['permissions'],
  role: string
): { guard: WorkspaceGuard; resolveAccess: jest.Mock } {
  const member: ResolvedWorkspaceMember = {
    tenantId: 't1',
    workspaceId: 'w1',
    userId: 'u1',
    role
  }
  const resolveAccess = jest.fn().mockResolvedValue({ kind: 'member', member })
  const options = resolveOptions({
    jwt: { secret: 'xY9!kL2@mN5#pQ8$rS1%tU4^vW7&zA0B' },
    roles: { hierarchy: { ADMIN: [] } },
    rateLimit: { clientIpSource: 'peer' },
    workspaces: {
      enabled: true,
      roles: { hierarchy: HIERARCHY, ownerRole: 'owner' },
      ...(permissions === undefined ? {} : { permissions })
    }
  })
  const access: Partial<WorkspaceAccessService> = { resolveAccess }
  return {
    guard: new WorkspaceGuard(new Reflector(), access as WorkspaceAccessService, options, DENIED),
    resolveAccess
  }
}

function contextOf(controller: new () => object, method: string): ExecutionContext {
  const handler = (controller.prototype as Record<string, () => void>)[method] as () => void
  const request = {
    headers: {},
    url: '/x',
    hostname: 'h',
    params: { workspaceId: 'w1' },
    user: { type: 'dashboard', sub: 'u1', tenantId: 't1', role: 'MEMBER', jti: 'j' }
  }
  const http: HttpArgumentsHost = {
    getRequest: <T>() => request as T,
    getResponse: <T>() => undefined as T,
    getNext: <T>() => undefined as T
  }
  const context: Partial<ExecutionContext> = {
    getHandler: () => handler,
    getClass: () => controller as never,
    switchToHttp: () => http
  }
  return context as ExecutionContext
}

async function outcome(guard: WorkspaceGuard, context: ExecutionContext): Promise<string> {
  try {
    await guard.canActivate(context)
    return 'allowed'
  } catch (error) {
    return ((error as AuthException).getResponse() as { error: { code: string } }).error.code
  }
}

describe('WorkspaceGuard with @WorkspacePermission', () => {
  it.each([
    ['rename', 'owner', 'allowed'],
    ['rename', 'editor', AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE],
    ['remove', 'owner', 'allowed'],
    ['remove', 'editor', AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE],
    ['members', 'owner', 'allowed'],
    ['members', 'editor', AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE],
    ['list', 'viewer', 'allowed']
  ])('applies the default roles of %s to a %s', async (method, role, expected) => {
    const { guard } = guardFor(undefined, role)

    await expect(outcome(guard, contextOf(Routes, method))).resolves.toBe(expected)
  })

  it.each([
    ['rename', { manageWorkspace: ['editor'] }],
    ['remove', { deleteWorkspace: ['editor'] }],
    ['members', { manageMembers: ['editor'] }],
    ['list', { viewMembers: ['owner'] }]
  ])('reads the roles of %s from the host configuration', async (method, permissions) => {
    const configured = permissions as WorkspaceOptions['permissions']
    const editor = guardFor(configured, 'editor')
    const viewer = guardFor(configured, 'viewer')

    const forEditor = await outcome(editor.guard, contextOf(Routes, method))
    const forViewer = await outcome(viewer.guard, contextOf(Routes, method))

    expect(forEditor).toBe(
      method === 'list' ? AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE : 'allowed'
    )
    expect(forViewer).toBe(AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE)
  })

  it('lets every member list when viewMembers is the any-member marker', async () => {
    const { guard } = guardFor({ viewMembers: [ANY_WORKSPACE_MEMBER] }, 'viewer')

    await expect(outcome(guard, contextOf(Routes, 'list'))).resolves.toBe('allowed')
  })

  it('refuses a target that declares both a permission and roles, before any lookup', async () => {
    const { guard, resolveAccess } = guardFor(undefined, 'owner')

    await expect(outcome(guard, contextOf(Routes, 'both'))).resolves.toBe(
      AUTH_ERROR_CODES.FORBIDDEN
    )
    expect(resolveAccess).not.toHaveBeenCalled()
  })

  it('uses the class permission when the handler declares nothing', async () => {
    const owner = guardFor(undefined, 'owner')
    const editor = guardFor(undefined, 'editor')

    await expect(outcome(owner.guard, contextOf(ClassPermission, 'inherit'))).resolves.toBe(
      'allowed'
    )
    await expect(outcome(editor.guard, contextOf(ClassPermission, 'inherit'))).resolves.toBe(
      AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE
    )
  })

  it('lets a handler roles declaration replace the class permission', async () => {
    const { guard } = guardFor(undefined, 'viewer')

    await expect(outcome(guard, contextOf(ClassPermission, 'override'))).resolves.toBe('allowed')
  })

  it('lets a handler permission replace the class roles', async () => {
    const { guard } = guardFor(undefined, 'viewer')

    await expect(outcome(guard, contextOf(ClassRoles, 'override'))).resolves.toBe(
      AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE
    )
  })

  // Scenario: a handler declares an empty roles list under a class that declares roles. Expected:
  // refused. Why: an empty list is a declaration of nothing, and falling through to the class
  // would admit a route that listed no role at all.
  it('refuses a handler with an empty roles list instead of using the class roles', async () => {
    const { guard, resolveAccess } = guardFor(undefined, 'viewer')

    await expect(outcome(guard, contextOf(ClassRoles, 'emptied'))).resolves.toBe(
      AUTH_ERROR_CODES.FORBIDDEN
    )
    expect(resolveAccess).not.toHaveBeenCalled()
  })

  // The metadata key is part of what a host that writes its own guard reads.
  it('stores the declared action under a stable metadata key', () => {
    const handler = Routes.prototype.rename

    expect(Reflect.getMetadata('workspacePermission', handler)).toBe('manageWorkspace')
  })
})
