/**
 * @fileoverview Tests for `WorkspaceGuard`: the declaration check, the token check, the workspace
 * resolution, the membership answer, the role check and what it attaches to the request.
 *
 * @layer Test
 */

import type { ExecutionContext } from '@nestjs/common'
import type { HttpArgumentsHost } from '@nestjs/common/interfaces'
import { Reflector } from '@nestjs/core'

import { resolveOptions } from '../config/resolved-options'
import { ANY_WORKSPACE_MEMBER } from '../constants/workspace-roles'
import { AllowPendingWorkspace } from '../decorators/allow-pending-workspace.decorator'
import { WorkspaceRoles } from '../decorators/workspace-roles.decorator'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'
import type {
  ResolvedWorkspaceMember,
  WorkspaceAccess,
  WorkspaceAccessService
} from '../services/workspace-access.service'
import type { WorkspaceDeniedEventsService } from '../services/workspace-denied-events.service'
import { WorkspaceGuard } from './workspace.guard'

/** Lets the decision through untouched: the emitter has its own specs. */
const DENIED = {
  admit: (_denied: unknown, decide: () => unknown) => decide()
} as Partial<WorkspaceDeniedEventsService> as WorkspaceDeniedEventsService

const SECRET = 'xY9!kL2@mN5#pQ8$rS1%tU4^vW7&zA0B'

/** Module options with a three-level hierarchy: owner includes editor, which includes viewer. */
function moduleOptions(extra: Partial<BymaxAuthModuleOptions> = {}): BymaxAuthModuleOptions {
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
      ...(extra.workspaces ?? {})
    }
  }
}

class Declared {
  @WorkspaceRoles('editor')
  edit(): void {}

  @WorkspaceRoles(ANY_WORKSPACE_MEMBER)
  read(): void {}

  @WorkspaceRoles('owner')
  own(): void {}

  @WorkspaceRoles('owner', 'viewer')
  either(): void {}

  undeclared(): void {}

  @WorkspaceRoles()
  empty(): void {}
}

class Pending {
  @WorkspaceRoles('owner')
  @AllowPendingWorkspace()
  restore(): void {}

  @WorkspaceRoles('owner')
  other(): void {}
}

@WorkspaceRoles('viewer')
class ClassDeclared {
  inherit(): void {}

  @WorkspaceRoles('owner')
  override(): void {}
}

interface Harness {
  guard: WorkspaceGuard
  /** What the existing cases drive: a member, or `null` for a refusal. */
  resolveMembership: jest.Mock
  /** The call the guard makes; it answers from `resolveMembership` unless a case overrides it. */
  resolveAccess: jest.Mock
}

function build(options: BymaxAuthModuleOptions = moduleOptions()): Harness {
  const resolveMembership = jest.fn()
  const resolveAccess = jest.fn(async (ref: unknown): Promise<WorkspaceAccess> => {
    const member = (await resolveMembership(ref)) as ResolvedWorkspaceMember | null
    return member === null ? { kind: 'denied' } : { kind: 'member', member }
  })
  const access: Partial<WorkspaceAccessService> = { resolveAccess }
  const guard = new WorkspaceGuard(
    new Reflector(),
    access as WorkspaceAccessService,
    resolveOptions(options),
    DENIED
  )
  return { guard, resolveMembership, resolveAccess }
}

/** A request with a verified dashboard user and the given route parameters. */
function requestFor(
  params: Record<string, unknown> | undefined,
  user?: object
): Record<string, unknown> {
  return {
    headers: {},
    url: '/x',
    hostname: 'h',
    ...(params === undefined ? {} : { params }),
    user: user ?? {
      type: 'dashboard',
      sub: 'u1',
      tenantId: 't1',
      role: 'MEMBER',
      jti: 'j',
      status: 'ACTIVE'
    }
  }
}

function contextOf(
  controller: new () => object,
  method: string,
  request: Record<string, unknown>
): ExecutionContext {
  const handler = (controller.prototype as Record<string, () => void>)[method] as () => void
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

/** The code the guard refuses with. */
async function refusal(guard: WorkspaceGuard, context: ExecutionContext): Promise<string> {
  try {
    await guard.canActivate(context)
  } catch (error) {
    return ((error as AuthException).getResponse() as { error: { code: string } }).error.code
  }
  return 'allowed'
}

describe('WorkspaceGuard', () => {
  it('refuses to exist without the workspace group', () => {
    const options = resolveOptions({ ...moduleOptions(), workspaces: { enabled: false } as never })

    expect(
      () => new WorkspaceGuard(new Reflector(), {} as WorkspaceAccessService, options, DENIED)
    ).toThrow('[BymaxAuthModule] WorkspaceGuard needs workspaces.enabled.')
  })

  describe('the declaration', () => {
    it.each(['undeclared', 'empty'])('closes a route whose declaration is %s', async (method) => {
      const { guard, resolveMembership } = build()
      const context = contextOf(Declared, method, requestFor({ workspaceId: 'w1' }))

      await expect(refusal(guard, context)).resolves.toBe(AUTH_ERROR_CODES.FORBIDDEN)
      expect(resolveMembership).not.toHaveBeenCalled()
    })

    it('refuses an undeclared route with 403 before the token, even for an anonymous caller', async () => {
      const { guard, resolveMembership } = build()
      const request = requestFor({ workspaceId: 'w1' }, {})
      delete request['user']

      await expect(refusal(guard, contextOf(Declared, 'undeclared', request))).resolves.toBe(
        AUTH_ERROR_CODES.FORBIDDEN
      )
      expect(resolveMembership).not.toHaveBeenCalled()
    })

    it('uses the class declaration when the handler has none', async () => {
      const { guard, resolveMembership } = build()
      resolveMembership.mockResolvedValue({
        tenantId: 't1',
        workspaceId: 'w1',
        userId: 'u1',
        role: 'viewer'
      })

      await expect(
        refusal(guard, contextOf(ClassDeclared, 'inherit', requestFor({ workspaceId: 'w1' })))
      ).resolves.toBe('allowed')
    })

    it('lets the handler declaration replace the class one', async () => {
      const { guard, resolveMembership } = build()
      resolveMembership.mockResolvedValue({
        tenantId: 't1',
        workspaceId: 'w1',
        userId: 'u1',
        role: 'viewer'
      })

      await expect(
        refusal(guard, contextOf(ClassDeclared, 'override', requestFor({ workspaceId: 'w1' })))
      ).resolves.toBe(AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE)
    })
  })

  describe('the token', () => {
    it.each([
      ['no user', undefined],
      ['a platform token', { type: 'platform', sub: 'a1', role: 'SUPER' }],
      ['a blank subject', { type: 'dashboard', sub: ' ', tenantId: 't1' }],
      ['a blank tenant', { type: 'dashboard', sub: 'u1', tenantId: '' }],
      ['a missing tenant', { type: 'dashboard', sub: 'u1' }]
    ])('refuses %s', async (_name, user) => {
      const { guard, resolveMembership } = build()
      const request = requestFor({ workspaceId: 'w1' }, user ?? {})
      if (user === undefined) delete request['user']

      await expect(refusal(guard, contextOf(Declared, 'read', request))).resolves.toBe(
        AUTH_ERROR_CODES.TOKEN_INVALID
      )
      expect(resolveMembership).not.toHaveBeenCalled()
    })
  })

  describe('the workspace', () => {
    it('refuses a request that names none', async () => {
      const { guard, resolveMembership } = build()

      await expect(refusal(guard, contextOf(Declared, 'read', requestFor({})))).resolves.toBe(
        AUTH_ERROR_CODES.WORKSPACE_REQUIRED
      )
      expect(resolveMembership).not.toHaveBeenCalled()
    })

    it('reads the workspace from the host resolver', async () => {
      const resolver = jest.fn().mockReturnValue('w9')
      const { guard, resolveMembership } = build(
        moduleOptions({ workspaces: { resolveRequestWorkspace: resolver } as never })
      )
      resolveMembership.mockResolvedValue({
        tenantId: 't1',
        workspaceId: 'w9',
        userId: 'u1',
        role: 'owner'
      })

      await guard.canActivate(contextOf(Declared, 'read', requestFor({})))

      expect(resolveMembership).toHaveBeenCalledWith({
        tenantId: 't1',
        workspaceId: 'w9',
        userId: 'u1'
      })
    })
  })

  describe('the membership', () => {
    it('asks for the caller in the workspace, with the tenant from the token', async () => {
      const { guard, resolveMembership } = build()
      resolveMembership.mockResolvedValue({
        tenantId: 't1',
        workspaceId: 'w1',
        userId: 'u1',
        role: 'owner'
      })

      await guard.canActivate(
        contextOf(Declared, 'read', requestFor({ workspaceId: 'w1', tenantId: 'attacker-tenant' }))
      )

      expect(resolveMembership).toHaveBeenCalledWith({
        tenantId: 't1',
        workspaceId: 'w1',
        userId: 'u1'
      })
    })

    it('answers workspace-not-found for a non-member, a missing workspace and an inactive one alike', async () => {
      const { guard, resolveMembership } = build()
      resolveMembership.mockResolvedValue(null)

      await expect(
        refusal(guard, contextOf(Declared, 'read', requestFor({ workspaceId: 'w1' })))
      ).resolves.toBe(AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND)
    })
  })

  describe('a workspace pending deletion', () => {
    const owner = { tenantId: 't1', workspaceId: 'w1', userId: 'u1', role: 'owner' }

    it('tells its owner with 409 on a route that does not admit it', async () => {
      const { guard, resolveAccess } = build()
      resolveAccess.mockResolvedValue({ kind: 'pending_deletion', member: owner })

      await expect(
        refusal(guard, contextOf(Pending, 'other', requestFor({ workspaceId: 'w1' })))
      ).resolves.toBe(AUTH_ERROR_CODES.WORKSPACE_PENDING_DELETION)
    })

    it('admits its owner on the route that carries @AllowPendingWorkspace', async () => {
      const { guard, resolveAccess } = build()
      resolveAccess.mockResolvedValue({ kind: 'pending_deletion', member: owner })
      const request = requestFor({ workspaceId: 'w1' })

      await expect(refusal(guard, contextOf(Pending, 'restore', request))).resolves.toBe('allowed')
      expect(request['workspace']).toEqual(owner)
    })

    it('still checks the role on the admitting route', async () => {
      const { guard, resolveAccess } = build()
      resolveAccess.mockResolvedValue({
        kind: 'pending_deletion',
        member: { ...owner, role: 'viewer' }
      })

      await expect(
        refusal(guard, contextOf(Pending, 'restore', requestFor({ workspaceId: 'w1' })))
      ).resolves.toBe(AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE)
    })
  })

  describe('the role', () => {
    it.each([
      ['edit', 'owner', 'allowed'],
      ['edit', 'editor', 'allowed'],
      ['edit', 'viewer', AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE],
      ['own', 'editor', AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE],
      ['read', 'viewer', 'allowed'],
      ['either', 'viewer', 'allowed'],
      ['either', 'editor', 'allowed'],
      ['either', 'unknown-role', AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE],
      ['edit', 'unknown-role', AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE]
    ])('on %s a %s is %s', async (method, role, expected) => {
      const { guard, resolveMembership } = build()
      resolveMembership.mockResolvedValue({ tenantId: 't1', workspaceId: 'w1', userId: 'u1', role })

      await expect(
        refusal(guard, contextOf(Declared, method, requestFor({ workspaceId: 'w1' })))
      ).resolves.toBe(expected)
    })
  })

  it('attaches the access, and only that, to the request', async () => {
    const { guard, resolveMembership } = build()
    resolveMembership.mockResolvedValue({
      tenantId: 't1',
      workspaceId: 'w1',
      userId: 'u1',
      role: 'editor',
      extra: 1
    })
    const request = requestFor({ workspaceId: 'w1' })

    const allowed = await guard.canActivate(contextOf(Declared, 'edit', request))

    expect(allowed).toBe(true)
    expect(request['workspace']).toEqual({
      tenantId: 't1',
      workspaceId: 'w1',
      userId: 'u1',
      role: 'editor',
      extra: 1
    })
  })
})
