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
import { WorkspaceRoles } from '../decorators/workspace-roles.decorator'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'
import type { WorkspaceAccessService } from '../services/workspace-access.service'
import { WorkspaceGuard } from './workspace.guard'

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

@WorkspaceRoles('viewer')
class ClassDeclared {
  inherit(): void {}

  @WorkspaceRoles('owner')
  override(): void {}
}

interface Harness {
  guard: WorkspaceGuard
  resolveMembership: jest.Mock
}

function build(options: BymaxAuthModuleOptions = moduleOptions()): Harness {
  const resolveMembership = jest.fn()
  const access: Partial<WorkspaceAccessService> = { resolveMembership }
  const guard = new WorkspaceGuard(
    new Reflector(),
    access as WorkspaceAccessService,
    resolveOptions(options)
  )
  return { guard, resolveMembership }
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
      () => new WorkspaceGuard(new Reflector(), {} as WorkspaceAccessService, options)
    ).toThrow('[BymaxAuthModule] WorkspaceGuard needs workspaces.enabled.')
  })

  describe('the declaration', () => {
    it.each(['undeclared', 'empty'])('closes a route whose declaration is %s', async (method) => {
      const { guard, resolveMembership } = build()
      const context = contextOf(Declared, method, requestFor({ workspaceId: 'w1' }))

      await expect(refusal(guard, context)).resolves.toBe(AUTH_ERROR_CODES.FORBIDDEN)
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
