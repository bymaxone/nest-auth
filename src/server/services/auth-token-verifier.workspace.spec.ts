/**
 * @fileoverview AuthTokenVerifierService with the `workspace` option: a stream admitted to a
 * workspace as a route would be, through the real access resolution over stubbed repositories.
 *
 * What it pins is that the stream refuses with the route's codes in the route's order, that a
 * workspace pending deletion is disclosed to its owner only, that a malformed id is refused before
 * any lookup, and that the option is a programmer's error where it cannot be answered. Kept apart
 * from `auth-token-verifier.service.spec.ts` because that file is over the size limit.
 *
 * @layer Test
 */

import { JwtService } from '@nestjs/jwt'
import { Test } from '@nestjs/testing'

import { AccountStatusService } from './account-status.service'
import { AuthRevocationService } from './auth-revocation.service'
import { AuthTokenVerifierService } from './auth-token-verifier.service'
import { WorkspaceAccessService } from './workspace-access.service'
import {
  BYMAX_AUTH_MEMBERSHIP_REPOSITORY,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_WORKSPACE_REPOSITORY
} from '../bymax-auth.constants'
import { ANY_WORKSPACE_MEMBER } from '../constants/workspace-roles'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import type { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'

const PAYLOAD = {
  jti: '3f2504e0-4f89-41d3-9a0c-0305e82c3301',
  sub: 'user-1',
  tenantId: 'tenant-1',
  role: 'member',
  type: 'dashboard',
  status: 'active',
  mfaEnabled: false,
  mfaVerified: false,
  epoch: 1,
  iat: 1,
  exp: 2
}

const WORKSPACES = {
  enabled: true,
  membershipCacheTtlSeconds: 0,
  roles: {
    hierarchy: { owner: ['editor', 'viewer'], editor: ['viewer'], viewer: [] },
    ownerRole: 'owner'
  }
}

const repos = {
  workspaces: { findById: jest.fn() },
  memberships: { find: jest.fn() }
}

/** The code a promise rejects with, or `undefined` when it resolves. */
async function code(promise: Promise<unknown>): Promise<string | undefined> {
  try {
    await promise
  } catch (error) {
    const response = (error as AuthException).getResponse() as { error: { code: string } }
    return response.error.code
  }
  return undefined
}

/** A verifier; `withWorkspaces` is whether the access service is provided and the group resolved. */
async function build(
  withWorkspaces = true,
  token: { verify?: jest.Mock; revoked?: boolean } = {}
): Promise<AuthTokenVerifierService> {
  const module = await Test.createTestingModule({
    providers: [
      AuthTokenVerifierService,
      {
        provide: JwtService,
        useValue: { verify: token.verify ?? jest.fn().mockReturnValue({ ...PAYLOAD }) }
      },
      {
        provide: BYMAX_AUTH_OPTIONS,
        useValue: {
          jwt: { algorithm: 'HS256', issuer: 'iss', audience: 'aud', previousSecrets: [] },
          ...(withWorkspaces ? { workspaces: WORKSPACES } : {})
        }
      },
      {
        provide: AuthRevocationService,
        useValue: { isAccessTokenRevoked: jest.fn().mockResolvedValue(token.revoked === true) }
      },
      {
        provide: AccountStatusService,
        useValue: { assertDashboardAccountUsable: jest.fn().mockResolvedValue(undefined) }
      },
      ...(withWorkspaces
        ? [
            WorkspaceAccessService,
            { provide: AuthRedisService, useValue: {} },
            { provide: BYMAX_AUTH_WORKSPACE_REPOSITORY, useValue: repos.workspaces },
            { provide: BYMAX_AUTH_MEMBERSHIP_REPOSITORY, useValue: repos.memberships }
          ]
        : [])
    ]
  }).compile()
  return module.get(AuthTokenVerifierService)
}

/** The state of the workspace and of the caller's membership in it. */
function world(workspace: string | null, membership: { role: string; status: string } | null) {
  repos.workspaces.findById.mockResolvedValue(workspace === null ? null : { status: workspace })
  repos.memberships.find.mockResolvedValue(membership)
}

const CHECK = { workspaceId: 'w1', roles: ['viewer'] }

describe('verifyAccessToken with a workspace', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('answers the identity and the membership for an active member', async () => {
    world('active', { role: 'editor', status: 'active' })
    const verifier = await build()

    const result = await verifier.verifyAccessToken('tok', { plane: 'dashboard', workspace: CHECK })

    expect(result.workspace).toEqual({
      tenantId: 'tenant-1',
      workspaceId: 'w1',
      userId: 'user-1',
      role: 'editor'
    })
    expect(result.payload.sub).toBe('user-1')
  })

  it('reads the membership for the caller of the token, in the tenant of the token', async () => {
    world('active', { role: 'viewer', status: 'active' })
    const verifier = await build()

    await verifier.verifyAccessToken('tok', { plane: 'dashboard', workspace: CHECK })

    expect(repos.memberships.find).toHaveBeenCalledWith({
      tenantId: 'tenant-1',
      workspaceId: 'w1',
      userId: 'user-1'
    })
  })

  it.each([
    ['a workspace that does not exist', null, null],
    ['a caller who is not a member', 'active', null],
    ['a suspended member', 'active', { role: 'viewer', status: 'suspended' }],
    [
      'a non-owner member of a workspace pending deletion',
      'pending_deletion',
      { role: 'editor', status: 'active' }
    ]
  ])('answers the identical workspace_not_found for %s', async (_name, workspace, membership) => {
    world(workspace, membership)
    const verifier = await build()

    expect(
      await code(verifier.verifyAccessToken('tok', { plane: 'dashboard', workspace: CHECK }))
    ).toBe(AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND)
  })

  it('tells the owner of a workspace pending deletion, and only the owner', async () => {
    world('pending_deletion', { role: 'owner', status: 'active' })
    const verifier = await build()

    expect(
      await code(verifier.verifyAccessToken('tok', { plane: 'dashboard', workspace: CHECK }))
    ).toBe(AUTH_ERROR_CODES.WORKSPACE_PENDING_DELETION)
  })

  it('admits that owner when the stream allows pending workspaces, and nobody else', async () => {
    const verifier = await build()
    const allow = { ...CHECK, allowPending: true }

    world('pending_deletion', { role: 'owner', status: 'active' })
    await expect(
      verifier.verifyAccessToken('tok', { plane: 'dashboard', workspace: allow })
    ).resolves.toMatchObject({ workspace: { role: 'owner' } })

    world('pending_deletion', { role: 'editor', status: 'active' })
    expect(
      await code(verifier.verifyAccessToken('tok', { plane: 'dashboard', workspace: allow }))
    ).toBe(AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND)
  })

  it('refuses a role no accepted one covers, and admits ANY_WORKSPACE_MEMBER', async () => {
    world('active', { role: 'viewer', status: 'active' })
    const verifier = await build()

    expect(
      await code(
        verifier.verifyAccessToken('tok', {
          plane: 'dashboard',
          workspace: { workspaceId: 'w1', roles: ['editor'] }
        })
      )
    ).toBe(AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE)
    await expect(
      verifier.verifyAccessToken('tok', {
        plane: 'dashboard',
        workspace: { workspaceId: 'w1', roles: [ANY_WORKSPACE_MEMBER] }
      })
    ).resolves.toBeDefined()
  })

  it.each([
    ['blank', '   '],
    ['empty', ''],
    ['over the bound', 'w'.repeat(129)],
    ['holding a control character', 'w\u0000x']
  ])(
    'refuses an id that is %s as a validation error naming workspaceId, before any lookup',
    async (_n, id) => {
      world('active', { role: 'viewer', status: 'active' })
      const verifier = await build()

      const failure = verifier.verifyAccessToken('tok', {
        plane: 'dashboard',
        workspace: { workspaceId: id, roles: ['viewer'] }
      })

      expect(await code(failure)).toBe(AUTH_ERROR_CODES.VALIDATION)
      expect(repos.workspaces.findById).not.toHaveBeenCalled()
      expect(repos.memberships.find).not.toHaveBeenCalled()
    }
  )

  it('names the field in the validation details', async () => {
    const verifier = await build()

    const error = await verifier
      .verifyAccessToken('tok', {
        plane: 'dashboard',
        workspace: { workspaceId: '', roles: ['viewer'] }
      })
      .catch((e: unknown) => e as AuthException)

    expect((error as AuthException).getResponse()).toMatchObject({
      error: { details: [{ field: 'workspaceId' }] }
    })
  })

  // Scenario: the workspace option on the platform plane. Expected: a TypeError, the caller's bug: a
  // platform token has no workspace and the overloads forbid the call.
  it('is a TypeError on the platform plane', async () => {
    const enabled = await build()

    await expect(
      enabled.verifyAccessToken('tok', { plane: 'platform', workspace: CHECK } as never)
    ).rejects.toThrow('workspace needs the dashboard plane')
  })

  // Scenario: the workspace option on a deployment that has not enabled workspaces, as a host that
  // takes the id from a client would pass it. Expected: auth.validation naming workspaceId, a 400
  // the host can answer as it is, and not a TypeError that reads as a 500.
  it('refuses with auth.validation naming workspaceId without workspaces enabled', async () => {
    const disabled = await build(false)

    const error = await disabled
      .verifyAccessToken('tok', { plane: 'dashboard', workspace: CHECK })
      .catch((e: unknown) => e as AuthException)

    expect(error).not.toBeInstanceOf(TypeError)
    expect((error as AuthException).getStatus()).toBe(400)
    expect((error as AuthException).getResponse()).toMatchObject({
      error: {
        code: AUTH_ERROR_CODES.VALIDATION,
        details: [
          {
            field: 'workspaceId',
            message: 'workspaceId is not accepted: workspaces are not enabled for this deployment'
          }
        ]
      }
    })
  })

  // Scenario: workspaces off and a token that does not verify, with a workspace option. Expected:
  // TOKEN_INVALID, so an anonymous caller learns nothing about the deployment's configuration.
  it('answers TOKEN_INVALID, not the workspaces refusal, for a token that does not verify', async () => {
    const verify = jest.fn().mockImplementation(() => {
      throw new Error('jwt expired')
    })
    const disabled = await build(false, { verify })

    await expect(
      code(disabled.verifyAccessToken('bad', { plane: 'dashboard', workspace: CHECK }))
    ).resolves.toBe(AUTH_ERROR_CODES.TOKEN_INVALID)
  })

  // Scenario: workspaces off and a revoked token, with a workspace option. Expected: TOKEN_INVALID.
  it('answers TOKEN_INVALID for a revoked token without workspaces enabled', async () => {
    const disabled = await build(false, { revoked: true })

    await expect(
      code(disabled.verifyAccessToken('tok', { plane: 'dashboard', workspace: CHECK }))
    ).resolves.toBe(AUTH_ERROR_CODES.TOKEN_INVALID)
  })

  it('does not touch the repositories when the option is absent', async () => {
    const verifier = await build()

    const result = await verifier.verifyAccessToken('tok', { plane: 'dashboard' })

    expect(result).not.toHaveProperty('workspace')
    expect(repos.memberships.find).not.toHaveBeenCalled()
  })
})
