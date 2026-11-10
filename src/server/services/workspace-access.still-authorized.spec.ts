/**
 * @fileoverview WorkspaceAccessService.assertStillAuthorized: the question a queued job asks before
 * it acts, "may this account act in this workspace right now?", answered from the repositories and
 * never from a cache.
 *
 * @layer Test
 */

import { AccountStatusService } from './account-status.service'
import { WorkspaceAccessService } from './workspace-access.service'
import { ANY_WORKSPACE_MEMBER } from '../constants/workspace-roles'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import type { AuthException } from '../errors/auth-exception'
import type { ResolvedOptions } from '../config/resolved-options'
import type { IMembershipRepository } from '../interfaces/membership-repository.interface'
import type { IUserRepository } from '../interfaces/user-repository.interface'
import type { IWorkspaceRepository } from '../interfaces/workspace-repository.interface'
import { stampJobContext } from '../utils/workspace-job'

const JOB = { tenantId: 't1', workspaceId: 'w1', actorUserId: 'u1' }

const repos = {
  workspaces: { findById: jest.fn() },
  memberships: { find: jest.fn() },
  users: { findById: jest.fn() }
}
const redis = { get: jest.fn(), set: jest.fn(), eval: jest.fn(), del: jest.fn() }

/** The code a promise rejects with, or `undefined` when it resolves. */
async function code(promise: Promise<unknown>): Promise<string | undefined> {
  try {
    await promise
  } catch (error) {
    return ((error as AuthException).getResponse() as { error: { code: string } }).error.code
  }
  return undefined
}

/** A service over stub repositories, with a membership cache that WOULD answer if it were read. */
function build(verificationRequired = false): WorkspaceAccessService {
  const options = Object.assign({} as ResolvedOptions, {
    hmacKey: 'k',
    blockedStatuses: ['BANNED'],
    userStatusCacheTtlSeconds: 60,
    emailVerification: { required: verificationRequired },
    workspaces: {
      enabled: true,
      membershipCacheTtlSeconds: 300,
      roles: {
        hierarchy: { owner: ['editor', 'viewer'], editor: ['viewer'], viewer: [] },
        ownerRole: 'owner'
      }
    }
  })
  const status = new AccountStatusService(
    redis as never,
    repos.users as Partial<IUserRepository> as IUserRepository,
    options
  )
  return new WorkspaceAccessService(
    redis as never,
    repos.workspaces as Partial<IWorkspaceRepository> as IWorkspaceRepository,
    repos.memberships as Partial<IMembershipRepository> as IMembershipRepository,
    options,
    status
  )
}

/** The workspace, the membership and the account as the repositories hold them now. */
function world(
  workspace: string | null,
  membership: { role: string; status: string } | null,
  account: { status: string; emailVerified: boolean } | null = {
    status: 'ACTIVE',
    emailVerified: true
  }
): void {
  repos.workspaces.findById.mockResolvedValue(workspace === null ? null : { status: workspace })
  repos.memberships.find.mockResolvedValue(membership)
  repos.users.findById.mockResolvedValue(account)
}

describe('assertStillAuthorized', () => {
  beforeEach(() => {
    jest.resetAllMocks()
  })

  it('answers the member and the role the account holds now', async () => {
    world('active', { role: 'editor', status: 'active' })

    await expect(build().assertStillAuthorized(JOB, ['viewer'])).resolves.toEqual({
      tenantId: 't1',
      workspaceId: 'w1',
      userId: 'u1',
      role: 'editor'
    })
  })

  it('reads the repositories and never the caches, whatever they hold', async () => {
    world('active', { role: 'viewer', status: 'active' })
    redis.get.mockResolvedValue('cached')
    redis.eval.mockResolvedValue(['1', '1', '{"role":"owner"}'])

    await build().assertStillAuthorized(JOB, [ANY_WORKSPACE_MEMBER])

    expect(redis.get).not.toHaveBeenCalled()
    expect(redis.eval).not.toHaveBeenCalled()
    expect(redis.set).not.toHaveBeenCalled()
    expect(repos.users.findById).toHaveBeenCalledWith({ id: 'u1', tenantId: 't1' })
    expect(repos.memberships.find).toHaveBeenCalledWith({
      tenantId: 't1',
      workspaceId: 'w1',
      userId: 'u1'
    })
  })

  it('refuses a member who was removed since the job was enqueued', async () => {
    world('active', null)

    expect(await code(build().assertStillAuthorized(JOB, ['viewer']))).toBe(
      AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND
    )
  })

  it('refuses a member who was demoted below the roles the job needs', async () => {
    world('active', { role: 'viewer', status: 'active' })

    expect(await code(build().assertStillAuthorized(JOB, ['editor']))).toBe(
      AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE
    )
  })

  it('refuses a banned account, which is the case the cache window would have missed', async () => {
    world('active', { role: 'owner', status: 'active' }, { status: 'BANNED', emailVerified: true })

    expect(await code(build().assertStillAuthorized(JOB, ['viewer']))).toBe(
      AUTH_ERROR_CODES.ACCOUNT_BANNED
    )
  })

  it('refuses an account that no longer exists', async () => {
    world('active', { role: 'owner', status: 'active' }, null)

    expect(await code(build().assertStillAuthorized(JOB, ['viewer']))).toBe(
      AUTH_ERROR_CODES.TOKEN_INVALID
    )
  })

  it('refuses an unverified account when verification is required, and only then', async () => {
    world('active', { role: 'owner', status: 'active' }, { status: 'ACTIVE', emailVerified: false })

    expect(await code(build(true).assertStillAuthorized(JOB, ['viewer']))).toBe(
      AUTH_ERROR_CODES.EMAIL_NOT_VERIFIED
    )
    await expect(build(false).assertStillAuthorized(JOB, ['viewer'])).resolves.toBeDefined()
  })

  it('tells the owner of a workspace pending deletion and nobody else, as the guard does', async () => {
    world('pending_deletion', { role: 'owner', status: 'active' })
    expect(await code(build().assertStillAuthorized(JOB, ['owner']))).toBe(
      AUTH_ERROR_CODES.WORKSPACE_PENDING_DELETION
    )
    await expect(
      build().assertStillAuthorized(JOB, ['owner'], { allowPending: true })
    ).resolves.toMatchObject({ role: 'owner' })

    world('pending_deletion', { role: 'editor', status: 'active' })
    expect(await code(build().assertStillAuthorized(JOB, ['viewer'], { allowPending: true }))).toBe(
      AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND
    )
  })

  it.each([
    ['tenantId', { ...JOB, tenantId: '  ' }],
    ['workspaceId', { ...JOB, workspaceId: '' }],
    ['workspaceId', { ...JOB, workspaceId: 'w'.repeat(129) }],
    ['actorUserId', { ...JOB, actorUserId: 'u\u0000' }],
    ['actorUserId', { ...JOB, actorUserId: 5 as never }]
  ])(
    'refuses a malformed %s as a validation error naming it, before any read',
    async (field, bad) => {
      world('active', { role: 'owner', status: 'active' })

      const error = await build()
        .assertStillAuthorized(bad, ['viewer'])
        .catch((e: unknown) => e as AuthException)

      expect((error as AuthException).getResponse()).toMatchObject({
        error: { code: AUTH_ERROR_CODES.VALIDATION, details: [{ field }] }
      })
      expect(repos.users.findById).not.toHaveBeenCalled()
      expect(repos.memberships.find).not.toHaveBeenCalled()
    }
  )

  it('says what a tenant or actor must be, in the validation detail', async () => {
    const error = await build()
      .assertStillAuthorized({ ...JOB, tenantId: '' }, ['viewer'])
      .catch((e: unknown) => e as AuthException)

    expect((error as AuthException).getResponse()).toMatchObject({
      error: {
        details: [
          {
            field: 'tenantId',
            message: 'tenantId must be 1 to 128 characters, not blank, with no control characters'
          }
        ]
      }
    })
  })

  it.each([
    ['null', null],
    ['undefined', undefined],
    ['a string', 'w1'],
    ['an array', []]
  ])('refuses a context that is %s as validation errors, not a crash', async (_name, bad) => {
    world('active', { role: 'owner', status: 'active' })

    const error = await build()
      .assertStillAuthorized(bad as never, ['viewer'])
      .catch((e: unknown) => e as AuthException)

    expect((error as AuthException).getResponse()).toMatchObject({
      error: { code: AUTH_ERROR_CODES.VALIDATION, details: [{ field: 'tenantId' }] }
    })
    expect(repos.users.findById).not.toHaveBeenCalled()
  })

  it('accepts a tenant and an actor of exactly 128 characters and refuses 129', async () => {
    world('active', { role: 'viewer', status: 'active' })
    const edge = { tenantId: 't'.repeat(128), workspaceId: 'w1', actorUserId: 'u'.repeat(128) }

    await expect(build().assertStillAuthorized(edge, ['viewer'])).resolves.toBeDefined()
    expect(
      await code(build().assertStillAuthorized({ ...edge, tenantId: 't'.repeat(129) }, ['viewer']))
    ).toBe(AUTH_ERROR_CODES.VALIDATION)
    expect(
      await code(
        build().assertStillAuthorized({ ...edge, actorUserId: 'u'.repeat(129) }, ['viewer'])
      )
    ).toBe(AUTH_ERROR_CODES.VALIDATION)
  })

  it('is a TypeError when built without the account status service', async () => {
    const options = Object.assign({} as ResolvedOptions, {
      workspaces: {
        enabled: true,
        membershipCacheTtlSeconds: 0,
        roles: { hierarchy: {}, ownerRole: 'owner' }
      }
    })
    const bare = new WorkspaceAccessService(
      redis as never,
      repos.workspaces as Partial<IWorkspaceRepository> as IWorkspaceRepository,
      repos.memberships as Partial<IMembershipRepository> as IMembershipRepository,
      options
    )

    await expect(bare.assertStillAuthorized(JOB, ['viewer'])).rejects.toThrow(
      'assertStillAuthorized needs the account status service'
    )
  })
})

describe('stampJobContext', () => {
  it('carries the tenant, the workspace and the account, and not the role', () => {
    expect(
      stampJobContext({ tenantId: 't1', workspaceId: 'w1', userId: 'u1', role: 'owner' })
    ).toEqual({ tenantId: 't1', workspaceId: 'w1', actorUserId: 'u1' })
  })
})
