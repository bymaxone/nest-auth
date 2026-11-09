/**
 * @fileoverview Tests for the workspace access service: the versioned membership cache, the
 * repository fallback and the invalidation counters.
 *
 * @layer Test
 */

import { Logger } from '@nestjs/common'

import { resolveOptions } from '../config/resolved-options'
import { BUMP_VERSION_SCRIPT, READ_MEMBERSHIP_SCRIPT } from '../constants/workspace-access-scripts'
import {
  WORKSPACE_VERSION_RETENTION_SECONDS,
  membershipCacheKeyBase,
  membershipVersionKey,
  workspaceVersionKey
} from '../constants/workspace-keys'
import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'
import type {
  AuthMembership,
  IMembershipRepository
} from '../interfaces/membership-repository.interface'
import type {
  AuthWorkspace,
  IWorkspaceRepository
} from '../interfaces/workspace-repository.interface'
import type { AuthRedisService } from '../redis/auth-redis.service'
import { WorkspaceAccessService } from './workspace-access.service'

const SECRET = 'xY9!kL2@mN5#pQ8$rS1%tU4^vW7&zA0B'
const REF = { tenantId: 't1', workspaceId: 'w1', userId: 'u1' }
const WORKSPACE_REF = { tenantId: 't1', workspaceId: 'w1' }

/** Valid module options; each case changes the cache TTL or drops the workspace group. */
function moduleOptions(cacheTtl: number | null = 60, withGroup = true): BymaxAuthModuleOptions {
  return {
    jwt: { secret: SECRET },
    roles: { hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] } },
    rateLimit: { clientIpSource: 'peer' },
    ...(withGroup
      ? {
          workspaces: {
            enabled: true,
            roles: { hierarchy: { owner: ['editor'], editor: [] }, ownerRole: 'owner' },
            ...(cacheTtl === null ? {} : { membershipCacheTtlSeconds: cacheTtl })
          }
        }
      : {})
  }
}

const WORKSPACE: AuthWorkspace = {
  id: 'w1',
  tenantId: 't1',
  name: 'W',
  status: 'active',
  createdAt: new Date(0),
  deletionScheduledAt: null
}

const MEMBERSHIP: AuthMembership = {
  ...REF,
  role: 'editor',
  status: 'active',
  invitedByUserId: null,
  createdAt: new Date(0),
  updatedAt: new Date(0)
}

interface Harness {
  service: WorkspaceAccessService
  redis: { eval: jest.Mock; set: jest.Mock }
  workspaces: { findById: jest.Mock }
  memberships: { find: jest.Mock }
  hmacKey: string
}

/** Builds the service over mocks; the cache misses at versions 0/0 unless a case says otherwise. */
function build(cacheTtl: number | null = 60): Harness {
  const options = resolveOptions(moduleOptions(cacheTtl))
  const redis = { eval: jest.fn().mockResolvedValue(['0', '0', '']), set: jest.fn() }
  const workspaces = { findById: jest.fn().mockResolvedValue(WORKSPACE) }
  const memberships = { find: jest.fn().mockResolvedValue(MEMBERSHIP) }
  const service = new WorkspaceAccessService(
    redis as Partial<AuthRedisService> as AuthRedisService,
    workspaces as Partial<IWorkspaceRepository> as IWorkspaceRepository,
    memberships as Partial<IMembershipRepository> as IMembershipRepository,
    options
  )
  return { service, redis, workspaces, memberships, hmacKey: options.hmacKey }
}

describe('WorkspaceAccessService', () => {
  let warn: jest.SpyInstance

  beforeEach(() => {
    warn = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  it('refuses to exist without the workspace group', () => {
    const options = resolveOptions(moduleOptions(60, false))

    expect(
      () =>
        new WorkspaceAccessService(
          {} as AuthRedisService,
          {} as IWorkspaceRepository,
          {} as IMembershipRepository,
          options
        )
    ).toThrow('[BymaxAuthModule] WorkspaceAccessService needs workspaces.enabled.')
  })

  describe('resolveMembership', () => {
    it('reads both versions and the entry with one script, over the pinned keys', async () => {
      const { service, redis, hmacKey } = build()

      await service.resolveMembership(REF)

      expect(redis.eval).toHaveBeenCalledWith(
        READ_MEMBERSHIP_SCRIPT,
        [
          workspaceVersionKey('t1', 'w1', hmacKey),
          membershipVersionKey('t1', 'w1', 'u1', hmacKey),
          membershipCacheKeyBase('t1', 'w1', 'u1', hmacKey)
        ],
        []
      )
    })

    it('serves a cached active entry without reading the repositories', async () => {
      const { service, redis, workspaces, memberships } = build()
      redis.eval.mockResolvedValue(['2', '5', JSON.stringify({ role: 'owner', status: 'active' })])

      const member = await service.resolveMembership(REF)

      expect(member).toEqual({ ...REF, role: 'owner' })
      expect(workspaces.findById).not.toHaveBeenCalled()
      expect(memberships.find).not.toHaveBeenCalled()
      expect(redis.set).not.toHaveBeenCalled()
    })

    it('reads the workspace and the membership by their full keys on a miss', async () => {
      const { service, workspaces, memberships } = build()

      const member = await service.resolveMembership(REF)

      expect(member).toEqual({ ...REF, role: 'editor' })
      expect(workspaces.findById).toHaveBeenCalledWith(WORKSPACE_REF)
      expect(memberships.find).toHaveBeenCalledWith(REF)
      // The empty reply of a plain miss is not JSON: it reads as no entry, silently.
      expect(warn).not.toHaveBeenCalled()
    })

    // The versions come from BEFORE the repository read, so a change that lands in between moves
    // a counter and the refill sits under a key nobody reads.
    it('writes the refill under the versions read before the repositories', async () => {
      const { service, redis, hmacKey } = build()
      redis.eval.mockResolvedValue(['3', '7', ''])

      await service.resolveMembership(REF)

      expect(redis.set).toHaveBeenCalledWith(
        `${membershipCacheKeyBase('t1', 'w1', 'u1', hmacKey)}:3:7`,
        JSON.stringify({ role: 'editor', status: 'active' }),
        60
      )
    })

    it('writes the refill with the configured cache lifetime', async () => {
      const { service, redis } = build(15)

      await service.resolveMembership(REF)

      expect(redis.set).toHaveBeenCalledWith(expect.any(String), expect.any(String), 15)
    })

    it('answers null for a workspace that does not exist, and caches nothing', async () => {
      const { service, redis, workspaces, memberships } = build()
      workspaces.findById.mockResolvedValue(null)

      await expect(service.resolveMembership(REF)).resolves.toBeNull()
      expect(memberships.find).not.toHaveBeenCalled()
      expect(redis.set).not.toHaveBeenCalled()
    })

    it.each(['pending_deletion', 'suspended', 'deleted'] as const)(
      'answers null for a %s workspace without reading the membership',
      async (status) => {
        const { service, redis, workspaces, memberships } = build()
        workspaces.findById.mockResolvedValue({ ...WORKSPACE, status })

        await expect(service.resolveMembership(REF)).resolves.toBeNull()
        expect(memberships.find).not.toHaveBeenCalled()
        expect(redis.set).not.toHaveBeenCalled()
      }
    )

    it('answers null for a missing membership, and caches nothing', async () => {
      const { service, redis, memberships } = build()
      memberships.find.mockResolvedValue(null)

      await expect(service.resolveMembership(REF)).resolves.toBeNull()
      expect(redis.set).not.toHaveBeenCalled()
    })

    it('answers null for a suspended membership, and caches nothing', async () => {
      const { service, redis, memberships } = build()
      memberships.find.mockResolvedValue({ ...MEMBERSHIP, status: 'suspended' })

      await expect(service.resolveMembership(REF)).resolves.toBeNull()
      expect(redis.set).not.toHaveBeenCalled()
    })

    it('skips the cache entirely when its lifetime is zero', async () => {
      const { service, redis } = build(0)

      await expect(service.resolveMembership(REF)).resolves.toEqual({ ...REF, role: 'editor' })
      expect(redis.eval).not.toHaveBeenCalled()
      expect(redis.set).not.toHaveBeenCalled()
    })

    it('answers from the repositories, writing nothing, when Redis is unreachable', async () => {
      const { service, redis } = build()
      redis.eval.mockRejectedValue(new Error('ECONNREFUSED'))

      await expect(service.resolveMembership(REF)).resolves.toEqual({ ...REF, role: 'editor' })
      expect(redis.set).not.toHaveBeenCalled()
      expect(warn).toHaveBeenCalledWith(
        'Workspace membership cache unavailable; reading the repositories.'
      )
    })

    it('still answers when the refill cannot be written', async () => {
      const { service, redis } = build()
      redis.set.mockRejectedValue(new Error('READONLY'))

      await expect(service.resolveMembership(REF)).resolves.toEqual({ ...REF, role: 'editor' })
      expect(warn).toHaveBeenCalledWith(
        'Workspace membership cache unavailable; the answer was not cached.'
      )
    })

    // A reply of the wrong shape carries no versions, so there is nothing to write a refill under.
    it.each([
      ['a reply that is not a list', 'oops'],
      ['a list of the wrong length', ['0', '0']],
      ['a list that is too long', ['0', '0', '', '']],
      ['a workspace version that is not text', [0, '0', '']],
      ['a membership version that is not text', ['0', 0, '']]
    ])('answers from the repositories and caches nothing for %s', async (_name, reply) => {
      const { service, redis, memberships } = build()
      redis.eval.mockResolvedValue(reply)

      await expect(service.resolveMembership(REF)).resolves.toEqual({ ...REF, role: 'editor' })
      expect(memberships.find).toHaveBeenCalledWith(REF)
      expect(redis.set).not.toHaveBeenCalled()
    })

    // The versions are valid, so the repository answer is refilled under them.
    it.each([
      ['an entry that is not JSON', ['0', '0', '{not json']],
      ['an entry that is not text', ['0', '0', 5]],
      ['an entry with a role that is not text', ['0', '0', '{"role":1,"status":"active"}']],
      ['an entry that is not active', ['0', '0', '{"role":"owner","status":"suspended"}']]
    ])('treats %s as a miss', async (_name, reply) => {
      const { service, redis, memberships } = build()
      redis.eval.mockResolvedValue(reply)

      await expect(service.resolveMembership(REF)).resolves.toEqual({ ...REF, role: 'editor' })
      expect(memberships.find).toHaveBeenCalledWith(REF)
      expect(redis.set).toHaveBeenCalledWith(
        expect.stringMatching(/:0:0$/),
        JSON.stringify({ role: 'editor', status: 'active' }),
        60
      )
    })

    it.each(['tenantId', 'workspaceId', 'userId'] as const)(
      'rejects a blank %s before touching any store',
      async (part) => {
        const { service, redis, workspaces } = build()

        await expect(service.resolveMembership({ ...REF, [part]: '  ' })).rejects.toThrow(
          `${part} must be a non-empty string`
        )
        expect(redis.eval).not.toHaveBeenCalled()
        expect(workspaces.findById).not.toHaveBeenCalled()
      }
    )
  })

  describe('invalidation', () => {
    it('bumps the membership version with the retention window', async () => {
      const { service, redis, hmacKey } = build()

      await service.invalidateMembership(REF)

      expect(redis.eval).toHaveBeenCalledWith(
        BUMP_VERSION_SCRIPT,
        [membershipVersionKey('t1', 'w1', 'u1', hmacKey)],
        [String(WORKSPACE_VERSION_RETENTION_SECONDS)]
      )
    })

    it('bumps the workspace version, which every member reads', async () => {
      const { service, redis, hmacKey } = build()

      await service.invalidateWorkspace(WORKSPACE_REF)

      expect(redis.eval).toHaveBeenCalledWith(
        BUMP_VERSION_SCRIPT,
        [workspaceVersionKey('t1', 'w1', hmacKey)],
        [String(WORKSPACE_VERSION_RETENTION_SECONDS)]
      )
    })

    it('surfaces a failed bump instead of reporting the change as invalidated', async () => {
      const { service, redis } = build()
      redis.eval.mockRejectedValue(new Error('ECONNREFUSED'))

      await expect(service.invalidateMembership(REF)).rejects.toThrow('ECONNREFUSED')
      await expect(service.invalidateWorkspace(WORKSPACE_REF)).rejects.toThrow('ECONNREFUSED')
    })

    it.each([[undefined], [42], [null]])('rejects a key part that is %p', async (value) => {
      const { service, redis } = build()
      const bad = Object.assign({}, REF, { userId: value })

      await expect(service.resolveMembership(bad)).rejects.toThrow(
        'userId must be a non-empty string'
      )
      expect(redis.eval).not.toHaveBeenCalled()
    })

    it('rejects a blank key part', async () => {
      const { service, redis } = build()

      await expect(service.invalidateMembership({ ...REF, userId: '' })).rejects.toThrow(
        'userId must be a non-empty string'
      )
      await expect(
        service.invalidateWorkspace({ ...WORKSPACE_REF, tenantId: ' ' })
      ).rejects.toThrow('tenantId must be a non-empty string')
      expect(redis.eval).not.toHaveBeenCalled()
    })
  })
})
