/**
 * @fileoverview Tests for the workspace access service: the versioned membership cache, the
 * repository fallback and the invalidation counters.
 *
 * @layer Test
 */

import { Logger } from '@nestjs/common'

import { resolveOptions } from '../config/resolved-options'
import {
  BUMP_VERSION_SCRIPT,
  FILL_MEMBERSHIP_SCRIPT,
  READ_MEMBERSHIP_SCRIPT
} from '../constants/workspace-access-scripts'
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
  redis: { eval: jest.Mock }
  workspaces: { findById: jest.Mock }
  memberships: { find: jest.Mock }
  hmacKey: string
}

/** Builds the service over mocks; the cache misses at versions 0/0 unless a case says otherwise. */
function build(cacheTtl: number | null = 60): Harness {
  const options = resolveOptions(moduleOptions(cacheTtl))
  const redis = { eval: jest.fn().mockResolvedValue(['0', '0', '']) }
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

/** The arguments of every cache fill the service sent: keys, then values. */
function fills(redis: { eval: jest.Mock }): unknown[][] {
  return redis.eval.mock.calls
    .filter(([script]) => script === FILL_MEMBERSHIP_SCRIPT)
    .map(([, keys, args]) => [keys, args])
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
      expect(fills(redis)).toEqual([])
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

      expect(fills(redis)).toEqual([
        [
          [
            workspaceVersionKey('t1', 'w1', hmacKey),
            membershipVersionKey('t1', 'w1', 'u1', hmacKey),
            `${membershipCacheKeyBase('t1', 'w1', 'u1', hmacKey)}:3:7`
          ],
          [
            JSON.stringify({ role: 'editor', status: 'active' }),
            '60',
            String(WORKSPACE_VERSION_RETENTION_SECONDS),
            '3',
            '7'
          ]
        ]
      ])
    })

    it('writes the refill with the configured cache lifetime', async () => {
      const { service, redis } = build(15)

      await service.resolveMembership(REF)

      expect(fills(redis).map(([, args]) => args)).toEqual([
        [expect.any(String), '15', String(WORKSPACE_VERSION_RETENTION_SECONDS), '0', '0']
      ])
    })

    // Every cause of "no access" costs the same repository work, so the time an answer takes does
    // not say which cause it was: both rows are read, by their full keys, whatever the first says.
    it.each([
      ['a workspace that does not exist', null, MEMBERSHIP],
      ['a pending_deletion workspace', { ...WORKSPACE, status: 'pending_deletion' }, MEMBERSHIP],
      ['a suspended workspace', { ...WORKSPACE, status: 'suspended' }, MEMBERSHIP],
      ['a deleted workspace', { ...WORKSPACE, status: 'deleted' }, MEMBERSHIP],
      ['a caller who is not a member', WORKSPACE, null]
    ])(
      'reads both rows and answers null for %s, caching nothing',
      async (_name, workspace, row) => {
        const { service, redis, workspaces, memberships } = build()
        workspaces.findById.mockResolvedValue(workspace)
        memberships.find.mockResolvedValue(row)

        await expect(service.resolveMembership(REF)).resolves.toBeNull()
        expect(workspaces.findById).toHaveBeenCalledWith(WORKSPACE_REF)
        expect(memberships.find).toHaveBeenCalledWith(REF)
        expect(fills(redis)).toEqual([])
      }
    )

    describe('resolveAccess', () => {
      const OWNER = { ...MEMBERSHIP, role: 'owner' }
      const PENDING = { ...WORKSPACE, status: 'pending_deletion' as const }

      it.each([
        ['an active member of an active workspace', WORKSPACE, MEMBERSHIP, 'member'],
        ['the owner of a workspace pending deletion', PENDING, OWNER, 'pending_deletion'],
        ['a non-owner member of a workspace pending deletion', PENDING, MEMBERSHIP, 'denied'],
        [
          'an owner whose membership is suspended, pending deletion',
          PENDING,
          { ...OWNER, status: 'suspended' },
          'denied'
        ],
        [
          'the owner of a suspended workspace',
          { ...WORKSPACE, status: 'suspended' },
          OWNER,
          'denied'
        ],
        ['the owner of a deleted workspace', { ...WORKSPACE, status: 'deleted' }, OWNER, 'denied'],
        ['a member of a missing workspace', null, MEMBERSHIP, 'denied'],
        ['a caller with no membership', WORKSPACE, null, 'denied']
      ])('answers %s with %s', async (_name, workspace, row, kind) => {
        const { service, workspaces, memberships } = build()
        workspaces.findById.mockResolvedValue(workspace)
        memberships.find.mockResolvedValue(row)

        const access = await service.resolveAccess(REF)

        expect(access.kind).toBe(kind)
      })

      it('carries the owner as the member of a pending deletion', async () => {
        const { service, workspaces, memberships } = build()
        workspaces.findById.mockResolvedValue(PENDING)
        memberships.find.mockResolvedValue(OWNER)

        await expect(service.resolveAccess(REF)).resolves.toEqual({
          kind: 'pending_deletion',
          member: { ...REF, role: 'owner' }
        })
      })

      it('does not cache the pending-deletion answer, and resolveMembership reads it as null', async () => {
        const { service, redis, workspaces, memberships } = build()
        workspaces.findById.mockResolvedValue(PENDING)
        memberships.find.mockResolvedValue(OWNER)

        await expect(service.resolveMembership(REF)).resolves.toBeNull()
        expect(fills(redis)).toEqual([])
      })

      // The 409 for an owner must not be a side channel: every refusal does the same work.
      it('makes the same repository calls with the same arguments for every refusal', async () => {
        const cases = [
          { workspace: WORKSPACE, row: null },
          { workspace: PENDING, row: MEMBERSHIP },
          { workspace: null, row: MEMBERSHIP },
          { workspace: { ...WORKSPACE, status: 'suspended' }, row: MEMBERSHIP },
          { workspace: PENDING, row: OWNER }
        ]
        const seen = []

        for (const { workspace, row } of cases) {
          const { service, redis, workspaces, memberships } = build()
          workspaces.findById.mockResolvedValue(workspace)
          memberships.find.mockResolvedValue(row)
          const access = await service.resolveAccess(REF)
          seen.push({
            kind: access.kind,
            workspaceCalls: workspaces.findById.mock.calls,
            membershipCalls: memberships.find.mock.calls,
            fills: fills(redis)
          })
        }

        expect(seen.map((entry) => entry.kind)).toEqual([
          'denied',
          'denied',
          'denied',
          'denied',
          'pending_deletion'
        ])
        for (const entry of seen) {
          expect(entry.workspaceCalls).toEqual([[WORKSPACE_REF]])
          expect(entry.membershipCalls).toEqual([[REF]])
          expect(entry.fills).toEqual([])
        }
      })
    })

    it('answers null for a missing membership, and caches nothing', async () => {
      const { service, redis, memberships } = build()
      memberships.find.mockResolvedValue(null)

      await expect(service.resolveMembership(REF)).resolves.toBeNull()
      expect(fills(redis)).toEqual([])
    })

    it('answers null for a suspended membership, and caches nothing', async () => {
      const { service, redis, memberships } = build()
      memberships.find.mockResolvedValue({ ...MEMBERSHIP, status: 'suspended' })

      await expect(service.resolveMembership(REF)).resolves.toBeNull()
      expect(fills(redis)).toEqual([])
    })

    it('skips the cache entirely when its lifetime is zero', async () => {
      const { service, redis } = build(0)

      await expect(service.resolveMembership(REF)).resolves.toEqual({ ...REF, role: 'editor' })
      expect(redis.eval).not.toHaveBeenCalled()
      expect(fills(redis)).toEqual([])
    })

    it('answers from the repositories, writing nothing, when Redis is unreachable', async () => {
      const { service, redis } = build()
      redis.eval.mockRejectedValue(new Error('ECONNREFUSED'))

      await expect(service.resolveMembership(REF)).resolves.toEqual({ ...REF, role: 'editor' })
      expect(fills(redis)).toEqual([])
      expect(warn).toHaveBeenCalledWith(
        'Workspace membership cache unavailable; reading the repositories.'
      )
    })

    it('still answers when the refill cannot be written', async () => {
      const { service, redis } = build()
      redis.eval.mockImplementation((script: string) =>
        script === FILL_MEMBERSHIP_SCRIPT
          ? Promise.reject(new Error('READONLY'))
          : Promise.resolve(['0', '0', ''])
      )

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
      expect(fills(redis)).toEqual([])
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
      expect(fills(redis).map(([keys]) => (keys as string[])[2])).toEqual([
        expect.stringMatching(/:0:0$/)
      ])
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
