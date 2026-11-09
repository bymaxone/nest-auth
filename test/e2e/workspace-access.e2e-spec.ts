/**
 * @fileoverview Runs the workspace membership cache's Lua scripts against a Redis, through the real
 * `AuthRedisService`.
 *
 * A unit test with a mocked `eval` proves the service's branches and nothing about the scripts. This
 * suite proves the two properties the design rests on: an entry is served until a version bump
 * makes its key unreachable, and a refill written after a concurrent change is never served.
 *
 * @layer Test
 */

import { resolveOptions } from '../../src/server/config/resolved-options'
import {
  WORKSPACE_VERSION_RETENTION_SECONDS,
  membershipVersionKey,
  workspaceVersionKey
} from '../../src/server/constants/workspace-keys'
import type {
  AuthMembership,
  IMembershipRepository
} from '../../src/server/interfaces/membership-repository.interface'
import type {
  AuthWorkspace,
  IWorkspaceRepository
} from '../../src/server/interfaces/workspace-repository.interface'
import { AuthRedisService } from '../../src/server/redis/auth-redis.service'
import { WorkspaceAccessService } from '../../src/server/services/workspace-access.service'
import { JWT_SECRET, createMockRedis, realRedisNamespace } from './setup'

const REF = { tenantId: 't1', workspaceId: 'w1', userId: 'u1' }
const WORKSPACE_REF = { tenantId: 't1', workspaceId: 'w1' }

/** The rows the in-memory repositories serve; each case edits them between requests. */
interface Store {
  workspace: AuthWorkspace
  membership: AuthMembership | null
  /** Runs inside `findById`, between the cache read and the repository answer. */
  duringWorkspaceRead?: (() => Promise<void>) | undefined
}

function freshStore(): Store {
  return {
    workspace: {
      id: 'w1',
      tenantId: 't1',
      name: 'W',
      status: 'active',
      createdAt: new Date(0),
      deletionScheduledAt: null
    },
    membership: {
      ...REF,
      role: 'editor',
      status: 'active',
      invitedByUserId: null,
      createdAt: new Date(0),
      updatedAt: new Date(0)
    }
  }
}

function build(store: Store): {
  service: WorkspaceAccessService
  redis: AuthRedisService
  hmacKey: string
} {
  const namespace = realRedisNamespace()
  const options = resolveOptions({
    ...(namespace === undefined ? {} : { redisNamespace: namespace }),
    jwt: { secret: JWT_SECRET },
    roles: { hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] } },
    rateLimit: { clientIpSource: 'peer' },
    workspaces: {
      enabled: true,
      roles: { hierarchy: { owner: ['editor'], editor: [] }, ownerRole: 'owner' }
    }
  })
  const redis = new AuthRedisService(createMockRedis(), options)
  const workspaces: Partial<IWorkspaceRepository> = {
    findById: async () => {
      await store.duringWorkspaceRead?.()
      return store.workspace
    }
  }
  const memberships: Partial<IMembershipRepository> = { find: async () => store.membership }
  const service = new WorkspaceAccessService(
    redis,
    workspaces as IWorkspaceRepository,
    memberships as IMembershipRepository,
    options
  )
  return { service, redis, hmacKey: options.hmacKey }
}

describe('workspace membership cache against Redis', () => {
  it('serves the cached role until the membership version is bumped', async () => {
    const store = freshStore()
    const { service } = build(store)
    await service.resolveMembership(REF)

    store.membership = store.membership && { ...store.membership, role: 'owner' }

    await expect(service.resolveMembership(REF)).resolves.toEqual({ ...REF, role: 'editor' })
    await service.invalidateMembership(REF)
    await expect(service.resolveMembership(REF)).resolves.toEqual({ ...REF, role: 'owner' })
  })

  it('ends every member access when the workspace version is bumped', async () => {
    const store = freshStore()
    const { service } = build(store)
    await service.resolveMembership(REF)

    store.workspace = { ...store.workspace, status: 'pending_deletion' }
    await service.invalidateWorkspace(WORKSPACE_REF)

    await expect(service.resolveMembership(REF)).resolves.toBeNull()
  })

  it('does not let one member bump reach another member', async () => {
    const store = freshStore()
    const { service } = build(store)
    const other = { ...REF, userId: 'u2' }
    store.membership = store.membership && { ...store.membership, userId: 'u2' }
    await service.resolveMembership(other)

    store.membership = null
    await service.invalidateMembership(REF)

    await expect(service.resolveMembership(other)).resolves.toEqual({ ...other, role: 'editor' })
  })

  // The refill is written under the versions read BEFORE the repository. A change that lands while
  // the repository is being read moves a counter, so the stale refill sits under a key that is
  // never read again and the next request reads the new state.
  it('never serves a refill written after a concurrent change', async () => {
    const store = freshStore()
    const { service } = build(store)
    store.duringWorkspaceRead = async () => {
      store.membership = store.membership && { ...store.membership, role: 'owner' }
      await service.invalidateMembership(REF)
      store.duringWorkspaceRead = undefined
    }

    await service.resolveMembership(REF)

    await expect(service.resolveMembership(REF)).resolves.toEqual({ ...REF, role: 'owner' })
  })

  it('keeps each version counter for the retention window', async () => {
    const store = freshStore()
    const { service, redis, hmacKey } = build(store)

    await service.invalidateMembership(REF)
    await service.invalidateWorkspace(WORKSPACE_REF)

    const membershipTtl = await redis.ttl(membershipVersionKey('t1', 'w1', 'u1', hmacKey))
    const workspaceTtl = await redis.ttl(workspaceVersionKey('t1', 'w1', hmacKey))
    expect(membershipTtl).toBeGreaterThan(WORKSPACE_VERSION_RETENTION_SECONDS - 5)
    expect(workspaceTtl).toBeGreaterThan(WORKSPACE_VERSION_RETENTION_SECONDS - 5)
  })

  it('refreshes the retention on every bump', async () => {
    const store = freshStore()
    const { service, redis, hmacKey } = build(store)
    const key = membershipVersionKey('t1', 'w1', 'u1', hmacKey)
    await service.invalidateMembership(REF)
    await redis.expire(key, 10)

    await service.invalidateMembership(REF)

    expect(await redis.ttl(key)).toBeGreaterThan(WORKSPACE_VERSION_RETENTION_SECONDS - 5)
  })
})
