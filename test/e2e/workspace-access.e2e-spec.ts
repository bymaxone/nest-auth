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

import type { Redis } from 'ioredis'

import { resolveOptions } from '../../src/server/config/resolved-options'
import {
  WORKSPACE_VERSION_RETENTION_SECONDS,
  membershipCacheKeyBase,
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
import { JWT_SECRET, createRedis, realRedisNamespace } from './setup'

const REF = { tenantId: 't1', workspaceId: 'w1', userId: 'u1' }
const WORKSPACE_REF = { tenantId: 't1', workspaceId: 'w1' }

/** The rows the in-memory repositories serve; each case edits them between requests. */
interface Store {
  workspace: AuthWorkspace
  membership: AuthMembership | null
  /** Runs after the membership row is read and before the repository answers: a concurrent change. */
  afterMembershipRead?: (() => Promise<void>) | undefined
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

/**
 * Wraps a client so every command rejects while an outage is switched on.
 *
 * The failure is injected at the client boundary so it is the same on the in-memory mock and on a
 * real server; a real disconnect would not fail the mock's commands at all.
 */
function failingWhile(outage: { active: boolean }, client: Redis): Redis {
  return new Proxy(client, {
    get(target, property, receiver) {
      const value: unknown = Reflect.get(target, property, receiver)
      if (typeof value !== 'function') return value
      return (...args: unknown[]) =>
        outage.active
          ? Promise.reject(new Error('Connection is closed.'))
          : (value as (...rest: unknown[]) => unknown).apply(target, args)
    }
  })
}

function build(store: Store): {
  service: WorkspaceAccessService
  redis: AuthRedisService
  outage: { active: boolean }
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
  const outage = { active: false }
  const client = failingWhile(outage, createRedis())
  const redis = new AuthRedisService(client, options)
  const workspaces: Partial<IWorkspaceRepository> = { findById: async () => store.workspace }
  const memberships: Partial<IMembershipRepository> = {
    find: async () => {
      const row = store.membership
      await store.afterMembershipRead?.()
      return row
    }
  }
  const service = new WorkspaceAccessService(
    redis,
    workspaces as IWorkspaceRepository,
    memberships as IMembershipRepository,
    options
  )
  return { service, redis, outage, hmacKey: options.hmacKey }
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
    const { service, redis, hmacKey } = build(store)
    // The repository answers `editor`; before the answer is cached the member is promoted and the
    // membership version is bumped. The answer in hand is stale by then.
    store.afterMembershipRead = async () => {
      store.membership = store.membership && { ...store.membership, role: 'owner' }
      await service.invalidateMembership(REF)
      store.afterMembershipRead = undefined
    }

    await expect(service.resolveMembership(REF)).resolves.toEqual({ ...REF, role: 'editor' })

    // The fill found the counter moved and wrote nothing, so no stale entry exists to be read.
    const base = membershipCacheKeyBase('t1', 'w1', 'u1', hmacKey)
    expect(await redis.get(`${base}:0:0`)).toBeNull()
    await expect(service.resolveMembership(REF)).resolves.toEqual({ ...REF, role: 'owner' })
  })

  it('answers from the repositories while Redis is down, and works normally after', async () => {
    const store = freshStore()
    const { service, outage } = build(store)
    await service.resolveMembership(REF)
    store.membership = store.membership && { ...store.membership, role: 'owner' }

    outage.active = true
    await expect(service.resolveMembership(REF)).resolves.toEqual({ ...REF, role: 'owner' })
    outage.active = false

    await service.invalidateMembership(REF)
    await expect(service.resolveMembership(REF)).resolves.toEqual({ ...REF, role: 'owner' })
  })

  it('refuses to report a change as invalidated while Redis is down', async () => {
    const store = freshStore()
    const { service, outage } = build(store)
    outage.active = true

    // The typed 503 the library answers an outage with, carrying the client's own error as `cause`.
    const refused = {
      status: 503,
      cause: expect.objectContaining({ message: 'Connection is closed.' })
    }
    await expect(service.invalidateMembership(REF)).rejects.toMatchObject(refused)
    await expect(service.invalidateWorkspace(WORKSPACE_REF)).rejects.toMatchObject(refused)
  })

  // A counter that expires while an entry bearing its value is alive restarts at 1 on the next
  // bump and makes that entry current again. The fill therefore carries the counters' retention.
  it('keeps a counter alive at least as long as an entry written under it', async () => {
    const store = freshStore()
    const { service, redis, hmacKey } = build(store)
    await service.invalidateMembership(REF)
    const counter = membershipVersionKey('t1', 'w1', 'u1', hmacKey)
    await redis.expire(counter, 5)

    await service.resolveMembership(REF)

    const entry = `${membershipCacheKeyBase('t1', 'w1', 'u1', hmacKey)}:0:1`
    expect(await redis.ttl(entry)).toBeGreaterThan(0)
    expect(await redis.ttl(counter)).toBeGreaterThan(await redis.ttl(entry))
  })

  // The counter expires after the versions were read and before the entry is written. The entry
  // would bear a value the next bump recreates, so a fill that finds the counters changed writes
  // nothing.
  it('writes nothing when a counter expired between the version read and the fill', async () => {
    const store = freshStore()
    const { service, redis, hmacKey } = build(store)
    await service.invalidateMembership(REF)
    const counter = membershipVersionKey('t1', 'w1', 'u1', hmacKey)
    store.afterMembershipRead = async () => {
      await redis.del(counter)
      store.afterMembershipRead = undefined
    }

    await expect(service.resolveMembership(REF)).resolves.toEqual({ ...REF, role: 'editor' })
    store.membership = store.membership && { ...store.membership, role: 'owner' }
    await service.invalidateMembership(REF)

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
