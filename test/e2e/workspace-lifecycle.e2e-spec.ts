/**
 * @fileoverview Drives the lifecycle services over a real access cache and in-memory repositories
 * that decide the last-owner rule the way a host must.
 *
 * Unit specs mock the access service, so they cannot show the property the cache bump exists for:
 * that a change is visible to the very next access check even when the previous answer was cached.
 *
 * @layer Test
 */

import { resolveOptions } from '../../src/server/config/resolved-options'
import type { HookContext, IAuthHooks } from '../../src/server/interfaces/auth-hooks.interface'
import type {
  AuthMembership,
  IMembershipRepository
} from '../../src/server/interfaces/membership-repository.interface'
import type { SafeAuthUser } from '../../src/server/interfaces/user-repository.interface'
import type {
  AuthWorkspace,
  IWorkspaceRepository
} from '../../src/server/interfaces/workspace-repository.interface'
import { AuthRedisService } from '../../src/server/redis/auth-redis.service'
import { MembershipService } from '../../src/server/services/membership.service'
import { WorkspaceAccessService } from '../../src/server/services/workspace-access.service'
import { WorkspaceEventsService } from '../../src/server/services/workspace-events.service'
import { WorkspaceService } from '../../src/server/services/workspace.service'
import { JWT_SECRET, createRedis, realRedisNamespace } from './setup'

const CONTEXT: HookContext = {
  plane: 'dashboard',
  tenantId: 't1',
  ip: '203.0.113.7',
  userAgent: 'jest',
  sanitizedHeaders: {}
}

const user = (id: string): SafeAuthUser =>
  ({ id, tenantId: 't1', email: `${id}@x.test` }) as SafeAuthUser

/** Repositories that keep rows in maps and decide the last-owner rule inside the call. */
function memoryRepositories(): {
  workspaces: IWorkspaceRepository
  memberships: IMembershipRepository
  seedMember: (workspaceId: string, userId: string, role: string) => void
  /** Runs once, right after the next membership read returns: a change that lands before the write. */
  afterNextFind: (change: () => void) => void
} {
  const rows = new Map<string, AuthWorkspace>()
  const members = new Map<string, AuthMembership>()
  let afterFind: (() => void) | undefined
  const key = (w: string, u: string): string => `${w}/${u}`
  const owners = (w: string, ownerRole: string): AuthMembership[] =>
    [...members.values()].filter(
      (m) => m.workspaceId === w && m.status === 'active' && m.role === ownerRole
    )
  const actorChanged = (w: string, actor: { userId: string; expectedRole: string }): boolean => {
    const row = members.get(key(w, actor.userId))
    return row?.status !== 'active' || row.role !== actor.expectedRole
  }
  const member = (w: string, u: string, role: string): AuthMembership => ({
    tenantId: 't1',
    workspaceId: w,
    userId: u,
    role,
    status: 'active',
    invitedByUserId: null,
    createdAt: new Date(0),
    updatedAt: new Date(0)
  })

  const workspaces: Partial<IWorkspaceRepository> = {
    createWithOwner: async (p) => {
      const workspace: AuthWorkspace = {
        id: p.workspaceId,
        tenantId: p.tenantId,
        name: p.name,
        status: 'active',
        createdAt: new Date(0),
        deletionScheduledAt: null
      }
      rows.set(p.workspaceId, workspace)
      members.set(
        key(p.workspaceId, p.ownerUserId),
        member(p.workspaceId, p.ownerUserId, p.ownerRole)
      )
      return { status: 'created', workspace }
    },
    findById: async ({ workspaceId }) => rows.get(workspaceId) ?? null,
    rename: async ({ workspaceId, name }) => {
      const row = rows.get(workspaceId)
      if (row === undefined) return false
      rows.set(workspaceId, { ...row, name })
      return true
    },
    updateStatus: async ({ workspaceId, status, expectedStatus, deletionScheduledAt }) => {
      const row = rows.get(workspaceId)
      if (row === undefined) return 'not_found'
      if (row.status !== expectedStatus) return 'status_conflict'
      rows.set(workspaceId, { ...row, status, deletionScheduledAt })
      return 'ok'
    }
  }
  const memberships: Partial<IMembershipRepository> = {
    find: async ({ workspaceId, userId }) => {
      const row = members.get(key(workspaceId, userId)) ?? null
      const change = afterFind
      afterFind = undefined
      change?.()
      return row
    },
    countOwned: async () => 0,
    changeRole: async ({ workspaceId, userId, role, ownerRole, expectedRole, actor }) => {
      const row = members.get(key(workspaceId, userId))
      if (actorChanged(workspaceId, actor)) return 'actor_changed'
      if (row === undefined || row.role !== expectedRole) return 'not_found'
      if (
        row.role === ownerRole &&
        role !== ownerRole &&
        owners(workspaceId, ownerRole).length === 1
      ) {
        return 'last_owner'
      }
      members.set(key(workspaceId, userId), { ...row, role })
      return 'ok'
    },
    remove: async ({ workspaceId, userId, ownerRole, expectedRole, actor }) => {
      const row = members.get(key(workspaceId, userId))
      if (actor !== undefined && actorChanged(workspaceId, actor)) return 'actor_changed'
      if (row === undefined || (expectedRole !== undefined && row.role !== expectedRole)) {
        return 'not_found'
      }
      if (row.role === ownerRole && owners(workspaceId, ownerRole).length === 1) return 'last_owner'
      members.delete(key(workspaceId, userId))
      return 'ok'
    },
    transferOwnership: async ({ workspaceId, fromUserId, toUserId, ownerRole, demoteFromTo }) => {
      const from = members.get(key(workspaceId, fromUserId))
      const to = members.get(key(workspaceId, toUserId))
      if (from?.role !== ownerRole) return 'not_found'
      if (to === undefined) return 'target_not_member'
      members.set(key(workspaceId, toUserId), { ...to, role: ownerRole })
      if (demoteFromTo !== null)
        members.set(key(workspaceId, fromUserId), { ...from, role: demoteFromTo })
      return 'ok'
    }
  }
  return {
    workspaces: workspaces as IWorkspaceRepository,
    memberships: memberships as IMembershipRepository,
    seedMember: (workspaceId, userId, role) => {
      members.set(key(workspaceId, userId), member(workspaceId, userId, role))
    },
    afterNextFind: (change) => {
      afterFind = change
    }
  }
}

interface Harness {
  workspaceService: WorkspaceService
  membershipService: MembershipService
  access: WorkspaceAccessService
  events: Array<{ type: string }>
  /** Adds a member the way a host's own flow would: a row, then the documented invalidation. */
  addMember: (workspaceId: string, userId: string, role: string) => Promise<void>
  /** Changes a member's role in the repository right after the service next reads a member. */
  changeAfterNextRead: (workspaceId: string, userId: string, role: string) => void
}

function build(): Harness {
  const namespace = realRedisNamespace()
  const options = resolveOptions({
    jwt: { secret: JWT_SECRET },
    roles: { hierarchy: { ADMIN: [] } },
    rateLimit: { clientIpSource: 'peer' },
    ...(namespace === undefined ? {} : { redisNamespace: namespace }),
    workspaces: {
      enabled: true,
      roles: {
        hierarchy: { owner: ['editor', 'viewer'], editor: ['viewer'], viewer: [] },
        ownerRole: 'owner'
      }
    }
  })
  const { workspaces, memberships, seedMember, afterNextFind } = memoryRepositories()
  const redis = new AuthRedisService(createRedis(), options)
  const access = new WorkspaceAccessService(redis, workspaces, memberships, options)
  const events: Array<{ type: string }> = []
  const hooks: IAuthHooks = { onWorkspaceEvent: (event) => void events.push(event) }
  const fanOut = new WorkspaceEventsService(hooks)
  return {
    workspaceService: new WorkspaceService(workspaces, memberships, access, fanOut, hooks, options),
    membershipService: new MembershipService(memberships, access, fanOut, options),
    access,
    events,
    addMember: async (workspaceId, userId, role) => {
      seedMember(workspaceId, userId, role)
      await access.invalidateMembership({ tenantId: 't1', workspaceId, userId })
    },
    changeAfterNextRead: (workspaceId, userId, role) => {
      afterNextFind(() => seedMember(workspaceId, userId, role))
    }
  }
}

const ALICE = { userId: 'alice', role: 'owner' }

describe('workspace lifecycle over a real access cache', () => {
  it('makes the creator the owner and reports the creation', async () => {
    const { workspaceService, access, events } = build()

    const { id } = await workspaceService.create(user('alice'), { name: 'Acme' }, CONTEXT)

    await expect(
      access.resolveMembership({ tenantId: 't1', workspaceId: id, userId: 'alice' })
    ).resolves.toMatchObject({ role: 'owner' })
    expect(events.map((event) => event.type)).toEqual(['workspace.created'])
  })

  it('shows a role change to the very next check although the old answer was cached', async () => {
    const { workspaceService, membershipService, access, addMember } = build()
    const { id } = await workspaceService.create(user('alice'), { name: 'Acme' }, CONTEXT)
    const ref = { tenantId: 't1', workspaceId: id }
    await addMember(id, 'bob', 'viewer')
    await expect(access.resolveMembership({ ...ref, userId: 'bob' })).resolves.toMatchObject({
      role: 'viewer'
    })

    await membershipService.changeRole(ref, 'bob', 'editor', ALICE, CONTEXT)

    await expect(access.resolveMembership({ ...ref, userId: 'bob' })).resolves.toMatchObject({
      role: 'editor'
    })
  })

  it("ends a removed member's access at once although the old answer was cached", async () => {
    const { workspaceService, membershipService, access, addMember } = build()
    const { id } = await workspaceService.create(user('alice'), { name: 'Acme' }, CONTEXT)
    const ref = { tenantId: 't1', workspaceId: id }
    await addMember(id, 'bob', 'viewer')
    await access.resolveMembership({ ...ref, userId: 'bob' })

    await membershipService.remove(ref, 'bob', ALICE, CONTEXT)

    await expect(access.resolveMembership({ ...ref, userId: 'bob' })).resolves.toBeNull()
  })

  it("ends every member's access when deletion is scheduled, and gives it back on restore", async () => {
    const { workspaceService, access, addMember } = build()
    const { id } = await workspaceService.create(user('alice'), { name: 'Acme' }, CONTEXT)
    const ref = { tenantId: 't1', workspaceId: id }
    await addMember(id, 'bob', 'viewer')
    await access.resolveMembership({ ...ref, userId: 'alice' })
    await access.resolveMembership({ ...ref, userId: 'bob' })

    await workspaceService.scheduleDeletion(ref, 'alice', CONTEXT)

    await expect(access.resolveAccess({ ...ref, userId: 'bob' })).resolves.toEqual({
      kind: 'denied'
    })
    await expect(access.resolveAccess({ ...ref, userId: 'alice' })).resolves.toMatchObject({
      kind: 'pending_deletion'
    })
    await workspaceService.restore(ref, 'alice', CONTEXT)
    await expect(access.resolveMembership({ ...ref, userId: 'bob' })).resolves.toMatchObject({
      role: 'viewer'
    })
  })

  it('refuses the last owner leaving, and allows it once ownership has moved', async () => {
    const { workspaceService, membershipService, addMember } = build()
    const { id } = await workspaceService.create(user('alice'), { name: 'Acme' }, CONTEXT)
    const ref = { tenantId: 't1', workspaceId: id }
    await addMember(id, 'bob', 'editor')

    await expect(membershipService.leave(ref, 'alice', CONTEXT)).rejects.toMatchObject({
      response: { error: { code: 'auth.last_owner' } }
    })
    await membershipService.transferOwnership(ref, ALICE, 'bob', 'editor', CONTEXT)
    await expect(membershipService.leave(ref, 'alice', CONTEXT)).resolves.toBeUndefined()
  })

  it('refuses to hand ownership to someone who belongs to another workspace only', async () => {
    const { workspaceService, membershipService } = build()
    const { id } = await workspaceService.create(user('alice'), { name: 'Acme' }, CONTEXT)
    await workspaceService.create(user('bob'), { name: 'Other' }, CONTEXT)

    await expect(
      membershipService.transferOwnership(
        { tenantId: 't1', workspaceId: id },
        ALICE,
        'bob',
        null,
        CONTEXT
      )
    ).rejects.toMatchObject({ response: { error: { code: 'auth.validation' } } })
  })

  it('refuses a transfer by anyone who is not an owner, and a transfer to oneself', async () => {
    const { workspaceService, membershipService, addMember } = build()
    const { id } = await workspaceService.create(user('alice'), { name: 'Acme' }, CONTEXT)
    const ref = { tenantId: 't1', workspaceId: id }
    await addMember(id, 'bob', 'editor')

    await expect(
      membershipService.transferOwnership(
        ref,
        { userId: 'bob', role: 'editor' },
        'bob',
        null,
        CONTEXT
      )
    ).rejects.toMatchObject({ response: { error: { code: 'auth.insufficient_workspace_role' } } })
    await expect(
      membershipService.transferOwnership(ref, ALICE, 'alice', null, CONTEXT)
    ).rejects.toMatchObject({ response: { error: { code: 'auth.validation' } } })
  })

  it('moves both roles together: the new owner and the demoted one are visible at once', async () => {
    const { workspaceService, membershipService, access, addMember } = build()
    const { id } = await workspaceService.create(user('alice'), { name: 'Acme' }, CONTEXT)
    const ref = { tenantId: 't1', workspaceId: id }
    await addMember(id, 'bob', 'editor')
    await access.resolveMembership({ ...ref, userId: 'alice' })
    await access.resolveMembership({ ...ref, userId: 'bob' })

    await membershipService.transferOwnership(ref, ALICE, 'bob', 'viewer', CONTEXT)

    await expect(access.resolveMembership({ ...ref, userId: 'bob' })).resolves.toMatchObject({
      role: 'owner'
    })
    await expect(access.resolveMembership({ ...ref, userId: 'alice' })).resolves.toMatchObject({
      role: 'viewer'
    })
  })

  // The ceiling is judged from roles read before the write. These show the write refusing when
  // one of them changed in between, which a mock of the port cannot show.
  describe('a role that changes between the read and the write', () => {
    const CAROL = { userId: 'carol', role: 'editor' }

    async function withTeam(): Promise<
      Harness & { ref: { tenantId: string; workspaceId: string } }
    > {
      const harness = build()
      const { id } = await harness.workspaceService.create(user('alice'), { name: 'Acme' }, CONTEXT)
      await harness.addMember(id, 'carol', 'editor')
      await harness.addMember(id, 'bob', 'viewer')
      return { ...harness, ref: { tenantId: 't1', workspaceId: id } }
    }

    it('keeps a member who was promoted after the actor judged them a viewer', async () => {
      const { membershipService, access, changeAfterNextRead, ref } = await withTeam()
      changeAfterNextRead(ref.workspaceId, 'bob', 'owner')

      await expect(membershipService.remove(ref, 'bob', CAROL, CONTEXT)).rejects.toMatchObject({
        response: { error: { code: 'auth.workspace_not_found' } }
      })

      await expect(access.resolveMembership({ ...ref, userId: 'bob' })).resolves.toMatchObject({
        role: 'owner'
      })
    })

    it('refuses an actor who was demoted after the action was judged', async () => {
      const { membershipService, access, changeAfterNextRead, ref } = await withTeam()
      changeAfterNextRead(ref.workspaceId, 'carol', 'viewer')

      await expect(membershipService.remove(ref, 'bob', CAROL, CONTEXT)).rejects.toMatchObject({
        response: { error: { code: 'auth.insufficient_workspace_role' } }
      })

      await expect(access.resolveMembership({ ...ref, userId: 'bob' })).resolves.toMatchObject({
        role: 'viewer'
      })
    })

    it('refuses a role change when the actor was demoted after it was judged', async () => {
      const { membershipService, access, addMember, changeAfterNextRead, ref } = await withTeam()
      await addMember(ref.workspaceId, 'olive', 'owner')
      changeAfterNextRead(ref.workspaceId, 'olive', 'editor')

      await expect(
        membershipService.changeRole(
          ref,
          'bob',
          'editor',
          { userId: 'olive', role: 'owner' },
          CONTEXT
        )
      ).rejects.toMatchObject({ response: { error: { code: 'auth.insufficient_workspace_role' } } })

      await expect(access.resolveMembership({ ...ref, userId: 'bob' })).resolves.toMatchObject({
        role: 'viewer'
      })
    })
  })

  it('does not finalize a deletion before its grace period is over', async () => {
    const { workspaceService, access } = build()
    const { id } = await workspaceService.create(user('alice'), { name: 'Acme' }, CONTEXT)
    const ref = { tenantId: 't1', workspaceId: id }
    await workspaceService.scheduleDeletion(ref, 'alice', CONTEXT)

    await expect(workspaceService.finalizeDeletion(ref)).resolves.toBe('not_due')

    await expect(access.resolveAccess({ ...ref, userId: 'alice' })).resolves.toMatchObject({
      kind: 'pending_deletion'
    })
  })
})
