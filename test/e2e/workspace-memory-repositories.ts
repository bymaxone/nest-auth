/**
 * @fileoverview In-memory workspace and membership repositories for the e2e suites.
 *
 * They decide the last-owner rule inside the call and honour the roles the library hands them, the
 * way a host's transactional repository must, so a suite can show what a change does to access
 * rather than what a mock was told to return.
 *
 * @layer Test
 */

import type {
  AuthMembership,
  IMembershipRepository
} from '../../src/server/interfaces/membership-repository.interface'
import type { ActingMember } from '../../src/server/interfaces/acting-member.interface'
import type {
  AuthWorkspace,
  IWorkspaceRepository
} from '../../src/server/interfaces/workspace-repository.interface'

/** What the repositories keep, and the one change that can land between a read and the next write. */
interface Store {
  rows: Map<string, AuthWorkspace>
  members: Map<string, AuthMembership>
  /** The workspace each user last switched to, by user id. */
  lastActive: Map<string, string>
  afterFind: (() => void) | undefined
}

/**
 * The key of one membership.
 *
 * The identifiers are encoded as a list, not joined with a delimiter, so `('a/b', 'c')` and
 * `('a', 'b/c')` stay two memberships whatever characters an identifier carries.
 *
 * @param workspaceId - The workspace.
 * @param userId - The member.
 * @returns The unambiguous key.
 */
export function membershipKey(workspaceId: string, userId: string): string {
  return JSON.stringify([workspaceId, userId])
}

/** An active membership in the single tenant these suites use. */
function member(workspaceId: string, userId: string, role: string): AuthMembership {
  return {
    tenantId: 't1',
    workspaceId,
    userId,
    role,
    status: 'active',
    invitedByUserId: null,
    createdAt: new Date(0),
    updatedAt: new Date(0)
  }
}

/** The active holders of the owner role in a workspace. */
function owners(store: Store, workspaceId: string, ownerRole: string): AuthMembership[] {
  return [...store.members.values()].filter(
    (m) => m.workspaceId === workspaceId && m.status === 'active' && m.role === ownerRole
  )
}

/** Whether the actor no longer holds, as an active member, the role the library judged them by. */
function actorChanged(store: Store, workspaceId: string, actor: ActingMember): boolean {
  const row = store.members.get(membershipKey(workspaceId, actor.userId))
  return row?.status !== 'active' || row.role !== actor.expectedRole
}

/** Whether the stored deadline is the one expected; an expectation of `undefined` compares nothing. */
function sameInstant(stored: Date | null, expected: Date | null | undefined): boolean {
  if (expected === undefined) return true
  return (stored?.getTime() ?? null) === (expected?.getTime() ?? null)
}

/** The workspace port: creation with its owner, reads, rename and the status compare-and-set. */
function workspaceRepository(store: Store): IWorkspaceRepository {
  const repository: Partial<IWorkspaceRepository> = {
    createWithOwner: async (p) => {
      const workspace: AuthWorkspace = {
        id: p.workspaceId,
        tenantId: p.tenantId,
        name: p.name,
        status: 'active',
        createdAt: new Date(0),
        deletionScheduledAt: null
      }
      store.rows.set(p.workspaceId, workspace)
      store.members.set(
        membershipKey(p.workspaceId, p.ownerUserId),
        member(p.workspaceId, p.ownerUserId, p.ownerRole)
      )
      return { status: 'created', workspace }
    },
    findById: async ({ workspaceId }) => store.rows.get(workspaceId) ?? null,
    rename: async ({ workspaceId, name, actor }) => {
      const row = store.rows.get(workspaceId)
      if (actorChanged(store, workspaceId, actor)) return 'actor_changed'
      if (row === undefined) return 'not_found'
      store.rows.set(workspaceId, { ...row, name })
      return 'ok'
    },
    updateStatus: async ({
      workspaceId,
      status,
      expectedStatus,
      expectedDeletionScheduledAt,
      deletionScheduledAt,
      actor
    }) => {
      const row = store.rows.get(workspaceId)
      if (actor !== undefined && actorChanged(store, workspaceId, actor)) return 'actor_changed'
      if (row === undefined) return 'not_found'
      if (row.status !== expectedStatus) return 'status_conflict'
      if (!sameInstant(row.deletionScheduledAt, expectedDeletionScheduledAt)) {
        return 'status_conflict'
      }
      store.rows.set(workspaceId, { ...row, status, deletionScheduledAt })
      return 'ok'
    }
  }
  return repository as IWorkspaceRepository
}

/** The membership port's reads. `find` runs the one-shot change that lands after a read. */
function membershipReads(store: Store): Partial<IMembershipRepository> {
  return {
    find: async ({ workspaceId, userId }) => {
      const row = store.members.get(membershipKey(workspaceId, userId)) ?? null
      const change = store.afterFind
      store.afterFind = undefined
      change?.()
      return row
    },
    countOwned: async () => 0,
    listForUser: async ({ userId, cursor, limit }) => {
      const mine = [...store.members.values()]
        .filter(
          (m) => m.userId === userId && m.status === 'active' && store.rows.has(m.workspaceId)
        )
        .sort((a, b) => a.workspaceId.localeCompare(b.workspaceId))
      const page = pageAfter(mine, (m) => m.workspaceId, cursor, limit)
      return {
        items: page.items.map((m) => ({
          ...m,
          workspace: store.rows.get(m.workspaceId) as AuthWorkspace
        })),
        nextCursor: page.nextCursor
      }
    },
    listForWorkspace: async ({ workspaceId, cursor, limit }) => {
      const members = [...store.members.values()]
        .filter((m) => m.workspaceId === workspaceId)
        .sort((a, b) => a.userId.localeCompare(b.userId))
      return pageAfter(members, (m) => m.userId, cursor, limit)
    },
    getLastActiveWorkspaceId: async ({ userId }) => store.lastActive.get(userId) ?? null,
    setLastActiveWorkspaceId: async ({ userId, workspaceId }) => {
      store.lastActive.set(userId, workspaceId)
    }
  }
}

/**
 * One keyset page over rows already in order. The cursor is the sort key of the last row of the
 * previous page and says only where to start inside THESE rows, so a cursor taken from another
 * list cannot bring a row from it.
 */
function pageAfter<T>(
  rows: T[],
  keyOf: (row: T) => string,
  cursor: string | undefined,
  limit: number
): { items: T[]; nextCursor: string | null } {
  const after = cursor === undefined ? [] : rows.filter((row) => keyOf(row) > cursor)
  const rest = cursor === undefined ? rows : after
  const items = rest.slice(0, limit)
  const last = items[items.length - 1]
  const more = rest.length > items.length && last !== undefined
  return { items, nextCursor: more ? keyOf(last) : null }
}

/** The membership port's writes, each deciding the last-owner rule and the judged roles itself. */
function membershipWrites(store: Store): Partial<IMembershipRepository> {
  return {
    changeRole: async ({ workspaceId, userId, role, ownerRole, expectedRole, actor }) => {
      const row = store.members.get(membershipKey(workspaceId, userId))
      if (actorChanged(store, workspaceId, actor)) return 'actor_changed'
      if (row === undefined || row.role !== expectedRole) return 'not_found'
      const lastOwner = owners(store, workspaceId, ownerRole).length === 1
      if (row.role === ownerRole && role !== ownerRole && lastOwner) return 'last_owner'
      store.members.set(membershipKey(workspaceId, userId), { ...row, role })
      return 'ok'
    },
    remove: async ({ workspaceId, userId, ownerRole, expectedRole, actor }) => {
      const row = store.members.get(membershipKey(workspaceId, userId))
      if (actor !== undefined && actorChanged(store, workspaceId, actor)) return 'actor_changed'
      if (row === undefined || (expectedRole !== undefined && row.role !== expectedRole)) {
        return 'not_found'
      }
      const lastOwner = owners(store, workspaceId, ownerRole).length === 1
      if (row.role === ownerRole && lastOwner) return 'last_owner'
      store.members.delete(membershipKey(workspaceId, userId))
      return 'ok'
    },
    transferOwnership: async ({ workspaceId, fromUserId, toUserId, ownerRole, demoteFromTo }) => {
      const from = store.members.get(membershipKey(workspaceId, fromUserId))
      const to = store.members.get(membershipKey(workspaceId, toUserId))
      if (from?.role !== ownerRole) return 'not_found'
      if (to === undefined) return 'target_not_member'
      store.members.set(membershipKey(workspaceId, toUserId), { ...to, role: ownerRole })
      if (demoteFromTo !== null) {
        store.members.set(membershipKey(workspaceId, fromUserId), { ...from, role: demoteFromTo })
      }
      return 'ok'
    }
  }
}

/** The repositories, and the two handles a suite uses to set up and to inject a change. */
export interface MemoryRepositories {
  workspaces: IWorkspaceRepository
  memberships: IMembershipRepository
  /** Writes a membership directly, as a host's own flow would. */
  seedMember: (workspaceId: string, userId: string, role: string) => void
  /** Runs once, right after the next membership read returns: a change that lands before the write. */
  afterNextFind: (change: () => void) => void
}

/**
 * Builds a fresh pair of repositories over an empty store.
 *
 * @returns The repositories and their two test handles.
 */
export function memoryRepositories(): MemoryRepositories {
  const store: Store = {
    rows: new Map(),
    members: new Map(),
    lastActive: new Map(),
    afterFind: undefined
  }
  return {
    workspaces: workspaceRepository(store),
    memberships: {
      ...membershipReads(store),
      ...membershipWrites(store)
    } as IMembershipRepository,
    seedMember: (workspaceId, userId, role) => {
      store.members.set(membershipKey(workspaceId, userId), member(workspaceId, userId, role))
    },
    afterNextFind: (change) => {
      store.afterFind = change
    }
  }
}
