/**
 * @fileoverview Pins that every write a workspace service makes after a role judgment hands the
 * repository the acting member, or is named below with the reason it does not.
 *
 * A role judged before a write can change before the write lands. The repository can close that gap
 * only if it is told the role, so a new method on either service has to choose here: pass the
 * actor, or be listed as exempt with a reason. The table must name exactly the public methods of
 * the two services, which is what makes the choice unavoidable.
 *
 * @layer Test
 */

import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import type { IMembershipRepository } from '../interfaces/membership-repository.interface'
import type { IWorkspaceRepository } from '../interfaces/workspace-repository.interface'
import type { SafeAuthUser } from '../interfaces/user-repository.interface'
import {
  CONTEXT,
  WORKSPACE_REF,
  workspaceOptions,
  workspaceRow
} from './__tests__/workspace-service-harness'
import { MembershipService } from './membership.service'
import type { WorkspaceAccessService } from './workspace-access.service'
import type { WorkspaceEventsService } from './workspace-events.service'
import { WorkspaceService } from './workspace.service'
import type { IAuthHooks } from '../interfaces/auth-hooks.interface'

const ACTOR = { userId: 'actor-1', role: 'owner' }
const JUDGED = { userId: 'actor-1', expectedRole: 'owner' }
const USER = { id: 'actor-1', tenantId: 't1', email: 'a@b.c' } as SafeAuthUser

interface Services {
  workspace: WorkspaceService
  membership: MembershipService
  workspaces: Record<string, jest.Mock>
  memberships: Record<string, jest.Mock>
}

/** A workspace repository that accepts every write. */
function acceptingWorkspaces(): Record<string, jest.Mock> {
  return {
    createWithOwner: jest.fn().mockResolvedValue({ status: 'created', workspace: workspaceRow() }),
    findById: jest
      .fn()
      .mockResolvedValue(workspaceRow({ status: 'pending_deletion', deletionScheduledAt: null })),
    rename: jest.fn().mockResolvedValue('ok'),
    updateStatus: jest.fn().mockResolvedValue('ok')
  }
}

/** A membership repository that accepts every write and holds one viewer. */
function acceptingMemberships(): Record<string, jest.Mock> {
  const page = { items: [], nextCursor: null }
  return {
    find: jest.fn().mockResolvedValue({
      ...WORKSPACE_REF,
      userId: 'u2',
      role: 'viewer',
      status: 'active',
      invitedByUserId: null,
      createdAt: new Date(0),
      updatedAt: new Date(0)
    }),
    changeRole: jest.fn().mockResolvedValue('ok'),
    remove: jest.fn().mockResolvedValue('ok'),
    transferOwnership: jest.fn().mockResolvedValue('ok'),
    listForUser: jest.fn().mockResolvedValue(page),
    listForWorkspace: jest.fn().mockResolvedValue(page),
    listSoleOwned: jest.fn().mockResolvedValue(page),
    countOwned: jest.fn().mockResolvedValue(0),
    setLastActiveWorkspaceId: jest.fn()
  }
}

/** The access service, with the actor resolving as the owner. */
function owningAccess(): Partial<WorkspaceAccessService> {
  return {
    invalidateWorkspace: jest.fn().mockResolvedValue(undefined),
    invalidateMembership: jest.fn().mockResolvedValue(undefined),
    resolveMembership: jest
      .fn()
      .mockResolvedValue({ ...WORKSPACE_REF, userId: 'actor-1', role: 'owner' })
  }
}

/** Both services over repositories that accept every write. */
function build(): Services {
  const workspaces = acceptingWorkspaces()
  const memberships = acceptingMemberships()
  const access = owningAccess() as WorkspaceAccessService
  const events = { emit: jest.fn() } as Partial<WorkspaceEventsService> as WorkspaceEventsService
  const options = workspaceOptions()
  const workspaceRepository = workspaces as Partial<IWorkspaceRepository> as IWorkspaceRepository
  const membershipRepository =
    memberships as Partial<IMembershipRepository> as IMembershipRepository
  return {
    workspace: new WorkspaceService(
      workspaceRepository,
      membershipRepository,
      access,
      events,
      {} as IAuthHooks,
      options
    ),
    membership: new MembershipService(membershipRepository, access, events, options),
    workspaces,
    memberships
  }
}

type Entry =
  | {
      kind: 'judged'
      write: 'workspaces' | 'memberships'
      method: string
      run: (s: Services) => Promise<unknown>
    }
  | { kind: 'giver'; run: (s: Services) => Promise<unknown> }
  | { kind: 'exempt'; reason: string }
  | { kind: 'read' }

/** Every public method of WorkspaceService, and what it does about the acting member. */
const WORKSPACE_METHODS: Record<string, Entry> = {
  create: {
    kind: 'exempt',
    reason:
      'any identity creates its own workspace; the gates are allowCreate, the cap and a hook, none a role in a workspace'
  },
  rename: {
    kind: 'judged',
    write: 'workspaces',
    method: 'rename',
    run: (s) => s.workspace.rename(WORKSPACE_REF, 'New', ACTOR, CONTEXT)
  },
  scheduleDeletion: {
    kind: 'judged',
    write: 'workspaces',
    method: 'updateStatus',
    run: (s) => s.workspace.scheduleDeletion(WORKSPACE_REF, ACTOR, CONTEXT)
  },
  restore: {
    kind: 'judged',
    write: 'workspaces',
    method: 'updateStatus',
    run: (s) => s.workspace.restore(WORKSPACE_REF, ACTOR, CONTEXT)
  },
  finalizeDeletion: {
    kind: 'exempt',
    reason: 'a host job runs it; no member authorized it, so there is no actor to check'
  },
  switchTo: {
    kind: 'exempt',
    reason:
      'it records a last-used preference after a membership check; a stale pointer is harmless because the guard re-checks membership on every request'
  },
  getAccess: { kind: 'read' }
}

/** Every public method of MembershipService, and what it does about the acting member. */
const MEMBERSHIP_METHODS: Record<string, Entry> = {
  listMine: { kind: 'read' },
  listMembers: { kind: 'read' },
  listSoleOwnedWorkspaces: { kind: 'read' },
  getMember: { kind: 'read' },
  assertMayTransfer: {
    kind: 'exempt',
    reason: 'a local check that writes nothing; transferOwnership repeats it before the write'
  },
  assertMayGrant: {
    kind: 'exempt',
    reason: 'a local check that writes nothing; the invitation service applies it before it stores'
  },
  mayActOn: {
    kind: 'exempt',
    reason: 'a local comparison of two roles that writes nothing'
  },
  changeRole: {
    kind: 'judged',
    write: 'memberships',
    method: 'changeRole',
    run: (s) => s.membership.changeRole(WORKSPACE_REF, 'u2', 'editor', ACTOR, CONTEXT)
  },
  remove: {
    kind: 'judged',
    write: 'memberships',
    method: 'remove',
    run: (s) => s.membership.remove(WORKSPACE_REF, 'u2', ACTOR, CONTEXT)
  },
  leave: {
    kind: 'exempt',
    reason: 'a member leaving acts on their own membership; no role authorized it'
  },
  transferOwnership: {
    kind: 'giver',
    run: (s) => s.membership.transferOwnership(WORKSPACE_REF, ACTOR, 'u2', null, CONTEXT)
  }
}

/**
 * The public methods a class declares, read from its source.
 *
 * Read from the file because TypeScript's `private` is erased at run time, so the prototype cannot
 * tell a helper from an entry point.
 *
 * @param file - The service file name.
 * @returns The names of the methods declared without `private`.
 */
function publicMethods(file: string): string[] {
  const source = readFileSync(join(__dirname, file), 'utf8')
  return [...source.matchAll(/^ {2}(?:async )?([a-zA-Z]+)\(/gm)]
    .map((match) => match[1] ?? '')
    .filter((name) => name !== 'constructor')
    .sort()
}

describe('the acting member on every write the workspace services make', () => {
  it('names exactly the public methods of WorkspaceService', () => {
    expect(Object.keys(WORKSPACE_METHODS).sort()).toEqual(publicMethods('workspace.service.ts'))
  })

  it('names exactly the public methods of MembershipService', () => {
    expect(Object.keys(MEMBERSHIP_METHODS).sort()).toEqual(publicMethods('membership.service.ts'))
  })

  const judged = [
    ...Object.entries(WORKSPACE_METHODS),
    ...Object.entries(MEMBERSHIP_METHODS)
  ].filter(([, entry]) => entry.kind === 'judged')

  it.each(judged)(
    '%s hands the repository the acting member and the role it judged',
    async (_name, entry) => {
      const services = build()
      if (entry.kind !== 'judged') throw new Error('unreachable')

      await entry.run(services)

      const sent = services[entry.write][entry.method]?.mock.calls[0]?.[0] as
        { actor?: unknown } | undefined
      expect(sent?.actor).toEqual(JUDGED)
    }
  )

  it('transferOwnership names the giver, whom the repository checks is still an active owner', async () => {
    const services = build()
    const entry = MEMBERSHIP_METHODS['transferOwnership']
    if (entry?.kind !== 'giver') throw new Error('unreachable')

    await entry.run(services)

    expect(services.memberships['transferOwnership']?.mock.calls[0]?.[0]).toMatchObject({
      fromUserId: ACTOR.userId
    })
  })

  it('gives every exemption a reason', () => {
    const exempt = Object.values({ ...WORKSPACE_METHODS, ...MEMBERSHIP_METHODS }).filter(
      (entry) => entry.kind === 'exempt'
    )

    expect(exempt.length).toBe(7)
    for (const entry of exempt) {
      expect(entry.kind === 'exempt' && entry.reason.length > 20).toBe(true)
    }
  })

  it('keeps create out of the judged writes, and the creator as the only owner', async () => {
    const services = build()

    await services.workspace.create(USER, { name: 'Acme' }, CONTEXT)

    const sent = services.workspaces['createWithOwner']?.mock.calls[0]?.[0] as Record<
      string,
      unknown
    >
    expect(Object.keys(sent)).not.toContain('actor')
    expect(sent['ownerUserId']).toBe('actor-1')
  })
})
