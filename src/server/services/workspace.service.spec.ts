/**
 * @fileoverview Tests for the workspace lifecycle service: creation and its three gates, rename,
 * scheduled and immediate deletion, restore, finalization, switching and the access view.
 *
 * @layer Test
 */

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import type { AuthException } from '../errors/auth-exception'
import type { IAuthHooks } from '../interfaces/auth-hooks.interface'
import type { IMembershipRepository } from '../interfaces/membership-repository.interface'
import type { SafeAuthUser } from '../interfaces/user-repository.interface'
import type { IWorkspaceRepository } from '../interfaces/workspace-repository.interface'
import {
  CONTEXT,
  NOW,
  optionsWithoutWorkspaces,
  WORKSPACE_REF,
  workspaceOptions,
  workspaceRow
} from './__tests__/workspace-service-harness'
import type { WorkspaceAccessService } from './workspace-access.service'
import type { WorkspaceEventsService } from './workspace-events.service'
import { WorkspaceService } from './workspace.service'

const ACTOR = { userId: 'u1', role: 'owner' }
const JUDGED = { userId: 'u1', expectedRole: 'owner' }
const USER = { id: 'u1', tenantId: 't1', email: 'a@b.c' } as SafeAuthUser
const DAY = 86_400_000

interface Harness {
  service: WorkspaceService
  workspaces: { [K in keyof IWorkspaceRepository]: jest.Mock }
  memberships: { countOwned: jest.Mock; setLastActiveWorkspaceId?: jest.Mock }
  access: { invalidateWorkspace: jest.Mock; resolveMembership: jest.Mock }
  events: { emit: jest.Mock }
  hooks: { beforeWorkspaceCreate?: jest.Mock }
}

function build(
  extra: Parameters<typeof workspaceOptions>[0] = {},
  withHook = false,
  withSwitchPort = true
): Harness {
  const workspaces = {
    createWithOwner: jest.fn(),
    findById: jest.fn(),
    rename: jest.fn().mockResolvedValue('ok'),
    updateStatus: jest.fn().mockResolvedValue('ok')
  }
  const memberships: Harness['memberships'] = {
    countOwned: jest.fn().mockResolvedValue(0),
    ...(withSwitchPort ? { setLastActiveWorkspaceId: jest.fn() } : {})
  }
  const access = {
    invalidateWorkspace: jest.fn().mockResolvedValue(undefined),
    resolveMembership: jest.fn()
  }
  const events = { emit: jest.fn() }
  const hooks: Harness['hooks'] = withHook
    ? { beforeWorkspaceCreate: jest.fn().mockResolvedValue({ allowed: true }) }
    : {}
  const service = new WorkspaceService(
    workspaces as Partial<IWorkspaceRepository> as IWorkspaceRepository,
    memberships as Partial<IMembershipRepository> as IMembershipRepository,
    access as Partial<WorkspaceAccessService> as WorkspaceAccessService,
    events as Partial<WorkspaceEventsService> as WorkspaceEventsService,
    hooks as IAuthHooks,
    workspaceOptions(extra)
  )
  return { service, workspaces, memberships, access, events, hooks }
}

/** The error code an operation fails with, or `'ok'`. */
async function code(promise: Promise<unknown>): Promise<string> {
  try {
    await promise
  } catch (error) {
    return ((error as AuthException).getResponse() as { error: { code: string } }).error.code
  }
  return 'ok'
}

describe('WorkspaceService', () => {
  beforeEach(() => {
    jest.useFakeTimers().setSystemTime(NOW)
  })

  afterEach(() => {
    jest.useRealTimers()
  })

  it('refuses to exist without the workspace group', () => {
    expect(
      () =>
        new WorkspaceService(
          {} as IWorkspaceRepository,
          {} as IMembershipRepository,
          {} as WorkspaceAccessService,
          {} as WorkspaceEventsService,
          {} as IAuthHooks,
          optionsWithoutWorkspaces()
        )
    ).toThrow('[BymaxAuthModule] WorkspaceService needs workspaces.enabled.')
  })

  describe('create', () => {
    it('writes the workspace and the owner with one audit event, then reports it', async () => {
      const { service, workspaces, events } = build({ maxWorkspacesPerUser: 3 })
      const row = workspaceRow()
      workspaces.createWithOwner.mockResolvedValue({ status: 'created', workspace: row })

      const created = await service.create(USER, { name: '  Acme  ' }, CONTEXT)

      const params = workspaces.createWithOwner.mock.calls[0]?.[0] as Record<string, unknown>
      expect(created).toBe(row)
      expect(params).toMatchObject({
        tenantId: 't1',
        name: 'Acme',
        ownerUserId: 'u1',
        ownerRole: 'owner',
        maxWorkspacesPerUser: 3
      })
      expect(params['workspaceId']).toMatch(/^[0-9a-f-]{36}$/)
      expect(params['audit']).toEqual({
        type: 'workspace.created',
        tenantId: 't1',
        workspaceId: params['workspaceId'],
        actorUserId: 'u1',
        at: NOW.toISOString()
      })
      expect(events.emit).toHaveBeenCalledWith(params['audit'], CONTEXT)
    })

    it('refuses a bad name before touching a repository', async () => {
      const { service, workspaces, memberships } = build({ maxWorkspacesPerUser: 1 })

      await expect(code(service.create(USER, { name: '   ' }, CONTEXT))).resolves.toBe(
        AUTH_ERROR_CODES.VALIDATION
      )
      expect(workspaces.createWithOwner).not.toHaveBeenCalled()
      expect(memberships.countOwned).not.toHaveBeenCalled()
    })

    it('answers workspace-limit-reached when the repository enforces the cap', async () => {
      const { service, workspaces, events } = build()
      workspaces.createWithOwner.mockResolvedValue({ status: 'limit_reached' })

      await expect(code(service.create(USER, { name: 'A' }, CONTEXT))).resolves.toBe(
        AUTH_ERROR_CODES.WORKSPACE_LIMIT_REACHED
      )
      expect(events.emit).not.toHaveBeenCalled()
    })

    describe('allowCreate', () => {
      it.each([false, async () => false, () => false])('refuses with %p', async (allowCreate) => {
        const { service, workspaces } = build({ allowCreate })

        await expect(code(service.create(USER, { name: 'A' }, CONTEXT))).resolves.toBe(
          AUTH_ERROR_CODES.FORBIDDEN
        )
        expect(workspaces.createWithOwner).not.toHaveBeenCalled()
      })

      it('hands the function the identity and accepts what it allows', async () => {
        const allowCreate = jest.fn().mockResolvedValue(true)
        const { service, workspaces } = build({ allowCreate })
        workspaces.createWithOwner.mockResolvedValue({
          status: 'created',
          workspace: workspaceRow()
        })

        await service.create(USER, { name: 'A' }, CONTEXT)

        expect(allowCreate).toHaveBeenCalledWith(USER)
      })
    })

    describe('the per-user limit', () => {
      it("counts the identity's owned workspaces by the full key", async () => {
        const { service, workspaces, memberships } = build({ maxWorkspacesPerUser: 2 })
        workspaces.createWithOwner.mockResolvedValue({
          status: 'created',
          workspace: workspaceRow()
        })
        memberships.countOwned.mockResolvedValue(1)

        await service.create(USER, { name: 'A' }, CONTEXT)

        expect(memberships.countOwned).toHaveBeenCalledWith({
          tenantId: 't1',
          userId: 'u1',
          ownerRole: 'owner'
        })
      })

      it.each([2, 3])('refuses at %p owned of 2 and writes nothing', async (owned) => {
        const { service, workspaces, memberships } = build({ maxWorkspacesPerUser: 2 })
        memberships.countOwned.mockResolvedValue(owned)

        await expect(code(service.create(USER, { name: 'A' }, CONTEXT))).resolves.toBe(
          AUTH_ERROR_CODES.WORKSPACE_LIMIT_REACHED
        )
        expect(workspaces.createWithOwner).not.toHaveBeenCalled()
      })

      it('does not count at all when there is no limit', async () => {
        const { service, workspaces, memberships } = build()
        workspaces.createWithOwner.mockResolvedValue({
          status: 'created',
          workspace: workspaceRow()
        })

        await service.create(USER, { name: 'A' }, CONTEXT)

        expect(memberships.countOwned).not.toHaveBeenCalled()
      })
    })

    describe('beforeWorkspaceCreate', () => {
      it('is asked with the identity, the trimmed name and the context, after the other gates', async () => {
        const { service, workspaces, hooks } = build({}, true)
        workspaces.createWithOwner.mockResolvedValue({
          status: 'created',
          workspace: workspaceRow()
        })

        await service.create(USER, { name: ' A ' }, CONTEXT)

        expect(hooks.beforeWorkspaceCreate).toHaveBeenCalledWith(USER, { name: 'A' }, CONTEXT)
      })

      it('is not asked when an earlier gate refused', async () => {
        const { service, hooks } = build({ allowCreate: false }, true)

        await code(service.create(USER, { name: 'A' }, CONTEXT))

        expect(hooks.beforeWorkspaceCreate).not.toHaveBeenCalled()
      })

      it('refuses with its reason in the details', async () => {
        const { service, workspaces, hooks } = build({}, true)
        hooks.beforeWorkspaceCreate?.mockResolvedValue({ allowed: false, reason: 'Plan limit' })

        const result = service.create(USER, { name: 'A' }, CONTEXT)

        await expect(result).rejects.toMatchObject({
          response: {
            error: {
              code: AUTH_ERROR_CODES.FORBIDDEN,
              details: [{ field: 'name', message: 'Plan limit' }]
            }
          }
        })
        expect(workspaces.createWithOwner).not.toHaveBeenCalled()
      })

      it('refuses with a default reason when it gives none', async () => {
        const { service, hooks } = build({}, true)
        hooks.beforeWorkspaceCreate?.mockResolvedValue({ allowed: false })

        await expect(service.create(USER, { name: 'A' }, CONTEXT)).rejects.toMatchObject({
          response: {
            error: { details: [{ field: 'name', message: 'Workspace creation was refused' }] }
          }
        })
      })

      it('refuses the creation when the hook throws', async () => {
        const { service, workspaces, hooks } = build({}, true)
        hooks.beforeWorkspaceCreate?.mockRejectedValue(new Error('down'))

        await expect(service.create(USER, { name: 'A' }, CONTEXT)).rejects.toThrow('down')
        expect(workspaces.createWithOwner).not.toHaveBeenCalled()
      })
    })
  })

  describe('rename', () => {
    it('writes the new name with its audit event and reports the same event', async () => {
      const { service, workspaces, events } = build()

      await service.rename(WORKSPACE_REF, '  New  ', ACTOR, CONTEXT)

      const audit = {
        type: 'workspace.renamed',
        ...WORKSPACE_REF,
        actorUserId: 'u1',
        at: NOW.toISOString()
      }
      expect(workspaces.rename).toHaveBeenCalledWith({
        ...WORKSPACE_REF,
        name: 'New',
        actor: JUDGED,
        audit
      })
      expect(events.emit).toHaveBeenCalledWith(audit, CONTEXT)
    })

    it('answers workspace-not-found when nothing was renamed, and reports nothing', async () => {
      const { service, workspaces, events } = build()
      workspaces.rename.mockResolvedValue('not_found')

      await expect(code(service.rename(WORKSPACE_REF, 'New', ACTOR, CONTEXT))).resolves.toBe(
        AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND
      )
      expect(events.emit).not.toHaveBeenCalled()
    })

    it('refuses a bad name before writing', async () => {
      const { service, workspaces } = build()

      await expect(code(service.rename(WORKSPACE_REF, '', ACTOR, CONTEXT))).resolves.toBe(
        AUTH_ERROR_CODES.VALIDATION
      )
      expect(workspaces.rename).not.toHaveBeenCalled()
    })
  })

  // The role the guard resolved was read before the write; the repository checks it again and
  // answers actor_changed when the actor was demoted in between.
  describe('an actor whose role changed before the write', () => {
    const pending = workspaceRow({ status: 'pending_deletion', deletionScheduledAt: null })

    it.each([
      ['rename', (h: Harness) => h.service.rename(WORKSPACE_REF, 'New', ACTOR, CONTEXT), 'rename'],
      [
        'scheduleDeletion',
        (h: Harness) => h.service.scheduleDeletion(WORKSPACE_REF, ACTOR, CONTEXT),
        'updateStatus'
      ],
      ['restore', (h: Harness) => h.service.restore(WORKSPACE_REF, ACTOR, CONTEXT), 'updateStatus']
    ])(
      'refuses %s with insufficient-role and changes and reports nothing',
      async (_name, run, write) => {
        const harness = build()
        harness.workspaces.findById.mockResolvedValue(pending)
        harness.workspaces[write as 'rename' | 'updateStatus'].mockResolvedValue('actor_changed')

        await expect(code(run(harness))).resolves.toBe(AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE)
        expect(harness.access.invalidateWorkspace).not.toHaveBeenCalled()
        expect(harness.events.emit).not.toHaveBeenCalled()
      }
    )

    it('does not send an actor with the write of a finalized deletion, which no member made', async () => {
      const { service, workspaces } = build()
      workspaces.findById.mockResolvedValue(pending)

      await service.finalizeDeletion(WORKSPACE_REF)

      const sent = workspaces.updateStatus.mock.calls[0]?.[0] as Record<string, unknown>
      expect(Object.keys(sent)).not.toContain('actor')
    })
  })

  describe('scheduleDeletion', () => {
    it('moves an active workspace to pending deletion for the grace period', async () => {
      const { service, workspaces } = build()
      const due = new Date(NOW.getTime() + 14 * DAY)

      const scheduled = await service.scheduleDeletion(WORKSPACE_REF, ACTOR, CONTEXT)

      expect(scheduled).toEqual({ status: 'pending_deletion', deletionScheduledAt: due })
      expect(workspaces.updateStatus).toHaveBeenCalledWith({
        ...WORKSPACE_REF,
        status: 'pending_deletion',
        expectedStatus: 'active',
        deletionScheduledAt: due,
        actor: JUDGED,
        audit: {
          type: 'workspace.deletion_scheduled',
          ...WORKSPACE_REF,
          actorUserId: 'u1',
          at: NOW.toISOString()
        }
      })
    })

    it("ends every member's access before it reports the event", async () => {
      const { service, access, events } = build()

      await service.scheduleDeletion(WORKSPACE_REF, ACTOR, CONTEXT)

      expect(access.invalidateWorkspace).toHaveBeenCalledWith(WORKSPACE_REF)
      expect(access.invalidateWorkspace.mock.invocationCallOrder[0]).toBeLessThan(
        events.emit.mock.invocationCallOrder[0] ?? 0
      )
    })

    it('deletes at once when the grace period is zero', async () => {
      const { service, workspaces, events } = build({ deletionGraceDays: 0 })

      const scheduled = await service.scheduleDeletion(WORKSPACE_REF, ACTOR, CONTEXT)

      expect(scheduled).toEqual({ status: 'deleted', deletionScheduledAt: null })
      expect(workspaces.updateStatus).toHaveBeenCalledWith(
        expect.objectContaining({
          status: 'deleted',
          expectedStatus: 'active',
          deletionScheduledAt: null
        })
      )
      expect(events.emit).toHaveBeenCalledWith(
        expect.objectContaining({ type: 'workspace.deleted', actorUserId: 'u1' }),
        CONTEXT
      )
    })

    it('answers workspace-not-found, without bumping or reporting', async () => {
      const { service, workspaces, access, events } = build()
      workspaces.updateStatus.mockResolvedValue('not_found')

      await expect(code(service.scheduleDeletion(WORKSPACE_REF, ACTOR, CONTEXT))).resolves.toBe(
        AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND
      )
      expect(access.invalidateWorkspace).not.toHaveBeenCalled()
      expect(events.emit).not.toHaveBeenCalled()
    })

    it.each([
      ['pending_deletion', AUTH_ERROR_CODES.WORKSPACE_PENDING_DELETION],
      ['deleted', AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND]
    ] as const)('answers a lost race against a %p workspace with %s', async (status, expected) => {
      const { service, workspaces, access } = build()
      workspaces.updateStatus.mockResolvedValue('status_conflict')
      workspaces.findById.mockResolvedValue(workspaceRow({ status }))

      await expect(code(service.scheduleDeletion(WORKSPACE_REF, ACTOR, CONTEXT))).resolves.toBe(
        expected
      )
      expect(workspaces.findById).toHaveBeenCalledWith(WORKSPACE_REF)
      expect(access.invalidateWorkspace).not.toHaveBeenCalled()
    })

    it('answers workspace-not-found when the lost race left no workspace', async () => {
      const { service, workspaces } = build()
      workspaces.updateStatus.mockResolvedValue('status_conflict')
      workspaces.findById.mockResolvedValue(null)

      await expect(code(service.scheduleDeletion(WORKSPACE_REF, ACTOR, CONTEXT))).resolves.toBe(
        AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND
      )
    })

    it('fails, and reports nothing, when the access bump fails', async () => {
      const { service, access, events } = build()
      access.invalidateWorkspace.mockRejectedValue(new Error('redis down'))

      await expect(service.scheduleDeletion(WORKSPACE_REF, ACTOR, CONTEXT)).rejects.toThrow(
        'redis down'
      )
      expect(events.emit).not.toHaveBeenCalled()
    })
  })

  describe('restore', () => {
    const pending = (due: Date | null) =>
      workspaceRow({ status: 'pending_deletion', deletionScheduledAt: due })

    it('returns a pending workspace to active within the grace period', async () => {
      const { service, workspaces, access, events } = build()
      workspaces.findById.mockResolvedValue(pending(new Date(NOW.getTime() + DAY)))

      await service.restore(WORKSPACE_REF, ACTOR, CONTEXT)

      const audit = {
        type: 'workspace.restored',
        ...WORKSPACE_REF,
        actorUserId: 'u1',
        at: NOW.toISOString()
      }
      expect(workspaces.updateStatus).toHaveBeenCalledWith({
        ...WORKSPACE_REF,
        status: 'active',
        expectedStatus: 'pending_deletion',
        deletionScheduledAt: null,
        actor: JUDGED,
        audit
      })
      expect(access.invalidateWorkspace).toHaveBeenCalledWith(WORKSPACE_REF)
      expect(events.emit).toHaveBeenCalledWith(audit, CONTEXT)
    })

    it('accepts a pending workspace that records no deadline', async () => {
      const { service, workspaces } = build()
      workspaces.findById.mockResolvedValue(pending(null))

      await expect(code(service.restore(WORKSPACE_REF, ACTOR, CONTEXT))).resolves.toBe('ok')
    })

    it.each([
      ['a missing workspace', null],
      ['an active workspace', workspaceRow()],
      ['a workspace whose grace period has just ended', pending(NOW)],
      ['a workspace whose grace period ended earlier', pending(new Date(NOW.getTime() - DAY))]
    ])('refuses %s', async (_name, row) => {
      const { service, workspaces } = build()
      workspaces.findById.mockResolvedValue(row)

      await expect(code(service.restore(WORKSPACE_REF, ACTOR, CONTEXT))).resolves.toBe(
        AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND
      )
      expect(workspaces.updateStatus).not.toHaveBeenCalled()
    })

    it('maps a refused write to an error and does not report it', async () => {
      const { service, workspaces, events } = build()
      workspaces.findById.mockResolvedValue(pending(null))
      workspaces.updateStatus.mockResolvedValue('not_found')

      await expect(code(service.restore(WORKSPACE_REF, ACTOR, CONTEXT))).resolves.toBe(
        AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND
      )
      expect(events.emit).not.toHaveBeenCalled()
    })
  })

  describe('finalizeDeletion', () => {
    const pending = (due: Date | null) =>
      workspaceRow({ status: 'pending_deletion', deletionScheduledAt: due })

    it.each([
      ['a missing workspace', null, 'not_found'],
      ['an active workspace', workspaceRow(), 'not_pending'],
      [
        'a workspace whose grace period is not over',
        pending(new Date(NOW.getTime() + 1)),
        'not_due'
      ]
    ] as const)('changes nothing for %s', async (_name, row, expected) => {
      const { service, workspaces } = build()
      workspaces.findById.mockResolvedValue(row)

      await expect(service.finalizeDeletion(WORKSPACE_REF)).resolves.toBe(expected)
      expect(workspaces.updateStatus).not.toHaveBeenCalled()
    })

    it.each([pending(NOW), pending(null)])('finalizes %#', async (row) => {
      const { service, workspaces, access } = build()
      workspaces.findById.mockResolvedValue(row)

      await expect(service.finalizeDeletion(WORKSPACE_REF)).resolves.toBe('deleted')
      expect(workspaces.updateStatus).toHaveBeenCalledWith({
        ...WORKSPACE_REF,
        status: 'deleted',
        expectedStatus: 'pending_deletion',
        expectedDeletionScheduledAt: row.deletionScheduledAt,
        deletionScheduledAt: null,
        audit: {
          type: 'workspace.deleted',
          ...WORKSPACE_REF,
          actorUserId: null,
          at: NOW.toISOString()
        }
      })
      expect(access.invalidateWorkspace).toHaveBeenCalledWith(WORKSPACE_REF)
    })

    it.each([
      ['no longer exists', null, 'not_found'],
      ['was restored', workspaceRow(), 'not_pending'],
      ['was scheduled again', pending(new Date(NOW.getTime() + 86_400_000)), 'not_due'],
      ['is due again under another schedule', pending(NOW), 'not_due']
    ] as const)(
      'writes and reports nothing when the workspace %s after it was read',
      async (_name, current, expected) => {
        const { service, workspaces, access, events } = build()
        workspaces.findById.mockResolvedValueOnce(pending(NOW)).mockResolvedValueOnce(current)
        workspaces.updateStatus.mockResolvedValue('status_conflict')

        await expect(service.finalizeDeletion(WORKSPACE_REF)).resolves.toBe(expected)
        expect(workspaces.findById).toHaveBeenCalledTimes(2)
        expect(access.invalidateWorkspace).not.toHaveBeenCalled()
        expect(events.emit).not.toHaveBeenCalled()
      }
    )

    it('reports with the context it was given, or a minimal one for a job', async () => {
      const first = build()
      first.workspaces.findById.mockResolvedValue(pending(null))
      const second = build()
      second.workspaces.findById.mockResolvedValue(pending(null))

      await first.service.finalizeDeletion(WORKSPACE_REF, CONTEXT)
      await second.service.finalizeDeletion(WORKSPACE_REF)

      expect(first.events.emit).toHaveBeenCalledWith(expect.anything(), CONTEXT)
      expect(second.events.emit).toHaveBeenCalledWith(expect.anything(), {
        plane: 'dashboard',
        tenantId: 't1',
        ip: '',
        userAgent: '',
        sanitizedHeaders: {}
      })
    })
  })

  describe('switchTo', () => {
    const member = { ...WORKSPACE_REF, userId: 'u1', role: 'editor' }

    it('records the workspace as last used and reports the switch', async () => {
      const { service, access, memberships, events } = build()
      access.resolveMembership.mockResolvedValue(member)

      await expect(service.switchTo(WORKSPACE_REF, 'u1', CONTEXT)).resolves.toBe(member)

      expect(access.resolveMembership).toHaveBeenCalledWith({ ...WORKSPACE_REF, userId: 'u1' })
      expect(memberships.setLastActiveWorkspaceId).toHaveBeenCalledWith({
        tenantId: 't1',
        userId: 'u1',
        workspaceId: 'w1'
      })
      expect(events.emit).toHaveBeenCalledWith(
        {
          type: 'workspace.switched',
          ...WORKSPACE_REF,
          actorUserId: 'u1',
          userId: 'u1',
          at: NOW.toISOString()
        },
        CONTEXT
      )
    })

    it('works when the host keeps no last-used preference', async () => {
      const { service, access } = build({}, false, false)
      access.resolveMembership.mockResolvedValue(member)

      await expect(service.switchTo(WORKSPACE_REF, 'u1', CONTEXT)).resolves.toBe(member)
    })

    it('answers workspace-not-found for a caller who is not an active member', async () => {
      const { service, access, memberships, events } = build()
      access.resolveMembership.mockResolvedValue(null)

      await expect(code(service.switchTo(WORKSPACE_REF, 'u1', CONTEXT))).resolves.toBe(
        AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND
      )
      expect(memberships.setLastActiveWorkspaceId).not.toHaveBeenCalled()
      expect(events.emit).not.toHaveBeenCalled()
    })
  })

  describe('getAccess', () => {
    it("returns the workspace and the caller's role", async () => {
      const { service, access, workspaces } = build()
      const row = workspaceRow()
      access.resolveMembership.mockResolvedValue({ ...WORKSPACE_REF, userId: 'u1', role: 'viewer' })
      workspaces.findById.mockResolvedValue(row)

      await expect(service.getAccess(WORKSPACE_REF, 'u1')).resolves.toEqual({
        workspace: row,
        role: 'viewer'
      })
    })

    it('answers workspace-not-found for a non-member without reading the workspace', async () => {
      const { service, access, workspaces } = build()
      access.resolveMembership.mockResolvedValue(null)

      await expect(code(service.getAccess(WORKSPACE_REF, 'u1'))).resolves.toBe(
        AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND
      )
      expect(workspaces.findById).not.toHaveBeenCalled()
    })

    it('answers workspace-not-found when the workspace row is gone', async () => {
      const { service, access, workspaces } = build()
      access.resolveMembership.mockResolvedValue({ ...WORKSPACE_REF, userId: 'u1', role: 'viewer' })
      workspaces.findById.mockResolvedValue(null)

      await expect(code(service.getAccess(WORKSPACE_REF, 'u1'))).resolves.toBe(
        AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND
      )
    })
  })
})
