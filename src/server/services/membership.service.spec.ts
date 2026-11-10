/**
 * @fileoverview Tests for the membership service: listings, role changes, removal, leaving and
 * ownership transfer, with the role ceiling on every action and the cache bump on every write.
 *
 * @layer Test
 */

import {
  DEMOTE_MESSAGE,
  EDITOR,
  OWNER,
  build,
  code,
  detailsOf,
  member
} from './__tests__/membership-service-harness'
import {
  CONTEXT,
  NOW,
  WORKSPACE_REF,
  optionsWithoutWorkspaces,
  workspaceRow
} from './__tests__/workspace-service-harness'
import { MembershipService } from './membership.service'
import type { WorkspaceAccessService } from './workspace-access.service'
import type { WorkspaceEventsService } from './workspace-events.service'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import type {
  AuthMembership,
  IMembershipRepository
} from '../interfaces/membership-repository.interface'

describe('MembershipService', () => {
  beforeEach(() => {
    jest.useFakeTimers().setSystemTime(NOW)
  })

  afterEach(() => {
    jest.useRealTimers()
  })

  it('refuses to exist without the workspace group', () => {
    expect(
      () =>
        new MembershipService(
          {} as IMembershipRepository,
          {} as WorkspaceAccessService,
          {} as WorkspaceEventsService,
          optionsWithoutWorkspaces()
        )
    ).toThrow('[BymaxAuthModule] MembershipService needs workspaces.enabled.')
  })

  describe('listings', () => {
    it("lists only the caller's memberships, with the last-used workspace", async () => {
      const { service, memberships } = build()

      const page = await service.listMine('t1', 'u1', { cursor: 'c', limit: 5 })

      expect(memberships['listForUser']).toHaveBeenCalledWith({
        tenantId: 't1',
        userId: 'u1',
        cursor: 'c',
        limit: 5
      })
      expect(memberships['getLastActiveWorkspaceId']).toHaveBeenCalledWith({
        tenantId: 't1',
        userId: 'u1'
      })
      expect(page).toEqual({ items: [], nextCursor: null, lastActiveWorkspaceId: 'w9' })
    })

    it('reports no last-used workspace when the host keeps none', async () => {
      const { service } = build(false)

      await expect(service.listMine('t1', 'u1')).resolves.toMatchObject({
        lastActiveWorkspaceId: null
      })
    })

    it('reports none when the host has recorded none', async () => {
      const { service, memberships } = build()
      memberships['getLastActiveWorkspaceId']?.mockResolvedValue(null)

      await expect(service.listMine('t1', 'u1')).resolves.toMatchObject({
        lastActiveWorkspaceId: null
      })
    })

    it.each([
      [undefined, 50],
      [0, 1],
      [-5, 1],
      [50, 50],
      [100, 100],
      [101, 100],
      [2.5, 50]
    ])('turns a requested size of %p into %p', async (asked, used) => {
      const { service, memberships } = build()

      await service.listMembers(WORKSPACE_REF, asked === undefined ? {} : { limit: asked })

      expect(memberships['listForWorkspace']).toHaveBeenCalledWith({
        ...WORKSPACE_REF,
        limit: used
      })
    })

    it('passes the cursor of a member listing through, and omits it when absent', async () => {
      const { service, memberships } = build()

      await service.listMembers(WORKSPACE_REF, { cursor: 'next' })
      await service.listMembers(WORKSPACE_REF)

      expect(memberships['listForWorkspace']?.mock.calls).toEqual([
        [{ ...WORKSPACE_REF, cursor: 'next', limit: 50 }],
        [{ ...WORKSPACE_REF, limit: 50 }]
      ])
    })

    // `cursor: undefined` and no `cursor` are different calls to a port written for
    // exactOptionalPropertyTypes, and an equality matcher cannot tell them apart.
    it('leaves the cursor key out of every listing call when none was given', async () => {
      const { service, memberships } = build()

      await service.listMine('t1', 'u1')
      await service.listMembers(WORKSPACE_REF)
      await service.listSoleOwnedWorkspaces('t1', 'u1')

      for (const name of ['listForUser', 'listForWorkspace', 'listSoleOwned']) {
        const sent = memberships[name]?.mock.calls[0]?.[0] as Record<string, unknown>
        expect(Object.keys(sent)).not.toContain('cursor')
      }
    })

    it('lists the workspaces a member alone owns, by the owner role', async () => {
      const { service, memberships } = build()
      const page = { items: [workspaceRow()], nextCursor: null }
      memberships['listSoleOwned']?.mockResolvedValue(page)

      await expect(
        service.listSoleOwnedWorkspaces('t1', 'u1', { cursor: 'c', limit: 7 })
      ).resolves.toBe(page)

      expect(memberships['listSoleOwned']).toHaveBeenCalledWith({
        tenantId: 't1',
        userId: 'u1',
        ownerRole: 'owner',
        cursor: 'c',
        limit: 7
      })
    })

    it('omits the cursor of the sole-owned listing when there is none', async () => {
      const { service, memberships } = build()

      await service.listSoleOwnedWorkspaces('t1', 'u1')

      expect(memberships['listSoleOwned']).toHaveBeenCalledWith({
        tenantId: 't1',
        userId: 'u1',
        ownerRole: 'owner',
        limit: 50
      })
    })
  })

  describe('changeRole', () => {
    it("writes the change with its audit event, ends the member's cached access, then reports it", async () => {
      const { service, memberships, access, events } = build()
      memberships['find']?.mockResolvedValue(member('u2', 'viewer'))

      await service.changeRole(WORKSPACE_REF, 'u2', 'editor', OWNER, CONTEXT)

      const audit = {
        type: 'member.role_changed',
        ...WORKSPACE_REF,
        actorUserId: 'owner-1',
        userId: 'u2',
        from: 'viewer',
        to: 'editor',
        at: NOW.toISOString()
      }
      expect(memberships['find']).toHaveBeenCalledWith({ ...WORKSPACE_REF, userId: 'u2' })
      expect(memberships['changeRole']).toHaveBeenCalledWith({
        ...WORKSPACE_REF,
        userId: 'u2',
        role: 'editor',
        expectedRole: 'viewer',
        actor: { userId: 'owner-1', expectedRole: 'owner' },
        ownerRole: 'owner',
        audit
      })
      expect(access.invalidateMembership).toHaveBeenCalledWith({ ...WORKSPACE_REF, userId: 'u2' })
      expect(events.emit).toHaveBeenCalledWith(audit, CONTEXT)
      expect(access.invalidateMembership.mock.invocationCallOrder[0]).toBeLessThan(
        events.emit.mock.invocationCallOrder[0] ?? 0
      )
    })

    it('writes and reports nothing for a member who already holds the role, but ends their cached access', async () => {
      const { service, memberships, access, events } = build()
      memberships['find']?.mockResolvedValue(member('u2', 'editor'))

      await service.changeRole(WORKSPACE_REF, 'u2', 'editor', OWNER, CONTEXT)

      expect(memberships['changeRole']).not.toHaveBeenCalled()
      expect(events.emit).not.toHaveBeenCalled()
      expect(access.invalidateMembership).toHaveBeenCalledWith({ ...WORKSPACE_REF, userId: 'u2' })
    })

    // The first attempt wrote the role and its bump failed; the retry finds the role already set.
    it('repairs the cached access when a retry follows a failed bump', async () => {
      const { service, memberships, access } = build()
      memberships['find']
        ?.mockResolvedValueOnce(member('u2', 'editor'))
        .mockResolvedValueOnce(member('u2', 'viewer'))
      access.invalidateMembership.mockRejectedValueOnce(new Error('redis down'))

      await expect(
        service.changeRole(WORKSPACE_REF, 'u2', 'viewer', OWNER, CONTEXT)
      ).rejects.toThrow('redis down')
      await expect(
        service.changeRole(WORKSPACE_REF, 'u2', 'viewer', OWNER, CONTEXT)
      ).resolves.toBeUndefined()

      expect(access.invalidateMembership.mock.calls).toEqual([
        [{ ...WORKSPACE_REF, userId: 'u2' }],
        [{ ...WORKSPACE_REF, userId: 'u2' }]
      ])
    })

    it('names the role field when the role is outside the hierarchy', async () => {
      const { service } = build()

      await expect(
        detailsOf(service.changeRole(WORKSPACE_REF, 'u2', 'admin', OWNER, CONTEXT))
      ).resolves.toEqual([{ field: 'role', message: 'role must be one of the workspace roles' }])
    })

    it('refuses a role outside the hierarchy, even an inherited property name', async () => {
      const { service, memberships } = build()

      await expect(
        code(service.changeRole(WORKSPACE_REF, 'u2', 'admin', OWNER, CONTEXT))
      ).resolves.toBe(AUTH_ERROR_CODES.VALIDATION)
      await expect(
        code(service.changeRole(WORKSPACE_REF, 'u2', 'constructor', OWNER, CONTEXT))
      ).resolves.toBe(AUTH_ERROR_CODES.VALIDATION)
      expect(memberships['find']).not.toHaveBeenCalled()
    })

    it("refuses to grant a role above the actor's own", async () => {
      const { service, memberships } = build()

      await expect(
        code(service.changeRole(WORKSPACE_REF, 'u2', 'owner', EDITOR, CONTEXT))
      ).resolves.toBe(AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE)
      expect(memberships['find']).not.toHaveBeenCalled()
    })

    it("refuses to change a member who holds a role above the actor's", async () => {
      const { service, memberships } = build()
      memberships['find']?.mockResolvedValue(member('u2', 'owner'))

      await expect(
        code(service.changeRole(WORKSPACE_REF, 'u2', 'viewer', EDITOR, CONTEXT))
      ).resolves.toBe(AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE)
      expect(memberships['changeRole']).not.toHaveBeenCalled()
    })

    it.each([null, member('u2', 'viewer', 'suspended')])(
      'refuses a member who is not active (%#)',
      async (row) => {
        const { service, memberships } = build()
        memberships['find']?.mockResolvedValue(row)

        await expect(
          code(service.changeRole(WORKSPACE_REF, 'u2', 'editor', OWNER, CONTEXT))
        ).resolves.toBe(AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND)
      }
    )

    it.each([
      ['last_owner', AUTH_ERROR_CODES.LAST_OWNER],
      ['not_found', AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND]
    ])('maps a %s refusal to %s, without bumping or reporting', async (result, expected) => {
      const { service, memberships, access, events } = build()
      memberships['find']?.mockResolvedValue(member('u2', 'owner'))
      memberships['changeRole']?.mockResolvedValue(result)

      await expect(
        code(service.changeRole(WORKSPACE_REF, 'u2', 'editor', OWNER, CONTEXT))
      ).resolves.toBe(expected)
      expect(access.invalidateMembership).not.toHaveBeenCalled()
      expect(events.emit).not.toHaveBeenCalled()
    })

    it('fails, and reports nothing, when the bump fails', async () => {
      const { service, memberships, access, events } = build()
      memberships['find']?.mockResolvedValue(member('u2', 'viewer'))
      access.invalidateMembership.mockRejectedValue(new Error('redis down'))

      await expect(
        service.changeRole(WORKSPACE_REF, 'u2', 'editor', OWNER, CONTEXT)
      ).rejects.toThrow('redis down')
      expect(events.emit).not.toHaveBeenCalled()
    })
  })

  describe('remove', () => {
    it('removes the member with an audit event naming the actor, then ends their access', async () => {
      const { service, memberships, access, events } = build()
      memberships['find']?.mockResolvedValue(member('u2', 'viewer'))

      await service.remove(WORKSPACE_REF, 'u2', EDITOR, CONTEXT)

      const audit = {
        type: 'member.removed',
        ...WORKSPACE_REF,
        actorUserId: 'editor-1',
        userId: 'u2',
        at: NOW.toISOString()
      }
      expect(memberships['remove']).toHaveBeenCalledWith({
        ...WORKSPACE_REF,
        userId: 'u2',
        expectedRole: 'viewer',
        actor: { userId: 'editor-1', expectedRole: 'editor' },
        ownerRole: 'owner',
        audit
      })
      expect(access.invalidateMembership).toHaveBeenCalledWith({ ...WORKSPACE_REF, userId: 'u2' })
      expect(events.emit).toHaveBeenCalledWith(audit, CONTEXT)
    })

    it("refuses to remove a member above the actor's role, or one who is not active", async () => {
      const { service, memberships } = build()
      memberships['find']?.mockResolvedValueOnce(member('u2', 'owner')).mockResolvedValueOnce(null)

      await expect(code(service.remove(WORKSPACE_REF, 'u2', EDITOR, CONTEXT))).resolves.toBe(
        AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE
      )
      await expect(code(service.remove(WORKSPACE_REF, 'u3', EDITOR, CONTEXT))).resolves.toBe(
        AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND
      )
      expect(memberships['remove']).not.toHaveBeenCalled()
    })

    it('answers last-owner when the repository refuses to orphan the workspace', async () => {
      const { service, memberships, access } = build()
      memberships['find']?.mockResolvedValue(member('owner-2', 'owner'))
      memberships['remove']?.mockResolvedValue('last_owner')

      await expect(code(service.remove(WORKSPACE_REF, 'owner-2', OWNER, CONTEXT))).resolves.toBe(
        AUTH_ERROR_CODES.LAST_OWNER
      )
      expect(access.invalidateMembership).not.toHaveBeenCalled()
    })
  })

  describe('leave', () => {
    it('removes the caller with a member.left event naming them', async () => {
      const { service, memberships, access, events } = build()

      await service.leave(WORKSPACE_REF, 'u2', CONTEXT)

      const audit = {
        type: 'member.left',
        ...WORKSPACE_REF,
        actorUserId: 'u2',
        userId: 'u2',
        at: NOW.toISOString()
      }
      expect(memberships['remove']).toHaveBeenCalledWith({
        ...WORKSPACE_REF,
        userId: 'u2',
        ownerRole: 'owner',
        audit
      })
      expect(memberships['find']).not.toHaveBeenCalled()
      const sent = memberships['remove']?.mock.calls[0]?.[0] as Record<string, unknown>
      expect(Object.keys(sent)).not.toContain('expectedRole')
      expect(Object.keys(sent)).not.toContain('actor')
      expect(access.invalidateMembership).toHaveBeenCalledWith({ ...WORKSPACE_REF, userId: 'u2' })
      expect(events.emit).toHaveBeenCalledWith(audit, CONTEXT)
    })

    it('tells the last owner to transfer or delete first', async () => {
      const { service, memberships } = build()
      memberships['remove']?.mockResolvedValue('last_owner')

      await expect(code(service.leave(WORKSPACE_REF, 'owner-1', CONTEXT))).resolves.toBe(
        AUTH_ERROR_CODES.LAST_OWNER
      )
    })
  })

  // The roles were read before the write; the repository checks them again in the write's own
  // transaction and these are its answers when either changed in between.
  describe('a role that changed between the read and the write', () => {
    it.each([
      ['changeRole', 'actor_changed', AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE],
      ['changeRole', 'not_found', AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND],
      ['remove', 'actor_changed', AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE],
      ['remove', 'not_found', AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND]
    ])(
      'answers %s with %s as %s and changes and reports nothing',
      async (call, result, expected) => {
        const { service, memberships, access, events } = build()
        memberships['find']?.mockResolvedValue(member('u2', 'viewer'))
        memberships[call]?.mockResolvedValue(result)

        const attempt =
          call === 'changeRole'
            ? service.changeRole(WORKSPACE_REF, 'u2', 'editor', OWNER, CONTEXT)
            : service.remove(WORKSPACE_REF, 'u2', OWNER, CONTEXT)

        await expect(code(attempt)).resolves.toBe(expected)
        expect(access.invalidateMembership).not.toHaveBeenCalled()
        expect(events.emit).not.toHaveBeenCalled()
      }
    )
  })

  // The rule: the owner role acts on any role; every other role acts only STRICTLY below itself.
  // Every pair of roles is listed as a literal, so a change to the rule is a change to this table.
  describe('the role ceiling across every pair of roles', () => {
    const ROLES = ['owner', 'editor', 'viewer'] as const
    const MAY: Record<(typeof ROLES)[number], Record<(typeof ROLES)[number], boolean>> = {
      owner: { owner: true, editor: true, viewer: true },
      editor: { owner: false, editor: false, viewer: true },
      viewer: { owner: false, editor: false, viewer: false }
    }
    const refusal = AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE

    it.each(ROLES.flatMap((actor) => ROLES.map((target) => [actor, target] as const)))(
      'as %s, removing a %s is allowed: %s',
      async (actorRole, targetRole) => {
        const { service, memberships } = build()
        memberships['find']?.mockResolvedValue(member('u2', targetRole))

        const outcome = await code(
          service.remove(WORKSPACE_REF, 'u2', { userId: 'actor-1', role: actorRole }, CONTEXT)
        )

        expect(outcome).toBe(MAY[actorRole][targetRole] ? 'ok' : refusal)
      }
    )

    it.each(
      ROLES.flatMap((actor) =>
        ROLES.flatMap((current) => ROLES.map((next) => [actor, current, next] as const))
      )
    )('as %s, changing a %s to %s', async (actorRole, currentRole, nextRole) => {
      const { service, memberships } = build()
      memberships['find']?.mockResolvedValue(member('u2', currentRole))

      const outcome = await code(
        service.changeRole(
          WORKSPACE_REF,
          'u2',
          nextRole,
          { userId: 'actor-1', role: actorRole },
          CONTEXT
        )
      )

      const allowed = MAY[actorRole][currentRole] && MAY[actorRole][nextRole]
      expect(outcome).toBe(allowed ? 'ok' : refusal)
    })

    it('does not let a non-owner change their own role', async () => {
      const { service, memberships } = build()
      memberships['find']?.mockResolvedValue(member('editor-1', 'editor'))

      await expect(
        code(service.changeRole(WORKSPACE_REF, 'editor-1', 'viewer', EDITOR, CONTEXT))
      ).resolves.toBe(refusal)
      expect(memberships['changeRole']).not.toHaveBeenCalled()
    })
  })

  describe('assertMayTransfer', () => {
    // The local check the transfer route runs before it spends a password check: it must refuse
    // the same requests transferOwnership refuses, and touch nothing.
    it.each([
      [
        'an editor',
        { userId: 'actor-1', role: 'editor' },
        'u2',
        null,
        AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE
      ],
      ['an owner handing it to themselves', OWNER, 'owner-1', null, AUTH_ERROR_CODES.VALIDATION],
      ['an owner keeping the owner role', OWNER, 'u2', 'owner', AUTH_ERROR_CODES.VALIDATION],
      [
        'an owner keeping a role outside the hierarchy',
        OWNER,
        'u2',
        'ghost',
        AUTH_ERROR_CODES.VALIDATION
      ]
    ])('refuses %s', async (_name, actor, to, keeps, expected) => {
      const { service, memberships } = build()

      expect(
        await code(Promise.resolve().then(() => service.assertMayTransfer(actor, to, keeps)))
      ).toBe(expected)
      expect(memberships['transferOwnership']).not.toHaveBeenCalled()
    })

    it.each([null, 'editor'])(
      'accepts an owner handing it to another member, keeping %p',
      (keeps) => {
        const { service } = build()

        expect(() => service.assertMayTransfer(OWNER, 'u2', keeps)).not.toThrow()
      }
    )
  })

  describe('getMember', () => {
    it('reads the member by the full key and answers the membership as it stands', async () => {
      const { service, memberships } = build()
      const found = member('u2', 'editor')
      memberships['find']?.mockResolvedValue(found)

      await expect(service.getMember(WORKSPACE_REF, 'u2')).resolves.toBe(found)
      expect(memberships['find']).toHaveBeenCalledWith({ ...WORKSPACE_REF, userId: 'u2' })
    })

    it('answers workspace-not-found for a member that does not exist', async () => {
      const { service, memberships } = build()
      memberships['find']?.mockResolvedValue(null)

      await expect(code(service.getMember(WORKSPACE_REF, 'u2'))).resolves.toBe(
        AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND
      )
    })
  })

  describe('transferOwnership', () => {
    it.each(['editor', 'viewer'])('refuses a transfer by a %s, before any write', async (role) => {
      const { service, memberships, access, events } = build()
      memberships['find']?.mockResolvedValue(member('u2', 'viewer'))

      await expect(
        code(
          service.transferOwnership(WORKSPACE_REF, { userId: 'actor-1', role }, 'u2', null, CONTEXT)
        )
      ).resolves.toBe(AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE)
      expect(memberships['transferOwnership']).not.toHaveBeenCalled()
      expect(access.invalidateMembership).not.toHaveBeenCalled()
      expect(events.emit).not.toHaveBeenCalled()
    })

    it("hands ownership over atomically, ends both members' access, then reports it", async () => {
      const { service, memberships, access, events } = build()
      memberships['find']?.mockResolvedValue(member('u2', 'viewer'))

      await service.transferOwnership(WORKSPACE_REF, OWNER, 'u2', 'editor', CONTEXT)

      const audit = {
        type: 'ownership.transferred',
        ...WORKSPACE_REF,
        actorUserId: 'owner-1',
        fromUserId: 'owner-1',
        toUserId: 'u2',
        at: NOW.toISOString()
      }
      expect(memberships['transferOwnership']).toHaveBeenCalledWith({
        ...WORKSPACE_REF,
        fromUserId: 'owner-1',
        toUserId: 'u2',
        ownerRole: 'owner',
        demoteFromTo: 'editor',
        audit
      })
      expect(access.invalidateMembership.mock.calls).toEqual([
        [{ ...WORKSPACE_REF, userId: 'owner-1' }],
        [{ ...WORKSPACE_REF, userId: 'u2' }]
      ])
      expect(events.emit).toHaveBeenCalledWith(audit, CONTEXT)
    })

    it('keeps both as owners when no demotion is asked', async () => {
      const { service, memberships } = build()
      memberships['find']?.mockResolvedValue(member('u2', 'viewer'))

      await service.transferOwnership(WORKSPACE_REF, OWNER, 'u2', null, CONTEXT)

      expect(memberships['transferOwnership']).toHaveBeenCalledWith(
        expect.objectContaining({ demoteFromTo: null })
      )
    })

    it.each([
      ['to oneself', 'owner-1', 'owner-1', null, 'userId', 'ownership cannot be handed to oneself'],
      ['to a role outside the hierarchy', 'owner-1', 'u2', 'admin', 'demoteSelfTo', DEMOTE_MESSAGE],
      ['demoting to the owner role', 'owner-1', 'u2', 'owner', 'demoteSelfTo', DEMOTE_MESSAGE],
      [
        'demoting to an inherited property name',
        'owner-1',
        'u2',
        'constructor',
        'demoteSelfTo',
        DEMOTE_MESSAGE
      ]
    ])('refuses a transfer %s', async (_name, from, to, demote, field, message) => {
      const { service, memberships } = build()
      memberships['find']?.mockResolvedValue(member('u2', 'viewer'))

      const result = service.transferOwnership(
        WORKSPACE_REF,
        { userId: from, role: 'owner' },
        to,
        demote,
        CONTEXT
      )

      await expect(result).rejects.toMatchObject({
        response: {
          error: {
            code: AUTH_ERROR_CODES.VALIDATION,
            details: [{ field, message }]
          }
        }
      })
      expect(memberships['transferOwnership']).not.toHaveBeenCalled()
    })

    it('refuses a target who is not an active member, without bumping or reporting', async () => {
      const { service, memberships, access, events } = build()
      memberships['find']?.mockResolvedValue(member('u2', 'viewer'))
      memberships['transferOwnership']?.mockResolvedValue('target_not_member')

      const result = service.transferOwnership(WORKSPACE_REF, OWNER, 'u2', null, CONTEXT)

      await expect(result).rejects.toMatchObject({
        response: {
          error: {
            code: AUTH_ERROR_CODES.VALIDATION,
            details: [{ field: 'userId', message: 'userId must be an active member' }]
          }
        }
      })
      expect(access.invalidateMembership).not.toHaveBeenCalled()
      expect(events.emit).not.toHaveBeenCalled()
    })

    it.each([
      ['not_found', AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND],
      ['last_owner', AUTH_ERROR_CODES.LAST_OWNER]
    ])('maps %s to %s', async (result, expected) => {
      const { service, memberships } = build()
      memberships['find']?.mockResolvedValue(member('u2', 'viewer'))
      memberships['transferOwnership']?.mockResolvedValue(result)

      await expect(
        code(service.transferOwnership(WORKSPACE_REF, OWNER, 'u2', null, CONTEXT))
      ).resolves.toBe(expected)
    })
  })
})
