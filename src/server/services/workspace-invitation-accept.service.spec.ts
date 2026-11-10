/**
 * @fileoverview Tests for `WorkspaceInvitationAcceptService`: what is decided before the token is
 * spent, that the membership is written before it is, and what an acceptance answers.
 *
 * @layer Test
 */

import { Logger } from '@nestjs/common'

import {
  CALLER,
  EMAIL,
  NOW,
  TOKEN,
  build,
  code,
  member,
  memberRecord,
  seed,
  user
} from './__tests__/workspace-invitation-accept-harness'
import type { Harness } from './__tests__/workspace-invitation-accept-harness'
import {
  CONTEXT,
  WORKSPACE_REF,
  optionsWithoutWorkspaces,
  workspaceRow
} from './__tests__/workspace-service-harness'
import type { MembershipService } from './membership.service'
import type { PasswordService } from './password.service'
import type { SessionService } from './session.service'
import type { TokenManagerService } from './token-manager.service'
import type { WorkspaceAccessService } from './workspace-access.service'
import type { WorkspaceEventsService } from './workspace-events.service'
import { WorkspaceInvitationAcceptService } from './workspace-invitation-accept.service'
import type { IAuthHooks } from '../interfaces/auth-hooks.interface'
import type { IMembershipRepository } from '../interfaces/membership-repository.interface'
import type { IUserRepository } from '../interfaces/user-repository.interface'
import type { IWorkspaceRepository } from '../interfaces/workspace-repository.interface'
import { invitationKey } from '../constants/workspace-invitation-keys'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import type { AuthMembership } from '../interfaces/membership-repository.interface'

describe('WorkspaceInvitationAcceptService', () => {
  beforeEach(() => {
    jest.spyOn(Date, 'now').mockReturnValue(NOW)
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  describe('accept', () => {
    it('writes the membership, spends the token, tells the cache and the hook, and answers where it joined', async () => {
      const h = build()
      await seed(h)

      const answer = await h.service.accept(CALLER, TOKEN, CONTEXT)

      expect(answer).toEqual({ workspaceId: 'w1', role: 'viewer' })
      expect(h.memberships.create).toHaveBeenCalledWith({
        ...WORKSPACE_REF,
        userId: 'caller',
        role: 'viewer',
        invitedByUserId: 'inviter',
        audit: {
          type: 'invitation.accepted',
          ...WORKSPACE_REF,
          actorUserId: 'caller',
          email: EMAIL,
          role: 'viewer',
          userId: 'caller',
          at: new Date(NOW).toISOString()
        }
      })
      expect(await h.store.readByHash(invitationKey(TOKEN).slice(5))).toBeNull()
      expect(await h.store.readByEmail(WORKSPACE_REF, EMAIL)).toBeNull()
      expect(await h.store.pending(WORKSPACE_REF)).toEqual([])
      expect(h.access.invalidateMembership).toHaveBeenCalledWith({
        ...WORKSPACE_REF,
        userId: 'caller'
      })
      expect(h.events.emit).toHaveBeenCalledWith(
        {
          type: 'invitation.accepted',
          ...WORKSPACE_REF,
          actorUserId: 'caller',
          email: EMAIL,
          role: 'viewer',
          userId: 'caller',
          at: new Date(NOW).toISOString()
        },
        CONTEXT
      )
    })

    /** Asserts that an acceptance was refused with `expected` and left everything as it was. */
    async function expectRefusedUnspent(h: Harness, expected: string): Promise<void> {
      expect(await code(h.service.accept(CALLER, TOKEN, CONTEXT))).toBe(expected)
      expect(h.memberships.create).not.toHaveBeenCalled()
      expect(h.access.invalidateMembership).not.toHaveBeenCalled()
      expect(h.events.emit).not.toHaveBeenCalled()
    }

    it('answers a token that names nothing as invalid', async () => {
      const h = build()

      await expectRefusedUnspent(h, AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN)
    })

    it('answers a record that grants a role outside the hierarchy as invalid', async () => {
      const h = build()
      await seed(h, memberRecord({ role: 'ghost' }))

      await expectRefusedUnspent(h, AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN)
    })

    it('answers a caller in another tenant as invalid, not as a mismatch', async () => {
      const h = build()
      await seed(h)
      h.users.findById.mockResolvedValueOnce(user('caller', { email: EMAIL, tenantId: 't2' }))

      await expectRefusedUnspent(h, AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN)
    })

    it('answers a caller who no longer exists as an invalid token of their own', async () => {
      const h = build()
      await seed(h)
      h.users.findById.mockResolvedValueOnce(null)

      await expectRefusedUnspent(h, AUTH_ERROR_CODES.TOKEN_INVALID)
    })

    it('answers an address that is not the invited one as a mismatch and leaves the token usable', async () => {
      const h = build()
      await seed(h)
      h.users.findById.mockResolvedValueOnce(user('caller', { email: 'other@example.com' }))

      await expectRefusedUnspent(h, AUTH_ERROR_CODES.INVITATION_EMAIL_MISMATCH)

      expect(
        await h.store.readByHash(TOKEN.length ? invitationKey(TOKEN).slice(5) : '')
      ).not.toBeNull()
    })

    it('answers the invited address, unverified, as unverified and leaves the token usable', async () => {
      const h = build()
      await seed(h)
      h.users.findById.mockResolvedValueOnce(user('caller', { email: EMAIL, emailVerified: false }))

      await expectRefusedUnspent(h, AUTH_ERROR_CODES.EMAIL_NOT_VERIFIED)

      expect(await h.store.readByEmail(WORKSPACE_REF, EMAIL)).not.toBeNull()
    })

    it('compares addresses without regard to case', async () => {
      const h = build()
      await seed(h)
      h.users.findById.mockResolvedValueOnce(user('caller', { email: 'Invitee@Example.COM' }))

      expect(await h.service.accept(CALLER, TOKEN, CONTEXT)).toEqual({
        workspaceId: 'w1',
        role: 'viewer'
      })
    })

    it.each([
      ['the inviter is gone', () => null],
      ['the inviter is blocked', () => user('inviter', { status: 'BANNED' })],
      ['the inviter is in another tenant', () => user('inviter', { tenantId: 't2' })]
    ])('answers an invitation whose %s as invalid', async (_name, inviter) => {
      const h = build()
      await seed(h)
      h.users.findById.mockImplementation(async ({ id }: { id: string }) =>
        id === 'caller' ? user('caller', { email: EMAIL }) : inviter()
      )

      await expectRefusedUnspent(h, AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN)
    })

    it('logs, without naming anyone, that the inviter can no longer grant the role', async () => {
      const h = build()
      await seed(h)
      h.memberships.find.mockResolvedValue(null)
      const warn = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      await code(h.service.accept(CALLER, TOKEN, CONTEXT))

      expect(warn).toHaveBeenCalledWith(
        'workspace invitation: the inviter can no longer grant the invited role'
      )
    })

    it.each([
      ['no longer a member', null],
      [
        'no longer an active member',
        member('inviter', 'editor', 'suspended' as AuthMembership['status'])
      ],
      ['no longer above the role granted', member('inviter', 'viewer')]
    ])('answers an invitation whose inviter is %s as invalid', async (_name, found) => {
      const h = build()
      await seed(h)
      h.memberships.find.mockResolvedValue(found)

      await expectRefusedUnspent(h, AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN)
    })

    it('accepts an invitation from an owner to any role, the owner role included', async () => {
      const h = build()
      await seed(h, memberRecord({ role: 'owner' }))
      h.memberships.find.mockImplementation(async ({ userId }: { userId: string }) =>
        userId === 'inviter' ? member('inviter', 'owner') : null
      )

      expect(await h.service.accept(CALLER, TOKEN, CONTEXT)).toEqual({
        workspaceId: 'w1',
        role: 'owner'
      })
    })

    it.each([[null], [workspaceRow({ status: 'pending_deletion' })]])(
      'answers a workspace that is gone or not active as invalid',
      async (found) => {
        const h = build()
        await seed(h)
        h.workspaces.findById.mockResolvedValue(found)

        await expectRefusedUnspent(h, AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN)
      }
    )

    it('answers a workspace the repository reports as missing at the write as invalid, token unspent', async () => {
      const h = build()
      await seed(h)
      h.memberships.create.mockResolvedValue('workspace_not_found')
      h.memberships.find.mockImplementation(async ({ userId }: { userId: string }) =>
        userId === 'inviter' ? member('inviter', 'editor') : member('caller', 'viewer')
      )

      expect(await code(h.service.accept(CALLER, TOKEN, CONTEXT))).toBe(
        AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN
      )

      expect(await h.store.readByEmail(WORKSPACE_REF, EMAIL)).not.toBeNull()
      expect(h.events.emit).not.toHaveBeenCalled()
    })

    it('answers the role the caller already holds when they were a member before, and still spends the token', async () => {
      const h = build()
      await seed(h, memberRecord({ role: 'editor' }))
      h.memberships.create.mockResolvedValue('already_member')
      h.memberships.find.mockImplementation(async ({ userId }: { userId: string }) =>
        userId === 'inviter' ? member('inviter', 'owner') : member('caller', 'viewer')
      )

      const answer = await h.service.accept(CALLER, TOKEN, CONTEXT)

      expect(answer).toEqual({ workspaceId: 'w1', role: 'viewer' })
      expect(await h.store.readByEmail(WORKSPACE_REF, EMAIL)).toBeNull()
      expect(h.events.emit).toHaveBeenCalledWith(
        expect.objectContaining({ role: 'viewer' }),
        CONTEXT
      )
    })

    it('answers an existing member who has vanished by the time of the read as invalid', async () => {
      const h = build()
      await seed(h)
      h.memberships.create.mockResolvedValue('already_member')

      expect(await code(h.service.accept(CALLER, TOKEN, CONTEXT))).toBe(
        AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN
      )
    })

    it('lets a revoke that lands between the write and the spend change nothing, and says so', async () => {
      const h = build()
      await seed(h)
      h.memberships.create.mockImplementation(async () => {
        await h.store.remove(WORKSPACE_REF, EMAIL, invitationKey(TOKEN))
        return 'ok'
      })

      const answer = await h.service.accept(CALLER, TOKEN, CONTEXT)

      expect(answer).toEqual({ workspaceId: 'w1', role: 'viewer' })
      expect(h.access.invalidateMembership).toHaveBeenCalled()
      expect(h.events.emit).toHaveBeenCalledWith(
        expect.objectContaining({ type: 'invitation.accepted', lostConsumeRace: true }),
        CONTEXT
      )
    })

    it('leaves a newer token for the address alone when the one accepted had already been replaced', async () => {
      const h = build()
      await seed(h)
      h.memberships.create.mockImplementation(async () => {
        const newer = invitationKey('b'.repeat(64))
        await h.store.publish(
          WORKSPACE_REF,
          EMAIL,
          newer,
          memberRecord({ resendCount: 1 }),
          604_800,
          0,
          invitationKey(TOKEN)
        )
        return 'ok'
      })

      await h.service.accept(CALLER, TOKEN, CONTEXT)

      expect((await h.store.readByEmail(WORKSPACE_REF, EMAIL))?.key).toBe(
        invitationKey('b'.repeat(64))
      )
    })

    it('does not mark the hook event when the spend went as expected', async () => {
      const h = build()
      await seed(h)

      await h.service.accept(CALLER, TOKEN, CONTEXT)

      const event = h.events.emit.mock.calls[0]?.[0] as Record<string, unknown>
      expect(Object.keys(event)).not.toContain('lostConsumeRace')
    })
  })

  describe('construction', () => {
    it('refuses to boot without the workspace group', () => {
      const h = build()
      const make = (): WorkspaceInvitationAcceptService =>
        new WorkspaceInvitationAcceptService(
          h.store,
          {} as MembershipService,
          h.access as Partial<WorkspaceAccessService> as WorkspaceAccessService,
          h.events as Partial<WorkspaceEventsService> as WorkspaceEventsService,
          h.passwords as Partial<PasswordService> as PasswordService,
          h.tokens as Partial<TokenManagerService> as TokenManagerService,
          h.sessions as Partial<SessionService> as SessionService,
          h.users as Partial<IUserRepository> as IUserRepository,
          h.workspaces as Partial<IWorkspaceRepository> as IWorkspaceRepository,
          h.memberships as Partial<IMembershipRepository> as IMembershipRepository,
          h.hooks as Partial<IAuthHooks> as IAuthHooks,
          optionsWithoutWorkspaces()
        )

      expect(make).toThrow(
        '[BymaxAuthModule] WorkspaceInvitationAcceptService needs workspaces.enabled.'
      )
    })
  })
})
