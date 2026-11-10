/**
 * @fileoverview Tests for `WorkspaceInvitationService`: who may invite to which role, what is
 * stored and mailed, how a second invitation, a resend and a revoke replace one another, and that
 * a preview gives no case of "no such invitation" away.
 *
 * @layer Test
 */

import {
  COOLDOWN_MS,
  EDITOR,
  NOW,
  OWNER,
  build,
  code,
  membership,
  sent,
  user
} from './__tests__/workspace-invitation-harness'
import type { Harness } from './__tests__/workspace-invitation-harness'
import {
  CONTEXT,
  WORKSPACE_REF,
  optionsWithoutWorkspaces,
  workspaceOptions,
  workspaceRow
} from './__tests__/workspace-service-harness'
import { MembershipService } from './membership.service'
import type { WorkspaceEventsService } from './workspace-events.service'
import { WorkspaceInvitationService } from './workspace-invitation.service'
import { invitationKey } from '../constants/workspace-invitation-keys'
import { sha256 } from '../crypto/secure-token'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import type { IEmailProvider } from '../interfaces/email-provider.interface'
import type {
  AuthMembership,
  IMembershipRepository
} from '../interfaces/membership-repository.interface'
import type { IUserRepository } from '../interfaces/user-repository.interface'
import type { IWorkspaceRepository } from '../interfaces/workspace-repository.interface'

describe('WorkspaceInvitationService', () => {
  beforeEach(() => {
    jest.spyOn(Date, 'now').mockReturnValue(NOW)
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  describe('invite', () => {
    it('stores the record under the token digest and mails the token with what the message states', async () => {
      const h = build()
      h.users.findByEmail.mockResolvedValue(user('existing'))

      await h.service.invite(WORKSPACE_REF, OWNER, 'New@Example.com', 'editor', CONTEXT)

      const { to, data } = sent(h)
      expect(to).toBe('new@example.com')
      expect(data).toEqual({
        inviterName: 'Name of owner-1',
        workspaceName: 'Acme',
        role: 'editor',
        inviteToken: expect.stringMatching(/^[0-9a-f]{64}$/),
        expiresAt: new Date(NOW + 604_800_000),
        accountExists: true
      })
      expect(await h.store.readByHash(sha256(data.inviteToken))).toEqual({
        kind: 'member',
        email: 'new@example.com',
        role: 'editor',
        tenantId: 't1',
        workspaceId: 'w1',
        inviterUserId: 'owner-1',
        createdAt: new Date(NOW).toISOString(),
        resendCount: 0
      })
      expect(await h.redis.ttl(invitationKey(data.inviteToken))).toBe(604_800)
    })

    it('states that no account exists when the address has none', async () => {
      const h = build()

      await h.service.invite(WORKSPACE_REF, OWNER, 'a@example.com', 'viewer', CONTEXT)

      expect(sent(h).data.accountExists).toBe(false)
    })

    it('reports the invitation to the hook after it is stored', async () => {
      const h = build()

      await h.service.invite(WORKSPACE_REF, OWNER, 'a@example.com', 'viewer', CONTEXT)

      expect(h.events.emit).toHaveBeenCalledWith(
        {
          type: 'member.invited',
          ...WORKSPACE_REF,
          actorUserId: 'owner-1',
          email: 'a@example.com',
          role: 'viewer',
          at: new Date(NOW).toISOString()
        },
        CONTEXT
      )
    })

    it.each([
      ['a role outside the hierarchy', OWNER, 'ghost', AUTH_ERROR_CODES.VALIDATION],
      ['a peer role', EDITOR, 'editor', AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE],
      ['a role above the actor', EDITOR, 'owner', AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE]
    ])('refuses %s before it touches anything', async (_name, actor, role, expected) => {
      const h = build()

      expect(
        await code(h.service.invite(WORKSPACE_REF, actor, 'a@example.com', role, CONTEXT))
      ).toBe(expected)

      expect(h.users.findByEmail).not.toHaveBeenCalled()
      expect(h.email.sendWorkspaceInvitation).not.toHaveBeenCalled()
      expect(await h.store.pending(WORKSPACE_REF)).toEqual([])
    })

    it('lets the owner grant the owner role and a non-owner a role strictly below', async () => {
      const h = build()

      await h.service.invite(WORKSPACE_REF, OWNER, 'a@example.com', 'owner', CONTEXT)
      await h.service.invite(WORKSPACE_REF, EDITOR, 'b@example.com', 'viewer', CONTEXT)

      expect(h.email.sendWorkspaceInvitation).toHaveBeenCalledTimes(2)
    })

    it('refuses an address that is an active member and mails nothing', async () => {
      const h = build()
      h.users.findByEmail.mockResolvedValue(user('u9'))
      h.memberships.find.mockResolvedValue(membership('u9', 'active'))

      expect(
        await code(h.service.invite(WORKSPACE_REF, OWNER, 'a@example.com', 'viewer', CONTEXT))
      ).toBe(AUTH_ERROR_CODES.ALREADY_MEMBER)

      expect(h.email.sendWorkspaceInvitation).not.toHaveBeenCalled()
    })

    it('invites an address whose membership is not active, and one with no membership', async () => {
      const h = build()
      h.users.findByEmail.mockResolvedValue(user('u9'))
      h.memberships.find.mockResolvedValueOnce(
        membership('u9', 'suspended' as AuthMembership['status'])
      )

      await h.service.invite(WORKSPACE_REF, OWNER, 'a@example.com', 'viewer', CONTEXT)
      await h.service.invite(WORKSPACE_REF, OWNER, 'b@example.com', 'viewer', CONTEXT)

      expect(h.email.sendWorkspaceInvitation).toHaveBeenCalledTimes(2)
    })

    it('looks the member up in this workspace by the account the address belongs to', async () => {
      const h = build()
      h.users.findByEmail.mockResolvedValue(user('u9'))

      await h.service.invite(WORKSPACE_REF, OWNER, 'a@example.com', 'viewer', CONTEXT)

      expect(h.users.findByEmail).toHaveBeenCalledWith({ email: 'a@example.com', tenantId: 't1' })
      expect(h.memberships.find).toHaveBeenCalledWith({ ...WORKSPACE_REF, userId: 'u9' })
    })

    it('refuses the twenty-first invitation of one inviter inside an hour', async () => {
      const h = build({ maxPendingInvitationsPerWorkspace: 1_000 })
      for (let i = 0; i < 20; i += 1) {
        await h.service.invite(WORKSPACE_REF, OWNER, `p${i}@example.com`, 'viewer', CONTEXT)
      }

      expect(
        await code(h.service.invite(WORKSPACE_REF, OWNER, 'p20@example.com', 'viewer', CONTEXT))
      ).toBe(AUTH_ERROR_CODES.TOO_MANY_REQUESTS)
      await h.service.invite(WORKSPACE_REF, EDITOR, 'other@example.com', 'viewer', CONTEXT)

      expect(h.email.sendWorkspaceInvitation).toHaveBeenCalledTimes(21)
    })

    it('refuses a new invitation once the workspace holds the configured number', async () => {
      const h = build({ maxPendingInvitationsPerWorkspace: 2 })
      await h.service.invite(WORKSPACE_REF, OWNER, 'a@example.com', 'viewer', CONTEXT)
      await h.service.invite(WORKSPACE_REF, OWNER, 'b@example.com', 'viewer', CONTEXT)

      expect(
        await code(h.service.invite(WORKSPACE_REF, OWNER, 'c@example.com', 'viewer', CONTEXT))
      ).toBe(AUTH_ERROR_CODES.TOO_MANY_REQUESTS)

      expect(h.email.sendWorkspaceInvitation).toHaveBeenCalledTimes(2)
    })

    /** Holds the first publish until `release` is called; every later publish runs at once. */
    function holdFirstPublish(h: Harness): () => void {
      const realPublish = h.store.publish.bind(h.store)
      let release: () => void = () => undefined
      const held = new Promise<void>((resolve) => {
        release = resolve
      })
      let first = true
      jest.spyOn(h.store, 'publish').mockImplementation(async (...args) => {
        if (first) {
          first = false
          await held
        }
        return realPublish(...args)
      })
      return release
    }

    const tick = (): Promise<void> => new Promise((resolve) => setImmediate(resolve))

    it('lets only one of two overlapping first invitations for one address publish', async () => {
      const h = build()
      const release = holdFirstPublish(h)

      const a = code(h.service.invite(WORKSPACE_REF, OWNER, 'a@example.com', 'viewer', CONTEXT))
      await tick()
      const b = code(h.service.invite(WORKSPACE_REF, OWNER, 'a@example.com', 'viewer', CONTEXT))
      await tick()
      release()
      const outcomes = await Promise.all([a, b])

      expect(outcomes.filter((c) => c === AUTH_ERROR_CODES.TOO_MANY_REQUESTS)).toHaveLength(1)
      expect(await h.store.pending(WORKSPACE_REF)).toHaveLength(1)
      expect(h.email.sendWorkspaceInvitation).toHaveBeenCalledTimes(1)
      expect((await h.store.readByEmail(WORKSPACE_REF, 'a@example.com'))?.record).not.toBeNull()
    })

    it('lets only one of two overlapping replacements of one invitation publish', async () => {
      const h = build()
      await h.service.invite(WORKSPACE_REF, OWNER, 'a@example.com', 'viewer', CONTEXT)
      jest.spyOn(Date, 'now').mockReturnValue(NOW + COOLDOWN_MS)
      const release = holdFirstPublish(h)

      const a = code(h.service.resend(WORKSPACE_REF, OWNER, 'a@example.com', CONTEXT))
      await tick()
      const b = code(h.service.resend(WORKSPACE_REF, OWNER, 'a@example.com', CONTEXT))
      await tick()
      release()
      const outcomes = await Promise.all([a, b])

      expect(outcomes.filter((c) => c === AUTH_ERROR_CODES.TOO_MANY_REQUESTS)).toHaveLength(1)
      expect(await h.store.pending(WORKSPACE_REF)).toHaveLength(1)
      expect(h.email.sendWorkspaceInvitation).toHaveBeenCalledTimes(2)
    })

    it('does not publish a first invitation over one a slower writer published first', async () => {
      const h = build()
      const release = holdFirstPublish(h)

      const a = code(h.service.invite(WORKSPACE_REF, OWNER, 'a@example.com', 'viewer', CONTEXT))
      await tick()
      await h.service.invite(WORKSPACE_REF, EDITOR, 'a@example.com', 'viewer', CONTEXT)
      release()

      expect(await a).toBe(AUTH_ERROR_CODES.TOO_MANY_REQUESTS)
      expect(await h.store.pending(WORKSPACE_REF)).toHaveLength(1)
    })

    it('lets only one of two concurrent invitations take the last place', async () => {
      const h = build({ maxPendingInvitationsPerWorkspace: 1 })

      const outcomes = await Promise.all(
        ['a@example.com', 'b@example.com'].map((email) =>
          code(h.service.invite(WORKSPACE_REF, OWNER, email, 'viewer', CONTEXT))
        )
      )

      expect(outcomes.filter((c) => c === AUTH_ERROR_CODES.TOO_MANY_REQUESTS)).toHaveLength(1)
      expect(await h.store.pending(WORKSPACE_REF)).toHaveLength(1)
      expect(h.email.sendWorkspaceInvitation).toHaveBeenCalledTimes(1)
      const loser = outcomes.indexOf(AUTH_ERROR_CODES.TOO_MANY_REQUESTS) === 0 ? 'a' : 'b'
      expect(await h.store.readByEmail(WORKSPACE_REF, `${loser}@example.com`)).toBeNull()
    })

    it('counts an invitation over an index whose record is gone as a first one for the cap', async () => {
      const h = build({ maxPendingInvitationsPerWorkspace: 1 })
      await h.service.invite(WORKSPACE_REF, OWNER, 'a@example.com', 'viewer', CONTEXT)
      await h.service
        .invite(WORKSPACE_REF, OWNER, 'b@example.com', 'viewer', CONTEXT)
        .catch(() => undefined)
      const first = sent(h).data.inviteToken
      await h.redis.del(invitationKey(first))

      await h.service.invite(WORKSPACE_REF, OWNER, 'a@example.com', 'viewer', CONTEXT)

      const record = (await h.store.readByEmail(WORKSPACE_REF, 'a@example.com'))?.record
      expect(record?.resendCount).toBe(0)
      expect(await h.store.pending(WORKSPACE_REF)).toHaveLength(1)
      expect(
        await code(h.service.invite(WORKSPACE_REF, OWNER, 'c@example.com', 'viewer', CONTEXT))
      ).toBe(AUTH_ERROR_CODES.TOO_MANY_REQUESTS)
    })

    it('does not count a replacement against the cap', async () => {
      const h = build({ maxPendingInvitationsPerWorkspace: 1 })
      await h.service.invite(WORKSPACE_REF, OWNER, 'a@example.com', 'viewer', CONTEXT)
      jest.spyOn(Date, 'now').mockReturnValue(NOW + COOLDOWN_MS)

      await h.service.invite(WORKSPACE_REF, OWNER, 'a@example.com', 'viewer', CONTEXT)

      expect(await h.store.pending(WORKSPACE_REF)).toHaveLength(1)
    })

    it('refuses a workspace that is not active, and an inviter who is gone', async () => {
      const h = build()
      h.workspaces.findById.mockResolvedValueOnce(workspaceRow({ status: 'pending_deletion' }))
      h.users.findById.mockResolvedValueOnce(null)

      expect(
        await code(h.service.invite(WORKSPACE_REF, OWNER, 'a@example.com', 'viewer', CONTEXT))
      ).toBe(AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND)
      h.workspaces.findById.mockResolvedValueOnce(null)
      expect(
        await code(h.service.invite(WORKSPACE_REF, EDITOR, 'a@example.com', 'viewer', CONTEXT))
      ).toBe(AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND)
      expect(
        await code(h.service.invite(WORKSPACE_REF, OWNER, 'b@example.com', 'viewer', CONTEXT))
      ).toBe(AUTH_ERROR_CODES.TOKEN_INVALID)
      expect(h.email.sendWorkspaceInvitation).not.toHaveBeenCalled()
    })

    it('leaves nothing behind and mails nothing when another writer moved the address first', async () => {
      const h = build()
      jest.spyOn(h.store, 'publish').mockResolvedValue('lost')

      expect(
        await code(h.service.invite(WORKSPACE_REF, OWNER, 'a@example.com', 'viewer', CONTEXT))
      ).toBe(AUTH_ERROR_CODES.TOO_MANY_REQUESTS)

      expect(await h.store.pending(WORKSPACE_REF)).toEqual([])
      expect(h.email.sendWorkspaceInvitation).not.toHaveBeenCalled()
      expect(h.events.emit).not.toHaveBeenCalled()
    })

    it('replaces an index whose record is gone instead of failing on it', async () => {
      const h = build()
      await h.service.invite(WORKSPACE_REF, OWNER, 'a@example.com', 'viewer', CONTEXT)
      const first = sent(h).data.inviteToken
      await h.redis.del(invitationKey(first))

      await h.service.invite(WORKSPACE_REF, OWNER, 'a@example.com', 'viewer', CONTEXT)

      expect(h.email.sendWorkspaceInvitation).toHaveBeenCalledTimes(2)
      expect((await h.store.readByEmail(WORKSPACE_REF, 'a@example.com'))?.record?.resendCount).toBe(
        0
      )
    })

    it('re-throws a delivery failure without the text that failed, which can quote the token', async () => {
      const h = build()
      h.email.sendWorkspaceInvitation.mockRejectedValue(new Error('relay said: token deadbeef'))

      const failure = await h.service
        .invite(WORKSPACE_REF, OWNER, 'a@example.com', 'viewer', CONTEXT)
        .catch((e: Error) => e)

      expect((failure as Error).message).not.toContain('deadbeef')
      expect(h.events.emit).not.toHaveBeenCalled()
    })
  })

  describe('a second invitation or a resend', () => {
    async function invited(h: Harness, actor = OWNER, role = 'viewer'): Promise<string> {
      await h.service.invite(WORKSPACE_REF, actor, 'a@example.com', role, CONTEXT)
      return sent(h, h.email.sendWorkspaceInvitation.mock.calls.length - 1).data.inviteToken
    }

    function later(ms: number): void {
      jest.spyOn(Date, 'now').mockReturnValue(NOW + ms)
    }

    it('refuses inside the cooldown, and allows it from the sixtieth second', async () => {
      const h = build()
      await invited(h)

      later(COOLDOWN_MS - 1)
      expect(await code(h.service.resend(WORKSPACE_REF, OWNER, 'a@example.com', CONTEXT))).toBe(
        AUTH_ERROR_CODES.TOO_MANY_REQUESTS
      )
      later(COOLDOWN_MS)
      await h.service.resend(WORKSPACE_REF, OWNER, 'a@example.com', CONTEXT)

      expect(h.email.sendWorkspaceInvitation).toHaveBeenCalledTimes(2)
    })

    it('retires the old token, counts the resend and keeps one pending invitation', async () => {
      const h = build()
      const first = await invited(h)
      later(COOLDOWN_MS)

      await h.service.resend(WORKSPACE_REF, OWNER, 'A@example.com', CONTEXT)
      const second = sent(h, 1).data.inviteToken

      expect(second).not.toBe(first)
      expect(await h.store.readByHash(sha256(first))).toBeNull()
      expect(await h.store.readByHash(sha256(second))).toMatchObject({
        resendCount: 1,
        createdAt: new Date(NOW + COOLDOWN_MS).toISOString()
      })
      expect(await h.store.pending(WORKSPACE_REF)).toHaveLength(1)
      expect(h.events.emit).toHaveBeenLastCalledWith(
        expect.objectContaining({
          type: 'invitation.resent',
          role: 'viewer',
          email: 'a@example.com'
        }),
        CONTEXT
      )
    })

    it('allows five resends and refuses the sixth', async () => {
      const h = build()
      await invited(h)
      for (let i = 1; i <= 5; i += 1) {
        later(i * COOLDOWN_MS)
        await h.service.resend(WORKSPACE_REF, OWNER, 'a@example.com', CONTEXT)
      }
      later(6 * COOLDOWN_MS)

      expect(await code(h.service.resend(WORKSPACE_REF, OWNER, 'a@example.com', CONTEXT))).toBe(
        AUTH_ERROR_CODES.TOO_MANY_REQUESTS
      )
      expect(
        await code(h.service.invite(WORKSPACE_REF, OWNER, 'a@example.com', 'viewer', CONTEXT))
      ).toBe(AUTH_ERROR_CODES.TOO_MANY_REQUESTS)
    })

    it('invites again as a resend that takes the new role and reports it as one', async () => {
      const h = build()
      await invited(h)
      later(COOLDOWN_MS)

      await h.service.invite(WORKSPACE_REF, OWNER, 'a@example.com', 'editor', CONTEXT)

      expect((await h.store.readByEmail(WORKSPACE_REF, 'a@example.com'))?.record).toMatchObject({
        role: 'editor',
        resendCount: 1
      })
      expect(h.events.emit).toHaveBeenLastCalledWith(
        expect.objectContaining({ type: 'invitation.resent', role: 'editor' }),
        CONTEXT
      )
    })

    it('refuses to displace an invitation above the actor and leaves it as it was', async () => {
      const h = build()
      const token = await invited(h, OWNER, 'editor')
      later(COOLDOWN_MS)

      expect(
        await code(h.service.invite(WORKSPACE_REF, EDITOR, 'a@example.com', 'viewer', CONTEXT))
      ).toBe(AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE)

      expect(await h.store.readByHash(sha256(token))).toMatchObject({ role: 'editor' })
    })

    it('answers an address with no invitation, or one above the actor, with no effect', async () => {
      const h = build()
      const token = await invited(h, OWNER, 'editor')
      later(COOLDOWN_MS)

      await h.service.resend(WORKSPACE_REF, OWNER, 'nobody@example.com', CONTEXT)
      await h.service.resend(WORKSPACE_REF, EDITOR, 'a@example.com', CONTEXT)

      expect(h.email.sendWorkspaceInvitation).toHaveBeenCalledTimes(1)
      expect(await h.store.readByHash(sha256(token))).not.toBeNull()
    })

    it('counts a resend against the inviter hour', async () => {
      const h = build({ maxPendingInvitationsPerWorkspace: 1_000 })
      await invited(h)
      for (let i = 0; i < 19; i += 1) {
        await h.service.invite(WORKSPACE_REF, OWNER, `p${i}@example.com`, 'viewer', CONTEXT)
      }
      later(COOLDOWN_MS)

      expect(await code(h.service.resend(WORKSPACE_REF, OWNER, 'a@example.com', CONTEXT))).toBe(
        AUTH_ERROR_CODES.TOO_MANY_REQUESTS
      )
    })
  })

  describe('revoke', () => {
    it('withdraws the record, the index and the listing, and reports it', async () => {
      const h = build()
      await h.service.invite(WORKSPACE_REF, OWNER, 'a@example.com', 'viewer', CONTEXT)
      const token = sent(h).data.inviteToken

      await h.service.revoke(WORKSPACE_REF, OWNER, 'A@example.com', CONTEXT)

      expect(await h.store.readByHash(sha256(token))).toBeNull()
      expect(await h.store.readByEmail(WORKSPACE_REF, 'a@example.com')).toBeNull()
      expect(await h.store.pending(WORKSPACE_REF)).toEqual([])
      expect(h.events.emit).toHaveBeenLastCalledWith(
        {
          type: 'invitation.revoked',
          ...WORKSPACE_REF,
          actorUserId: 'owner-1',
          email: 'a@example.com',
          role: 'viewer',
          at: new Date(NOW).toISOString()
        },
        CONTEXT
      )
    })

    it('does nothing, and reports nothing, for an absent invitation or one above the actor', async () => {
      const h = build()
      await h.service.invite(WORKSPACE_REF, OWNER, 'a@example.com', 'editor', CONTEXT)
      h.events.emit.mockClear()

      await h.service.revoke(WORKSPACE_REF, OWNER, 'nobody@example.com', CONTEXT)
      await h.service.revoke(WORKSPACE_REF, EDITOR, 'a@example.com', CONTEXT)

      expect(h.events.emit).not.toHaveBeenCalled()
      expect(await h.store.pending(WORKSPACE_REF)).toHaveLength(1)
    })
  })

  describe('list', () => {
    it('shows each pending invitation with when it expires and never its token', async () => {
      const h = build()
      await h.service.invite(WORKSPACE_REF, OWNER, 'a@example.com', 'viewer', CONTEXT)

      const page = await h.service.list(WORKSPACE_REF, {})

      expect(page).toEqual({
        items: [
          {
            email: 'a@example.com',
            role: 'viewer',
            inviterUserId: 'owner-1',
            createdAt: new Date(NOW).toISOString(),
            expiresAt: new Date(NOW + 604_800_000).toISOString(),
            resendCount: 0
          }
        ],
        nextCursor: null
      })
    })
  })

  describe('preview', () => {
    it('tells what the token is for, with the address masked', async () => {
      const h = build()
      h.users.findByEmail.mockResolvedValue(user('existing'))
      await h.service.invite(WORKSPACE_REF, OWNER, 'someone@example.com', 'editor', CONTEXT)

      const answer = await h.service.preview(sent(h).data.inviteToken)

      expect(answer).toEqual({
        workspaceName: 'Acme',
        inviterName: 'Name of owner-1',
        role: 'editor',
        maskedEmail: expect.stringMatching(/^s.*@example\.com$/),
        accountExists: true
      })
      expect(answer.maskedEmail).not.toContain('someone')
    })

    it('states that no account exists for an address that has none', async () => {
      const h = build()
      await h.service.invite(WORKSPACE_REF, OWNER, 'a@example.com', 'viewer', CONTEXT)

      expect((await h.service.preview(sent(h).data.inviteToken)).accountExists).toBe(false)
    })

    it('looks up inert values where the token names nothing', async () => {
      const h = build()

      await code(h.service.preview('0'.repeat(64)))

      expect(h.workspaces.findById).toHaveBeenCalledWith({ tenantId: '', workspaceId: '' })
      expect(h.users.findById).toHaveBeenCalledWith({ id: '', tenantId: '' })
      expect(h.users.findByEmail).toHaveBeenCalledWith({
        email: 'no-invitation@invalid.invalid',
        tenantId: ''
      })
    })

    it('answers one error for a token that never existed, one that was revoked, and a workspace or inviter that is gone', async () => {
      const h = build()
      await h.service.invite(WORKSPACE_REF, OWNER, 'a@example.com', 'viewer', CONTEXT)
      const token = sent(h).data.inviteToken
      const answers: Array<string | undefined> = [await code(h.service.preview('0'.repeat(64)))]
      h.workspaces.findById.mockResolvedValueOnce(workspaceRow({ status: 'pending_deletion' }))
      answers.push(await code(h.service.preview(token)))
      h.workspaces.findById.mockResolvedValueOnce(null)
      answers.push(await code(h.service.preview(token)))
      h.users.findById.mockResolvedValueOnce(null)
      answers.push(await code(h.service.preview(token)))
      await h.service.revoke(WORKSPACE_REF, OWNER, 'a@example.com', CONTEXT)
      answers.push(await code(h.service.preview(token)))

      expect(answers).toEqual(Array(5).fill(AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN))
    })

    it('reads the same repositories the same number of times for a token that exists and one that does not', async () => {
      const h = build()
      await h.service.invite(WORKSPACE_REF, OWNER, 'a@example.com', 'viewer', CONTEXT)
      const token = sent(h).data.inviteToken
      const counts = (): number[] => [
        h.workspaces.findById.mock.calls.length,
        h.users.findById.mock.calls.length,
        h.users.findByEmail.mock.calls.length
      ]

      h.workspaces.findById.mockClear()
      h.users.findById.mockClear()
      h.users.findByEmail.mockClear()
      await h.service.preview(token)
      const found = counts()
      h.workspaces.findById.mockClear()
      h.users.findById.mockClear()
      h.users.findByEmail.mockClear()
      await code(h.service.preview('0'.repeat(64)))

      expect(counts()).toEqual(found)
      expect(found).toEqual([1, 1, 1])
    })
  })

  describe('construction', () => {
    it('refuses to boot without the workspace group, and without the email method', () => {
      const h = build()
      const options = workspaceOptions()
      const make = (opts: typeof options, email: object): WorkspaceInvitationService =>
        new WorkspaceInvitationService(
          h.store,
          h.redis,
          {} as MembershipService,
          h.events as Partial<WorkspaceEventsService> as WorkspaceEventsService,
          h.users as Partial<IUserRepository> as IUserRepository,
          h.workspaces as Partial<IWorkspaceRepository> as IWorkspaceRepository,
          h.memberships as Partial<IMembershipRepository> as IMembershipRepository,
          email as Partial<IEmailProvider> as IEmailProvider,
          opts
        )

      expect(() => make(optionsWithoutWorkspaces(), h.email)).toThrow(
        '[BymaxAuthModule] WorkspaceInvitationService needs workspaces.enabled.'
      )
      expect(() => make(options, {}).onModuleInit()).toThrow(
        'BymaxAuthModule: controllers.workspaceInvitations is enabled but the configured email ' +
          'provider implements no sendWorkspaceInvitation. The flow cannot deliver its token ' +
          'without it.'
      )
      expect(() => make(options, h.email).onModuleInit()).not.toThrow()
    })
  })
})
