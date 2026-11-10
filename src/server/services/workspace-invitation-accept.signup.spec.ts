/**
 * @fileoverview Tests for `WorkspaceInvitationAcceptService`: the signup path that creates the
 * account, and the acceptance of a platform bootstrap invitation.
 *
 * @layer Test
 */

import { Logger } from '@nestjs/common'

import {
  CALLER,
  EMAIL,
  REQUEST,
  SIGNUP,
  NOW,
  TOKEN,
  build,
  bootstrapRecord,
  code,
  member,
  memberRecord,
  seed,
  user
} from './__tests__/workspace-invitation-accept-harness'
import type { Harness } from './__tests__/workspace-invitation-accept-harness'
import { CONTEXT, WORKSPACE_REF, workspaceRow } from './__tests__/workspace-service-harness'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import type { AuthMembership } from '../interfaces/membership-repository.interface'
import type { BootstrapInvitationRecord } from '../interfaces/workspace-invitation.interface'

describe('WorkspaceInvitationAcceptService', () => {
  beforeEach(() => {
    jest.spyOn(Date, 'now').mockReturnValue(NOW)
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  describe('accept of a bootstrap invitation', () => {
    async function bootstrapped(
      overrides: Partial<BootstrapInvitationRecord> = {}
    ): Promise<Harness> {
      const h = build()
      await seed(h, bootstrapRecord(overrides))
      h.workspaces.findById.mockResolvedValue(null)
      return h
    }

    it('creates the workspace under the pre-allocated id, owned by the caller, then spends the token', async () => {
      const h = await bootstrapped()

      const answer = await h.service.accept(CALLER, TOKEN, CONTEXT)

      expect(answer).toEqual({ workspaceId: 'w1', role: 'owner' })
      expect(h.workspaces.createWithOwner).toHaveBeenCalledWith({
        ...WORKSPACE_REF,
        name: 'Acme',
        ownerUserId: 'caller',
        ownerRole: 'owner',
        maxWorkspacesPerUser: 0,
        audit: {
          type: 'workspace.created',
          ...WORKSPACE_REF,
          actorUserId: 'caller',
          at: new Date(NOW).toISOString()
        }
      })
      expect(h.memberships.create).not.toHaveBeenCalled()
      expect(await h.store.readByEmail(WORKSPACE_REF, EMAIL)).toBeNull()
      expect(h.users.findById).not.toHaveBeenCalledWith(expect.objectContaining({ id: 'inviter' }))
    })

    it('answers the owner limit as such and leaves the token usable', async () => {
      const h = await bootstrapped()
      h.workspaces.createWithOwner.mockResolvedValue({ status: 'limit_reached' })

      expect(await code(h.service.accept(CALLER, TOKEN, CONTEXT))).toBe(
        AUTH_ERROR_CODES.WORKSPACE_LIMIT_REACHED
      )

      expect(await h.store.readByEmail(WORKSPACE_REF, EMAIL)).not.toBeNull()
    })

    it('treats a workspace an earlier attempt created, with this caller as owner, as done', async () => {
      const h = await bootstrapped()
      h.workspaces.findById.mockResolvedValue(workspaceRow())
      h.memberships.find.mockResolvedValue(member('caller', 'owner'))

      expect(await h.service.accept(CALLER, TOKEN, CONTEXT)).toEqual({
        workspaceId: 'w1',
        role: 'owner'
      })

      expect(h.workspaces.createWithOwner).not.toHaveBeenCalled()
      expect(await h.store.readByEmail(WORKSPACE_REF, EMAIL)).toBeNull()
    })

    it.each([
      ['has no member of that id', null],
      ['has this caller as a plain member', member('caller', 'viewer')],
      [
        'has this caller as a suspended owner',
        member('caller', 'owner', 'suspended' as AuthMembership['status'])
      ]
    ])('refuses a workspace that already exists and %s', async (_name, found) => {
      const h = await bootstrapped()
      h.workspaces.findById.mockResolvedValue(workspaceRow())
      h.memberships.find.mockResolvedValue(found)

      expect(await code(h.service.accept(CALLER, TOKEN, CONTEXT))).toBe(
        AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN
      )

      expect(await h.store.readByEmail(WORKSPACE_REF, EMAIL)).not.toBeNull()
    })

    it('refuses a workspace that exists and is not active, even to its active owner', async () => {
      const h = await bootstrapped()
      h.workspaces.findById.mockResolvedValue(workspaceRow({ status: 'pending_deletion' }))
      h.memberships.find.mockResolvedValue(member('caller', 'owner'))

      expect(await code(h.service.accept(CALLER, TOKEN, CONTEXT))).toBe(
        AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN
      )
    })

    it('refuses a record whose role is not the owner role', async () => {
      const h = await bootstrapped({ role: 'viewer' })

      expect(await code(h.service.accept(CALLER, TOKEN, CONTEXT))).toBe(
        AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN
      )
      expect(h.workspaces.createWithOwner).not.toHaveBeenCalled()
    })
  })

  describe('acceptSignup', () => {
    it('creates a verified account, joins it, spends the token and signs it in, in that order', async () => {
      const h = build(true)
      await seed(h)
      const order: string[] = []
      h.users.findByEmail.mockImplementation(async () => (order.push('lookup'), null))
      h.passwords.assertAcceptable.mockImplementation(async () => void order.push('policy'))
      h.passwords.hash.mockImplementation(async () => (order.push('hash'), 'hash'))
      h.users.create.mockImplementation(
        async (d: { email: string; name: string }) => (
          order.push('account'),
          user('new', { email: d.email, name: d.name })
        )
      )
      h.memberships.create.mockImplementation(async () => (order.push('member'), 'ok'))
      h.access.invalidateMembership.mockImplementation(async () => void order.push('cache'))
      h.tokens.issueTokens.mockImplementation(
        async () => (
          order.push('tokens'),
          { user: { id: 'new' }, accessToken: 'a', rawRefreshToken: 'r' }
        )
      )
      h.sessions.createSession.mockImplementation(async () => (order.push('session'), 'sid'))

      const answer = await h.service.acceptSignup(SIGNUP, REQUEST)

      expect(order).toEqual([
        'lookup',
        'policy',
        'hash',
        'account',
        'member',
        'cache',
        'tokens',
        'session'
      ])
      expect(answer.accepted).toEqual({ workspaceId: 'w1', role: 'viewer' })
      expect(answer.result).toMatchObject({ accessToken: 'a' })
      expect(h.users.create).toHaveBeenCalledWith({
        email: EMAIL,
        name: 'Ada Lovelace',
        passwordHash: 'hash',
        tenantId: 't1',
        emailVerified: true
      })
      expect(Object.keys(h.users.create.mock.calls[0]?.[0] as object)).not.toContain('role')
      expect(await h.store.readByEmail(WORKSPACE_REF, EMAIL)).toBeNull()
      expect(h.sessions.createSession).toHaveBeenCalledWith({
        userId: 'new',
        tenantId: 't1',
        rawRefreshToken: 'r',
        ip: '203.0.113.7',
        userAgent: 'jest'
      })
      expect(h.tokens.issueTokens).toHaveBeenCalledWith(
        expect.objectContaining({ id: 'new' }),
        '203.0.113.7',
        'jest'
      )
    })

    it('hands the hook the account and the request, and does not wait for it or fail on it', async () => {
      const afterInvitationAccepted = jest.fn().mockRejectedValue(new Error('hook down'))
      const h = build(false, { afterInvitationAccepted })
      await seed(h)

      const error = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)

      await expect(h.service.acceptSignup(SIGNUP, REQUEST)).resolves.toBeDefined()
      await new Promise((resolve) => setImmediate(resolve))

      expect(error).toHaveBeenCalledWith(
        expect.stringContaining('afterInvitationAccepted hook threw')
      )

      expect(afterInvitationAccepted).toHaveBeenCalledWith(expect.objectContaining({ id: 'new' }), {
        plane: 'dashboard',
        tenantId: 't1',
        userId: 'new',
        ip: '203.0.113.7',
        userAgent: 'jest',
        sanitizedHeaders: { 'user-agent': 'jest' }
      })
    })

    it('makes no session when sessions are off, and needs no hook', async () => {
      const h = build(false)
      await seed(h)

      await h.service.acceptSignup(SIGNUP, REQUEST)

      expect(h.sessions.createSession).not.toHaveBeenCalled()
    })

    it('refuses an address that already has an account before it judges the password or hashes', async () => {
      const h = build()
      await seed(h)
      h.users.findByEmail.mockResolvedValue(user('existing'))

      expect(await code(h.service.acceptSignup(SIGNUP, REQUEST))).toBe(
        AUTH_ERROR_CODES.EMAIL_ALREADY_EXISTS
      )

      expect(h.passwords.assertAcceptable).not.toHaveBeenCalled()
      expect(h.passwords.hash).not.toHaveBeenCalled()
      expect(await h.store.readByEmail(WORKSPACE_REF, EMAIL)).not.toBeNull()
    })

    it('names the password field when it judges the password', async () => {
      const h = build()
      await seed(h)

      await h.service.acceptSignup(SIGNUP, REQUEST)

      expect(h.passwords.assertAcceptable).toHaveBeenCalledWith(SIGNUP.password, 'password')
    })

    it('judges the password before anything is written or spent, and leaves the token usable', async () => {
      const h = build()
      await seed(h)
      h.passwords.assertAcceptable.mockRejectedValue(new Error('too short'))

      await expect(h.service.acceptSignup(SIGNUP, REQUEST)).rejects.toThrow('too short')

      expect(h.users.create).not.toHaveBeenCalled()
      expect(await h.store.readByEmail(WORKSPACE_REF, EMAIL)).not.toBeNull()
    })

    it('answers a token that names nothing, or an inviter who no longer grants it, as invalid', async () => {
      const h = build()

      expect(await code(h.service.acceptSignup(SIGNUP, REQUEST))).toBe(
        AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN
      )
      await seed(h)
      h.memberships.find.mockResolvedValue(null)
      expect(await code(h.service.acceptSignup(SIGNUP, REQUEST))).toBe(
        AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN
      )

      expect(h.users.create).not.toHaveBeenCalled()
    })

    it('answers a concurrent creation of the same address as the account that now exists', async () => {
      const h = build()
      await seed(h)
      h.users.create.mockRejectedValue(new Error('duplicate key'))
      h.users.findByEmail.mockResolvedValueOnce(null).mockResolvedValueOnce(user('winner'))

      expect(await code(h.service.acceptSignup(SIGNUP, REQUEST))).toBe(
        AUTH_ERROR_CODES.EMAIL_ALREADY_EXISTS
      )

      expect(await h.store.readByEmail(WORKSPACE_REF, EMAIL)).not.toBeNull()
    })

    it('re-throws a creation failure that no account explains', async () => {
      const h = build()
      await seed(h)
      h.users.create.mockRejectedValue(new Error('database down'))

      await expect(h.service.acceptSignup(SIGNUP, REQUEST)).rejects.toThrow('database down')
    })

    it('keeps the token usable when the account was created and the membership failed', async () => {
      const h = build()
      await seed(h)
      h.memberships.create.mockRejectedValue(new Error('membership down'))

      await expect(h.service.acceptSignup(SIGNUP, REQUEST)).rejects.toThrow('membership down')

      expect(await h.store.readByEmail(WORKSPACE_REF, EMAIL)).not.toBeNull()
      expect(h.tokens.issueTokens).not.toHaveBeenCalled()
    })

    it('creates the workspace for a bootstrap invitation and answers the owner role', async () => {
      const h = build()
      await seed(h, bootstrapRecord())
      h.workspaces.findById.mockResolvedValue(null)

      const answer = await h.service.acceptSignup(SIGNUP, REQUEST)

      expect(answer.accepted).toEqual({ workspaceId: 'w1', role: 'owner' })
      expect(h.workspaces.createWithOwner).toHaveBeenCalledWith(
        expect.objectContaining({ ownerUserId: 'new' })
      )
    })
  })
})
