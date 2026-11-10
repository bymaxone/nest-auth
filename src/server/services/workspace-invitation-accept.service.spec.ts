/**
 * @fileoverview Tests for `WorkspaceInvitationAcceptService`: what is decided before the token is
 * spent, that the membership is written before it is, what an acceptance answers, and the signup
 * path that creates the account.
 *
 * @layer Test
 */

/// <reference path="../../../test/e2e/ioredis-mock.d.ts" />

import { Logger } from '@nestjs/common'
import type { Redis } from 'ioredis'
import RedisMock from 'ioredis-mock'

import { MembershipService } from './membership.service'
import type { PasswordService } from './password.service'
import type { SessionService } from './session.service'
import type { TokenManagerService } from './token-manager.service'
import type { WorkspaceAccessService } from './workspace-access.service'
import type { WorkspaceEventsService } from './workspace-events.service'
import { WorkspaceInvitationAcceptService } from './workspace-invitation-accept.service'
import { WorkspaceInvitationStore } from './workspace-invitation.store'
import {
  CONTEXT,
  WORKSPACE_REF,
  optionsWithoutWorkspaces,
  workspaceOptions,
  workspaceRow
} from './__tests__/workspace-service-harness'
import { invitationKey } from '../constants/workspace-invitation-keys'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import type { AuthException } from '../errors/auth-exception'
import type { IAuthHooks } from '../interfaces/auth-hooks.interface'
import type {
  AuthMembership,
  IMembershipRepository
} from '../interfaces/membership-repository.interface'
import type { AuthUser, IUserRepository } from '../interfaces/user-repository.interface'
import type {
  BootstrapInvitationRecord,
  MemberInvitationRecord
} from '../interfaces/workspace-invitation.interface'
import type { IWorkspaceRepository } from '../interfaces/workspace-repository.interface'
import { AuthRedisService } from '../redis/auth-redis.service'

const NOW = Date.parse('2026-01-10T12:00:00.000Z')
const TOKEN = 'a'.repeat(64)
const EMAIL = 'invitee@example.com'
let port = 45_000

function user(id: string, overrides: Partial<AuthUser> = {}): AuthUser {
  return {
    id,
    email: `${id}@example.com`,
    name: `Name of ${id}`,
    passwordHash: null,
    role: 'member',
    status: 'active',
    tenantId: 't1',
    emailVerified: true,
    mfaEnabled: false,
    lastLoginAt: null,
    createdAt: new Date(0),
    ...overrides
  }
}

function member(
  userId: string,
  role: string,
  status: AuthMembership['status'] = 'active'
): AuthMembership {
  return {
    ...WORKSPACE_REF,
    userId,
    role,
    status,
    invitedByUserId: null,
    createdAt: new Date(0),
    updatedAt: new Date(0)
  }
}

function memberRecord(overrides: Partial<MemberInvitationRecord> = {}): MemberInvitationRecord {
  return {
    kind: 'member',
    email: EMAIL,
    role: 'viewer',
    ...WORKSPACE_REF,
    inviterUserId: 'inviter',
    createdAt: new Date(NOW).toISOString(),
    resendCount: 0,
    ...overrides
  }
}

function bootstrapRecord(
  overrides: Partial<BootstrapInvitationRecord> = {}
): BootstrapInvitationRecord {
  return {
    kind: 'bootstrap',
    email: EMAIL,
    role: 'owner',
    ...WORKSPACE_REF,
    createdAt: new Date(NOW).toISOString(),
    resendCount: 0,
    workspaceName: 'Acme',
    ...overrides
  }
}

interface Harness {
  service: WorkspaceInvitationAcceptService
  store: WorkspaceInvitationStore
  users: { findById: jest.Mock; findByEmail: jest.Mock; create: jest.Mock }
  workspaces: { findById: jest.Mock; createWithOwner: jest.Mock }
  memberships: { find: jest.Mock; create: jest.Mock }
  access: { invalidateMembership: jest.Mock }
  events: { emit: jest.Mock }
  passwords: { assertAcceptable: jest.Mock; hash: jest.Mock }
  tokens: { issueTokens: jest.Mock }
  sessions: { createSession: jest.Mock }
  hooks: { afterInvitationAccepted?: jest.Mock }
}

function build(sessionsEnabled = false, hooks: Harness['hooks'] = {}): Harness {
  const options = workspaceOptions()
  Object.assign(options.sessions, { enabled: sessionsEnabled })
  const redis = new AuthRedisService(
    new RedisMock({ port: (port += 1) }) as Partial<Redis> as Redis,
    options
  )
  const store = new WorkspaceInvitationStore(redis, options)
  const users = {
    findById: jest.fn(async ({ id }: { id: string }) =>
      id === 'caller' ? user('caller', { email: EMAIL }) : user(id)
    ),
    findByEmail: jest.fn().mockResolvedValue(null),
    create: jest.fn(async (data: { email: string; name: string }) =>
      user('new', { email: data.email, name: data.name })
    )
  }
  const workspaces = {
    findById: jest.fn().mockResolvedValue(workspaceRow()),
    createWithOwner: jest.fn().mockResolvedValue({ status: 'created', workspace: workspaceRow() })
  }
  const memberships = {
    find: jest.fn(async ({ userId }: { userId: string }) =>
      userId === 'inviter' ? member('inviter', 'editor') : null
    ),
    create: jest.fn().mockResolvedValue('ok')
  }
  const access = { invalidateMembership: jest.fn().mockResolvedValue(undefined) }
  const events = { emit: jest.fn() }
  const passwords = {
    assertAcceptable: jest.fn().mockResolvedValue(undefined),
    hash: jest.fn().mockResolvedValue('hash')
  }
  const tokens = {
    issueTokens: jest
      .fn()
      .mockResolvedValue({ user: { id: 'new' }, accessToken: 'a', rawRefreshToken: 'r' })
  }
  const sessions = { createSession: jest.fn().mockResolvedValue('sid') }
  const ceiling = new MembershipService(
    {} as Partial<IMembershipRepository> as IMembershipRepository,
    {} as never,
    {} as never,
    options
  )
  const service = new WorkspaceInvitationAcceptService(
    store,
    ceiling,
    access as Partial<WorkspaceAccessService> as WorkspaceAccessService,
    events as Partial<WorkspaceEventsService> as WorkspaceEventsService,
    passwords as Partial<PasswordService> as PasswordService,
    tokens as Partial<TokenManagerService> as TokenManagerService,
    sessions as Partial<SessionService> as SessionService,
    users as Partial<IUserRepository> as IUserRepository,
    workspaces as Partial<IWorkspaceRepository> as IWorkspaceRepository,
    memberships as Partial<IMembershipRepository> as IMembershipRepository,
    hooks as Partial<IAuthHooks> as IAuthHooks,
    options
  )
  return {
    service,
    store,
    users,
    workspaces,
    memberships,
    access,
    events,
    passwords,
    tokens,
    sessions,
    hooks
  }
}

/** Publishes a record under `TOKEN` the way the issuing side does. */
async function seed(
  h: Harness,
  record: MemberInvitationRecord | BootstrapInvitationRecord = memberRecord()
): Promise<void> {
  const outcome = await h.store.publish(
    { tenantId: record.tenantId, workspaceId: record.workspaceId },
    record.email,
    invitationKey(TOKEN),
    record,
    604_800,
    0,
    null
  )
  if (outcome !== 'published') throw new Error('seed failed')
}

async function code(promise: Promise<unknown>): Promise<string | undefined> {
  try {
    await promise
  } catch (error) {
    return ((error as AuthException).getResponse() as { error: { code: string } }).error.code
  }
  return undefined
}

const CALLER = { sub: 'caller', tenantId: 't1' }
const REQUEST = { ip: '203.0.113.7', userAgent: 'jest', headers: { 'user-agent': 'jest' } }
const SIGNUP = { token: TOKEN, name: 'Ada Lovelace', password: 'correct horse battery' }

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
