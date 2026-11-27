/**
 * @fileoverview Tests for what `WorkspaceInvitationAcceptService` tells the host's hooks: the
 * workspace a bootstrap acceptance creates, an acceptance whose cache step fails, and the point at
 * which `beforeWorkspaceCreate` is asked on an invitation signup.
 *
 * @layer Test
 */

import { Logger } from '@nestjs/common'

import {
  CALLER,
  EMAIL,
  NOW,
  REQUEST,
  SIGNUP,
  TOKEN,
  bootstrapRecord,
  build,
  code,
  member,
  memberRecord,
  seed,
  user
} from './__tests__/workspace-invitation-accept-harness'
import type { Harness } from './__tests__/workspace-invitation-accept-harness'
import { CONTEXT, WORKSPACE_REF, workspaceRow } from './__tests__/workspace-service-harness'
import { sha256 } from '../crypto/secure-token'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import type { HookContext } from '../interfaces/auth-hooks.interface'

/** A signup whose bootstrap workspace does not exist yet, over the given host hook. */
async function bootstrapSignup(beforeWorkspaceCreate: jest.Mock): Promise<Harness> {
  const h = build(false, { beforeWorkspaceCreate })
  h.workspaces.findById.mockResolvedValue(null)
  await seed(h, bootstrapRecord())
  return h
}

/** Whether the invitation under `TOKEN` is still there to be accepted. */
async function unspent(h: Harness): Promise<boolean> {
  return (await h.store.readByEmail(WORKSPACE_REF, EMAIL)) !== null
}

/** The event types the host's `onWorkspaceEvent` is given, in order. */
function emitted(h: Harness): string[] {
  return h.events.emit.mock.calls.map(([event]) => (event as { type: string }).type)
}

beforeEach(() => {
  jest.spyOn(Date, 'now').mockReturnValue(NOW)
  for (const level of ['log', 'warn', 'error'] as const) {
    jest.spyOn(Logger.prototype, level).mockImplementation(() => undefined)
  }
})

afterEach(() => {
  jest.restoreAllMocks()
})

describe('the events of a bootstrap acceptance', () => {
  it('reports the workspace it created, then the acceptance', async () => {
    const h = build()
    h.workspaces.findById.mockResolvedValue(null)
    await seed(h, bootstrapRecord())

    await h.service.accept(CALLER, TOKEN, CONTEXT)

    expect(emitted(h)).toEqual(['workspace.created', 'invitation.accepted'])
    expect(h.events.emit).toHaveBeenNthCalledWith(
      1,
      {
        type: 'workspace.created',
        ...WORKSPACE_REF,
        actorUserId: 'caller',
        at: new Date(NOW).toISOString()
      },
      CONTEXT
    )
  })

  it('reports the workspace even when the token cannot be spent afterwards', async () => {
    const h = build()
    h.workspaces.findById.mockResolvedValue(null)
    await seed(h, bootstrapRecord())
    jest.spyOn(h.store, 'remove').mockRejectedValue(new Error('redis down'))

    await expect(h.service.accept(CALLER, TOKEN, CONTEXT)).rejects.toThrow('redis down')

    expect(emitted(h)).toEqual(['workspace.created'])
  })

  it('does not report a creation it did not make, on a retry or at the owner cap', async () => {
    const retry = build()
    retry.memberships.find.mockResolvedValue(member('caller', 'owner'))
    await seed(retry, bootstrapRecord())
    const capped = build()
    capped.workspaces.findById.mockResolvedValue(null)
    capped.workspaces.createWithOwner.mockResolvedValue({ status: 'limit_reached' })
    await seed(capped, bootstrapRecord())

    await retry.service.accept(CALLER, TOKEN, CONTEXT)
    await expect(code(capped.service.accept(CALLER, TOKEN, CONTEXT))).resolves.toBe(
      AUTH_ERROR_CODES.WORKSPACE_LIMIT_REACHED
    )

    expect(emitted(retry)).toEqual(['invitation.accepted'])
    expect(emitted(capped)).toEqual([])
  })
})

describe('an acceptance whose cache step fails', () => {
  it('fails, and still reports the membership it wrote', async () => {
    const h = build()
    await seed(h)
    h.access.invalidateMembership.mockRejectedValue(new Error('redis down'))

    await expect(h.service.accept(CALLER, TOKEN, CONTEXT)).rejects.toThrow('redis down')

    expect(emitted(h)).toEqual(['invitation.accepted'])
  })
})

describe('beforeWorkspaceCreate on an invitation signup', () => {
  const context = {
    plane: 'dashboard',
    tenantId: 't1',
    ip: '203.0.113.7',
    userAgent: 'jest',
    sanitizedHeaders: { 'user-agent': 'jest' },
    accountPending: true
  }

  it('leaves no account, no workspace and an unspent token when the host refuses', async () => {
    const h = await bootstrapSignup(
      jest.fn().mockResolvedValue({ allowed: false, reason: 'no plan' })
    )

    await expect(code(h.service.acceptSignup(SIGNUP, REQUEST))).resolves.toBe(
      AUTH_ERROR_CODES.FORBIDDEN
    )

    expect(h.users.create).not.toHaveBeenCalled()
    expect(h.workspaces.createWithOwner).not.toHaveBeenCalled()
    expect(await unspent(h)).toBe(true)
  })

  it('asks once, before the account, with a frozen provisional user and the marker', async () => {
    const beforeWorkspaceCreate = jest.fn().mockResolvedValue({ allowed: true })
    const h = await bootstrapSignup(beforeWorkspaceCreate)

    await h.service.acceptSignup(SIGNUP, REQUEST)

    expect(beforeWorkspaceCreate).toHaveBeenCalledTimes(1)
    expect(beforeWorkspaceCreate).toHaveBeenCalledWith(
      {
        id: '',
        email: EMAIL,
        name: 'Ada Lovelace',
        tenantId: 't1',
        role: '',
        status: '',
        emailVerified: true,
        mfaEnabled: false,
        lastLoginAt: null,
        createdAt: new Date(NOW)
      },
      { name: 'Acme' },
      context
    )
    expect(Object.isFrozen(beforeWorkspaceCreate.mock.calls[0]?.[0])).toBe(true)
    expect(beforeWorkspaceCreate.mock.invocationCallOrder[0]).toBeLessThan(
      h.users.create.mock.invocationCallOrder[0] as number
    )
    expect(h.users.create).toHaveBeenCalledTimes(1)
    expect(h.users.create).toHaveBeenCalledWith(
      expect.objectContaining({ email: EMAIL, name: SIGNUP.name, tenantId: 't1' })
    )
    expect(h.workspaces.createWithOwner).toHaveBeenCalledWith(
      expect.objectContaining({ ownerUserId: 'new' })
    )
    expect(await unspent(h)).toBe(false)
  })

  it('refuses closed for a hook that looks the provisional user up by id', async () => {
    const beforeWorkspaceCreate = jest.fn()
    const h = await bootstrapSignup(beforeWorkspaceCreate)
    h.users.findById.mockResolvedValue(null)
    beforeWorkspaceCreate.mockImplementation(async ({ id }: { id: string }) => ({
      allowed: (await h.users.findById({ id })) !== null
    }))

    await expect(code(h.service.acceptSignup(SIGNUP, REQUEST))).resolves.toBe(
      AUTH_ERROR_CODES.FORBIDDEN
    )

    expect(h.users.create).not.toHaveBeenCalled()
  })

  it('sets no marker for an account that exists', async () => {
    const beforeWorkspaceCreate = jest.fn().mockResolvedValue({ allowed: true })
    const h = await bootstrapSignup(beforeWorkspaceCreate)

    await h.service.accept(CALLER, TOKEN, CONTEXT)

    expect(beforeWorkspaceCreate).toHaveBeenCalledWith(
      expect.objectContaining({ id: 'caller' }),
      { name: 'Acme' },
      CONTEXT
    )
    expect(beforeWorkspaceCreate.mock.calls[0]?.[2]).not.toHaveProperty('accountPending')
  })

  it.each([
    ['a member invitation', memberRecord(), workspaceRow()],
    ['a bootstrap invitation whose workspace exists', bootstrapRecord(), workspaceRow()]
  ])('asks nothing for %s', async (_name, record, row) => {
    const beforeWorkspaceCreate = jest.fn()
    const h = build(false, { beforeWorkspaceCreate })
    h.workspaces.findById.mockResolvedValue(row)
    h.memberships.find.mockImplementation(async ({ userId }: { userId: string }) =>
      member(userId, userId === 'inviter' ? 'editor' : 'owner')
    )
    await seed(h, record)

    await h.service.acceptSignup(SIGNUP, REQUEST)

    expect(beforeWorkspaceCreate).not.toHaveBeenCalled()
    expect(h.users.create).toHaveBeenCalledTimes(1)
    expect(h.users.create).toHaveBeenCalledWith(
      expect.objectContaining({ email: EMAIL, name: SIGNUP.name, tenantId: 't1' })
    )
  })
})

describe('beforeWorkspaceCreate for an account an OAuth flow is about to create', () => {
  const account = { email: EMAIL, name: 'Ada' }
  const asked: HookContext = { ...CONTEXT, email: EMAIL }

  it('asks nothing again at completion once the host was asked before the account', async () => {
    const beforeWorkspaceCreate = jest.fn().mockResolvedValue({ allowed: true })
    const h = await bootstrapSignup(beforeWorkspaceCreate)
    const loaded = await h.service.prepareOAuth(sha256(TOKEN), 't1', {
      email: EMAIL,
      emailVerified: true
    })

    const hostAsked = await h.service.judgeNewAccount(loaded, account, asked)
    await h.service.completeOAuth(loaded, user('new', { email: EMAIL }), true, CONTEXT, hostAsked)

    expect(hostAsked).toBe(true)
    expect(beforeWorkspaceCreate).toHaveBeenCalledTimes(1)
    expect(beforeWorkspaceCreate).toHaveBeenCalledWith(
      expect.objectContaining({ id: '', name: 'Ada' }),
      { name: 'Acme' },
      { ...asked, accountPending: true }
    )
    expect(h.workspaces.createWithOwner).toHaveBeenCalledTimes(1)
    expect(h.workspaces.createWithOwner).toHaveBeenCalledWith(
      expect.objectContaining({ ownerUserId: 'new', name: 'Acme' })
    )
  })

  it('refuses when the host refuses, with the token unspent', async () => {
    const h = await bootstrapSignup(jest.fn().mockResolvedValue({ allowed: false }))
    const loaded = await h.service.prepareOAuth(sha256(TOKEN), 't1', {
      email: EMAIL,
      emailVerified: true
    })

    await expect(code(h.service.judgeNewAccount(loaded, account, asked))).resolves.toBe(
      AUTH_ERROR_CODES.FORBIDDEN
    )

    expect(await unspent(h)).toBe(true)
  })

  it('answers that the host was not asked when the bootstrap workspace exists', async () => {
    const h = await bootstrapSignup(jest.fn())
    const loaded = await h.service.prepareOAuth(sha256(TOKEN), 't1', {
      email: EMAIL,
      emailVerified: true
    })
    h.workspaces.findById.mockResolvedValue(workspaceRow())

    await expect(h.service.judgeNewAccount(loaded, account, asked)).resolves.toBe(false)
  })

  it('asks nothing for a member invitation', async () => {
    const beforeWorkspaceCreate = jest.fn()
    const h = build(false, { beforeWorkspaceCreate })
    await seed(h)
    const loaded = await h.service.prepareOAuth(sha256(TOKEN), 't1', {
      email: EMAIL,
      emailVerified: true
    })

    await expect(h.service.judgeNewAccount(loaded, account, asked)).resolves.toBe(false)

    expect(beforeWorkspaceCreate).not.toHaveBeenCalled()
  })
})
