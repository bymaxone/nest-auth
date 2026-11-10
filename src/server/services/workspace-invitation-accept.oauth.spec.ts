/**
 * @fileoverview Tests for the OAuth halves of `WorkspaceInvitationAcceptService`: vetting an
 * invitation against a provider profile before the account is known, and completing it once it is.
 *
 * @layer Test
 */

import { Logger } from '@nestjs/common'

import {
  EMAIL,
  NOW,
  TOKEN,
  bootstrapRecord,
  build,
  code,
  memberRecord,
  seed,
  user
} from './__tests__/workspace-invitation-accept-harness'
import type { Harness } from './__tests__/workspace-invitation-accept-harness'
import { CONTEXT, WORKSPACE_REF, workspaceRow } from './__tests__/workspace-service-harness'
import { invitationKey } from '../constants/workspace-invitation-keys'
import { sha256 } from '../crypto/secure-token'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'

const HASH = sha256(TOKEN)
const VERIFIED = { email: EMAIL, emailVerified: true }

/** Whether the invitation seeded under `TOKEN` is still redeemable. */
async function stillThere(h: Harness): Promise<boolean> {
  return (await h.store.readByHash(invitationKey(TOKEN).slice(5))) !== null
}

describe('WorkspaceInvitationAcceptService OAuth acceptance', () => {
  beforeEach(() => {
    jest.spyOn(Date, 'now').mockReturnValue(NOW)
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  describe('prepareOAuth', () => {
    it('vets a record against a verified profile without spending it', async () => {
      const h = build()
      await seed(h)

      await expect(h.service.prepareOAuth(HASH, 't1', VERIFIED)).resolves.toBeDefined()

      expect(await stillThere(h)).toBe(true)
      expect(h.memberships.create).not.toHaveBeenCalled()
    })

    it.each([
      [
        'an unknown hash',
        'f'.repeat(64),
        't1',
        VERIFIED,
        AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN
      ],
      ['another tenant', HASH, 't2', VERIFIED, AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN],
      [
        'a verified profile for another address',
        HASH,
        't1',
        { email: 'other@example.com', emailVerified: true },
        AUTH_ERROR_CODES.INVITATION_EMAIL_MISMATCH
      ],
      [
        'an unverified profile for another address',
        HASH,
        't1',
        { email: 'other@example.com', emailVerified: false },
        AUTH_ERROR_CODES.INVITATION_EMAIL_MISMATCH
      ],
      [
        'an unverified profile for the invited address',
        HASH,
        't1',
        { email: EMAIL, emailVerified: false },
        AUTH_ERROR_CODES.EMAIL_NOT_VERIFIED
      ]
    ])(
      'refuses %s with %s and leaves the token usable',
      async (_n, hash, tenant, profile, expected) => {
        const h = build()
        await seed(h)

        expect(await code(h.service.prepareOAuth(hash, tenant, profile))).toBe(expected)

        expect(await stillThere(h)).toBe(true)
      }
    )

    it('compares the profile address in lowercase', async () => {
      const h = build()
      await seed(h)

      await expect(
        h.service.prepareOAuth(HASH, 't1', { email: EMAIL.toUpperCase(), emailVerified: true })
      ).resolves.toBeDefined()
    })

    it('refuses when the inviter can no longer grant the role', async () => {
      const h = build()
      await seed(h)
      h.memberships.find.mockResolvedValue(null)
      jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      expect(await code(h.service.prepareOAuth(HASH, 't1', VERIFIED))).toBe(
        AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN
      )
    })
  })

  describe('completeOAuth', () => {
    it('writes the membership, spends the token and tells the cache and the hook', async () => {
      const h = build()
      await seed(h)
      const invitation = await h.service.prepareOAuth(HASH, 't1', VERIFIED)

      const answer = await h.service.completeOAuth(
        invitation,
        user('new', { email: EMAIL }),
        true,
        CONTEXT
      )

      expect(answer).toEqual({ workspaceId: 'w1', role: 'viewer' })
      expect(h.memberships.create).toHaveBeenCalledWith(
        expect.objectContaining({ ...WORKSPACE_REF, userId: 'new', role: 'viewer' })
      )
      expect(await stillThere(h)).toBe(false)
      expect(h.access.invalidateMembership).toHaveBeenCalledWith({
        ...WORKSPACE_REF,
        userId: 'new'
      })
      expect(h.events.emit).toHaveBeenCalledWith(
        expect.objectContaining({ type: 'invitation.accepted', userId: 'new', role: 'viewer' }),
        CONTEXT
      )
    })

    it('refuses when the invitation is revoked between the vetting and the completion, writing nothing', async () => {
      const h = build()
      await seed(h)
      const invitation = await h.service.prepareOAuth(HASH, 't1', VERIFIED)
      await h.store.remove(WORKSPACE_REF, EMAIL, invitationKey(TOKEN))

      const refused = h.service.completeOAuth(
        invitation,
        user('new', { email: EMAIL }),
        true,
        CONTEXT
      )

      expect(await code(refused)).toBe(AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN)
      expect(h.memberships.create).not.toHaveBeenCalled()
    })

    it.each([
      ['the inviter is removed', (h: Harness) => h.memberships.find.mockResolvedValue(null)],
      [
        'the workspace is no longer active',
        (h: Harness) =>
          h.workspaces.findById.mockResolvedValue(workspaceRow({ status: 'pending_deletion' }))
      ]
    ])(
      'refuses when %s between the vetting and the completion, writing and spending nothing',
      async (_n, change) => {
        const h = build()
        await seed(h)
        const invitation = await h.service.prepareOAuth(HASH, 't1', VERIFIED)
        change(h)
        jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

        const refused = h.service.completeOAuth(
          invitation,
          user('new', { email: EMAIL }),
          true,
          CONTEXT
        )

        expect(await code(refused)).toBe(AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN)
        expect(h.memberships.create).not.toHaveBeenCalled()
        expect(await stillThere(h)).toBe(true)
      }
    )

    it('refuses an account of another tenant, writing and spending nothing', async () => {
      const h = build()
      await seed(h)
      const invitation = await h.service.prepareOAuth(HASH, 't1', VERIFIED)

      const refused = h.service.completeOAuth(
        invitation,
        user('new', { email: EMAIL, tenantId: 't2' }),
        false,
        CONTEXT
      )

      expect(await code(refused)).toBe(AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN)
      expect(h.memberships.create).not.toHaveBeenCalled()
      expect(await stillThere(h)).toBe(true)
    })

    it('refuses an account whose address is not the invited one, writing and spending nothing', async () => {
      const h = build()
      await seed(h)
      const invitation = await h.service.prepareOAuth(HASH, 't1', VERIFIED)

      const refused = h.service.completeOAuth(invitation, user('other'), false, CONTEXT)

      expect(await code(refused)).toBe(AUTH_ERROR_CODES.INVITATION_EMAIL_MISMATCH)
      expect(h.memberships.create).not.toHaveBeenCalled()
      expect(await stillThere(h)).toBe(true)
    })

    it('refuses an account whose address is not verified, writing and spending nothing', async () => {
      const h = build()
      await seed(h)
      const invitation = await h.service.prepareOAuth(HASH, 't1', VERIFIED)

      const refused = h.service.completeOAuth(
        invitation,
        user('new', { email: EMAIL, emailVerified: false }),
        false,
        CONTEXT
      )

      expect(await code(refused)).toBe(AUTH_ERROR_CODES.EMAIL_NOT_VERIFIED)
      expect(h.memberships.create).not.toHaveBeenCalled()
      expect(await stillThere(h)).toBe(true)
    })

    it.each([
      ['a created account', true, 1],
      ['an existing account', false, 0]
    ])('runs the after-acceptance hook for %s %s time(s)', async (_n, created, calls) => {
      const afterInvitationAccepted = jest.fn()
      const h = build(false, { afterInvitationAccepted })
      await seed(h)
      const invitation = await h.service.prepareOAuth(HASH, 't1', VERIFIED)

      await h.service.completeOAuth(invitation, user('new', { email: EMAIL }), created, CONTEXT)

      expect(afterInvitationAccepted).toHaveBeenCalledTimes(calls)
    })

    it('does not let a throwing after-acceptance hook change the answer', async () => {
      const afterInvitationAccepted = jest.fn(() => {
        throw new Error('hook')
      })
      jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
      const error = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
      const h = build(false, { afterInvitationAccepted })
      await seed(h)
      const invitation = await h.service.prepareOAuth(HASH, 't1', VERIFIED)

      await expect(
        h.service.completeOAuth(invitation, user('new', { email: EMAIL }), true, CONTEXT)
      ).resolves.toEqual({ workspaceId: 'w1', role: 'viewer' })
      expect(error).toHaveBeenCalledWith(
        expect.stringContaining('afterInvitationAccepted hook threw')
      )
    })
  })

  describe('a bootstrap invitation', () => {
    it('creates the workspace owned by the account and never consults allowCreate', async () => {
      const h = build(false, {}, { allowCreate: false })
      await seed(h, bootstrapRecord())
      h.workspaces.findById.mockResolvedValue(null)
      const invitation = await h.service.prepareOAuth(HASH, 't1', VERIFIED)

      const answer = await h.service.completeOAuth(
        invitation,
        user('new', { email: EMAIL }),
        true,
        CONTEXT
      )

      expect(answer).toEqual({ workspaceId: 'w1', role: 'owner' })
      expect(h.workspaces.createWithOwner).toHaveBeenCalledWith(
        expect.objectContaining({ ownerUserId: 'new', name: 'Acme' })
      )
      expect(await stillThere(h)).toBe(false)
    })

    it('refuses at the owner cap with auth.workspace_limit_reached and spends nothing', async () => {
      const h = build(false, {}, { maxWorkspacesPerUser: 1 })
      await seed(h, bootstrapRecord())
      h.workspaces.findById.mockResolvedValue(null)
      h.memberships.countOwned.mockResolvedValue(1)
      const invitation = await h.service.prepareOAuth(HASH, 't1', VERIFIED)

      const refused = h.service.completeOAuth(
        invitation,
        user('new', { email: EMAIL }),
        true,
        CONTEXT
      )

      expect(await code(refused)).toBe(AUTH_ERROR_CODES.WORKSPACE_LIMIT_REACHED)
      expect(h.workspaces.createWithOwner).not.toHaveBeenCalled()
      expect(await stillThere(h)).toBe(true)
    })

    it('refuses when beforeWorkspaceCreate does, with its reason, and spends nothing', async () => {
      const beforeWorkspaceCreate = jest.fn().mockResolvedValue({ allowed: false, reason: 'plan' })
      const h = build(false, { beforeWorkspaceCreate })
      await seed(h, bootstrapRecord())
      h.workspaces.findById.mockResolvedValue(null)
      const invitation = await h.service.prepareOAuth(HASH, 't1', VERIFIED)

      const refused = h.service.completeOAuth(
        invitation,
        user('new', { email: EMAIL }),
        true,
        CONTEXT
      )

      expect(await code(refused)).toBe(AUTH_ERROR_CODES.FORBIDDEN)
      expect(beforeWorkspaceCreate).toHaveBeenCalledWith(
        expect.objectContaining({ id: 'new' }),
        { name: 'Acme' },
        CONTEXT
      )
      expect(h.workspaces.createWithOwner).not.toHaveBeenCalled()
      expect(await stillThere(h)).toBe(true)
    })
  })

  // A member record is still a member record when read through the OAuth door.
  it('treats a member record as a member invitation, not a bootstrap one', async () => {
    const h = build()
    await seed(h, memberRecord({ role: 'viewer' }))
    const invitation = await h.service.prepareOAuth(HASH, 't1', VERIFIED)

    await h.service.completeOAuth(invitation, user('new', { email: EMAIL }), false, CONTEXT)

    expect(h.workspaces.createWithOwner).not.toHaveBeenCalled()
  })
})
