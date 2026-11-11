/**
 * @fileoverview Tests for the platform bootstrap invitations of `WorkspaceInvitationService`: the
 * invitation of someone to own a workspace that does not exist yet, its preview and its withdrawal.
 *
 * @layer Test
 */

import { NOW, build, code, sent, user } from './__tests__/workspace-invitation-harness'
import { CONTEXT, WORKSPACE_REF, workspaceRow } from './__tests__/workspace-service-harness'
import { OWNER } from './__tests__/workspace-invitation-harness'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'

describe('WorkspaceInvitationService', () => {
  beforeEach(() => {
    jest.spyOn(Date, 'now').mockReturnValue(NOW)
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  describe('platform bootstrap invitations', () => {
    const PLATFORM = {
      tenantId: 't1',
      email: 'Owner@Example.com',
      workspaceName: '  Acme  ',
      inviterName: 'The Platform'
    }

    it('stores a bootstrap record under a fresh workspace id, mails it and answers the id', async () => {
      const h = build()

      const { workspaceId } = await h.service.inviteAsPlatform(PLATFORM, CONTEXT)

      expect(workspaceId).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
      )
      const ref = { tenantId: 't1', workspaceId }
      const stored = await h.store.readByEmail(ref, 'owner@example.com')
      expect(stored?.record).toEqual({
        kind: 'bootstrap',
        email: 'owner@example.com',
        role: 'owner',
        ...ref,
        createdAt: new Date(NOW).toISOString(),
        resendCount: 0,
        workspaceName: 'Acme'
      })
      expect(sent(h)).toEqual({
        to: 'owner@example.com',
        data: {
          inviterName: 'The Platform',
          workspaceName: 'Acme',
          role: 'owner',
          inviteToken: expect.stringMatching(/^[0-9a-f]{64}$/),
          expiresAt: new Date(NOW + 604_800_000),
          accountExists: false,
          kind: 'bootstrap'
        }
      })
      expect(h.events.emit).toHaveBeenCalledWith(
        {
          type: 'member.invited',
          ...ref,
          actorUserId: null,
          email: 'owner@example.com',
          role: 'owner',
          at: new Date(NOW).toISOString()
        },
        CONTEXT
      )
    })

    it('tells the message an account exists, and gives each call its own workspace', async () => {
      const h = build()
      h.users.findByEmail.mockResolvedValue(user('existing'))

      const first = await h.service.inviteAsPlatform(PLATFORM, CONTEXT)
      const second = await h.service.inviteAsPlatform(PLATFORM, CONTEXT)

      expect(first.workspaceId).not.toBe(second.workspaceId)
      expect(sent(h).data.accountExists).toBe(true)
      expect(h.email.sendWorkspaceInvitation).toHaveBeenCalledTimes(2)
    })

    it('answers a publish that could not happen, an index already taken, as too many requests', async () => {
      const h = build()
      jest.spyOn(h.store, 'publish').mockResolvedValue('lost')

      expect(await code(h.service.inviteAsPlatform(PLATFORM, CONTEXT))).toBe(
        AUTH_ERROR_CODES.TOO_MANY_REQUESTS
      )

      expect(h.email.sendWorkspaceInvitation).not.toHaveBeenCalled()
    })

    it('refuses an unusable workspace name before storing or mailing anything', async () => {
      const h = build()

      expect(
        await code(h.service.inviteAsPlatform({ ...PLATFORM, workspaceName: '   ' }, CONTEXT))
      ).toBe(AUTH_ERROR_CODES.VALIDATION)

      expect(h.email.sendWorkspaceInvitation).not.toHaveBeenCalled()
    })

    it('previews as the workspace to be created, with no inviter, after the same three reads', async () => {
      const h = build()
      h.workspaces.findById.mockResolvedValue(null)
      await h.service.inviteAsPlatform(PLATFORM, CONTEXT)
      h.workspaces.findById.mockClear()
      h.users.findById.mockClear()
      h.users.findByEmail.mockClear()

      const answer = await h.service.preview(sent(h).data.inviteToken)

      expect(answer).toEqual({
        kind: 'bootstrap',
        workspaceName: 'Acme',
        role: 'owner',
        maskedEmail: expect.stringMatching(/^o.*@example\.com$/),
        accountExists: false
      })
      expect(h.workspaces.findById).toHaveBeenCalledTimes(1)
      expect(h.users.findById).toHaveBeenCalledTimes(1)
      expect(h.users.findByEmail).toHaveBeenCalledTimes(1)
    })

    it('previews as invalid when the workspace exists and is not active, and still when it is active', async () => {
      const h = build()
      await h.service.inviteAsPlatform(PLATFORM, CONTEXT)
      const token = sent(h).data.inviteToken
      h.workspaces.findById.mockResolvedValueOnce(workspaceRow({ status: 'pending_deletion' }))

      expect(await code(h.service.preview(token))).toBe(AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN)
      h.workspaces.findById.mockResolvedValueOnce(workspaceRow())

      expect(Object.keys(await h.service.preview(token))).not.toContain('inviterName')
    })

    it('lists no bootstrap invitation in a workspace list', async () => {
      const h = build()
      const { workspaceId } = await h.service.inviteAsPlatform(PLATFORM, CONTEXT)

      expect(await h.service.list({ tenantId: 't1', workspaceId }, {})).toEqual({
        items: [],
        nextCursor: null
      })
    })

    it('revokes a bootstrap invitation by its workspace id and reports it', async () => {
      const h = build()
      const { workspaceId } = await h.service.inviteAsPlatform(PLATFORM, CONTEXT)
      const ref = { tenantId: 't1', workspaceId }
      const token = sent(h).data.inviteToken
      h.events.emit.mockClear()

      await h.service.revokeAsPlatform(ref, 'OWNER@example.com', CONTEXT)

      expect(await h.store.readByEmail(ref, 'owner@example.com')).toBeNull()
      expect(await code(h.service.preview(token))).toBe(AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN)
      expect(h.events.emit).toHaveBeenCalledWith(
        {
          type: 'invitation.revoked',
          ...ref,
          actorUserId: null,
          email: 'owner@example.com',
          role: 'owner',
          at: new Date(NOW).toISOString()
        },
        CONTEXT
      )
    })

    it('leaves a member invitation, and an address with none, alone', async () => {
      const h = build()
      await h.service.invite(WORKSPACE_REF, OWNER, 'a@example.com', 'viewer', CONTEXT)
      h.events.emit.mockClear()

      await h.service.revokeAsPlatform(WORKSPACE_REF, 'a@example.com', CONTEXT)
      await h.service.revokeAsPlatform(WORKSPACE_REF, 'nobody@example.com', CONTEXT)

      expect(await h.store.pending(WORKSPACE_REF)).toHaveLength(1)
      expect(h.events.emit).not.toHaveBeenCalled()
    })
  })
})
