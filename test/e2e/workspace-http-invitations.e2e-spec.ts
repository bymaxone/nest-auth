/**
 * End-to-end workspace invitation routes: invite, list, resend, revoke and preview.
 *
 * The specs drive the real HTTP stack over in-memory repositories and a captured mailbox. What they
 * pin is who may invite to which role, that a token is shown to nobody but the mailbox, that a
 * resend retires the previous token, and that every token a preview cannot honour gets one answer.
 *
 * @layer Test
 */

import type { INestApplication } from '@nestjs/common'
import request from 'supertest'

import {
  BYMAX_AUTH_MEMBERSHIP_REPOSITORY,
  BYMAX_AUTH_WORKSPACE_REPOSITORY
} from '../../src/server/bymax-auth.constants'
import { WorkspaceAccessService } from '../../src/server/services/workspace-access.service'
import { bootstrapTestApp, expectAuthError, freezeClock, restoreClock } from './setup'
import type { BootstrappedTestApp } from './setup'
import { memoryRepositories } from './workspace-memory-repositories'

const PASSWORD = 'SuperSecret123!'
const TOKEN_IN_MAIL = /[0-9a-f]{64}/

interface Account {
  id: string
  email: string
  authorization: string
}

describe('workspace invitation routes (E2E)', () => {
  let boot: BootstrappedTestApp
  let app: INestApplication
  let repositories: ReturnType<typeof memoryRepositories>
  let sequence = 0

  beforeAll(async () => {
    repositories = memoryRepositories()
    boot = await bootstrapTestApp(
      {
        tokenDelivery: 'bearer',
        workspaces: {
          enabled: true,
          roles: {
            hierarchy: { owner: ['editor', 'viewer'], editor: ['viewer'], viewer: [] },
            ownerRole: 'owner'
          },
          permissions: { manageMembers: ['owner', 'editor'] }
        }
      },
      {
        controllers: { auth: true, workspaces: true, workspaceInvitations: true },
        extraModuleProviders: [
          { provide: BYMAX_AUTH_WORKSPACE_REPOSITORY, useValue: repositories.workspaces },
          { provide: BYMAX_AUTH_MEMBERSHIP_REPOSITORY, useValue: repositories.memberships }
        ]
      }
    )
    app = boot.app
  })

  afterAll(async () => {
    await app.close()
  })

  afterEach(() => {
    restoreClock()
  })

  async function signUp(): Promise<Account> {
    sequence += 1
    const email = `invitee${sequence}@example.com`
    const res = await request(app.getHttpServer())
      .post('/register')
      .send({ email, password: PASSWORD, name: `Person ${sequence}`, tenantId: 'tenant-1' })
    const body = res.body as { accessToken: string; user: { id: string } }
    return { id: body.user.id, email, authorization: `Bearer ${body.accessToken}` }
  }

  async function team(): Promise<{ id: string; owner: Account; editor: Account }> {
    const [owner, editor] = [await signUp(), await signUp()]
    const created = await request(app.getHttpServer())
      .post('/workspaces')
      .set('Authorization', owner.authorization)
      .send({ name: 'Team' })
    const id = (created.body as { id: string }).id
    repositories.seedMember(id, editor.id, 'editor')
    await app
      .get(WorkspaceAccessService, { strict: false })
      .invalidateMembership({ tenantId: 'tenant-1', workspaceId: id, userId: editor.id })
    return { id, owner, editor }
  }

  function post(path: string, account: Account, body: object): request.Test {
    return request(app.getHttpServer())
      .post(path)
      .set('Authorization', account.authorization)
      .send(body)
  }

  function invite(id: string, account: Account, email: string, role = 'viewer'): request.Test {
    return post(`/workspaces/${id}/invitations`, account, { email, role })
  }

  function preview(token: string): request.Test {
    return request(app.getHttpServer()).post('/workspaces/invitations/preview').send({ token })
  }

  /** The token of the newest message sent to an address. */
  function tokenSentTo(email: string): string {
    const mail = [...boot.email.sentEmails].reverse().find((sent) => sent.to === email)
    return TOKEN_IN_MAIL.exec(mail?.html ?? '')?.[0] ?? ''
  }

  function list(id: string, account: Account, query = ''): request.Test {
    return request(app.getHttpServer())
      .get(`/workspaces/${id}/invitations${query}`)
      .set('Authorization', account.authorization)
  }

  describe('POST /workspaces/:workspaceId/invitations', () => {
    it('answers 204 and mails a token that previews what it is for', async () => {
      const { id, owner } = await team()

      const res = await invite(id, owner, 'new.person@example.com')

      expect(res.status).toBe(204)
      expect((await preview(tokenSentTo('new.person@example.com'))).body).toEqual({
        kind: 'member',
        workspaceName: 'Team',
        inviterName: expect.stringContaining('Person'),
        role: 'viewer',
        maskedEmail: expect.stringMatching(/^n.*@example\.com$/),
        accountExists: false
      })
    })

    it('tells the message and the preview that the address already has an account', async () => {
      const { id, owner } = await team()
      const existing = await signUp()

      await invite(id, owner, existing.email)

      expect(boot.email.sentEmails.at(-1)?.html).toContain('signin')
      expect((await preview(tokenSentTo(existing.email))).body).toMatchObject({
        accountExists: true
      })
    })

    it('refuses an address that already belongs to the workspace', async () => {
      const { id, owner, editor } = await team()

      expectAuthError(await invite(id, owner, editor.email), 'auth.already_member')
    })

    it('refuses a role outside the hierarchy, naming the role', async () => {
      const { id, owner } = await team()

      const res = await invite(id, owner, 'a@example.com', 'ghost')

      expectAuthError(res, 'auth.validation')
      expect(res.body).toMatchObject({ error: { details: [{ field: 'role' }] } })
    })

    it('lets a non-owner invite only to a role strictly below their own', async () => {
      const { id, editor } = await team()

      expect((await invite(id, editor, 'low@example.com', 'viewer')).status).toBe(204)
      expectAuthError(
        await invite(id, editor, 'peer@example.com', 'editor'),
        'auth.insufficient_workspace_role'
      )
      expectAuthError(
        await invite(id, editor, 'boss@example.com', 'owner'),
        'auth.insufficient_workspace_role'
      )
    })

    it('lets the owner invite to any role, the owner role included', async () => {
      const { id, owner } = await team()

      expect((await invite(id, owner, 'second.owner@example.com', 'owner')).status).toBe(204)
    })

    it('refuses a caller whose role does not allow managing members', async () => {
      const { id } = await team()
      const outsider = await signUp()

      expectAuthError(await invite(id, outsider, 'x@example.com'), 'auth.workspace_not_found')
    })

    it('refuses an unknown property, naming it', async () => {
      const { id, owner } = await team()

      const res = await post(`/workspaces/${id}/invitations`, owner, {
        email: 'a@example.com',
        role: 'viewer',
        extra: 1
      })

      expectAuthError(res, 'auth.validation')
    })
  })

  describe('a second invitation for the same address', () => {
    it('is held to the resend cooldown and then replaces the first token', async () => {
      freezeClock()
      const { id, owner } = await team()
      await invite(id, owner, 'again@example.com')
      const first = tokenSentTo('again@example.com')

      expectAuthError(await invite(id, owner, 'again@example.com'), 'auth.too_many_requests')

      jest.setSystemTime(Date.now() + 61_000)
      expect((await invite(id, owner, 'again@example.com')).status).toBe(204)
      const second = tokenSentTo('again@example.com')
      expect(second).not.toBe(first)
      expectAuthError(await preview(first), 'auth.invalid_invitation_token')
      expect((await preview(second)).status).toBe(200)
      expect((await list(id, owner)).body).toMatchObject({
        items: [{ email: 'again@example.com', resendCount: 1 }]
      })
    })

    it('may not displace an invitation to a role above the caller', async () => {
      freezeClock()
      const { id, owner, editor } = await team()
      await invite(id, owner, 'senior@example.com', 'editor')
      jest.setSystemTime(Date.now() + 61_000)

      expectAuthError(
        await invite(id, editor, 'senior@example.com', 'viewer'),
        'auth.insufficient_workspace_role'
      )
      expect((await preview(tokenSentTo('senior@example.com'))).body).toMatchObject({
        role: 'editor'
      })
    })
  })

  describe('POST /workspaces/:workspaceId/invitations/resend', () => {
    it('mails a new token, retires the old one and counts the resend', async () => {
      freezeClock()
      const { id, owner } = await team()
      await invite(id, owner, 'resend@example.com')
      const first = tokenSentTo('resend@example.com')
      jest.setSystemTime(Date.now() + 61_000)

      const res = await post(`/workspaces/${id}/invitations/resend`, owner, {
        email: 'RESEND@example.com '
      })

      expect(res.status).toBe(204)
      expectAuthError(await preview(first), 'auth.invalid_invitation_token')
      expect((await preview(tokenSentTo('resend@example.com'))).status).toBe(200)
      expect((await list(id, owner)).body).toMatchObject({ items: [{ resendCount: 1 }] })
    })

    it('refuses inside the cooldown and after the fifth resend', async () => {
      freezeClock()
      const { id, owner } = await team()
      await invite(id, owner, 'limit@example.com')
      expectAuthError(
        await post(`/workspaces/${id}/invitations/resend`, owner, { email: 'limit@example.com' }),
        'auth.too_many_requests'
      )

      for (let i = 0; i < 5; i += 1) {
        jest.setSystemTime(Date.now() + 61_000)
        expect(
          (
            await post(`/workspaces/${id}/invitations/resend`, owner, {
              email: 'limit@example.com'
            })
          ).status
        ).toBe(204)
      }
      jest.setSystemTime(Date.now() + 61_000)

      expectAuthError(
        await post(`/workspaces/${id}/invitations/resend`, owner, { email: 'limit@example.com' }),
        'auth.too_many_requests'
      )
    })

    it('answers 204 and sends nothing for an address that has no invitation', async () => {
      const { id, owner } = await team()
      const before = boot.email.sentEmails.length

      const res = await post(`/workspaces/${id}/invitations/resend`, owner, {
        email: 'nobody@example.com'
      })

      expect(res.status).toBe(204)
      expect(boot.email.sentEmails).toHaveLength(before)
    })

    it('answers 204 and changes nothing for an invitation above the caller', async () => {
      freezeClock()
      const { id, owner, editor } = await team()
      await invite(id, owner, 'above@example.com', 'editor')
      const token = tokenSentTo('above@example.com')
      jest.setSystemTime(Date.now() + 61_000)

      const res = await post(`/workspaces/${id}/invitations/resend`, editor, {
        email: 'above@example.com'
      })

      expect(res.status).toBe(204)
      expect((await preview(token)).status).toBe(200)
    })
  })

  describe('POST /workspaces/:workspaceId/invitations/revoke', () => {
    it('withdraws the invitation so its token previews as invalid and the list is empty', async () => {
      const { id, owner } = await team()
      await invite(id, owner, 'gone@example.com')
      const token = tokenSentTo('gone@example.com')

      const res = await post(`/workspaces/${id}/invitations/revoke`, owner, {
        email: 'gone@example.com'
      })

      expect(res.status).toBe(204)
      expectAuthError(await preview(token), 'auth.invalid_invitation_token')
      expect((await list(id, owner)).body).toEqual({ items: [], nextCursor: null })
    })

    it('leaves an invitation above the caller in place and answers as for an absent one', async () => {
      const { id, owner, editor } = await team()
      await invite(id, owner, 'keep@example.com', 'editor')

      const res = await post(`/workspaces/${id}/invitations/revoke`, editor, {
        email: 'keep@example.com'
      })

      expect(res.status).toBe(204)
      expect((await preview(tokenSentTo('keep@example.com'))).status).toBe(200)
    })
  })

  describe('GET /workspaces/:workspaceId/invitations', () => {
    it('lists pending invitations oldest first, without any token', async () => {
      freezeClock()
      const { id, owner } = await team()
      await invite(id, owner, 'one@example.com')
      jest.setSystemTime(Date.now() + 1_000)
      await invite(id, owner, 'two@example.com', 'editor')

      const res = await list(id, owner)

      expect(res.body).toEqual({
        items: [
          expect.objectContaining({ email: 'one@example.com', role: 'viewer', resendCount: 0 }),
          expect.objectContaining({ email: 'two@example.com', role: 'editor', resendCount: 0 })
        ],
        nextCursor: null
      })
      expect(JSON.stringify(res.body)).not.toMatch(TOKEN_IN_MAIL)
    })

    it('pages with the cursor it hands back', async () => {
      freezeClock()
      const { id, owner } = await team()
      for (const name of ['a', 'b', 'c']) {
        await invite(id, owner, `${name}@example.com`)
        jest.setSystemTime(Date.now() + 1_000)
      }

      const first = await list(id, owner, '?limit=2')
      const cursor = (first.body as { nextCursor: string }).nextCursor
      const second = await list(id, owner, `?limit=2&cursor=${encodeURIComponent(cursor)}`)

      expect((first.body as { items: unknown[] }).items).toHaveLength(2)
      expect(second.body).toMatchObject({ items: [{ email: 'c@example.com' }], nextCursor: null })
    })
  })

  describe('POST /workspaces/invitations/preview', () => {
    it('answers the same body for a token that never existed and one that was revoked', async () => {
      const { id, owner } = await team()
      await invite(id, owner, 'revoked@example.com')
      const revoked = tokenSentTo('revoked@example.com')
      await post(`/workspaces/${id}/invitations/revoke`, owner, { email: 'revoked@example.com' })

      const answers = [
        await preview('f'.repeat(64)),
        await preview('0'.repeat(64)),
        await preview(revoked)
      ]

      for (const answer of answers) expectAuthError(answer, 'auth.invalid_invitation_token')
      expect(new Set(answers.map((a) => JSON.stringify(a.body))).size).toBe(1)
    })

    it('needs no sign-in and refuses a token of the wrong length', async () => {
      expectAuthError(await preview('short'), 'auth.validation')
    })
  })
})
