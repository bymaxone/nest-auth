/**
 * End-to-end acceptance of a workspace invitation: as the signed-in account it names, and by
 * creating the account it was addressed to.
 *
 * The specs drive the real HTTP stack over in-memory repositories and a captured mailbox. What they
 * pin is who may accept, that every refusal before the write leaves the token usable, that the
 * answer carries the role the caller actually holds, and that two submissions of one signup never
 * end in a server error.
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
import { bootstrapTestApp, expectAuthError } from './setup'
import type { BootstrappedTestApp } from './setup'
import { memoryRepositories } from './workspace-memory-repositories'

const PASSWORD = 'SuperSecret123!'
const TOKEN_IN_MAIL = /[0-9a-f]{64}/

interface Account {
  id: string
  email: string
  authorization: string
}

describe('workspace invitation acceptance (E2E)', () => {
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

  async function signUp(verified = true): Promise<Account> {
    sequence += 1
    const email = `accept${sequence}@example.com`
    const res = await request(app.getHttpServer())
      .post('/register')
      .send({ email, password: PASSWORD, name: `Person ${sequence}`, tenantId: 'tenant-1' })
    const body = res.body as { accessToken: string; user: { id: string } }
    if (verified) {
      await boot.repo.updateEmailVerified({
        id: body.user.id,
        tenantId: 'tenant-1',
        verified: true
      })
    }
    return { id: body.user.id, email, authorization: `Bearer ${body.accessToken}` }
  }

  async function workspace(): Promise<{ id: string; owner: Account }> {
    const owner = await signUp()
    const created = await request(app.getHttpServer())
      .post('/workspaces')
      .set('Authorization', owner.authorization)
      .send({ name: 'Team' })
    const id = (created.body as { id: string }).id
    // The contract relies on it: a library-generated id is never the word `invitations`.
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
    return { id, owner }
  }

  async function invite(
    id: string,
    owner: Account,
    email: string,
    role = 'viewer'
  ): Promise<string> {
    const res = await request(app.getHttpServer())
      .post(`/workspaces/${id}/invitations`)
      .set('Authorization', owner.authorization)
      .send({ email, role })
    expect(res.status).toBe(204)
    const mail = [...boot.email.sentEmails].reverse().find((sent) => sent.to === email)
    return TOKEN_IN_MAIL.exec(mail?.html ?? '')?.[0] ?? ''
  }

  function accept(account: Account, token: string): request.Test {
    return request(app.getHttpServer())
      .post('/workspaces/invitations/accept')
      .set('Authorization', account.authorization)
      .send({ token })
  }

  function signup(token: string, password = PASSWORD): request.Test {
    return request(app.getHttpServer())
      .post('/workspaces/invitations/accept-signup')
      .send({ token, name: 'New Person', password })
  }

  function preview(token: string): request.Test {
    return request(app.getHttpServer()).post('/workspaces/invitations/preview').send({ token })
  }

  function access(id: string, account: Account): request.Test {
    return request(app.getHttpServer())
      .get(`/workspaces/${id}/access`)
      .set('Authorization', account.authorization)
  }

  describe('POST /workspaces/invitations/accept', () => {
    it('joins the workspace with the invited role, answers where, and spends the token', async () => {
      const { id, owner } = await workspace()
      const invitee = await signUp()
      const token = await invite(id, owner, invitee.email, 'editor')

      const res = await accept(invitee, token)

      expect(res.status).toBe(200)
      expect(res.body).toEqual({ workspaceId: id, role: 'editor' })
      expect((await access(id, invitee)).body).toMatchObject({ role: 'editor' })
      expectAuthError(await preview(token), 'auth.invalid_invitation_token')
      expectAuthError(await accept(invitee, token), 'auth.invalid_invitation_token')
    })

    it('refuses an account the invitation is not addressed to and leaves the token usable', async () => {
      const { id, owner } = await workspace()
      const invitee = await signUp()
      const stranger = await signUp()
      const token = await invite(id, owner, invitee.email)

      expectAuthError(await accept(stranger, token), 'auth.invitation_email_mismatch')

      expect((await preview(token)).status).toBe(200)
      expect((await accept(invitee, token)).status).toBe(200)
    })

    it('refuses the addressed account while its address is unverified, and leaves the token usable', async () => {
      const { id, owner } = await workspace()
      const invitee = await signUp(false)
      const token = await invite(id, owner, invitee.email)

      expectAuthError(await accept(invitee, token), 'auth.email_not_verified')

      expect((await preview(token)).status).toBe(200)
    })

    it('needs a signed-in caller', async () => {
      const res = await request(app.getHttpServer())
        .post('/workspaces/invitations/accept')
        .send({ token: 'a'.repeat(64) })

      expect(res.status).toBe(401)
    })

    it('answers the role a member already holds, and still spends the invitation', async () => {
      const { id, owner } = await workspace()
      const invitee = await signUp()
      const token = await invite(id, owner, invitee.email, 'editor')
      repositories.seedMember(id, invitee.id, 'viewer')
      await app
        .get(WorkspaceAccessService, { strict: false })
        .invalidateMembership({ tenantId: 'tenant-1', workspaceId: id, userId: invitee.id })

      const res = await accept(invitee, token)

      expect(res.body).toEqual({ workspaceId: id, role: 'viewer' })
      expectAuthError(await preview(token), 'auth.invalid_invitation_token')
    })

    it('stops honouring an invitation whose inviter was demoted below the role', async () => {
      const { id, owner } = await workspace()
      const editor = await signUp()
      repositories.seedMember(id, editor.id, 'editor')
      await app
        .get(WorkspaceAccessService, { strict: false })
        .invalidateMembership({ tenantId: 'tenant-1', workspaceId: id, userId: editor.id })
      const invitee = await signUp()
      const token = await invite(id, editor, invitee.email, 'viewer')
      repositories.seedMember(id, editor.id, 'viewer')

      expectAuthError(await accept(invitee, token), 'auth.invalid_invitation_token')
    })
  })

  describe('POST /workspaces/invitations/accept-signup', () => {
    it('creates the account, joins it, signs it in and answers where it joined', async () => {
      const { id, owner } = await workspace()
      const email = 'brand.new@example.com'
      const token = await invite(id, owner, email, 'editor')

      const res = await signup(token)

      expect(res.status).toBe(201)
      expect(res.body).toMatchObject({
        accessToken: expect.any(String),
        user: { email, emailVerified: true },
        workspaceId: id,
        role: 'editor'
      })
      const account = {
        authorization: `Bearer ${(res.body as { accessToken: string }).accessToken}`
      } as Account
      expect((await access(id, account)).body).toMatchObject({ role: 'editor' })
      expectAuthError(await preview(token), 'auth.invalid_invitation_token')
    })

    it('points an address that already has an account at signing in, and leaves the token usable', async () => {
      const { id, owner } = await workspace()
      const existing = await signUp()
      const token = await invite(id, owner, existing.email)

      expectAuthError(await signup(token), 'auth.email_already_exists')

      expect((await preview(token)).status).toBe(200)
    })

    it('judges the password before spending the token', async () => {
      const { id, owner } = await workspace()
      const token = await invite(id, owner, 'weak.password@example.com')

      const refused = await signup(token, 'short')

      expectAuthError(refused, 'auth.validation')
      expect((await signup(token)).status).toBe(201)
    })

    it('ends two submissions of one signup in one account and never in a server error', async () => {
      const { id, owner } = await workspace()
      const token = await invite(id, owner, 'double.submit@example.com')

      const [a, b] = await Promise.all([signup(token), signup(token)])

      expect([a.status, b.status].sort()).toEqual([201, 409])
      expect(
        [a, b].map(
          (res) => res.status === 409 && (res.body as { error: { code: string } }).error.code
        )
      ).toContain('auth.email_already_exists')
    })

    it('refuses a token of the wrong length as a validation error', async () => {
      expectAuthError(await signup('short'), 'auth.validation')
    })
  })
})
