/**
 * End-to-end acceptance of a workspace invitation through the OAuth provider, and the sign-up gate
 * of `registration: 'invitation-only'`.
 *
 * The Google plugin is an in-memory mock, so the suite drives the real HTTP stack, the real state
 * record and the real accept service over in-memory repositories without a network. What it pins:
 * the invitation travels as a hash, a refusal before the write leaves the token usable, the
 * state stays bound to the browser that started the flow, and a closed registration refuses every
 * self sign-up path while an invitation still opens one.
 *
 * @layer Test
 */

import type { INestApplication } from '@nestjs/common'
import { Logger } from '@nestjs/common'
import request from 'supertest'

import {
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_MEMBERSHIP_REPOSITORY,
  BYMAX_AUTH_WORKSPACE_REPOSITORY
} from '../../src/server/bymax-auth.constants'
import type { IAuthHooks, OAuthLoginResult } from '../../src/server/interfaces/auth-hooks.interface'
import type {
  OAuthProfile,
  OAuthProviderPlugin
} from '../../src/server/interfaces/oauth-provider.interface'
import { OAUTH_PLUGINS } from '../../src/server/oauth/oauth.constants'
import { WorkspaceInvitationService } from '../../src/server/services/workspace-invitation.service'
import { createEmptyHookContext } from '../../src/server/utils/sanitize-headers'
import { bootstrapTestApp, expectAuthError } from './setup'
import type { BootstrappedTestApp } from './setup'
import { memoryRepositories } from './workspace-memory-repositories'

const PASSWORD = 'SuperSecret123!'
const TOKEN_IN_MAIL = /[0-9a-f]{64}/
const INVITEE = 'invitee@example.com'

/** The profile and the hook decision the next callback sees. */
const flow: { profile: OAuthProfile; decision: OAuthLoginResult } = {
  profile: profileFor(INVITEE, true),
  decision: { action: 'create' }
}

/** A provider profile for an address. */
function profileFor(email: string, emailVerified: boolean): OAuthProfile {
  return { provider: 'google', providerId: `g-${email}`, email, name: 'Invitee', emailVerified }
}

const plugin: OAuthProviderPlugin = {
  name: 'google',
  authorizeUrl: (state: string) => `https://example.com/oauth/google?state=${state}`,
  exchangeCode: async () => ({ access_token: 'at', token_type: 'Bearer' }),
  fetchProfile: async () => flow.profile
}

const hooks: IAuthHooks = { onOAuthLogin: async () => flow.decision }

/** The roles every app here uses. */
const WORKSPACES = {
  enabled: true,
  roles: {
    hierarchy: { owner: ['editor', 'viewer'], editor: ['viewer'], viewer: [] },
    ownerRole: 'owner'
  }
}

/** Boots an app with OAuth, workspaces and the given registration mode. */
async function boot(registration: 'open' | 'invitation-only'): Promise<BootstrappedTestApp> {
  const repositories = memoryRepositories()
  return bootstrapTestApp(
    {
      registration,
      workspaces: WORKSPACES,
      oauth: {
        google: {
          clientId: 'id',
          clientSecret: 'secret',
          callbackUrl: 'https://app.example.com/auth/oauth/google/callback'
        }
      }
    },
    {
      controllers: { auth: true, workspaces: true, workspaceInvitations: true, oauth: true },
      extraModuleProviders: [
        { provide: BYMAX_AUTH_HOOKS, useValue: hooks },
        { provide: BYMAX_AUTH_WORKSPACE_REPOSITORY, useValue: repositories.workspaces },
        { provide: BYMAX_AUTH_MEMBERSHIP_REPOSITORY, useValue: repositories.memberships }
      ],
      mutateBuilder: (builder) =>
        builder.overrideProvider(OAUTH_PLUGINS).useValue([plugin]) as typeof builder
    }
  )
}

/** The cookie a browser would send back, and the state, from a start response. */
function started(res: request.Response): { state: string; cookie: string } {
  const location = res.headers['location'] as string
  if (location === undefined)
    throw new Error(`start answered ${res.status} ${JSON.stringify(res.body)}`)
  const state = new URL(location).searchParams.get('state') ?? ''
  return { state, cookie: `oauth_state=${state}` }
}

describe('workspace invitation through OAuth (E2E)', () => {
  describe('with open registration', () => {
    let b: BootstrappedTestApp
    let app: INestApplication
    let sequence = 0

    beforeAll(async () => {
      b = await boot('open')
      app = b.app
    })

    afterAll(async () => {
      await app.close()
    })

    beforeEach(() => {
      flow.profile = profileFor(INVITEE, true)
      flow.decision = { action: 'create' }
    })

    /** A signed-in owner with a workspace, who has invited `email`; returns what a test needs. */
    async function invitation(email: string): Promise<{ id: string; token: string }> {
      sequence += 1
      const signUp = await request(app.getHttpServer())
        .post('/register')
        .send({
          email: `owner${sequence}@example.com`,
          password: PASSWORD,
          name: 'Owner',
          tenantId: 'tenant-1'
        })
      const owner = signUp.body as { accessToken: string; user: { id: string } }
      await b.repo.updateEmailVerified({ id: owner.user.id, tenantId: 'tenant-1', verified: true })
      const authorization = `Bearer ${owner.accessToken}`
      const created = await request(app.getHttpServer())
        .post('/workspaces')
        .set('Authorization', authorization)
        .send({ name: 'Team' })
      const id = (created.body as { id: string }).id
      const invited = await request(app.getHttpServer())
        .post(`/workspaces/${id}/invitations`)
        .set('Authorization', authorization)
        .send({ email, role: 'editor' })
      if (invited.status !== 204)
        throw new Error(`invite ${invited.status} ${JSON.stringify(invited.body)}`)
      const mail = [...b.email.sentEmails].reverse().find((sent) => sent.to === email)
      return { id, token: TOKEN_IN_MAIL.exec(mail?.html ?? '')?.[0] ?? '' }
    }

    function start(token: string): request.Test {
      return request(app.getHttpServer())
        .get('/oauth/google')
        .query({ tenantId: 'tenant-1', workspaceInvitation: token })
    }

    function finish(res: request.Response): request.Test {
      const { state, cookie } = started(res)
      return request(app.getHttpServer())
        .get('/oauth/google/callback')
        .query({ code: 'code', state })
        .set('Cookie', cookie)
    }

    function preview(token: string): request.Test {
      return request(app.getHttpServer()).post('/workspaces/invitations/preview').send({ token })
    }

    it('creates the account, joins the workspace and signs in, spending the token', async () => {
      const { id, token } = await invitation(INVITEE)

      const started1 = await start(token)
      const res = await finish(started1)

      expect(started1.headers['referrer-policy']).toBe('no-referrer')
      expect(res.status).toBe(200)
      const body = res.body as { accessToken: string }
      const access = await request(app.getHttpServer())
        .get(`/workspaces/${id}/access`)
        .set('Authorization', `Bearer ${body.accessToken}`)
      expect(access.body).toMatchObject({ role: 'editor' })
      expectAuthError(await preview(token), 'auth.invalid_invitation_token')
    })

    it('refuses a provider address that is not the invited one and leaves the token usable', async () => {
      const { token } = await invitation('someone.else@example.com')
      flow.profile = profileFor(INVITEE, true)

      const res = await finish(await start(token))

      expectAuthError(res, 'auth.invitation_email_mismatch')
      expect(JSON.stringify(res.body)).not.toContain(token)
      expect((await preview(token)).status).toBe(200)
    })

    it('refuses an address the provider did not verify and leaves the token usable', async () => {
      const { token } = await invitation(INVITEE)
      flow.profile = profileFor(INVITEE, false)

      const res = await finish(await start(token))

      expectAuthError(res, 'auth.email_not_verified')
      expect((await preview(token)).status).toBe(200)
    })

    it('lets an existing account sign in and join a second workspace', async () => {
      const first = await invitation(INVITEE)
      await finish(await start(first.token))
      const second = await invitation(INVITEE)
      flow.decision = { action: 'link' }

      const res = await finish(await start(second.token))

      expect(res.status).toBe(200)
      const access = await request(app.getHttpServer())
        .get(`/workspaces/${second.id}/access`)
        .set('Authorization', `Bearer ${(res.body as { accessToken: string }).accessToken}`)
      expect(access.body).toMatchObject({ role: 'editor' })
    })

    it('hands an account with a second factor the challenge, leaving the token for the signed-in accept', async () => {
      const mfaPerson = 'mfa.person@example.com'
      flow.profile = profileFor(mfaPerson, true)
      const first = await invitation(mfaPerson)
      const signedIn = await finish(await start(first.token))
      const bearer = `Bearer ${(signedIn.body as { accessToken: string }).accessToken}`
      const account = await b.repo.findByEmail({ email: mfaPerson, tenantId: 'tenant-1' })
      await b.repo.updateMfa({
        id: account?.id ?? '',
        tenantId: 'tenant-1',
        data: { mfaEnabled: true, mfaSecret: 'secret', mfaRecoveryCodes: [] }
      })
      const second = await invitation(mfaPerson)
      flow.decision = { action: 'link' }

      const challenge = await finish(await start(second.token))

      expect(challenge.body).toMatchObject({ mfaRequired: true })
      expect((await preview(second.token)).status).toBe(200)
      const accepted = await request(app.getHttpServer())
        .post('/workspaces/invitations/accept')
        .set('Authorization', bearer)
        .send({ token: second.token })
      expect(accepted.body).toEqual({ workspaceId: second.id, role: 'editor' })
      expectAuthError(await preview(second.token), 'auth.invalid_invitation_token')
    })

    it('keeps the state bound to the browser that started the flow', async () => {
      const { token } = await invitation(INVITEE)
      const startRes = await start(token)
      const { state } = started(startRes)

      const withoutCookie = await request(app.getHttpServer())
        .get('/oauth/google/callback')
        .query({ code: 'code', state })

      expectAuthError(withoutCookie, 'auth.oauth_failed')
      expect((await preview(token)).status).toBe(200)
    })

    it('never records the raw token in the library logs, across a success and a refusal', async () => {
      const sinks = (['log', 'warn', 'error', 'debug', 'verbose'] as const).map((level) =>
        jest.spyOn(Logger.prototype, level)
      )
      const ok = await invitation(INVITEE)
      await finish(await start(ok.token))
      const bad = await invitation('another@example.com')
      await finish(await start(bad.token))

      const logged = JSON.stringify(sinks.flatMap((sink) => sink.mock.calls))
      jest.restoreAllMocks()
      expect(logged).not.toContain(ok.token)
      expect(logged).not.toContain(bad.token)
    })

    it('refuses a start request whose token is not 64 characters', async () => {
      const res = await start('short')

      expect(res.status).toBe(400)
    })
  })

  describe('with invitation-only registration', () => {
    let b: BootstrappedTestApp
    let app: INestApplication

    beforeAll(async () => {
      b = await boot('invitation-only')
      app = b.app
    })

    afterAll(async () => {
      await app.close()
    })

    beforeEach(() => {
      flow.profile = profileFor(INVITEE, true)
      flow.decision = { action: 'create' }
    })

    async function bootstrapInvitation(email: string): Promise<{ id: string; token: string }> {
      const { workspaceId } = await app
        .get(WorkspaceInvitationService, { strict: false })
        .inviteAsPlatform(
          { tenantId: 'tenant-1', email, workspaceName: 'Acme', inviterName: 'Platform' },
          createEmptyHookContext()
        )
      const mail = [...b.email.sentEmails].reverse().find((sent) => sent.to === email)
      return { id: workspaceId, token: TOKEN_IN_MAIL.exec(mail?.html ?? '')?.[0] ?? '' }
    }

    function callbackFor(start: request.Response): request.Test {
      const { state, cookie } = started(start)
      return request(app.getHttpServer())
        .get('/oauth/google/callback')
        .query({ code: 'code', state })
        .set('Cookie', cookie)
    }

    it('closes the password sign-up route', async () => {
      const res = await request(app.getHttpServer())
        .post('/register')
        .send({ email: 'x@example.com', password: PASSWORD, name: 'Xavier', tenantId: 'tenant-1' })

      expectAuthError(res, 'auth.registration_closed')
    })

    it('refuses the OAuth create action without an invitation, creating no account', async () => {
      const start = await request(app.getHttpServer())
        .get('/oauth/google')
        .query({ tenantId: 'tenant-1' })

      const res = await callbackFor(start)

      expectAuthError(res, 'auth.registration_closed')
      expect(await b.repo.findByEmail({ email: INVITEE, tenantId: 'tenant-1' })).toBeNull()
    })

    it('lets a bootstrap invitation create the account and its workspace through OAuth', async () => {
      const { id, token } = await bootstrapInvitation(INVITEE)
      const start = await request(app.getHttpServer())
        .get('/oauth/google')
        .query({ tenantId: 'tenant-1', workspaceInvitation: token })

      const res = await callbackFor(start)

      expect(res.status).toBe(200)
      const access = await request(app.getHttpServer())
        .get(`/workspaces/${id}/access`)
        .set('Authorization', `Bearer ${(res.body as { accessToken: string }).accessToken}`)
      expect(access.body).toMatchObject({ role: 'owner' })
    })

    it('still lets an existing account sign in through OAuth', async () => {
      const { token } = await bootstrapInvitation('second@example.com')
      flow.profile = profileFor('second@example.com', true)
      await callbackFor(
        await request(app.getHttpServer())
          .get('/oauth/google')
          .query({ tenantId: 'tenant-1', workspaceInvitation: token })
      )
      flow.decision = { action: 'link' }

      const res = await callbackFor(
        await request(app.getHttpServer()).get('/oauth/google').query({ tenantId: 'tenant-1' })
      )

      expect(res.status).toBe(200)
    })
  })
})
