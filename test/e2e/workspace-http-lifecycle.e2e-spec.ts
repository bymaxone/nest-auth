/**
 * End-to-end workspace lifecycle routes: create, rename, schedule deletion and restore.
 *
 * The specs drive the real HTTP stack over in-memory repositories. What they pin is who may do
 * what, in what order: the guard decides whether the caller may act before anything is spent on
 * them, the password is re-proved only for a caller who may delete, and a workspace the caller is
 * not in answers exactly as one that does not exist.
 *
 * @layer Test
 */

import type { INestApplication } from '@nestjs/common'
import request from 'supertest'

import {
  BYMAX_AUTH_MEMBERSHIP_REPOSITORY,
  BYMAX_AUTH_WORKSPACE_REPOSITORY
} from '../../src/server/bymax-auth.constants'
import { MfaFlowLockoutService } from '../../src/server/services/mfa-flow-lockout.service'
import { PasswordService } from '../../src/server/services/password.service'
import { WorkspaceAccessService } from '../../src/server/services/workspace-access.service'
import { bootstrapTestApp, expectAuthError, type BootstrappedTestApp } from './setup'
import { memoryRepositories } from './workspace-memory-repositories'

const PASSWORD = 'SuperSecret123!'

interface Account {
  id: string
  email: string
  authorization: string
}

describe('workspace lifecycle routes (E2E)', () => {
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
          }
        }
      },
      {
        controllers: { auth: true, workspaces: true },
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
    jest.restoreAllMocks()
  })

  async function signUp(): Promise<Account> {
    sequence += 1
    const email = `life${sequence}@example.com`
    const res = await request(app.getHttpServer())
      .post('/register')
      .send({ email, password: PASSWORD, name: `Life ${sequence}`, tenantId: 'tenant-1' })
    const body = res.body as { accessToken: string; user: { id: string } }
    return { id: body.user.id, email, authorization: `Bearer ${body.accessToken}` }
  }

  function post(path: string, account: Account, body?: object): request.Test {
    return request(app.getHttpServer())
      .post(path)
      .set('Authorization', account.authorization)
      .send(body ?? {})
  }

  async function createWorkspace(owner: Account, name = 'Acme'): Promise<string> {
    const res = await post('/workspaces', owner, { name })
    return (res.body as { id: string }).id
  }

  async function addMember(workspaceId: string, account: Account, role: string): Promise<void> {
    repositories.seedMember(workspaceId, account.id, role)
    await app
      .get(WorkspaceAccessService, { strict: false })
      .invalidateMembership({ tenantId: 'tenant-1', workspaceId, userId: account.id })
  }

  function access(workspaceId: string, account: Account): request.Test {
    return request(app.getHttpServer())
      .get(`/workspaces/${workspaceId}/access`)
      .set('Authorization', account.authorization)
  }

  describe('POST /workspaces', () => {
    it('creates a workspace the caller owns', async () => {
      const alice = await signUp()

      const res = await post('/workspaces', alice, { name: '  Acme  ' })

      expect(res.status).toBe(201)
      expect(res.body).toMatchObject({ name: 'Acme', status: 'active', deletionScheduledAt: null })
      const id = (res.body as { id: string }).id
      expect((await access(id, alice)).body).toMatchObject({ role: 'owner' })
    })

    it.each([
      ['a blank name', { name: '   ' }],
      ['an empty name', { name: '' }],
      ['a name over the bound', { name: 'a'.repeat(121) }],
      ['a name with a control character', { name: 'a\u0000b' }],
      ['no name', {}],
      ['a name that is not a string', { name: 5 }],
      ['a parameter the route does not take', { name: 'ok', tenantId: 'other' }]
    ])('refuses %s with 400 validation', async (_label, body) => {
      const alice = await signUp()

      const res = await post('/workspaces', alice, body)

      expectAuthError(res, 'auth.validation')
    })

    it('answers 401 without a token', async () => {
      const res = await request(app.getHttpServer()).post('/workspaces').send({ name: 'Acme' })

      expectAuthError(res, 'auth.token_invalid')
    })
  })

  describe('PATCH /workspaces/:workspaceId', () => {
    it('lets the owner rename and answers the workspace as it now reads', async () => {
      const alice = await signUp()
      const id = await createWorkspace(alice)

      const res = await request(app.getHttpServer())
        .patch(`/workspaces/${id}`)
        .set('Authorization', alice.authorization)
        .send({ name: 'Renamed' })

      expect(res.status).toBe(200)
      expect(res.body).toMatchObject({ id, name: 'Renamed' })
      expect((await access(id, alice)).body).toMatchObject({ workspace: { name: 'Renamed' } })
    })

    it('refuses a member below the manage role, and answers a non-member as a missing workspace', async () => {
      const alice = await signUp()
      const bob = await signUp()
      const outsider = await signUp()
      const id = await createWorkspace(alice)
      await addMember(id, bob, 'editor')
      const rename = (account: Account, target: string): request.Test =>
        request(app.getHttpServer())
          .patch(`/workspaces/${target}`)
          .set('Authorization', account.authorization)
          .send({ name: 'Nope' })

      expectAuthError(await rename(bob, id), 'auth.insufficient_workspace_role')
      const foreign = await rename(outsider, id)
      const missing = await rename(outsider, 'does-not-exist')

      expectAuthError(foreign, 'auth.workspace_not_found')
      expect(foreign.body).toEqual(missing.body)
      expect((await access(id, alice)).body).toMatchObject({ workspace: { name: 'Acme' } })
    })
  })

  describe('POST /workspaces/:workspaceId/schedule-deletion', () => {
    it('re-proves the owner, ends everyone access at once, and lets the owner see why', async () => {
      const alice = await signUp()
      const bob = await signUp()
      const id = await createWorkspace(alice)
      await addMember(id, bob, 'viewer')

      const res = await post(`/workspaces/${id}/schedule-deletion`, alice, { password: PASSWORD })

      expect(res.status).toBe(204)
      expectAuthError(await access(id, alice), 'auth.workspace_pending_deletion')
      expectAuthError(await access(id, bob), 'auth.workspace_not_found')
    })

    it.each([
      ['a wrong password', { password: 'Wrong-Password-1!' }],
      ['no password', {}]
    ])('refuses %s with invalid credentials and schedules nothing', async (_label, body) => {
      const alice = await signUp()
      const id = await createWorkspace(alice)

      const res = await post(`/workspaces/${id}/schedule-deletion`, alice, body)

      expectAuthError(res, 'auth.invalid_credentials')
      expect((await access(id, alice)).status).toBe(200)
    })

    // Scenario: a member below the delete role sends a WRONG password. Expected: 403 from the
    // guard, with no key derivation and no lockout attempt recorded. Why: permission is decided
    // before the password is judged, so a caller who may not delete cannot spend either.
    it('refuses a caller who may not delete before the password is looked at', async () => {
      const alice = await signUp()
      const bob = await signUp()
      const id = await createWorkspace(alice)
      await addMember(id, bob, 'editor')
      const compare = jest.spyOn(app.get(PasswordService, { strict: false }), 'compare')
      const failure = jest.spyOn(app.get(MfaFlowLockoutService, { strict: false }), 'recordFailure')

      const res = await post(`/workspaces/${id}/schedule-deletion`, bob, { password: 'Wrong-1!' })

      expectAuthError(res, 'auth.insufficient_workspace_role')
      expect(compare).not.toHaveBeenCalled()
      expect(failure).not.toHaveBeenCalled()
    })

    it('answers a non-member as a missing workspace without checking a password', async () => {
      const alice = await signUp()
      const outsider = await signUp()
      const id = await createWorkspace(alice)
      const compare = jest.spyOn(app.get(PasswordService, { strict: false }), 'compare')

      const res = await post(`/workspaces/${id}/schedule-deletion`, outsider, {
        password: PASSWORD
      })

      expectAuthError(res, 'auth.workspace_not_found')
      expect(compare).not.toHaveBeenCalled()
    })

    // Scenario: an account with no password (provisioned through OAuth). Expected: it is refused
    // for want of a recent sign-in, and accepted once the sign-in marker is fresh.
    it('re-proves a passwordless account by a recent sign-in', async () => {
      const alice = await signUp()
      const id = await createWorkspace(alice)
      const user = boot.repo.users.get(alice.id)
      if (user === undefined) throw new Error('the account was not stored')
      boot.repo.users.set(alice.id, { ...user, passwordHash: null })
      // Signing up wrote the marker; take it away to model a session that has gone stale. The
      // store prefixes every key, so the stored name is found rather than rebuilt.
      const markers = await boot.redis.keys('*ra:*')
      await boot.redis.del(...markers)

      const refused = await post(`/workspaces/${id}/schedule-deletion`, alice, {})
      for (const marker of markers) await boot.redis.set(marker, '1')
      const accepted = await post(`/workspaces/${id}/schedule-deletion`, alice, {})

      expectAuthError(refused, 'auth.reauthentication_required')
      expect(accepted.status).toBe(204)
    })
  })

  describe('POST /workspaces/:workspaceId/restore', () => {
    it('lets the owner undo a scheduled deletion within the grace period', async () => {
      const alice = await signUp()
      const id = await createWorkspace(alice)
      await post(`/workspaces/${id}/schedule-deletion`, alice, { password: PASSWORD })

      const res = await post(`/workspaces/${id}/restore`, alice)

      expect(res.status).toBe(204)
      expect((await access(id, alice)).status).toBe(200)
    })

    it('answers a member other than the owner, and an active workspace, as a missing workspace', async () => {
      const alice = await signUp()
      const bob = await signUp()
      const id = await createWorkspace(alice)
      await addMember(id, bob, 'editor')

      const active = await post(`/workspaces/${id}/restore`, alice)
      await post(`/workspaces/${id}/schedule-deletion`, alice, { password: PASSWORD })
      const other = await post(`/workspaces/${id}/restore`, bob)

      expectAuthError(active, 'auth.workspace_not_found')
      expectAuthError(other, 'auth.workspace_not_found')
    })
  })
})
