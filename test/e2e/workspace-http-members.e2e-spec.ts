/**
 * End-to-end workspace member routes: change a role, remove a member, leave, and hand ownership
 * over.
 *
 * The specs drive the real HTTP stack over in-memory repositories that decide the last-owner rule
 * inside the call. What they pin is who may change whom, and in what order the checks run: the
 * guard decides who may act, everything the request alone decides is checked before a password is
 * looked at, and the password before the write.
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
  authorization: string
}

describe('workspace member routes (E2E)', () => {
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
    const res = await request(app.getHttpServer())
      .post('/register')
      .send({
        email: `member${sequence}@example.com`,
        password: PASSWORD,
        name: `Member ${sequence}`,
        tenantId: 'tenant-1'
      })
    const body = res.body as { accessToken: string; user: { id: string } }
    return { id: body.user.id, authorization: `Bearer ${body.accessToken}` }
  }

  async function team(): Promise<{ id: string; owner: Account; editor: Account; viewer: Account }> {
    const [owner, editor, viewer] = [await signUp(), await signUp(), await signUp()]
    const created = await request(app.getHttpServer())
      .post('/workspaces')
      .set('Authorization', owner.authorization)
      .send({ name: 'Team' })
    const id = (created.body as { id: string }).id
    for (const [account, role] of [
      [editor, 'editor'],
      [viewer, 'viewer']
    ] as const) {
      repositories.seedMember(id, account.id, role)
      await app
        .get(WorkspaceAccessService, { strict: false })
        .invalidateMembership({ tenantId: 'tenant-1', workspaceId: id, userId: account.id })
    }
    return { id, owner, editor, viewer }
  }

  function send(
    method: 'patch' | 'post' | 'delete',
    path: string,
    account: Account,
    body?: object
  ): request.Test {
    const call = request(app.getHttpServer())
      [method](path)
      .set('Authorization', account.authorization)
    return body === undefined ? call : call.send(body)
  }

  function access(id: string, account: Account): request.Test {
    return request(app.getHttpServer())
      .get(`/workspaces/${id}/access`)
      .set('Authorization', account.authorization)
  }

  describe('PATCH /workspaces/:workspaceId/members/:userId', () => {
    it('lets the owner change a role and answers the membership as it now stands', async () => {
      const { id, owner, viewer } = await team()

      const res = await send('patch', `/workspaces/${id}/members/${viewer.id}`, owner, {
        role: 'editor'
      })

      expect(res.status).toBe(200)
      expect(res.body).toMatchObject({ userId: viewer.id, role: 'editor', status: 'active' })
      expect((await access(id, viewer)).body).toMatchObject({ role: 'editor' })
    })

    it('refuses a role outside the hierarchy with a validation error naming the role', async () => {
      const { id, owner, viewer } = await team()

      const res = await send('patch', `/workspaces/${id}/members/${viewer.id}`, owner, {
        role: 'ghost'
      })

      expectAuthError(res, 'auth.validation')
      expect(
        (res.body as { error: { details: { field: string }[] } }).error.details[0]?.field
      ).toBe('role')
    })

    it('refuses a member below the manage role, and the sole owner demoting themselves', async () => {
      const { id, owner, editor, viewer } = await team()

      const byEditor = await send('patch', `/workspaces/${id}/members/${viewer.id}`, editor, {
        role: 'editor'
      })
      const lastOwner = await send('patch', `/workspaces/${id}/members/${owner.id}`, owner, {
        role: 'viewer'
      })

      expectAuthError(byEditor, 'auth.insufficient_workspace_role')
      expectAuthError(lastOwner, 'auth.last_owner')
    })

    it('answers a non-member exactly as it answers a missing workspace', async () => {
      const { id, viewer } = await team()
      const outsider = await signUp()
      const change = (target: string): request.Test =>
        send('patch', `/workspaces/${target}/members/${viewer.id}`, outsider, { role: 'editor' })

      const foreign = await change(id)
      const missing = await change('does-not-exist')

      expectAuthError(foreign, 'auth.workspace_not_found')
      expect(foreign.body).toEqual(missing.body)
    })
  })

  describe('DELETE /workspaces/:workspaceId/members/:userId', () => {
    it('removes a member, who then reads the workspace as missing', async () => {
      const { id, owner, editor } = await team()

      const res = await send('delete', `/workspaces/${id}/members/${editor.id}`, owner)

      expect(res.status).toBe(204)
      expectAuthError(await access(id, editor), 'auth.workspace_not_found')
    })

    it('refuses removing the sole owner, and answers a member that does not exist as not found', async () => {
      const { id, owner } = await team()

      const last = await send('delete', `/workspaces/${id}/members/${owner.id}`, owner)
      const ghost = await send('delete', `/workspaces/${id}/members/nobody`, owner)

      expectAuthError(last, 'auth.last_owner')
      expectAuthError(ghost, 'auth.workspace_not_found')
    })
  })

  describe('POST /workspaces/:workspaceId/leave', () => {
    it('lets a member leave, and refuses the last owner', async () => {
      const { id, owner, viewer } = await team()

      const left = await send('post', `/workspaces/${id}/leave`, viewer)
      const last = await send('post', `/workspaces/${id}/leave`, owner)

      expect(left.status).toBe(204)
      expectAuthError(await access(id, viewer), 'auth.workspace_not_found')
      expectAuthError(last, 'auth.last_owner')
    })
  })

  describe('POST /workspaces/:workspaceId/transfer-ownership', () => {
    it('re-proves the owner, hands ownership over and demotes the giver as asked', async () => {
      const { id, owner, editor } = await team()

      const res = await send('post', `/workspaces/${id}/transfer-ownership`, owner, {
        userId: editor.id,
        demoteSelfTo: 'viewer',
        password: PASSWORD
      })

      expect(res.status).toBe(204)
      expect((await access(id, editor)).body).toMatchObject({ role: 'owner' })
      expect((await access(id, owner)).body).toMatchObject({ role: 'viewer' })
    })

    it('refuses a wrong or missing password and changes nothing', async () => {
      const { id, owner, editor } = await team()

      const wrong = await send('post', `/workspaces/${id}/transfer-ownership`, owner, {
        userId: editor.id,
        password: 'Wrong-Password-1!'
      })
      const none = await send('post', `/workspaces/${id}/transfer-ownership`, owner, {
        userId: editor.id
      })

      expectAuthError(wrong, 'auth.invalid_credentials')
      expectAuthError(none, 'auth.invalid_credentials')
      expect((await access(id, owner)).body).toMatchObject({ role: 'owner' })
    })

    // Scenario: a member who is not the owner sends a wrong password, and the owner sends requests
    // that are malformed whatever the password is. Expected: each is refused for what it is, with
    // no key derivation and no lockout attempt. Why: everything the request alone decides runs
    // before the password, so a caller who cannot succeed cannot spend either.
    it('refuses a non-owner and a malformed hand-over before the password is looked at', async () => {
      const { id, owner, editor, viewer } = await team()
      const compare = jest.spyOn(app.get(PasswordService, { strict: false }), 'compare')
      const failure = jest.spyOn(app.get(MfaFlowLockoutService, { strict: false }), 'recordFailure')
      const transfer = (account: Account, body: object): request.Test =>
        send('post', `/workspaces/${id}/transfer-ownership`, account, body)

      const byEditor = await transfer(editor, { userId: viewer.id, password: 'Wrong-1!' })
      const toSelf = await transfer(owner, { userId: owner.id, password: 'Wrong-1!' })
      const keepsOwner = await transfer(owner, {
        userId: editor.id,
        demoteSelfTo: 'owner',
        password: 'Wrong-1!'
      })
      const keepsGhost = await transfer(owner, {
        userId: editor.id,
        demoteSelfTo: 'ghost',
        password: 'Wrong-1!'
      })

      expectAuthError(byEditor, 'auth.insufficient_workspace_role')
      for (const res of [toSelf, keepsOwner, keepsGhost]) expectAuthError(res, 'auth.validation')
      expect(compare).not.toHaveBeenCalled()
      expect(failure).not.toHaveBeenCalled()
    })

    it('refuses a receiver who is not an active member of this workspace', async () => {
      const { id, owner } = await team()
      const outsider = await signUp()

      const res = await send('post', `/workspaces/${id}/transfer-ownership`, owner, {
        userId: outsider.id,
        password: PASSWORD
      })

      expectAuthError(res, 'auth.validation')
      expect((await access(id, owner)).body).toMatchObject({ role: 'owner' })
    })
  })

  describe('names counted in code points', () => {
    // Scenario: a name of exactly the bound in emoji, each one code point and two UTF-16 units.
    // Expected: created and renamed; one more is refused. Why: the contract counts code points.
    it('accepts 120 emoji as a workspace name and refuses 121', async () => {
      const { id, owner } = await team()
      const emoji = '\u{1F600}'

      const created = await send('post', '/workspaces', owner, { name: emoji.repeat(120) })
      const renamed = await send('patch', `/workspaces/${id}`, owner, { name: emoji.repeat(120) })
      const over = await send('post', '/workspaces', owner, { name: emoji.repeat(121) })

      expect(created.status).toBe(201)
      expect(renamed.status).toBe(200)
      expectAuthError(over, 'auth.validation')
    })
  })
})
