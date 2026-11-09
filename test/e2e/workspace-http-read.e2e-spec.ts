/**
 * End-to-end workspace read routes: the caller's own memberships, one workspace's access, the
 * switch, and the member list.
 *
 * The specs drive the real HTTP stack over in-memory repositories that page by a positional cursor.
 * What they pin is who can learn what: a list answers only data the caller already belongs to, a
 * workspace the caller is not in answers exactly as one that does not exist, and a cursor says
 * where a page starts but never which workspace or whose memberships are read.
 *
 * @layer Test
 */

import type { INestApplication } from '@nestjs/common'
import request from 'supertest'

import {
  BYMAX_AUTH_MEMBERSHIP_REPOSITORY,
  BYMAX_AUTH_WORKSPACE_REPOSITORY
} from '../../src/server/bymax-auth.constants'
import type { SafeAuthUser } from '../../src/server/interfaces/user-repository.interface'
import type { HookContext } from '../../src/server/interfaces/auth-hooks.interface'
import { WorkspaceAccessService } from '../../src/server/services/workspace-access.service'
import { WorkspaceService } from '../../src/server/services/workspace.service'
import { bootstrapTestApp, expectAuthError, type BootstrappedTestApp } from './setup'
import { memoryRepositories } from './workspace-memory-repositories'

const CONTEXT: HookContext = {
  plane: 'dashboard',
  tenantId: 'tenant-1',
  ip: '203.0.113.7',
  userAgent: 'jest',
  sanitizedHeaders: {}
}

interface Account {
  id: string
  user: SafeAuthUser
  authorization: string
}

describe('workspace read routes (E2E)', () => {
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

  function service(): WorkspaceService {
    return app.get(WorkspaceService, { strict: false })
  }

  /** A registered account with a live access token. */
  async function signUp(): Promise<Account> {
    sequence += 1
    const res = await request(app.getHttpServer())
      .post('/register')
      .send({
        email: `reader${sequence}@example.com`,
        password: 'SuperSecret123!',
        name: `Reader ${sequence}`,
        tenantId: 'tenant-1'
      })
    const body = res.body as { accessToken: string; user: { id: string } }
    return {
      id: body.user.id,
      user: {
        id: body.user.id,
        tenantId: 'tenant-1',
        email: `reader${sequence}@example.com`
      } as SafeAuthUser,
      authorization: `Bearer ${body.accessToken}`
    }
  }

  async function createWorkspace(owner: Account, name: string): Promise<string> {
    return (await service().create(owner.user, { name }, CONTEXT)).id
  }

  async function addMember(workspaceId: string, account: Account, role: string): Promise<void> {
    repositories.seedMember(workspaceId, account.id, role)
    await app
      .get(WorkspaceAccessService, { strict: false })
      .invalidateMembership({ tenantId: 'tenant-1', workspaceId, userId: account.id })
  }

  function get(path: string, account: Account): request.Test {
    return request(app.getHttpServer()).get(path).set('Authorization', account.authorization)
  }

  describe('GET /workspaces', () => {
    // Scenario: two accounts each own a workspace. Expected: each sees only their own, with the
    // role. Why: the list is the caller's memberships and nothing else.
    it("lists only the caller's own memberships", async () => {
      const alice = await signUp()
      const bob = await signUp()
      const mine = await createWorkspace(alice, 'Alice Co')
      await createWorkspace(bob, 'Bob Co')

      const res = await get('/workspaces', alice)

      expect(res.status).toBe(200)
      const body = res.body as {
        items: { workspace: { id: string; name: string }; role: string }[]
      }
      expect(body.items.map((item) => [item.workspace.id, item.workspace.name, item.role])).toEqual(
        [[mine, 'Alice Co', 'owner']]
      )
    })

    // Scenario: a workspace was switched to. Expected: the list names it as the last active one.
    it('names the workspace the caller last switched to', async () => {
      const alice = await signUp()
      const id = await createWorkspace(alice, 'First')

      await request(app.getHttpServer())
        .post(`/workspaces/${id}/switch`)
        .set('Authorization', alice.authorization)
        .expect(204)

      const res = await get('/workspaces', alice)
      expect((res.body as { lastActiveWorkspaceId: string }).lastActiveWorkspaceId).toBe(id)
    })

    // Scenario: three workspaces, a page of two. Expected: two items and a cursor, then the rest
    // and no cursor, with no workspace repeated or skipped.
    it('pages by cursor', async () => {
      const alice = await signUp()
      const ids = [
        await createWorkspace(alice, 'A'),
        await createWorkspace(alice, 'B'),
        await createWorkspace(alice, 'C')
      ]

      const first = await get('/workspaces?limit=2', alice)
      const firstBody = first.body as { items: { workspace: { id: string } }[]; nextCursor: string }
      const second = await get(
        `/workspaces?limit=2&cursor=${encodeURIComponent(firstBody.nextCursor)}`,
        alice
      )
      const secondBody = second.body as { items: { workspace: { id: string } }[]; nextCursor: null }

      const seen = [...firstBody.items, ...secondBody.items].map((item) => item.workspace.id)
      expect(firstBody.items).toHaveLength(2)
      expect(secondBody.nextCursor).toBeNull()
      expect([...seen].sort()).toEqual([...ids].sort())
    })

    // Scenario: no token. Expected: 401 before anything is read.
    it('answers 401 without a token', async () => {
      const res = await request(app.getHttpServer()).get('/workspaces')

      expectAuthError(res, 'auth.token_invalid')
    })
  })

  describe('GET /workspaces/:workspaceId/access', () => {
    it('answers a member with the workspace and their role', async () => {
      const alice = await signUp()
      const bob = await signUp()
      const id = await createWorkspace(alice, 'Acme')
      await addMember(id, bob, 'editor')

      const res = await get(`/workspaces/${id}/access`, bob)

      expect(res.status).toBe(200)
      expect(res.body).toMatchObject({
        role: 'editor',
        workspace: { id, name: 'Acme', status: 'active' }
      })
    })

    // Scenario: a workspace the caller is not in, and one that does not exist. Expected: the same
    // status and body. Why: the answer must not reveal which workspaces exist.
    it('answers a non-member exactly as it answers a missing workspace', async () => {
      const alice = await signUp()
      const outsider = await signUp()
      const id = await createWorkspace(alice, 'Private')

      const foreign = await get(`/workspaces/${id}/access`, outsider)
      const missing = await get('/workspaces/does-not-exist/access', outsider)

      expectAuthError(foreign, 'auth.workspace_not_found')
      expect(foreign.status).toBe(missing.status)
      expect(foreign.body).toEqual(missing.body)
    })

    // Scenario: the owner of a workspace pending deletion. Expected: 409, so the client can offer
    // the restore, and nobody else can tell the workspace exists.
    it('answers the owner of a workspace pending deletion with 409', async () => {
      const alice = await signUp()
      const id = await createWorkspace(alice, 'Going')
      await service().scheduleDeletion(
        { tenantId: 'tenant-1', workspaceId: id },
        { userId: alice.id, role: 'owner' },
        CONTEXT
      )

      const res = await get(`/workspaces/${id}/access`, alice)

      expectAuthError(res, 'auth.workspace_pending_deletion')
    })
  })

  describe('POST /workspaces/:workspaceId/switch', () => {
    it('answers a non-member as a missing workspace and records nothing', async () => {
      const alice = await signUp()
      const outsider = await signUp()
      const id = await createWorkspace(alice, 'Private')

      const res = await request(app.getHttpServer())
        .post(`/workspaces/${id}/switch`)
        .set('Authorization', outsider.authorization)

      expectAuthError(res, 'auth.workspace_not_found')
      const list = await get('/workspaces', outsider)
      expect(
        (list.body as { lastActiveWorkspaceId: string | null }).lastActiveWorkspaceId
      ).toBeNull()
    })
  })

  describe('GET /workspaces/:workspaceId/members', () => {
    it('lists every member to a viewer, with role and status', async () => {
      const alice = await signUp()
      const bob = await signUp()
      const id = await createWorkspace(alice, 'Team')
      await addMember(id, bob, 'viewer')

      const res = await get(`/workspaces/${id}/members`, bob)

      expect(res.status).toBe(200)
      const members = (res.body as { items: { userId: string; role: string; status: string }[] })
        .items
      expect(members.map((m) => [m.userId, m.role, m.status]).sort()).toEqual(
        [
          [alice.id, 'owner', 'active'],
          [bob.id, 'viewer', 'active']
        ].sort()
      )
    })

    // Scenario: a cursor taken from one workspace's member list, replayed on another. Expected:
    // the second list holds only the second workspace's members. Why: the workspace of a list
    // comes from the guarded path, so a cursor cannot widen what is read.
    it('does not let a cursor from another workspace widen the result', async () => {
      const alice = await signUp()
      const bob = await signUp()
      const carol = await signUp()
      const first = await createWorkspace(alice, 'First')
      const second = await createWorkspace(bob, 'Second')
      await addMember(first, carol, 'viewer')

      const page = await get(`/workspaces/${first}/members?limit=1`, alice)
      const cursor = (page.body as { nextCursor: string }).nextCursor
      const replay = await get(
        `/workspaces/${second}/members?cursor=${encodeURIComponent(cursor)}`,
        bob
      )

      const ids = (replay.body as { items: { userId: string }[] }).items.map((m) => m.userId)
      expect(replay.status).toBe(200)
      expect(ids.every((id) => id === bob.id)).toBe(true)
      expect(ids).not.toContain(carol.id)
    })

    // Scenario: a caller that is not in the workspace asks for its members. Expected: a missing
    // workspace's answer, not an empty list.
    it('answers a non-member as a missing workspace', async () => {
      const alice = await signUp()
      const outsider = await signUp()
      const id = await createWorkspace(alice, 'Closed')

      const res = await get(`/workspaces/${id}/members`, outsider)

      expectAuthError(res, 'auth.workspace_not_found')
    })
  })

  describe('malformed page parameters', () => {
    const MALFORMED: [label: string, query: string][] = [
      ['a limit of zero', 'limit=0'],
      ['a limit over the maximum', 'limit=101'],
      ['a limit that is not a number', 'limit=abc'],
      ['a fractional limit', 'limit=1.5'],
      ['an empty limit', 'limit='],
      ['an empty cursor', 'cursor='],
      ['a cursor over the length bound', `cursor=${'a'.repeat(513)}`],
      ['a cursor with a control character', 'cursor=ab%00cd'],
      ['a parameter the route does not take', 'workspaceId=other']
    ]

    // Scenario: each malformed value on both list routes. Expected: 400 validation before any
    // repository call. Why: the cursor is opaque, so only its shape can be checked here.
    it.each(MALFORMED)('answers %s with 400 on both lists', async (_label, query) => {
      const alice = await signUp()
      const id = await createWorkspace(alice, 'Pages')

      const mine = await get(`/workspaces?${query}`, alice)
      const members = await get(`/workspaces/${id}/members?${query}`, alice)

      expectAuthError(mine, 'auth.validation')
      expectAuthError(members, 'auth.validation')
    })

    it('accepts the bounds of the limit', async () => {
      const alice = await signUp()

      const low = await get('/workspaces?limit=1', alice)
      const high = await get('/workspaces?limit=100', alice)

      expect([low.status, high.status]).toEqual([200, 200])
    })
  })
})
