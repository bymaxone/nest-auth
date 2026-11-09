/**
 * @fileoverview Drives `WorkspaceGuard` from a host's own controller, over HTTP, behind the real
 * `JwtAuthGuard` and `UserStatusGuard`.
 *
 * A unit test hands the guard an `ExecutionContext` no pipeline would build. This suite plays the
 * consumer: the controller is declared in the test module, so the guard is instantiated in the
 * host's injector and can resolve only what `BymaxAuthModule` exports. It proves the route is
 * reachable, that the answers a caller sees do not distinguish a missing workspace from one it may
 * not enter, and that the workspace is never taken from anywhere but the route.
 *
 * @layer Test
 */

import { Controller, Get, Post, UseGuards } from '@nestjs/common'
import type { INestApplication } from '@nestjs/common'
import request from 'supertest'

import {
  BYMAX_AUTH_MEMBERSHIP_REPOSITORY,
  BYMAX_AUTH_WORKSPACE_REPOSITORY
} from '../../src/server/bymax-auth.constants'
import { ANY_WORKSPACE_MEMBER } from '../../src/server/constants/workspace-roles'
import { AllowPendingWorkspace } from '../../src/server/decorators/allow-pending-workspace.decorator'
import { CurrentWorkspace } from '../../src/server/decorators/current-workspace.decorator'
import type { CurrentWorkspaceContext } from '../../src/server/decorators/current-workspace.decorator'
import { WorkspaceRoles } from '../../src/server/decorators/workspace-roles.decorator'
import { AUTH_ERROR_CODES } from '../../src/server/errors/auth-error-codes'
import { JwtAuthGuard } from '../../src/server/guards/jwt-auth.guard'
import { UserStatusGuard } from '../../src/server/guards/user-status.guard'
import { WorkspaceGuard } from '../../src/server/guards/workspace.guard'
import type {
  AuthMembership,
  IMembershipRepository
} from '../../src/server/interfaces/membership-repository.interface'
import type {
  AuthWorkspace,
  IWorkspaceRepository
} from '../../src/server/interfaces/workspace-repository.interface'
import { WorkspaceAccessService } from '../../src/server/services/workspace-access.service'
import type { BootstrappedTestApp } from './setup'
import { bootstrapTestApp, expectAuthError } from './setup'

const PASSWORD = 'Workspace-Guard-Passphrase'

/** The workspaces and memberships the in-memory repositories serve, keyed `tenant/workspace`. */
const workspaces = new Map<string, AuthWorkspace>()
const memberships = new Map<string, AuthMembership>()

function seedWorkspace(
  tenantId: string,
  id: string,
  status: AuthWorkspace['status'] = 'active'
): void {
  workspaces.set(`${tenantId}/${id}`, {
    id,
    tenantId,
    name: id,
    status,
    createdAt: new Date(0),
    deletionScheduledAt: null
  })
}

function seedMembership(tenantId: string, workspaceId: string, userId: string, role: string): void {
  memberships.set(`${tenantId}/${workspaceId}/${userId}`, {
    tenantId,
    workspaceId,
    userId,
    role,
    status: 'active',
    invitedByUserId: null,
    createdAt: new Date(0),
    updatedAt: new Date(0)
  })
}

const workspaceRepository: Partial<IWorkspaceRepository> = {
  findById: async ({ tenantId, workspaceId }) =>
    workspaces.get(`${tenantId}/${workspaceId}`) ?? null
}

const membershipRepository: Partial<IMembershipRepository> = {
  find: async ({ tenantId, workspaceId, userId }) =>
    memberships.get(`${tenantId}/${workspaceId}/${userId}`) ?? null
}

/** A consumer's controller: every route is the documented composition. */
@Controller('host')
class HostWorkspaceController {
  @Get('w/:workspaceId/edit')
  @UseGuards(JwtAuthGuard, UserStatusGuard, WorkspaceGuard)
  @WorkspaceRoles('editor')
  edit(@CurrentWorkspace() workspace: CurrentWorkspaceContext): CurrentWorkspaceContext {
    return workspace
  }

  @Get('w/:workspaceId/read')
  @UseGuards(JwtAuthGuard, UserStatusGuard, WorkspaceGuard)
  @WorkspaceRoles(ANY_WORKSPACE_MEMBER)
  read(@CurrentWorkspace() workspace: CurrentWorkspaceContext): CurrentWorkspaceContext {
    return workspace
  }

  @Get('w/:workspaceId/undeclared')
  @UseGuards(JwtAuthGuard, UserStatusGuard, WorkspaceGuard)
  undeclared(): { reached: true } {
    return { reached: true }
  }

  @Post('w/:workspaceId/restore')
  @UseGuards(JwtAuthGuard, UserStatusGuard, WorkspaceGuard)
  @WorkspaceRoles('owner')
  @AllowPendingWorkspace()
  restore(@CurrentWorkspace() workspace: CurrentWorkspaceContext): CurrentWorkspaceContext {
    return workspace
  }

  @Get('w/:workspaceId/no-auth')
  @UseGuards(WorkspaceGuard)
  @WorkspaceRoles(ANY_WORKSPACE_MEMBER)
  withoutAuth(): { reached: true } {
    return { reached: true }
  }

  @Get('no-workspace')
  @UseGuards(JwtAuthGuard, UserStatusGuard, WorkspaceGuard)
  @WorkspaceRoles(ANY_WORKSPACE_MEMBER)
  noWorkspace(): { reached: true } {
    return { reached: true }
  }

  @Post('w/:workspaceId/write')
  @UseGuards(JwtAuthGuard, UserStatusGuard, WorkspaceGuard)
  @WorkspaceRoles('editor')
  write(@CurrentWorkspace() workspace: CurrentWorkspaceContext): CurrentWorkspaceContext {
    return workspace
  }
}

/** Registers an account in a tenant and returns its token and id. */
async function register(
  app: INestApplication,
  email: string,
  tenantId: string
): Promise<{ accessToken: string; userId: string }> {
  const res = await request(app.getHttpServer())
    .post('/register')
    .send({ email, password: PASSWORD, name: 'Member', tenantId })
  return {
    accessToken: res.body.accessToken as string,
    userId: (res.body.user as { id: string }).id
  }
}

describe('WorkspaceGuard (E2E)', () => {
  let boot: BootstrappedTestApp
  let app: INestApplication
  let alice: { accessToken: string; userId: string }

  const get = (path: string, token = alice.accessToken) =>
    request(app.getHttpServer()).get(path).set('Authorization', `Bearer ${token}`)

  beforeAll(async () => {
    boot = await bootstrapTestApp(
      {
        workspaces: {
          enabled: true,
          roles: {
            hierarchy: { owner: ['editor', 'viewer'], editor: ['viewer'], viewer: [] },
            ownerRole: 'owner'
          }
        }
      },
      {
        extraModuleProviders: [
          { provide: BYMAX_AUTH_WORKSPACE_REPOSITORY, useValue: workspaceRepository },
          { provide: BYMAX_AUTH_MEMBERSHIP_REPOSITORY, useValue: membershipRepository }
        ],
        hostControllers: [HostWorkspaceController]
      }
    )
    app = boot.app
    alice = await register(app, 'alice@example.com', 'tenant-1')
    seedWorkspace('tenant-1', 'w1')
    seedWorkspace('tenant-1', 'w-pending', 'pending_deletion')
    seedWorkspace('tenant-2', 'w-other')
    seedMembership('tenant-1', 'w1', alice.userId, 'editor')
    seedMembership('tenant-1', 'w-pending', alice.userId, 'owner')
    seedMembership('tenant-2', 'w-other', alice.userId, 'owner')
  })

  afterAll(async () => {
    await app.close()
  })

  it('admits an active member holding the required role and exposes the access', async () => {
    const res = await get('/host/w/w1/edit')

    expect(res.status).toBe(200)
    expect(res.body).toEqual({
      tenantId: 'tenant-1',
      workspaceId: 'w1',
      userId: alice.userId,
      role: 'editor'
    })
  })

  it('admits any member where the route accepts the any-member marker', async () => {
    const res = await get('/host/w/w1/read')

    expect(res.status).toBe(200)
  })

  it('refuses a role below the one the route declares', async () => {
    seedMembership('tenant-1', 'w1', alice.userId, 'viewer')
    await app.get(WorkspaceAccessService).invalidateMembership({
      tenantId: 'tenant-1',
      workspaceId: 'w1',
      userId: alice.userId
    })

    expectAuthError(await get('/host/w/w1/edit'), AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE)

    seedMembership('tenant-1', 'w1', alice.userId, 'editor')
    await app.get(WorkspaceAccessService).invalidateMembership({
      tenantId: 'tenant-1',
      workspaceId: 'w1',
      userId: alice.userId
    })
  })

  // The three cases a caller must not be able to tell apart.
  it('answers a missing workspace and a foreign tenant identically', async () => {
    const missing = await get('/host/w/nope/read')
    const foreign = await get('/host/w/w-other/read')

    for (const res of [missing, foreign]) {
      expectAuthError(res, AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND)
    }
    expect(foreign.body).toEqual(missing.body)
  })

  describe('a workspace pending deletion', () => {
    it('tells its owner with 409, and only on routes that do not admit it', async () => {
      const res = await get('/host/w/w-pending/read')

      expectAuthError(res, AUTH_ERROR_CODES.WORKSPACE_PENDING_DELETION)
    })

    it('admits its owner on the restore route', async () => {
      const res = await request(app.getHttpServer())
        .post('/host/w/w-pending/restore')
        .set('Authorization', `Bearer ${alice.accessToken}`)

      expect(res.status).toBe(201)
      expect(res.body).toEqual({
        tenantId: 'tenant-1',
        workspaceId: 'w-pending',
        userId: alice.userId,
        role: 'owner'
      })
    })

    it('gives a non-owner member the same answer as a missing workspace', async () => {
      const dave = await register(app, 'dave@example.com', 'tenant-1')
      seedMembership('tenant-1', 'w-pending', dave.userId, 'editor')

      const pending = await get('/host/w/w-pending/read', dave.accessToken)
      const missing = await get('/host/w/nope/read', dave.accessToken)

      expectAuthError(pending, AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND)
      expect(pending.body).toEqual(missing.body)
    })
  })

  it('refuses a route that declares no roles, even for an owner', async () => {
    seedMembership('tenant-1', 'w1', alice.userId, 'owner')
    await app.get(WorkspaceAccessService).invalidateMembership({
      tenantId: 'tenant-1',
      workspaceId: 'w1',
      userId: alice.userId
    })

    expectAuthError(await get('/host/w/w1/undeclared'), AUTH_ERROR_CODES.FORBIDDEN)

    seedMembership('tenant-1', 'w1', alice.userId, 'editor')
    await app.get(WorkspaceAccessService).invalidateMembership({
      tenantId: 'tenant-1',
      workspaceId: 'w1',
      userId: alice.userId
    })
  })

  describe('where the workspace may come from', () => {
    it('refuses a request that names none, whatever it carries elsewhere', async () => {
      const res = await get('/host/no-workspace?workspaceId=w1').set('X-Workspace-Id', 'w1')

      expectAuthError(res, AUTH_ERROR_CODES.WORKSPACE_REQUIRED)
    })

    it('ignores a workspace id in the body', async () => {
      const res = await request(app.getHttpServer())
        .post('/host/w/w-other/write')
        .set('Authorization', `Bearer ${alice.accessToken}`)
        .send({ workspaceId: 'w1' })

      expectAuthError(res, AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND)
    })

    // A blank id passes the character check, so it has to be refused as an id: reaching the
    // access service with it would be a 500, and the caller supplied it.
    it('answers 400, not 500, for a whitespace-only id', async () => {
      const res = await get('/host/w/%20%20%20/read')

      expectAuthError(res, AUTH_ERROR_CODES.VALIDATION)
    })

    it('refuses an id that is not a usable workspace id', async () => {
      const res = await get(`/host/w/${'x'.repeat(200)}/read`)

      expectAuthError(res, AUTH_ERROR_CODES.VALIDATION)
    })
  })

  describe('the token', () => {
    it('refuses a request with no token before the guard is consulted', async () => {
      const res = await request(app.getHttpServer()).get('/host/w/w1/read')

      expectAuthError(res, AUTH_ERROR_CODES.TOKEN_INVALID)
    })

    // The guard reads the user the guards before it attach. Mounted alone it must refuse, not throw.
    it('answers 401 when mounted without the guard that verifies the token', async () => {
      const res = await get('/host/w/w1/no-auth')

      expectAuthError(res, AUTH_ERROR_CODES.TOKEN_INVALID)
    })

    it('uses the tenant of the token, not one the caller supplies', async () => {
      const bob = await register(app, 'bob@example.com', 'tenant-2')
      seedWorkspace('tenant-2', 'w1')
      seedMembership('tenant-2', 'w1', bob.userId, 'owner')

      // `w1` exists in both tenants and Bob belongs only to tenant-2's. A guard that read the
      // tenant from the query would look in tenant-1, where he is no member, and answer 404.
      const res = await get('/host/w/w1/read?tenantId=tenant-1', bob.accessToken)

      expect(res.status).toBe(200)
      expect(res.body).toEqual({
        tenantId: 'tenant-2',
        workspaceId: 'w1',
        userId: bob.userId,
        role: 'owner'
      })
    })
  })

  it('ends access as soon as the membership change is invalidated', async () => {
    const carol = await register(app, 'carol@example.com', 'tenant-1')
    seedMembership('tenant-1', 'w1', carol.userId, 'viewer')
    expect((await get('/host/w/w1/read', carol.accessToken)).status).toBe(200)

    memberships.delete(`tenant-1/w1/${carol.userId}`)
    await app.get(WorkspaceAccessService).invalidateMembership({
      tenantId: 'tenant-1',
      workspaceId: 'w1',
      userId: carol.userId
    })

    expectAuthError(
      await get('/host/w/w1/read', carol.accessToken),
      AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND
    )
  })
})
