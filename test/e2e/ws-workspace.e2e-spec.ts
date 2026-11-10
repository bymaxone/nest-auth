/**
 * End-to-end workspace authorization on a socket, and for a queued job.
 *
 * A real Socket.IO handshake reaches a gateway guarded by `WsJwtGuard` and `WsWorkspaceGuard`, over
 * in-memory repositories. What it pins is that a member is admitted per message with the route's
 * role rules, that a stranger and a malformed id are refused with the route's codes, that a member
 * removed between two messages is refused on the second, that the workspace is never read from the
 * handshake, and that the live check a job asks answers from the repositories while the streams
 * answer from the access cache.
 *
 * @layer Test
 */

import type { INestApplication } from '@nestjs/common'
import { UseFilters, UseGuards } from '@nestjs/common'
import { MessageBody, SubscribeMessage, WebSocketGateway } from '@nestjs/websockets'
import { io } from 'socket.io-client'
import type { Socket as ClientSocket } from 'socket.io-client'
import request from 'supertest'

import {
  BYMAX_AUTH_MEMBERSHIP_REPOSITORY,
  BYMAX_AUTH_WORKSPACE_REPOSITORY
} from '../../src/server/bymax-auth.constants'
import { CurrentWsWorkspace } from '../../src/server/decorators/current-ws-workspace.decorator'
import type { CurrentWorkspaceContext } from '../../src/server/decorators/current-workspace.decorator'
import { WorkspaceRoles } from '../../src/server/decorators/workspace-roles.decorator'
import { WsAuthExceptionFilter } from '../../src/server/filters/ws-auth-exception.filter'
import { WsJwtGuard } from '../../src/server/guards/ws-jwt.guard'
import { WsWorkspaceGuard } from '../../src/server/guards/ws-workspace.guard'
import { AuthTokenVerifierService } from '../../src/server/services/auth-token-verifier.service'
import { WorkspaceAccessService } from '../../src/server/services/workspace-access.service'
import { bootstrapTestApp } from './setup'
import type { BootstrappedTestApp } from './setup'
import { memoryRepositories } from './workspace-memory-repositories'

const PASSWORD = 'Ws-Workspace-Passphrase'

type Answer = { ok: true; data: unknown } | { ok: false; code: string | undefined }

@WebSocketGateway({ transports: ['websocket'] })
@UseFilters(new WsAuthExceptionFilter())
class WorkspaceGateway {
  constructor(private readonly verifier: AuthTokenVerifierService) {}

  @UseGuards(WsJwtGuard, WsWorkspaceGuard)
  @WorkspaceRoles('viewer')
  @SubscribeMessage('read')
  read(@CurrentWsWorkspace() workspace: CurrentWorkspaceContext, @MessageBody() _m: unknown) {
    return workspace
  }

  @UseGuards(WsJwtGuard, WsWorkspaceGuard)
  @WorkspaceRoles('editor')
  @SubscribeMessage('write')
  write(@CurrentWsWorkspace() workspace: CurrentWorkspaceContext, @MessageBody() _m: unknown) {
    return workspace
  }

  // Awaits before it answers: a slot on the connection would be overwritten by the other message
  // meanwhile, a per-message workspace is not.
  @UseGuards(WsJwtGuard, WsWorkspaceGuard)
  @WorkspaceRoles('viewer')
  @SubscribeMessage('slow')
  async slow(@CurrentWsWorkspace() workspace: CurrentWorkspaceContext, @MessageBody() _m: unknown) {
    await new Promise((resolve) => setTimeout(resolve, 150))
    return workspace
  }

  @SubscribeMessage('verify')
  async verify(@MessageBody() body: { token: string; workspaceId: string }) {
    const result = await this.verifier.verifyAccessToken(body.token, {
      plane: 'dashboard',
      workspace: { workspaceId: body.workspaceId, roles: ['viewer'] }
    })
    return result.workspace
  }
}

/** Sends one message and reports the answer, or the library code the filter delivered. */
async function send(
  port: number,
  token: string,
  event: string,
  body: unknown,
  query: Record<string, string> = {}
): Promise<Answer> {
  const socket: ClientSocket = io(`http://127.0.0.1:${String(port)}`, {
    transports: ['websocket'],
    forceNew: true,
    reconnection: false,
    query,
    extraHeaders: { Authorization: `Bearer ${token}` }
  })
  try {
    return await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('no answer')), 5_000)
      const settle = (value: Answer): void => {
        clearTimeout(timer)
        resolve(value)
      }
      socket.on('exception', (error: { error?: { code?: string } }) =>
        settle({ ok: false, code: error.error?.code })
      )
      socket.on('connect_error', () => settle({ ok: false, code: undefined }))
      socket.emit(event, body, (data: unknown) => settle({ ok: true, data }))
    })
  } finally {
    socket.disconnect()
  }
}

describe('workspace authorization on a socket and in a job (E2E)', () => {
  let boot: BootstrappedTestApp
  let app: INestApplication
  let port: number
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
        hostProviders: [WorkspaceGateway],
        extraModuleProviders: [
          { provide: BYMAX_AUTH_WORKSPACE_REPOSITORY, useValue: repositories.workspaces },
          { provide: BYMAX_AUTH_MEMBERSHIP_REPOSITORY, useValue: repositories.memberships }
        ]
      }
    )
    app = boot.app
    await app.listen(0)
    port = (app.getHttpServer() as { address: () => { port: number } }).address().port
  })

  afterAll(async () => {
    await app.close()
  })

  async function signUp(): Promise<{ id: string; token: string }> {
    sequence += 1
    const res = await request(app.getHttpServer())
      .post('/register')
      .send({
        email: `ws${sequence}@example.com`,
        password: PASSWORD,
        name: `Person ${sequence}`,
        tenantId: 'tenant-1'
      })
    const body = res.body as { accessToken: string; user: { id: string } }
    await boot.repo.updateEmailVerified({ id: body.user.id, tenantId: 'tenant-1', verified: true })
    return { id: body.user.id, token: body.accessToken }
  }

  /** A workspace and a member of it with `role`, plus a stranger who belongs to nothing. */
  async function world(role = 'viewer') {
    const owner = await signUp()
    const created = await request(app.getHttpServer())
      .post('/workspaces')
      .set('Authorization', `Bearer ${owner.token}`)
      .send({ name: 'Team' })
    const id = (created.body as { id: string }).id
    const member = await signUp()
    repositories.seedMember(id, member.id, role)
    return { id, owner, member, stranger: await signUp() }
  }

  async function forget(workspaceId: string, userId: string): Promise<void> {
    await app
      .get(WorkspaceAccessService, { strict: false })
      .invalidateMembership({ tenantId: 'tenant-1', workspaceId, userId })
  }

  it('admits a member to a handler their role covers and hands it the membership', async () => {
    const { id, member } = await world('viewer')

    const answer = await send(port, member.token, 'read', { workspaceId: id })

    expect(answer).toEqual({
      ok: true,
      data: { tenantId: 'tenant-1', workspaceId: id, userId: member.id, role: 'viewer' }
    })
  })

  it('refuses a role below the handler with the route code', async () => {
    const { id, member } = await world('viewer')

    expect(await send(port, member.token, 'write', { workspaceId: id })).toEqual({
      ok: false,
      code: 'auth.insufficient_workspace_role'
    })
  })

  it('answers a stranger and an unknown workspace with the identical not-found', async () => {
    const { id, stranger } = await world()

    const stranded = await send(port, stranger.token, 'read', { workspaceId: id })
    const unknown = await send(port, stranger.token, 'read', {
      workspaceId: '00000000-0000-4000-8000-000000000000'
    })

    expect(stranded).toEqual({ ok: false, code: 'auth.workspace_not_found' })
    expect(unknown).toEqual(stranded)
  })

  it('refuses a malformed id as a validation error before any lookup', async () => {
    const { member } = await world()

    expect(await send(port, member.token, 'read', { workspaceId: '   ' })).toEqual({
      ok: false,
      code: 'auth.validation'
    })
  })

  it('never reads the workspace from the handshake query', async () => {
    const { id, member } = await world()

    expect(await send(port, member.token, 'read', {}, { workspaceId: id })).toEqual({
      ok: false,
      code: 'auth.validation'
    })
  })

  it('keeps two overlapping messages on one socket in their own workspaces', async () => {
    const first = await world('viewer')
    const second = await world('viewer')
    // One account, a member of both workspaces.
    repositories.seedMember(second.id, first.member.id, 'viewer')
    const socket: ClientSocket = io(`http://127.0.0.1:${String(port)}`, {
      transports: ['websocket'],
      forceNew: true,
      reconnection: false,
      extraHeaders: { Authorization: `Bearer ${first.member.token}` }
    })
    try {
      const ask = (event: string, workspaceId: string): Promise<unknown> =>
        new Promise((resolve) => socket.emit(event, { workspaceId }, resolve))

      const [slow, fast] = await Promise.all([ask('slow', first.id), ask('read', second.id)])

      expect(slow).toMatchObject({ workspaceId: first.id })
      expect(fast).toMatchObject({ workspaceId: second.id })
    } finally {
      socket.disconnect()
    }
  })

  it('refuses a member who was removed between two messages on the second', async () => {
    const { id, member } = await world()
    expect((await send(port, member.token, 'read', { workspaceId: id })).ok).toBe(true)

    repositories.seedMember(id, member.id, 'viewer', 'suspended')
    await forget(id, member.id)

    expect(await send(port, member.token, 'read', { workspaceId: id })).toEqual({
      ok: false,
      code: 'auth.workspace_not_found'
    })
  })

  it('admits a stream through the verifier option with the same rules', async () => {
    const { id, member, stranger } = await world()

    const admitted = await send(port, member.token, 'verify', {
      token: member.token,
      workspaceId: id
    })
    const refused = await send(port, stranger.token, 'verify', {
      token: stranger.token,
      workspaceId: id
    })

    expect(admitted).toMatchObject({ ok: true, data: { workspaceId: id, role: 'viewer' } })
    expect(refused).toEqual({ ok: false, code: 'auth.workspace_not_found' })
  })

  it('answers a job from the repositories while a stream still answers from the cache', async () => {
    const { id, member } = await world()
    const access = app.get(WorkspaceAccessService, { strict: false })
    const job = { tenantId: 'tenant-1', workspaceId: id, actorUserId: member.id }
    expect(await access.assertStillAuthorized(job, ['viewer'])).toMatchObject({ role: 'viewer' })
    expect((await send(port, member.token, 'read', { workspaceId: id })).ok).toBe(true)

    repositories.seedMember(id, member.id, 'viewer', 'suspended')

    await expect(access.assertStillAuthorized(job, ['viewer'])).rejects.toMatchObject({
      response: { error: { code: 'auth.workspace_not_found' } }
    })
    expect((await send(port, member.token, 'read', { workspaceId: id })).ok).toBe(true)
  })
})
