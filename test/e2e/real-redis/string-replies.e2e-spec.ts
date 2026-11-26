/**
 * @fileoverview A host client built with `stringNumbers: true`, against a REAL Redis.
 *
 * Such a client answers every integer reply as a string. Each case drives a route whose answer
 * depends on one of those replies: a counter, a TTL, a set command or the integer a script
 * returns. Only a real server and a real client produce the reply shape under test.
 *
 * @layer Test
 */

import type { INestApplication } from '@nestjs/common'
import Redis from 'ioredis'
import request from 'supertest'

import {
  BYMAX_AUTH_MEMBERSHIP_REPOSITORY,
  BYMAX_AUTH_REDIS_CLIENT,
  BYMAX_AUTH_WORKSPACE_REPOSITORY
} from '../../../src/server/bymax-auth.constants'
import type { BootstrappedTestApp, ExtraBootstrapOptions } from '../setup'
import { bootstrapTestApp, expectAuthError } from '../setup'
import { memoryRepositories } from '../workspace-memory-repositories'
import type { BymaxAuthModuleOptions } from '../../../src/server/interfaces/auth-module-options.interface'

const PASSWORD = 'SuperSecret123!'
const TENANT = 'tenant-1'

/** Boots the application over a client of its own, built with `stringNumbers`. */
async function bootWithStringNumbers(
  overrides: Partial<BymaxAuthModuleOptions> = {},
  extra: ExtraBootstrapOptions = {}
): Promise<{ boot: BootstrappedTestApp; client: Redis }> {
  const client = new Redis(process.env['BYMAX_E2E_REDIS_URL'] as string, { stringNumbers: true })
  const boot = await bootstrapTestApp(overrides, {
    ...extra,
    mutateBuilder: (builder) => builder.overrideProvider(BYMAX_AUTH_REDIS_CLIENT).useValue(client)
  })
  return { boot, client }
}

/** Registers an account and returns its token pair. */
async function register(
  app: INestApplication,
  email: string
): Promise<{ id: string; accessToken: string; refreshToken: string }> {
  const res = await request(app.getHttpServer())
    .post('/register')
    .send({ email, password: PASSWORD, name: 'String Replies', tenantId: TENANT })
  const body = res.body as { accessToken: string; refreshToken: string; user: { id: string } }
  return { id: body.user.id, accessToken: body.accessToken, refreshToken: body.refreshToken }
}

/** One login attempt. */
function login(app: INestApplication, email: string, password: string): request.Test {
  return request(app.getHttpServer()).post('/login').send({ email, password, tenantId: TENANT })
}

describe('a client built with stringNumbers (E2E, real Redis)', () => {
  let boot: BootstrappedTestApp
  let client: Redis
  let app: INestApplication

  beforeAll(async () => {
    ;({ boot, client } = await bootWithStringNumbers())
    app = boot.app
  })

  afterAll(async () => {
    await app.close()
    client.disconnect()
  })

  // The premise of every case below: without it they would pass for the wrong reason.
  it('answers an integer reply as a string', async () => {
    const key = `${boot.options.redisNamespace ?? 'auth'}:probe`

    await expect(client.incr(key)).resolves.toBe('1')
  })

  it('answers the lockout wait as a number', async () => {
    await register(app, 'lockout@example.com')
    for (let attempt = 1; attempt <= 5; attempt += 1) {
      expectAuthError(
        await login(app, 'lockout@example.com', 'WrongPassword123!'),
        'auth.invalid_credentials'
      )
    }

    const locked = await login(app, 'lockout@example.com', PASSWORD)

    expectAuthError(locked, 'auth.account_locked')
    const body = locked.body as { error: { details: { retryAfterSeconds: unknown } } }
    expect(body.error.details.retryAfterSeconds).toEqual(expect.any(Number))
    expect(body.error.details.retryAfterSeconds).toBeGreaterThan(0)
  })

  it('serves a refresh token presented again inside its grace window', async () => {
    const account = await register(app, 'grace@example.com')
    const refresh = (): request.Test =>
      request(app.getHttpServer()).post('/refresh').send({ refreshToken: account.refreshToken })

    expect((await refresh()).status).toBe(200)
    expect((await refresh()).status).toBe(200)
  })

  it('answers the revocation of a session as done and cuts the access tokens', async () => {
    const account = await register(app, 'revoke@example.com')
    const second = await login(app, 'revoke@example.com', PASSWORD)
    const { accessToken, refreshToken } = second.body as {
      accessToken: string
      refreshToken: string
    }
    const listed = await request(app.getHttpServer())
      .get('/sessions')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ refreshToken })
    const other = (listed.body as { sessionHash: string; isCurrent: boolean }[]).find(
      (session) => !session.isCurrent
    )

    const me = (): request.Test =>
      request(app.getHttpServer()).get('/me').set('Authorization', `Bearer ${account.accessToken}`)
    expect((await me()).status).toBe(200)

    const revoked = await request(app.getHttpServer())
      .delete(`/sessions/${other?.sessionHash ?? ''}`)
      .set('Authorization', `Bearer ${accessToken}`)

    expect(revoked.status).toBe(204)
    expectAuthError(await me(), 'auth.token_invalid')
  })
})

describe('a client built with stringNumbers, per-IP limits (E2E, real Redis)', () => {
  let client: Redis
  let app: INestApplication

  beforeAll(async () => {
    const started = await bootWithStringNumbers({
      rateLimit: { enabled: true, clientIpSource: 'peer' }
    })
    client = started.client
    app = started.boot.app
  })

  afterAll(async () => {
    await app.close()
    client.disconnect()
  })

  it('refuses the sixth login attempt from one address inside the window', async () => {
    for (let attempt = 1; attempt <= 5; attempt += 1) {
      expectAuthError(
        await login(app, 'limited@example.com', 'WrongPassword123!'),
        'auth.invalid_credentials'
      )
    }

    expectAuthError(
      await login(app, 'limited@example.com', 'WrongPassword123!'),
      'auth.too_many_requests'
    )
  })
})

describe('a client built with stringNumbers, workspace invitations (E2E, real Redis)', () => {
  const repositories = memoryRepositories()
  let client: Redis
  let app: INestApplication

  beforeAll(async () => {
    const started = await bootWithStringNumbers(
      {
        workspaces: {
          enabled: true,
          roles: { hierarchy: { owner: ['viewer'], viewer: [] }, ownerRole: 'owner' },
          permissions: { manageMembers: ['owner'] }
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
    client = started.client
    app = started.boot.app
  })

  afterAll(async () => {
    await app.close()
    client.disconnect()
  })

  it('answers a stored invitation as done', async () => {
    const owner = await register(app, 'owner@example.com')
    const post = (path: string, body: object): request.Test =>
      request(app.getHttpServer())
        .post(path)
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send(body)
    const created = await post('/workspaces', { name: 'Team' })
    const id = (created.body as { id: string }).id

    const invited = await post(`/workspaces/${id}/invitations`, {
      email: 'invitee@example.com',
      role: 'viewer'
    })

    expect(invited.status).toBe(204)
  })
})
