/**
 * @fileoverview Rotating `jwt.secret` with and without a pinned `identifierKey`.
 *
 * Every Redis name that identifies an account — the session index, the token epoch, the MFA
 * keys, the recent-authentication marker — is an HMAC under a key derived from one secret. When
 * that secret is `jwt.secret`, rotating it renames all of them: the live sessions lose their
 * index and every epoch reads zero, which brings back tokens a password reset or a revoke-all
 * had already refused. `identifierKey` names the secret the identifiers derive from instead, so
 * the signing secret can change while the names stay put.
 *
 * Two applications run over ONE Redis and ONE repository, the second built with a new signing
 * secret and the first one listed as retired, which is the shape of a rotation in production.
 */

import type { INestApplication } from '@nestjs/common'
import request from 'supertest'

import {
  BYMAX_AUTH_REDIS_CLIENT,
  BYMAX_AUTH_USER_REPOSITORY
} from '../../src/server/bymax-auth.constants'
import { WsTicketService } from '../../src/server/services/ws-ticket.service'
import type { BootstrappedTestApp } from './setup'
import { bootstrapTestApp } from './setup'

const OLD_SECRET = 'xY9!kL2@mN5#pQ8$rS1%tU4^vW7&zA0B'
const NEW_SECRET = 'Qw3$eR6%tY9&uI2*oP5(aS8)dF1!gH4@jK7'
const EMAIL = 'rotating@example.com'
const PASSWORD = 'RotationSecret123!'
const TENANT = 'tenant-1'

interface Session {
  accessToken: string
  refreshToken: string
}

/** Boots the first application: the deployment as it stands before the rotation. */
function bootBefore(identifierKey: string | undefined): Promise<BootstrappedTestApp> {
  return bootstrapTestApp({
    jwt: { secret: OLD_SECRET },
    ...(identifierKey === undefined ? {} : { identifierKey })
  })
}

/** Boots the application after the rotation, over the same Redis and users as `before`. */
function bootAfter(
  before: BootstrappedTestApp,
  identifierKey: string | undefined
): Promise<BootstrappedTestApp> {
  return bootstrapTestApp(
    {
      jwt: { secret: NEW_SECRET, previousSecrets: [OLD_SECRET] },
      ...(identifierKey === undefined ? {} : { identifierKey })
    },
    {
      mutateBuilder: (builder) =>
        builder
          .overrideProvider(BYMAX_AUTH_REDIS_CLIENT)
          .useValue(before.redis)
          .overrideProvider(BYMAX_AUTH_USER_REPOSITORY)
          .useValue(before.repo)
    }
  )
}

async function login(app: INestApplication, userAgent: string): Promise<Session> {
  const res = await request(app.getHttpServer())
    .post('/login')
    .set('User-Agent', userAgent)
    .send({ email: EMAIL, password: PASSWORD, tenantId: TENANT })

  return {
    accessToken: res.body.accessToken as string,
    refreshToken: res.body.refreshToken as string
  }
}

/** Lists the caller's sessions with an access token; the status is what the epoch decides. */
function listSessions(app: INestApplication, accessToken: string): request.Test {
  return request(app.getHttpServer()).get('/sessions').set('Authorization', `Bearer ${accessToken}`)
}

describe('jwt.secret rotation (E2E)', () => {
  const apps: INestApplication[] = []

  /**
   * Builds the state every case starts from: a user with two live sessions, the second of which
   * revokes the others. That advances the token epoch, so the first session's access token is
   * the "revoked token" a rotation must not bring back.
   */
  async function prepare(before: BootstrappedTestApp): Promise<{
    revoked: Session
    live: Session
    ticket: string
  }> {
    apps.push(before.app)
    await request(before.app.getHttpServer())
      .post('/register')
      .send({ email: EMAIL, password: PASSWORD, name: 'Rotating User', tenantId: TENANT })
    const revoked = await login(before.app, 'agent-a')
    const live = await login(before.app, 'agent-b')

    await request(before.app.getHttpServer())
      .post('/sessions/revoke-all')
      .set('Authorization', `Bearer ${live.accessToken}`)
      .send({ refreshToken: live.refreshToken })
      .expect(204)

    // The revoke advanced the epoch past the token the live session holds, so it signs in again
    // from its refresh token, exactly as a client would.
    const refreshed = await request(before.app.getHttpServer())
      .post('/refresh')
      .send({ refreshToken: live.refreshToken })
    const current: Session = {
      accessToken: refreshed.body.accessToken as string,
      refreshToken: refreshed.body.refreshToken as string
    }

    const ticket = (
      await request(before.app.getHttpServer())
        .post('/ws-ticket')
        .set('Authorization', `Bearer ${current.accessToken}`)
    ).body.ticket as string

    return { revoked, live: current, ticket }
  }

  afterEach(async () => {
    await Promise.all(apps.splice(0).map((app) => app.close()))
  })

  // The epoch that refused the token before the rotation is found under the same name after it,
  // so the token stays refused. This is the property the option exists for.
  it('keeps a revoked access token refused after the signing secret changes', async () => {
    const before = await bootBefore(OLD_SECRET)
    const { revoked } = await prepare(before)
    expect((await listSessions(before.app, revoked.accessToken)).status).toBe(401)

    const after = await bootAfter(before, OLD_SECRET)
    apps.push(after.app)

    expect((await listSessions(after.app, revoked.accessToken)).status).toBe(401)
  })

  // The refresh token is opaque and the session index is found by name, so a session that was
  // alive when the secret changed keeps refreshing and keeps its place in the session list.
  it('keeps a live session refreshing and listed after the signing secret changes', async () => {
    const before = await bootBefore(OLD_SECRET)
    const { live } = await prepare(before)

    const after = await bootAfter(before, OLD_SECRET)
    apps.push(after.app)

    // Listed straight after the rotation, before any refresh could write the index afresh: the
    // session is found only if the index kept its name.
    const listed = await listSessions(after.app, live.accessToken)
    expect(listed.status).toBe(200)
    expect((listed.body as unknown[]).length).toBe(1)

    const refreshed = await request(after.app.getHttpServer())
      .post('/refresh')
      .send({ refreshToken: live.refreshToken })
    expect(refreshed.status).toBe(200)
  })

  // The WebSocket ticket family is part of the rotation too: a ticket issued before it redeems
  // after it, and a new one issued after it redeems as well.
  it('redeems a WebSocket ticket issued before the rotation and one issued after it', async () => {
    const before = await bootBefore(OLD_SECRET)
    const { live, ticket } = await prepare(before)

    const after = await bootAfter(before, OLD_SECRET)
    apps.push(after.app)

    const old = await after.app.get(WsTicketService).redeem(ticket)
    expect(old.sub).toBe(before.repo.users.values().next().value?.id)

    const refreshed = await request(after.app.getHttpServer())
      .post('/refresh')
      .send({ refreshToken: live.refreshToken })
    const issued = await request(after.app.getHttpServer())
      .post('/ws-ticket')
      .set('Authorization', `Bearer ${refreshed.body.accessToken as string}`)
    expect(issued.status).toBe(200)
    await expect(
      after.app.get(WsTicketService).redeem(issued.body.ticket as string)
    ).resolves.toMatchObject({ sub: old.sub })
  })

  // The control: with no `identifierKey` the identifiers derive from `jwt.secret`, so the
  // rotation renames the epoch and the token it had refused is accepted again. This is the
  // exposure the rotation guide exists for, pinned so a change to the default is seen.
  it('without identifierKey, a rotation renames the epoch and the revoked token is accepted again', async () => {
    const before = await bootBefore(undefined)
    const { revoked } = await prepare(before)
    expect((await listSessions(before.app, revoked.accessToken)).status).toBe(401)

    const after = await bootAfter(before, undefined)
    apps.push(after.app)

    expect((await listSessions(after.app, revoked.accessToken)).status).toBe(200)
  })
})
