/**
 * End-to-end behaviour of every route group while Redis is unreachable, against a REAL Redis
 * container that this suite pauses and stops.
 *
 * A library that holds sessions, revocations, counters and single-use records in Redis answers
 * every request with a Redis call in it. When that store stops answering the answer must be one a
 * client can act on: a typed `503 auth.service_unavailable` in the library's envelope, with none of
 * the store's text in the body, and nothing admitted. These specs drive the real HTTP stack, the
 * real exception filter and a real ioredis client through the three ways the store goes away:
 * paused (it holds the connection and never answers), stopped (the connection is refused) and
 * stopped under the two other client configurations a host may use (no offline queue, a bounded
 * retry count), which are the other two errors ioredis raises.
 *
 * The container is this file's own: the shared one the real-Redis run starts is never paused.
 */

import type { INestApplication } from '@nestjs/common'
import Redis from 'ioredis'
import request from 'supertest'
import { getContainerRuntimeClient } from 'testcontainers'

import { bootstrapTestApp } from '../setup'
import { startRedisContainer, type StartedRedis } from './redis-container'
import { BYMAX_AUTH_REDIS_CLIENT } from '../../../src/server/bymax-auth.constants'

const PASSWORD = 'SuperSecret123!'
const TENANT = 'tenant-1'

/** What a client of the library sees for an outage: the envelope and nothing of the store. */
const UNAVAILABLE = {
  error: {
    code: 'auth.service_unavailable',
    message: 'Service temporarily unavailable',
    details: null
  }
}

/** Fragments of what ioredis and the network say, none of which may reach a body. */
const STORE_TEXT =
  /redis|ioredis|timed out|connection is closed|writeable|max retries|econn|127\.0\.0\.1|localhost/i

/** How the store goes away. */
type Outage = 'pause' | 'stop'

/** A way a host may configure its ioredis client, and the error that configuration raises. */
interface ClientCase {
  readonly name: string
  readonly outage: Outage
  readonly options: {
    readonly commandTimeout?: number
    readonly enableOfflineQueue?: boolean
    readonly maxRetriesPerRequest?: number
  }
}

const CASES: readonly ClientCase[] = [
  {
    name: 'paused, with a command timeout ("Command timed out")',
    outage: 'pause',
    options: { commandTimeout: 400 }
  },
  {
    name: 'stopped, with a command timeout ("Command timed out")',
    outage: 'stop',
    options: { commandTimeout: 400 }
  },
  {
    name: 'stopped, with no offline queue ("Stream isn\'t writeable")',
    outage: 'stop',
    options: { commandTimeout: 400, enableOfflineQueue: false }
  },
  {
    name: 'stopped, with a bounded retry count (MaxRetriesPerRequestError)',
    outage: 'stop',
    options: { maxRetriesPerRequest: 1 }
  }
]

/** Takes the store away the way `outage` says. */
async function takeAway(store: StartedRedis, outage: Outage): Promise<void> {
  if (outage === 'stop') {
    await store.container.stop({ remove: false, timeout: 1 })
    return
  }
  const client = await getContainerRuntimeClient()
  await client.container.getById(store.container.getId()).pause()
}

/** Asserts a response is the library's 503 envelope and nothing else. */
function expectUnavailable(res: request.Response): void {
  expect(res.status).toBe(503)
  expect(res.body).toEqual(UNAVAILABLE)
  expect(JSON.stringify(res.body)).not.toMatch(STORE_TEXT)
  expect(res.headers['set-cookie']).toBeUndefined()
  expect(res.headers['retry-after']).toBeUndefined()
}

describe.each(CASES)('Redis outage, $name (real Redis, E2E)', ({ outage, options }) => {
  let store: StartedRedis
  let client: Redis
  let app: INestApplication
  let bearer: string
  let refreshToken: string

  beforeAll(async () => {
    store = await startRedisContainer()
    client = new Redis(store.url, { retryStrategy: () => 200, ...options })
    client.on('error', () => undefined)
    const boot = await bootstrapTestApp(
      { tokenDelivery: 'bearer', redisNamespace: 'outage' },
      {
        mutateBuilder: (builder) =>
          builder.overrideProvider(BYMAX_AUTH_REDIS_CLIENT).useValue(client)
      }
    )
    app = boot.app
    const registered = await request(app.getHttpServer())
      .post('/register')
      .send({ email: 'outage@example.com', password: PASSWORD, name: 'Outage', tenantId: TENANT })
    expect(registered.status).toBe(201)
    const body = registered.body as { accessToken: string; refreshToken: string }
    bearer = `Bearer ${body.accessToken}`
    refreshToken = body.refreshToken
    await takeAway(store, outage)
  })

  afterAll(async () => {
    await app.close()
    client.disconnect()
    if (outage === 'pause') {
      const runtime = await getContainerRuntimeClient()
      // Already running when the recovery scenario unpaused it.
      await runtime.container
        .getById(store.container.getId())
        .unpause()
        .catch(() => undefined)
    }
    await store.container.stop().catch(() => undefined)
  })

  // Scenario: a login, right or wrong password. Expected: the brute-force read comes first and
  // fails, so neither password gets a 401 or a token.
  it.each([
    ['right', PASSWORD],
    ['wrong', 'not-the-password']
  ])('answers 503 to a login with the %s password', async (_label, password) => {
    const res = await request(app.getHttpServer())
      .post('/login')
      .send({ email: 'outage@example.com', password, tenantId: TENANT })

    expectUnavailable(res)
  })

  // Scenario: an authenticated request. Expected: the guard cannot read the revocation list, so
  // it refuses with 503 and not with 401, which a client would read as "signed out".
  it('answers 503 to an authenticated read and does not call the session signed out', async () => {
    expectUnavailable(await request(app.getHttpServer()).get('/me').set('Authorization', bearer))
    expectUnavailable(
      await request(app.getHttpServer()).get('/sessions').set('Authorization', bearer)
    )
  })

  // Scenario: a refresh. Expected: the rotation script cannot run, so 503, and the refresh token
  // is not reported invalid.
  it('answers 503 to a refresh', async () => {
    expectUnavailable(await request(app.getHttpServer()).post('/refresh').send({ refreshToken }))
  })

  // Scenario: a logout. Expected: 503, because the revocation could not be written.
  it('answers 503 to a logout', async () => {
    expectUnavailable(
      await request(app.getHttpServer()).post('/logout').set('Authorization', bearer)
    )
  })

  // Scenario: a registration, which writes a session. Expected: 503 with no tokens.
  it('answers 503 to a registration', async () => {
    expectUnavailable(
      await request(app.getHttpServer())
        .post('/register')
        .send({ email: 'new@example.com', password: PASSWORD, name: 'New', tenantId: TENANT })
    )
  })

  // Scenario: an MFA setup, which writes a pending secret. Expected: 503.
  it('answers 503 to an MFA setup', async () => {
    expectUnavailable(
      await request(app.getHttpServer()).post('/mfa/setup').set('Authorization', bearer)
    )
  })

  // Scenario: a password-reset request for an address that exists and one that does not.
  // Expected: the cooldown is the first thing both consult, so both answer the same 503 with the
  // same body, and both take at least the anti-enumeration floor.
  it('answers a reset request for a known and an unknown address identically', async () => {
    const send = async (email: string): Promise<{ res: request.Response; ms: number }> => {
      const started = Date.now()
      const res = await request(app.getHttpServer())
        .post('/password/forgot-password')
        .send({ email, tenantId: TENANT })
      return { res, ms: Date.now() - started }
    }

    const known = await send('outage@example.com')
    const unknown = await send('nobody@example.com')

    expectUnavailable(known.res)
    expectUnavailable(unknown.res)
    expect(known.res.body).toEqual(unknown.res.body)
    // Both wait on the store's command timeout and the floor, so a difference of about a second would
    // mean one address takes a longer path. The bound is loose because a loaded machine delays
    // either request; the identical code path, not this number, is what the property rests on.
    expect(Math.abs(known.ms - unknown.ms)).toBeLessThan(1_000)
  })

  // Scenario: the store comes back (only a pause can: a stopped container was removed from the
  // run). Expected: the same login that was refused now succeeds, so nothing the outage touched
  // left the service in a state it could not leave.
  it('recovers when the store returns', async () => {
    if (outage === 'stop') return
    const runtime = await getContainerRuntimeClient()
    await runtime.container.getById(store.container.getId()).unpause()
    await new Promise((resolve) => setTimeout(resolve, 500))

    const res = await request(app.getHttpServer())
      .post('/login')
      .send({ email: 'outage@example.com', password: PASSWORD, tenantId: TENANT })

    expect(res.status).toBe(200)
  })
})
