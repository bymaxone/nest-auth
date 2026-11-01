/**
 * End-to-end session listing when the store fails to read a session's detail.
 *
 * `GET /sessions` is the caller's only view of their own sessions, and the sessions they cannot
 * see are the ones they cannot revoke. A read fault on one session's detail record must therefore
 * fail the listing, not leave that session out of an answer that still looks complete. The
 * cleanup that does not depend on the outcome still runs, and a live session's index entry is
 * never lost to a read fault. These specs drive the real HTTP stack, controller and error filter
 * over a Redis whose detail reads can be made to fail on demand.
 */

import type { INestApplication } from '@nestjs/common'
import type Redis from 'ioredis'
import request from 'supertest'

import { BYMAX_AUTH_REDIS_CLIENT } from '../../src/server/bymax-auth.constants'
import { bootstrapTestApp, createMockRedis, expectAuthError } from './setup'

const FAULT = 'ECONNRESET secret-store-detail'

/** A Redis whose `get` of any `sd:` key fails while `failing.current` is set. */
function flaky(redis: Redis, failing: { current: boolean }): Redis {
  return new Proxy(redis, {
    get(target, prop, receiver): unknown {
      const value: unknown = Reflect.get(target, prop, receiver)
      if (typeof value !== 'function') return value
      return (...args: unknown[]): unknown => {
        if (failing.current && String(prop) === 'get' && String(args[0]).includes('sd:')) {
          return Promise.reject(new Error(FAULT))
        }
        return (value as (...a: unknown[]) => unknown).apply(target, args)
      }
    }
  })
}

describe('session listing when a detail read fails (E2E)', () => {
  let app: INestApplication
  let store: Redis
  let bearer: string
  const failing = { current: false }

  beforeEach(async () => {
    failing.current = false
    store = createMockRedis()
    const boot = await bootstrapTestApp(
      { tokenDelivery: 'bearer' },
      {
        mutateBuilder: (builder) =>
          builder.overrideProvider(BYMAX_AUTH_REDIS_CLIENT).useValue(flaky(store, failing))
      }
    )
    app = boot.app
    const registered = await request(app.getHttpServer()).post('/register').send({
      email: 'listing-fault@example.com',
      password: 'SuperSecret123!',
      name: 'Listing User',
      tenantId: 'tenant-1'
    })
    expect(registered.status).toBe(201)
    bearer = `Bearer ${(registered.body as { accessToken: string }).accessToken}`
  })

  afterEach(async () => {
    await app.close()
  })

  // Scenario: the store is healthy. Expected: 200 and the one live session is listed.
  it('lists the live session when the store is healthy', async () => {
    const res = await request(app.getHttpServer()).get('/sessions').set('Authorization', bearer)

    expect(res.status).toBe(200)
    expect(res.body).toHaveLength(1)
  })

  // Scenario: the detail read of that session fails. Expected: 500 `auth.internal`, with none of
  // the store's error text in the body, instead of a 200 with the session left out; and once the
  // store recovers the same session is listed again, because the failed read cost the index
  // nothing.
  it('answers 500 auth.internal without leaking the fault, and loses no index entry', async () => {
    const indexKeys = await store.keys('*sess:*')
    const before = await store.smembers(indexKeys[0] as string)
    failing.current = true

    const res = await request(app.getHttpServer()).get('/sessions').set('Authorization', bearer)

    expectAuthError(res, 'auth.internal')
    expect(JSON.stringify(res.body)).not.toContain('secret-store-detail')
    failing.current = false
    // Room for the fire-and-forget prune that the failed listing still dispatched.
    await new Promise((resolve) => setTimeout(resolve, 50))
    expect(await store.smembers(indexKeys[0] as string)).toEqual(before)
    const recovered = await request(app.getHttpServer())
      .get('/sessions')
      .set('Authorization', bearer)
    expect(recovered.status).toBe(200)
    expect(recovered.body).toHaveLength(1)
  })
})
