/**
 * End-to-end client address resolution behind a trusted proxy.
 *
 * `X-Forwarded-For` is written by whoever sent the request. Express's `req.ip` believes it as far
 * as the app's `trust proxy` setting reaches and returns the first entry that setting does not
 * trust, which is an arbitrary string when that entry is not an address. Every consumer of the
 * client address has to cope with that: the rate limiter must not hand each such string its own
 * budget, and no hook, session record or audit event may carry it.
 *
 * These specs drive a real Express application, because the shape `req.ip` and `req.ips` take
 * behind a trust predicate is the framework's, not something a hand-built request can be trusted
 * to reproduce.
 */

import { isIP } from 'node:net'

import type { INestApplication } from '@nestjs/common'
import request from 'supertest'

import { BYMAX_AUTH_HOOKS } from '../../src/server/bymax-auth.constants'
import type { HookContext, IAuthHooks } from '../../src/server/interfaces/auth-hooks.interface'
import { JWT_SECRET, bootstrapTestApp, expectAuthError } from './setup'

/** Trusts the loopback peer supertest connects from, and the 10.0.0.0/8 hops behind it. */
const trustLoopbackAndInternal = (address: string): boolean =>
  address === '127.0.0.1' ||
  address === '::1' ||
  address === '::ffff:127.0.0.1' ||
  address.startsWith('10.')

interface Fixture {
  app: INestApplication
  contexts: HookContext[]
  redis: Awaited<ReturnType<typeof bootstrapTestApp>>['redis']
}

async function bootstrap(clientIpSource: 'peer' | 'trusted-proxy'): Promise<Fixture> {
  const contexts: HookContext[] = []
  const hooks: IAuthHooks = {
    afterRegister: (_user, context) => {
      contexts.push(context)
    }
  }
  const { app, redis } = await bootstrapTestApp(
    {
      tokenDelivery: 'bearer',
      jwt: { secret: JWT_SECRET },
      rateLimit: { enabled: true, clientIpSource }
    },
    {
      extraModuleProviders: [{ provide: BYMAX_AUTH_HOOKS, useValue: hooks }],
      beforeInit: (nest) => {
        const express = nest.getHttpAdapter().getInstance() as {
          set(name: string, value: unknown): void
        }
        express.set('trust proxy', trustLoopbackAndInternal)
      }
    }
  )
  return { app, contexts, redis }
}

/**
 * One login attempt with wrong credentials; it still counts against the limit. Each attempt uses
 * its own email, so the per-account lockout never answers in place of the per-address limiter.
 */
function attemptLogin(app: INestApplication, attempt: number, forwardedFor: string): request.Test {
  return request(app.getHttpServer())
    .post('/login')
    .set('X-Forwarded-For', forwardedFor)
    .send({
      email: `nobody-${attempt}@example.com`,
      password: 'WrongPassword123!',
      tenantId: 'tenant-1'
    })
}

/** Sends `count` attempts and returns how many were refused by the address limiter. */
async function refusedOf(
  app: INestApplication,
  count: number,
  forwardedFor: (attempt: number) => string
): Promise<number> {
  let refused = 0
  for (let attempt = 1; attempt <= count; attempt += 1) {
    const res = await attemptLogin(app, attempt, forwardedFor(attempt))
    if (res.status === 429) {
      expectAuthError(res, 'auth.too_many_requests')
      refused += 1
    } else {
      expectAuthError(res, 'auth.invalid_credentials')
    }
  }
  return refused
}

describe('client address behind a trusted proxy (E2E)', () => {
  describe("clientIpSource 'trusted-proxy'", () => {
    let fixture: Fixture

    beforeEach(async () => {
      fixture = await bootstrap('trusted-proxy')
    })

    afterEach(async () => {
      await fixture.app.close()
    })

    // Scenario: a client varies a client-written entry that is not an address on every request,
    // through a hop that forwards the header without appending. Expected: the limiter charges all
    // of them to the same bucket, so the sixth login is refused. Why: otherwise each string is a
    // fresh budget and the limit enforces nothing.
    it('charges requests with a non-address client entry to one bucket', async () => {
      const refused = await refusedOf(fixture.app, 10, (attempt) => `junk-${attempt}`)

      expect(refused).toBe(5)
    })

    // Mirrors rust-auth's `an_entry_that_is_not_an_address_ends_the_walk_at_the_last_hop_that_was_one`
    // (crates/bymax-auth-axum/src/client_ip/tests.rs): behind a peer it trusts, `198.51.100.7,
    // garbage, 10.0.0.2` resolves to 10.0.0.2 and `not-an-ip` resolves to the peer itself. With
    // several trusted hops in `req.ips` and a non-address client entry, the nearest hop to the
    // client that is an address is the one charged, so these ten requests share one bucket.
    it('charges a non-address client entry to the hop nearest the client', async () => {
      const refused = await refusedOf(
        fixture.app,
        10,
        (attempt) => `198.51.100.${attempt}, garbage-${attempt}, 10.0.0.2`
      )

      expect(refused).toBe(5)
    })

    // The control for the case above: the same shape with a different nearest hop each time must
    // not share a bucket, or the fix would be collapsing everything behind the proxy into one.
    it('keeps distinct nearest hops in distinct buckets', async () => {
      const refused = await refusedOf(
        fixture.app,
        10,
        (attempt) => `198.51.100.7, garbage-${attempt}, 10.0.0.${attempt}`
      )

      expect(refused).toBe(0)
    })

    // A header with no address in it at all falls back to the peer the proxy connected from.
    it('charges a header with no address in it to the peer', async () => {
      const refused = await refusedOf(fixture.app, 10, (attempt) => `not-an-ip-${attempt}`)

      expect(refused).toBe(5)
    })

    // Scenario: a client-written non-address string arrives as the client entry. Expected: the
    // hook context and the stored session record carry an address, never that string. Why: both
    // are written by the server and read later by people and tools that trust them.
    it('never hands a non-address string to a hook or a session record', async () => {
      const junk = 'junk-'.concat('x'.repeat(200))
      await request(fixture.app.getHttpServer())
        .post('/register')
        .set('X-Forwarded-For', junk)
        .send({
          email: 'alice@example.com',
          password: 'SuperSecret123!',
          name: 'Alice',
          tenantId: 'tenant-1'
        })
        .expect(201)

      expect(fixture.contexts).toHaveLength(1)
      expect(isIP(fixture.contexts[0]!.ip)).not.toBe(0)
      const stored = await storedSessionAddresses(fixture.redis)
      expect(stored).not.toHaveLength(0)
      for (const address of stored) expect(isIP(address)).not.toBe(0)
    })
  })

  describe("clientIpSource 'peer' with the app's trust proxy set", () => {
    let fixture: Fixture

    beforeEach(async () => {
      fixture = await bootstrap('peer')
    })

    afterEach(async () => {
      await fixture.app.close()
    })

    // Scenario: the limiter is keyed on the socket, but the app's `trust proxy` makes `req.ip`
    // follow the header for everything else. Expected: the same guarantee holds there, because
    // it is a property of what reaches the sinks, not of which source the limiter reads.
    it('never hands a non-address string to a hook or a session record', async () => {
      await request(fixture.app.getHttpServer())
        .post('/register')
        .set('X-Forwarded-For', 'junk-peer-mode')
        .send({
          email: 'bob@example.com',
          password: 'SuperSecret123!',
          name: 'Bob',
          tenantId: 'tenant-1'
        })
        .expect(201)

      expect(fixture.contexts).toHaveLength(1)
      expect(isIP(fixture.contexts[0]!.ip)).not.toBe(0)
      const stored = await storedSessionAddresses(fixture.redis)
      expect(stored).not.toHaveLength(0)
      for (const address of stored) expect(isIP(address)).not.toBe(0)
    })
  })
})

/** The `ip` of every stored session record. */
async function storedSessionAddresses(redis: Fixture['redis']): Promise<string[]> {
  const keys = await redis.keys('*sd:*')
  const records = await Promise.all(keys.map((key) => redis.get(key)))
  return records.flatMap((raw) => (raw === null ? [] : [(JSON.parse(raw) as { ip: string }).ip]))
}
