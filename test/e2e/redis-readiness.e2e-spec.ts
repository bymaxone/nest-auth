/**
 * @fileoverview The startup Redis check against a REAL ioredis client.
 *
 * The unit specs drive the check with fakes whose shape the spec chooses, so they cannot establish
 * what ioredis really does. The constraint held here is a lifecycle one: a real client that reaches
 * the `end` state (it gave up connecting) must fail bootstrap promptly, not wait out the deadline.
 * A client pointed at a port nothing listens on reaches it with no Redis server, so the case lives
 * in this suite and not in the unit suite, which mocks Redis.
 */

import { Test } from '@nestjs/testing'
import Redis from 'ioredis'

import { BYMAX_AUTH_REDIS_CLIENT } from '../../src/server/bymax-auth.constants'
import { RedisReadinessService } from '../../src/server/redis/redis-readiness.service'

/** The check over a client, built through the injector as the module builds it. */
async function check(client: Redis): Promise<RedisReadinessService> {
  const module = await Test.createTestingModule({
    providers: [RedisReadinessService, { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: client }]
  }).compile()
  return module.get(RedisReadinessService)
}

describe('RedisReadinessService against a real ioredis client (E2E)', () => {
  // Scenario: a client pointed at a port nothing listens on, which gives up at once
  // (`retryStrategy` returns null, so the status becomes `end`). Expected: boot fails promptly with
  // the address and nothing else, a password the client was built with included.
  it('refuses a client that cannot connect, naming only the address', async () => {
    const client = new Redis({
      host: '127.0.0.1',
      port: 1,
      password: 'real-secret',
      retryStrategy: () => null,
      maxRetriesPerRequest: 1,
      commandTimeout: 500
    })
    client.on('error', () => undefined)
    // The pause between two PING attempts is a 250 ms timer; a client that has ended must never
    // arm one, which says "fails at once" without reading the clock.
    const timers = jest.spyOn(global, 'setTimeout')
    try {
      const attempt = (await check(client)).onApplicationBootstrap()

      await expect(attempt).rejects.toThrow(
        '[BymaxAuthModule] Redis at 127.0.0.1:1 did not answer PING'
      )
      await expect(attempt).rejects.not.toThrow(/real-secret/)
      expect(timers.mock.calls.filter(([, delay]) => delay === 250)).toHaveLength(0)
    } finally {
      timers.mockRestore()
      client.disconnect()
    }
  })
})
