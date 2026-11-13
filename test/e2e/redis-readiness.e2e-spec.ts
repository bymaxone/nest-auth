/**
 * @fileoverview The startup Redis check against a REAL ioredis client.
 *
 * The unit specs drive the check with fakes whose shape the author chose, which proves each branch
 * runs and cannot prove ioredis presents that shape: the first real-client run found that a client
 * which gave up connecting (status `end`) was waited on until the deadline. A real client pointed
 * at a port nothing listens on is the cheapest way to hold the check to what ioredis really does,
 * and it needs no Redis server, so it lives here and not in the unit suite that mocks Redis.
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
    try {
      const started = Date.now()
      const attempt = (await check(client)).onApplicationBootstrap()

      await expect(attempt).rejects.toThrow(
        '[BymaxAuthModule] Redis at 127.0.0.1:1 did not answer PING'
      )
      await expect(attempt).rejects.not.toThrow(/real-secret/)
      expect(Date.now() - started).toBeLessThan(4000)
    } finally {
      client.disconnect()
    }
  })
})
