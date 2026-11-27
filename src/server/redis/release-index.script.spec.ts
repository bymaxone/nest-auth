/**
 * @fileoverview The integer replies a removal is decided by, as a number and as the string a client built with `stringNumbers` hands
 * back.
 *
 * @layer Test
 */

import { Redis } from 'ioredis'

import { AuthRedisService } from './auth-redis.service'
import { releaseIndex } from './release-index.script'
import type { ResolvedOptions } from '../config/resolved-options'

/** The service over a client whose `EVAL` and `DEL` both answer `reply`. */
function answering(reply: unknown): AuthRedisService {
  const client: Redis = Object.assign(Object.create(null), {
    eval: (): Promise<unknown> => Promise.resolve(reply),
    del: (): Promise<unknown> => Promise.resolve(reply)
  })
  const options: ResolvedOptions = Object.assign(Object.create(null), {
    redisNamespace: 'spec',
    hmacKey: 'release-index-spec-key'
  })
  return new AuthRedisService(client, options)
}

describe('releaseIndex and del over the reply of the client', () => {
  // Scenario: the client answers the count as a number or as its string. Expected: both say the same. Why: a client built with
  // `stringNumbers` decodes every integer reply as a string, and a removal read as none leaves an invitation redeemable.
  it.each([
    ['the number one', 1, true],
    ['the string one', '1', true],
    ['the number zero', 0, false],
    ['the string zero', '0', false]
  ])('reads %s', async (_label, reply, removed) => {
    const service = answering(reply)

    await expect(releaseIndex(service, 'invidx:t1:a', 'hash')).resolves.toBe(removed)
    await expect(service.del('inv:hash')).resolves.toBe(removed)
  })
})
