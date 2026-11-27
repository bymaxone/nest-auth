/// <reference path="../../../test/e2e/ioredis-mock.d.ts" />
/**
 * @fileoverview The verify script's reading of the attempt counter, run on the in-memory Redis.
 *
 * An empty counter is not here: the in-memory Redis answers it differently from a server, so
 * `test/e2e/real-redis/otp-attempts.e2e-spec.ts` holds that row.
 *
 * @layer Test
 */

import RedisMock from 'ioredis-mock'

import type { ResolvedOptions } from '../config/resolved-options'
import type { AuthRedisService } from '../redis/auth-redis.service'
import { OtpService } from './otp.service'

const CODE = '123456'
const KEY = 'otp:reset:who'

const redis = new RedisMock({ port: 7600 })
const run = (script: string, keys: string[], args: string[]): Promise<unknown> =>
  redis.eval(script, keys.length, ...keys, ...args)
const service = new OtpService(
  { eval: run } as Partial<AuthRedisService> as AuthRedisService,
  { hmacKey: 'k'.repeat(64) } as Partial<ResolvedOptions> as ResolvedOptions
)

/** Stores a code, then sets the counter to `attempts`, or removes the field for `null`. */
async function recordWith(attempts: string | null): Promise<void> {
  await service.store('reset', 'who', CODE, 60)
  if (attempts === null) await redis.hdel(KEY, 'attempts')
  else await redis.hset(KEY, 'attempts', attempts)
}

describe('the verify script and the attempt counter', () => {
  // An absent counter is the first attempt; a canonical count below the ceiling still verifies.
  it.each([[null], ['0'], ['4']])(
    'verifies the right code over a counter of %p',
    async (stored) => {
      await recordWith(stored)

      await expect(service.verify('reset', 'who', CODE)).resolves.toBeUndefined()
    }
  )

  // The ceiling, and everything that is not a non-negative integer, refuse even the right code.
  it.each([
    ['5'],
    ['nan'],
    ['inf'],
    ['-inf'],
    ['abc'],
    ['1.0'],
    ['1e3'],
    ['0x1'],
    [' 1'],
    ['1 '],
    ['+1'],
    ['01'],
    ['-0'],
    ['-1'],
    ['-1000000'],
    ['1000000000000000000']
  ])('refuses and consumes a record whose counter is %p', async (stored) => {
    await recordWith(stored)

    await expect(service.verify('reset', 'who', CODE)).rejects.toMatchObject({
      response: { error: { code: 'auth.otp_invalid' } }
    })
    await expect(redis.exists(KEY)).resolves.toBe(0)
  })

  // A wrong guess below the ceiling is counted.
  it('counts a wrong guess', async () => {
    await recordWith('4')

    await expect(service.verify('reset', 'who', '000000')).rejects.toThrow()

    await expect(redis.hget(KEY, 'attempts')).resolves.toBe('5')
  })
})
