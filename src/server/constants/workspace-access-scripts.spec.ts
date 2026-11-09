/**
 * @fileoverview Runs the workspace-membership Lua scripts against an in-memory Redis, so a change
 * to the script text is caught by what the script does and not by what it says.
 *
 * @layer Test
 */

/// <reference path="../../../test/e2e/ioredis-mock.d.ts" />

import RedisMock from 'ioredis-mock'

import { BUMP_VERSION_SCRIPT, READ_MEMBERSHIP_SCRIPT } from './workspace-access-scripts'

/** One isolated in-memory keyspace per case. */
let port = 41_000

function client(): InstanceType<typeof RedisMock> {
  port += 1
  return new RedisMock({ port })
}

const KEYS = ['wsv:a', 'wmv:b', 'wm:c']

describe('READ_MEMBERSHIP_SCRIPT', () => {
  it('reads absent counters as zero and a miss as the empty string', async () => {
    const redis = client()

    const reply = await redis.eval(READ_MEMBERSHIP_SCRIPT, 3, ...KEYS)

    expect(reply).toEqual(['0', '0', ''])
  })

  it('returns both versions and the entry stored under them', async () => {
    const redis = client()
    await redis.set('wsv:a', '4')
    await redis.set('wmv:b', '9')
    await redis.set('wm:c:4:9', '{"role":"owner","status":"active"}')

    const reply = await redis.eval(READ_MEMBERSHIP_SCRIPT, 3, ...KEYS)

    expect(reply).toEqual(['4', '9', '{"role":"owner","status":"active"}'])
  })

  it('does not return an entry stored under other versions', async () => {
    const redis = client()
    await redis.set('wsv:a', '5')
    await redis.set('wmv:b', '9')
    await redis.set('wm:c:4:9', 'stale')
    await redis.set('wm:c:5:8', 'stale')

    const reply = await redis.eval(READ_MEMBERSHIP_SCRIPT, 3, ...KEYS)

    expect(reply).toEqual(['5', '9', ''])
  })
})

describe('BUMP_VERSION_SCRIPT', () => {
  it('increments the counter and returns the new value', async () => {
    const redis = client()

    const first = await redis.eval(BUMP_VERSION_SCRIPT, 1, 'wmv:b', '1000')
    const second = await redis.eval(BUMP_VERSION_SCRIPT, 1, 'wmv:b', '1000')

    expect([first, second]).toEqual([1, 2])
    expect(await redis.get('wmv:b')).toBe('2')
  })

  it('gives the counter the retention it was passed, on every bump', async () => {
    const redis = client()
    await redis.eval(BUMP_VERSION_SCRIPT, 1, 'wmv:b', '1000')
    await redis.expire('wmv:b', 10)

    await redis.eval(BUMP_VERSION_SCRIPT, 1, 'wmv:b', '1000')

    expect(await redis.ttl('wmv:b')).toBeGreaterThan(990)
  })
})
