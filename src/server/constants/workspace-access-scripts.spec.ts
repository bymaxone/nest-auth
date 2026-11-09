/**
 * @fileoverview Runs the workspace-membership Lua scripts against an in-memory Redis, so a change
 * to the script text is caught by what the script does and not by what it says.
 *
 * @layer Test
 */

/// <reference path="../../../test/e2e/ioredis-mock.d.ts" />

import RedisMock from 'ioredis-mock'

import {
  BUMP_VERSION_SCRIPT,
  FILL_MEMBERSHIP_SCRIPT,
  READ_MEMBERSHIP_SCRIPT
} from './workspace-access-scripts'

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

describe('FILL_MEMBERSHIP_SCRIPT', () => {
  const fill = (
    redis: InstanceType<typeof RedisMock>,
    seen: [string, string] = ['0', '0']
  ): Promise<unknown> =>
    redis.eval(
      FILL_MEMBERSHIP_SCRIPT,
      3,
      ...KEYS,
      '{"role":"owner","status":"active"}',
      '60',
      '1000',
      ...seen
    )

  it('writes the entry with the given lifetime', async () => {
    const redis = client()

    await fill(redis)

    expect(await redis.get('wm:c')).toBe('{"role":"owner","status":"active"}')
    expect(await redis.ttl('wm:c')).toBeGreaterThan(55)
    expect(await redis.ttl('wm:c')).toBeLessThanOrEqual(60)
  })

  it('refreshes the retention of both counters that exist', async () => {
    const redis = client()
    await redis.set('wsv:a', '4', 'EX', 5)
    await redis.set('wmv:b', '9', 'EX', 5)

    await fill(redis, ['4', '9'])

    expect(await redis.ttl('wsv:a')).toBeGreaterThan(990)
    expect(await redis.ttl('wmv:b')).toBeGreaterThan(990)
  })

  it('does not create a counter that does not exist', async () => {
    const redis = client()

    await fill(redis)

    expect(await redis.exists('wsv:a', 'wmv:b')).toBe(0)
  })

  it("leaves the counters' values alone", async () => {
    const redis = client()
    await redis.set('wsv:a', '4')
    await redis.set('wmv:b', '9')

    await fill(redis, ['4', '9'])

    expect([await redis.get('wsv:a'), await redis.get('wmv:b')]).toEqual(['4', '9'])
  })

  it('returns 1 when it wrote and 0 when a counter had moved', async () => {
    const redis = client()
    await redis.set('wmv:b', '2')

    const stale = await fill(redis, ['0', '1'])
    const current = await fill(redis, ['0', '2'])

    expect([stale, current]).toEqual([0, 1])
  })

  it.each([
    ['the workspace counter', 'wsv:a', ['5', '9'] as [string, string]],
    ['the membership counter', 'wmv:b', ['4', '8'] as [string, string]]
  ])('writes nothing when %s has moved', async (_name, _key, seen) => {
    const redis = client()
    await redis.set('wsv:a', '4')
    await redis.set('wmv:b', '9')

    await fill(redis, seen)

    expect(await redis.exists('wm:c')).toBe(0)
  })

  it('treats an absent counter as 0 against what the reader saw', async () => {
    const redis = client()

    await fill(redis, ['0', '1'])

    expect(await redis.exists('wm:c')).toBe(0)
  })
})
