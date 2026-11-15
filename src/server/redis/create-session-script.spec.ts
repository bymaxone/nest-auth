/// <reference path="../../../test/e2e/ioredis-mock.d.ts" />
/**
 * @fileoverview The script that writes a new refresh session, run for real against the in-memory
 * Redis, and the check of the records handed to it.
 */

import RedisMock from 'ioredis-mock'

import { CREATE_SESSION_LUA, sessionExtraArgs } from './create-session-script'

const FAMILY = '4d6e1c2a-8b3f-4a5e-9c7d-0e1f2a3b4c5d'
let port = 7300

/** Runs the script the way `AuthRedisService.writeNewSession` calls it. */
async function run(
  redis: InstanceType<typeof RedisMock>,
  extras: Array<{ key: string; value: string; ttl: number }>
): Promise<void> {
  const { keys, argv } = sessionExtraArgs(extras)
  const allKeys = ['rt:h1', 'sess:u1', `fam:${FAMILY}`, ...keys]
  await redis.eval(
    CREATE_SESSION_LUA,
    allKeys.length,
    ...allKeys,
    '{"userId":"u1"}',
    '604800',
    FAMILY,
    'rt',
    'h1',
    ...argv
  )
}

describe('CREATE_SESSION_LUA', () => {
  let redis: InstanceType<typeof RedisMock>

  beforeEach(() => {
    redis = new RedisMock({ port: port++ })
  })

  afterEach(() => redis.disconnect())

  // Scenario: no extras. Expected: the session, its index member and its family, each with the
  // refresh lifetime, and nothing else.
  it('writes the three records of the session and nothing else without extras', async () => {
    await run(redis, [])

    expect(await redis.get('rt:h1')).toBe('{"userId":"u1"}')
    expect(await redis.smembers('sess:u1')).toEqual(['rt:h1'])
    expect(await redis.smembers(`fam:${FAMILY}`)).toEqual(['h1'])
    expect(await redis.ttl('rt:h1')).toBe(604800)
    expect((await redis.keys('*')).sort()).toEqual([`fam:${FAMILY}`, 'rt:h1', 'sess:u1'])
  })

  // Scenario: two extras with different lifetimes. Expected: each key holds its OWN value and its
  // OWN lifetime. Why: the mark must keep its five minutes and the detail the refresh lifetime;
  // a script that paired a value with another record's lifetime would undo the mark's freshness.
  it('writes each extra with its own value and its own lifetime', async () => {
    await run(redis, [
      { key: 'ra:mark', value: '1', ttl: 300 },
      { key: 'sd:h1', value: '{"device":"Chrome on macOS"}', ttl: 604800 }
    ])

    expect(await redis.get('ra:mark')).toBe('1')
    expect(await redis.ttl('ra:mark')).toBe(300)
    expect(await redis.get('sd:h1')).toBe('{"device":"Chrome on macOS"}')
    expect(await redis.ttl('sd:h1')).toBe(604800)
    expect(await redis.ttl('rt:h1')).toBe(604800)
  })

  it('writes a single extra', async () => {
    await run(redis, [{ key: 'psd:h1', value: '{"device":"x"}', ttl: 604800 }])

    expect(await redis.get('psd:h1')).toBe('{"device":"x"}')
  })
})

describe('sessionExtraArgs', () => {
  it('returns the keys, and each value followed by its lifetime, in order', () => {
    expect(
      sessionExtraArgs([
        { key: 'a', value: 'va', ttl: 300 },
        { key: 'b', value: 'vb', ttl: 604800 }
      ])
    ).toEqual({ keys: ['a', 'b'], argv: ['va', '300', 'vb', '604800'] })
  })

  it('returns nothing for no extras', () => {
    expect(sessionExtraArgs([])).toEqual({ keys: [], argv: [] })
  })

  // Scenario: a record that would make the script fail. Expected: refused before anything is sent.
  // Why: a lifetime of zero makes `SET ... EX` error inside the script and abort the whole birth
  // of a session; that is a bug in the caller, found here and not as a failed login.
  it.each([
    ['an empty key', { key: '', value: 'v', ttl: 300 }],
    ['an empty value', { key: 'k', value: '', ttl: 300 }],
    ['a zero lifetime', { key: 'k', value: 'v', ttl: 0 }],
    ['a negative lifetime', { key: 'k', value: 'v', ttl: -1 }],
    ['a fractional lifetime', { key: 'k', value: 'v', ttl: 1.5 }],
    ['an infinite lifetime', { key: 'k', value: 'v', ttl: Infinity }],
    ['a lifetime that is not a number', { key: 'k', value: 'v', ttl: Number.NaN }]
  ])('refuses %s', (_name, extra) => {
    expect(() => sessionExtraArgs([extra])).toThrow(TypeError)
  })

  it('refuses the whole list when one record is bad', () => {
    expect(() =>
      sessionExtraArgs([
        { key: 'a', value: 'va', ttl: 300 },
        { key: 'b', value: 'vb', ttl: 0 }
      ])
    ).toThrow(TypeError)
  })
})
