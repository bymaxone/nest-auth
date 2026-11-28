/**
 * @fileoverview Unit tests for the removal of the sessions the session limit pushed out.
 *
 * @layer Test
 */

import { Logger } from '@nestjs/common'

import { evictSessions } from './evict-sessions'
import type { EvictionStore } from './evict-sessions'

const request = {
  userId: 'u1',
  tenantId: 't1',
  ip: 'ip',
  userAgent: 'ua',
  index: 'sess:x',
  jwt: { accessExpiresIn: '15m' }
}
const familyOf = {
  'rt:a': '3f2b8c1e-9d4a-4f6b-8a2e-1c5d7e9f0a1b',
  'rt:b': '7a1c2d3e-4b5f-4a6c-9d8e-0f1a2b3c4d5e'
}
const entries = [
  { member: 'rt:a', memberHash: 'a' },
  { member: 'rt:b', memberHash: 'b' }
]

/** A store that refuses to delete the keys named. */
function store(refused: string[] = [], siblings: string[] = []): EvictionStore {
  return {
    revokeFamily: jest.fn(async () => ({
      removed: siblings.length,
      sessionHashes: siblings,
      ownerId: 'u1',
      tenantId: 't1'
    })),
    readSessionOwner: jest.fn(async (key: string) => ({
      userId: 'u1',
      tenantId: 't1',
      familyId: familyOf[key as keyof typeof familyOf]
    })),
    set: jest.fn(async (key: string) => {
      if (refused.includes(key)) throw new Error('refused')
    }),
    del: jest.fn(async (key: string) => {
      if (refused.includes(key)) throw new Error('refused')
      return true
    }),
    srem: jest.fn(async () => 1)
  }
}

describe('evictSessions', () => {
  beforeEach(() => {
    jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
    jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
  })
  afterEach(() => jest.restoreAllMocks())

  // Scenario: two sessions pushed out. Expected: each removed from every key, one hook each, and
  // one revocation event naming both.
  it('removes each session and announces the pass once', async () => {
    const redis = store()
    const hooks = { onSessionsRevoked: jest.fn(), onSessionEvicted: jest.fn() }

    await evictSessions(redis, hooks, new Logger(), request, entries)

    expect((redis.del as jest.Mock).mock.calls.flat()).toEqual(['rt:a', 'sd:a', 'rt:b', 'sd:b'])
    expect((redis.srem as jest.Mock).mock.calls).toEqual([
      ['sess:x', 'rt:a'],
      ['sess:x', 'rt:b']
    ])
    expect(hooks.onSessionEvicted.mock.calls.map((call) => call[1])).toEqual(['a', 'b'])
    expect(hooks.onSessionsRevoked.mock.calls).toStrictEqual([
      [
        {
          userId: 'u1',
          plane: 'dashboard',
          reason: 'session_evicted',
          tenantId: 't1',
          sessionIds: ['a', 'b']
        }
      ]
    ])
  })

  // Scenario: the evicted session shares its sign-in with others. Expected: all named, each once,
  // and one eviction hook for the session the limit chose.
  it('names the other sessions of an evicted sign-in', async () => {
    const hooks = { onSessionsRevoked: jest.fn(), onSessionEvicted: jest.fn() }
    const redis = store([], ['c', 'a'])

    await evictSessions(redis, hooks, new Logger(), request, [{ member: 'rt:a', memberHash: 'a' }])

    expect(redis.revokeFamily).toHaveBeenCalledWith(familyOf['rt:a'], 'dashboard')
    expect(hooks.onSessionsRevoked).toHaveBeenCalledWith(
      expect.objectContaining({ sessionIds: ['a', 'c'] })
    )
    expect(hooks.onSessionEvicted.mock.calls.map((call) => call[1])).toEqual(['a'])
  })

  // Scenario: one session cannot be deleted. Expected: only the deleted one is named.
  it('names only the sessions it deleted', async () => {
    const onSessionsRevoked = jest.fn()

    await evictSessions(store(['rt:a']), { onSessionsRevoked }, new Logger(), request, entries)

    expect(onSessionsRevoked).toHaveBeenCalledWith(expect.objectContaining({ sessionIds: ['b'] }))
  })

  // Scenario: the session key is deleted and its detail record is refused. Expected: still named.
  // Why: the session can no longer be refreshed.
  it('names a session whose cleanup failed after its deletion', async () => {
    const onSessionsRevoked = jest.fn()

    await evictSessions(store(['sd:a']), { onSessionsRevoked }, new Logger(), request, [
      { member: 'rt:a', memberHash: 'a' }
    ])

    expect(onSessionsRevoked).toHaveBeenCalledWith(expect.objectContaining({ sessionIds: ['a'] }))
  })

  // Scenario: nothing could be deleted. Expected: no event.
  it('announces nothing when it deleted nothing', async () => {
    const onSessionsRevoked = jest.fn()

    await evictSessions(
      store(['rt:a', 'rt:b']),
      { onSessionsRevoked },
      new Logger(),
      request,
      entries
    )

    expect(onSessionsRevoked).not.toHaveBeenCalled()
  })

  // Scenario: two sessions pushed out. Expected: the access tokens of each are ended.
  it('ends the access tokens of each evicted session', async () => {
    const redis = store()

    await evictSessions(redis, null, new Logger(), request, entries)

    expect((redis.set as jest.Mock).mock.calls).toEqual([
      [`rvs:${familyOf['rt:a']}`, '1', 960],
      [`rvs:${familyOf['rt:b']}`, '1', 960]
    ])
  })

  // Scenario: the session cannot be deleted. Expected: its access tokens are left alone.
  // Why: it was not evicted.
  it('ends no access token of a session it could not delete', async () => {
    const redis = store(['rt:a'])

    await evictSessions(redis, null, new Logger(), request, [{ member: 'rt:a', memberHash: 'a' }])

    expect(redis.set).not.toHaveBeenCalled()
  })

  // Scenario: the entry is refused. Expected: the index and detail cleanup still run, and the
  // session is still named.
  it('finishes the cleanup when the entry is refused', async () => {
    const redis = store([`rvs:${familyOf['rt:a']}`])
    const onSessionsRevoked = jest.fn()

    await evictSessions(redis, { onSessionsRevoked }, new Logger(), request, [
      { member: 'rt:a', memberHash: 'a' }
    ])

    expect(redis.srem).toHaveBeenCalledWith('sess:x', 'rt:a')
    expect(redis.del).toHaveBeenCalledWith('sd:a')
    expect(onSessionsRevoked).toHaveBeenCalledWith(expect.objectContaining({ sessionIds: ['a'] }))
  })
})
