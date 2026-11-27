/**
 * @fileoverview Unit tests for the removal of the sessions the session limit pushed out.
 *
 * @layer Test
 */

import { Logger } from '@nestjs/common'

import { evictSessions } from './evict-sessions'
import type { AuthRedisService } from '../redis/auth-redis.service'

const request = { userId: 'u1', tenantId: 't1', ip: 'ip', userAgent: 'ua', index: 'sess:x' }
const entries = [
  { member: 'rt:a', memberHash: 'a' },
  { member: 'rt:b', memberHash: 'b' }
]

/** A store that refuses to delete the keys named. */
function store(refused: string[] = []): AuthRedisService {
  return {
    del: jest.fn(async (key: string) => {
      if (refused.includes(key)) throw new Error('refused')
    }),
    srem: jest.fn(async () => 1)
  } as unknown as AuthRedisService
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
})
