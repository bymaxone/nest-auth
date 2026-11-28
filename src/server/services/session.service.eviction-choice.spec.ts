/**
 * @fileoverview Which sessions the session limit chooses to end.
 */

import { Logger } from '@nestjs/common'
import { Test } from '@nestjs/testing'

import {
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  GUARDED_USER_REPOSITORY
} from '../bymax-auth.constants'
import { sha256 } from '../crypto/secure-token'
import { AuthRedisService } from '../redis/auth-redis.service'
import { SessionService } from './session.service'

/** Six listed sessions against a limit of five, the first the oldest. */
const HASHES = Array.from({ length: 6 }, (_, i) => sha256(`refused-eviction-${i}`))

const redis = {
  get: jest.fn((key: string) =>
    Promise.resolve(JSON.stringify({ createdAt: HASHES.indexOf(key.replace(/^sd:/, '')) + 1 }))
  ),
  set: jest.fn().mockResolvedValue(undefined),
  del: jest.fn().mockRejectedValue(new Error('READONLY')),
  srem: jest.fn().mockResolvedValue(1),
  smembers: jest.fn().mockResolvedValue(HASHES.map((hash) => `rt:${hash}`)),
  eval: jest.fn().mockResolvedValue(1),
  pruneExpiredGraceMembers: jest.fn().mockResolvedValue(0),
  readSessionOwner: jest.fn().mockResolvedValue({})
}

const options = {
  hmacKey: 'test-hmac-key',
  jwt: { accessExpiresIn: '15m', refreshExpiresInDays: 7 },
  sessions: { enabled: true, defaultMaxSessions: 5, evictionStrategy: 'fifo' }
}

const hooks = { onSessionEvicted: jest.fn() }

describe('SessionService session limit', () => {
  afterEach(() => {
    jest.restoreAllMocks()
  })

  // Scenario: one session over the limit, and the store refuses to delete the one chosen.
  // Expected: no other session is touched. Why: only as many sessions as the account is over by
  // are chosen, so a failed removal must not move on to a newer one.
  it('ends no newer session when the chosen one cannot be removed', async () => {
    jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
    const module = await Test.createTestingModule({
      providers: [
        SessionService,
        { provide: AuthRedisService, useValue: redis },
        { provide: BYMAX_AUTH_OPTIONS, useValue: options },
        { provide: GUARDED_USER_REPOSITORY, useValue: { findById: jest.fn() } },
        { provide: BYMAX_AUTH_HOOKS, useValue: hooks }
      ]
    }).compile()

    await module.get(SessionService).createSession({
      userId: 'user-1',
      tenantId: 'tenant-1',
      rawRefreshToken: 'raw-refresh-token',
      ip: '127.0.0.1',
      userAgent: 'jest'
    })

    expect(redis.del.mock.calls).toEqual([[`rt:${HASHES[0]}`]])
    expect(hooks.onSessionEvicted).not.toHaveBeenCalled()
  })
})
