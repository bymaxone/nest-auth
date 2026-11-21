/**
 * @fileoverview The callback of the host that sizes a session cap is handed the entity its own repository returned,
 * with the prototype getters and methods of that entity, while the library keeps reading the copy.
 *
 * @layer Test
 */

import { Test } from '@nestjs/testing'

import {
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  GUARDED_USER_REPOSITORY
} from '../bymax-auth.constants'
import { AuthRedisService } from '../redis/auth-redis.service'
import { guardRepository } from '../utils/host-read'
import { SessionService } from './session.service'

/** An entity whose limit is a prototype getter and whose permission is a prototype method. */
class Plan {
  id = 'u1'
  tenantId = 'tenant-1'
  get limit(): number {
    return 3
  }
  allows(): boolean {
    return true
  }
}

describe('SessionService with a guarded user repository', () => {
  // Scenario: the user repository is behind the guarded view and the host configured a maxSessionsResolver that
  // uses a getter and a method of its entity. Expected: the resolver receives the very entity the repository
  // returned and answers from it. Why: the host's code gets the host's own object, with its prototype, and a mutation
  // there cannot reach what the library reads.
  it('hands maxSessionsResolver the entity the repository returned', async () => {
    const entity = new Plan()
    const guarded = guardRepository({ findById: async (): Promise<unknown> => entity })
    const resolver = jest.fn(async (user: unknown): Promise<number> => {
      const plan = user as Plan
      return plan.allows() ? plan.limit : 1
    })
    const redis = {
      get: jest.fn().mockResolvedValue(null),
      set: jest.fn().mockResolvedValue(undefined),
      del: jest.fn().mockResolvedValue(undefined),
      srem: jest.fn().mockResolvedValue(0),
      smembers: jest.fn().mockResolvedValue([]),
      eval: jest.fn().mockResolvedValue(undefined),
      pruneExpiredGraceMembers: jest.fn().mockResolvedValue(0),
      pruneDeadMembers: jest.fn().mockResolvedValue(0),
      bumpUserTokenEpoch: jest.fn()
    }
    const module = await Test.createTestingModule({
      providers: [
        SessionService,
        { provide: AuthRedisService, useValue: redis },
        {
          provide: BYMAX_AUTH_OPTIONS,
          useValue: {
            hmacKey: 'test-hmac-key',
            jwt: { secret: 'test-secret', refreshExpiresInDays: 7 },
            sessions: {
              enabled: true,
              defaultMaxSessions: 5,
              evictionStrategy: 'fifo',
              maxSessionsResolver: resolver
            }
          }
        },
        {
          provide: GUARDED_USER_REPOSITORY,
          useValue: { findById: async (): Promise<unknown> => guarded.findById() }
        },
        { provide: BYMAX_AUTH_HOOKS, useValue: null }
      ]
    }).compile()

    await module.get(SessionService).createSession({
      userId: 'u1',
      tenantId: 'tenant-1',
      rawRefreshToken: 'raw-token',
      ip: '127.0.0.1',
      userAgent: 'jest'
    })

    expect(resolver.mock.calls[0]?.[0]).toBe(entity)
    await expect(resolver.mock.results[0]?.value).resolves.toBe(3)
  })
})
