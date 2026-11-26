/**
 * @fileoverview SessionService over a client built with `stringNumbers`.
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
import { SessionService } from './session.service'

describe('SessionService.revokeSession over string replies', () => {
  // Scenario: the client answers the script's `1` as a string. Expected: the revocation is
  // reported. Why: read as `0`, a removed session answers as not found and the access tokens of
  // the account are never cut.
  it('reads the string a client answers for a removed session', async () => {
    const redis = { eval: jest.fn().mockResolvedValue('1') }
    const module = await Test.createTestingModule({
      providers: [
        SessionService,
        { provide: AuthRedisService, useValue: redis },
        {
          provide: BYMAX_AUTH_OPTIONS,
          useValue: { hmacKey: 'test-hmac-key', sessions: {}, jwt: {} }
        },
        { provide: GUARDED_USER_REPOSITORY, useValue: {} },
        { provide: BYMAX_AUTH_HOOKS, useValue: null }
      ]
    }).compile()
    const service = module.get(SessionService)

    await expect(
      service.revokeSession({
        userId: 'user-1',
        tenantId: 'tenant-1',
        sessionHash: 'a'.repeat(64)
      })
    ).resolves.toBeUndefined()
    expect(redis.eval).toHaveBeenCalledTimes(1)
  })
})
