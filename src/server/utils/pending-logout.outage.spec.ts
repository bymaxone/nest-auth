/**
 * @fileoverview What the retry marker helpers answer when the store cannot: the typed 503 the
 * client retries, not the internal failure that means a defect.
 */

import type { Logger } from '@nestjs/common'

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { AuthRedisService } from '../redis/auth-redis.service'
import { settlePendingLogout } from './pending-logout'

const KEY = 'lp:abc'
const OWNER = { userId: 'user-1', tenantId: 'tenant-1' }
const UNAVAILABLE = new AuthException(AUTH_ERROR_CODES.SERVICE_UNAVAILABLE)

describe('settlePendingLogout under a store outage', () => {
  const redis = { set: jest.fn(), del: jest.fn(), get: jest.fn() }
  const logger = { warn: jest.fn() }
  const asRedis = redis as unknown as AuthRedisService
  const asLogger = logger as unknown as Logger

  beforeEach(() => {
    jest.resetAllMocks()
    redis.set.mockResolvedValue(undefined)
  })

  // Scenario: an owner read from the marker whose claim cannot be made because the store does not
  // answer. Expected: the same 503, so the client retries and the marker announces once.
  it('rethrows the 503 when the claim of a marker-sourced owner cannot be made', async () => {
    redis.del.mockRejectedValue(UNAVAILABLE)

    await expect(settlePendingLogout(asRedis, KEY, false, OWNER, 900, asLogger)).rejects.toBe(
      UNAVAILABLE
    )
  })

  // Scenario: the claim fails for a reason that is not an outage. Expected: still the internal
  // failure.
  it('keeps the internal failure for a claim that fails otherwise', async () => {
    redis.del.mockRejectedValue(new Error('WRONGTYPE'))

    const failure = (await settlePendingLogout(asRedis, KEY, false, OWNER, 900, asLogger).catch(
      (error: unknown) => error
    )) as AuthException

    expect(failure.getStatus()).toBe(500)
  })

  // Scenario: a session-sourced owner whose stale marker could not be removed, and whose second
  // read cannot be answered either. Expected: the marker is written again and the 503 is raised.
  it('rethrows the 503 when the second read of the stale marker cannot be answered', async () => {
    redis.del.mockRejectedValue(new Error('Command timed out'))
    redis.get.mockRejectedValue(UNAVAILABLE)

    await expect(settlePendingLogout(asRedis, KEY, true, OWNER, 900, asLogger)).rejects.toBe(
      UNAVAILABLE
    )
    expect(redis.set).toHaveBeenCalledTimes(1)
  })

  // Scenario: the second read fails with something that is not an outage. Expected: the internal
  // failure, as before.
  it('keeps the internal failure when the second read fails otherwise', async () => {
    redis.del.mockRejectedValue(new Error('Command timed out'))
    redis.get.mockRejectedValue(new Error('WRONGTYPE'))

    const failure = (await settlePendingLogout(asRedis, KEY, true, OWNER, 900, asLogger).catch(
      (error: unknown) => error
    )) as AuthException

    expect(failure.getStatus()).toBe(500)
  })
})
