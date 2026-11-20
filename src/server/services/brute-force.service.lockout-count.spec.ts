/**
 * @fileoverview A lockout is counted once, at the failure that reaches the threshold, and the count is
 * optional: with no tally registered, recording a failure updates the counter in Redis and succeeds.
 */

import { Test } from '@nestjs/testing'

import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import { AuthMetricsTally } from '../observability/auth-metrics-tally'
import { AuthRedisService } from '../redis/auth-redis.service'
import { BruteForceService } from './brute-force.service'

const IDENTIFIER = 'a3f2b8c1d4e5f6071234567890abcdef'
const MAX_ATTEMPTS = 5

const redis = { incrWithFixedTtl: jest.fn() }
const options = { bruteForce: { maxAttempts: MAX_ATTEMPTS, windowSeconds: 900 } }

/** A service over the given count of failures so far, with or without the tally registered. */
async function build(
  withTally: boolean
): Promise<{ service: BruteForceService; tally: AuthMetricsTally }> {
  const tally = new AuthMetricsTally()
  const module = await Test.createTestingModule({
    providers: [
      BruteForceService,
      { provide: AuthRedisService, useValue: redis },
      { provide: BYMAX_AUTH_OPTIONS, useValue: options },
      ...(withTally ? [{ provide: AuthMetricsTally, useValue: tally }] : [])
    ]
  }).compile()
  return { service: module.get(BruteForceService), tally }
}

describe('BruteForceService — counting a lockout', () => {
  beforeEach(() => {
    jest.resetAllMocks()
  })

  // Scenario: the counter at each value around the threshold. Expected: only the failure that makes it equal
  // to the threshold is a lockout; the ones before it and the ones after it are not.
  it.each([
    [MAX_ATTEMPTS - 1, 0],
    [MAX_ATTEMPTS, 1],
    [MAX_ATTEMPTS + 1, 0],
    [MAX_ATTEMPTS + 40, 0]
  ])('with the counter at %i it counts %i lockout(s)', async (count, lockouts) => {
    redis.incrWithFixedTtl.mockResolvedValue(count)
    const { service, tally } = await build(true)

    await service.recordFailure(IDENTIFIER)

    expect(tally.snapshot().lockouts).toBe(lockouts)
  })

  // Scenario: the failures of one run, in order. Expected: one lockout for the whole run.
  it('counts one lockout for a whole run of failures', async () => {
    const { service, tally } = await build(true)

    for (let attempt = 1; attempt <= MAX_ATTEMPTS + 3; attempt += 1) {
      redis.incrWithFixedTtl.mockResolvedValueOnce(attempt)
      await service.recordFailure(IDENTIFIER)
    }

    expect(tally.snapshot().lockouts).toBe(1)
  })

  // Scenario: no tally registered (a module built without it). Expected: the failure is recorded, nothing
  // throws.
  it('records the failure without a tally', async () => {
    redis.incrWithFixedTtl.mockResolvedValue(MAX_ATTEMPTS)
    const { service } = await build(false)

    await expect(service.recordFailure(IDENTIFIER)).resolves.toBeUndefined()

    expect(redis.incrWithFixedTtl).toHaveBeenCalledWith(`lf:${IDENTIFIER}`, 900)
  })
})
