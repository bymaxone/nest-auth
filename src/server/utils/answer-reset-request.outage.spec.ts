/**
 * @fileoverview What `answerResetRequest` answers when the store cannot.
 *
 * The cooldown is the first thing every request consults, before any step that depends on the
 * account, so an unreachable store answers the same 503 for every address and tells the caller
 * nothing about one. A failure after the account is known keeps the 200 the contract promises: it
 * happens only for a registered address, and a 5xx would answer the enumeration question.
 */

import { Logger } from '@nestjs/common'

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { answerResetRequest, type ResetRequest } from './answer-reset-request'

const UNAVAILABLE = new AuthException(AUTH_ERROR_CODES.SERVICE_UNAVAILABLE)
const FLOOR_MS = 120

describe('answerResetRequest under a store outage', () => {
  const redis = { setnx: jest.fn(), del: jest.fn() }
  const logger = new Logger('answer-reset-request-test')
  const deps = { redis, logger }
  const findAccount = jest.fn()
  const issue = jest.fn()

  /** One request that began just now. */
  function request(): ResetRequest {
    return {
      label: 'initiateReset',
      cooldownKey: 'cooldown:k',
      cooldownSeconds: 60,
      floorMs: FLOOR_MS,
      start: Date.now(),
      findAccount,
      isBlocked: () => false,
      issue
    }
  }

  beforeEach(() => {
    jest.resetAllMocks()
    jest.spyOn(logger, 'error').mockImplementation(() => undefined)
    redis.del.mockResolvedValue(true)
    findAccount.mockResolvedValue({ id: 'user-1', status: 'ACTIVE' })
    issue.mockResolvedValue(undefined)
  })

  // Scenario: the cooldown store cannot answer, for an address that exists and one that does not.
  // Expected: the same typed 503 for both, after the floor, and the account is never looked up.
  it.each([
    ['an address that exists', { id: 'user-1', status: 'ACTIVE' }],
    ['an address that does not', null]
  ])('answers 503 after the floor for %s', async (_label, account) => {
    redis.setnx.mockRejectedValue(UNAVAILABLE)
    findAccount.mockResolvedValue(account)
    const started = Date.now()

    const rejection = (await answerResetRequest(deps, request()).catch(
      (error: unknown) => error
    )) as AuthException

    expect(rejection).toBe(UNAVAILABLE)
    expect(Date.now() - started).toBeGreaterThanOrEqual(FLOOR_MS - 5)
    expect(findAccount).not.toHaveBeenCalled()
  })

  // Scenario: the cooldown store fails with something that is not an outage. Expected: still the
  // 500 the contract documents for every other failure before the account is known.
  it('answers 500 for a cooldown failure that is not an outage', async () => {
    redis.setnx.mockRejectedValue(new Error('WRONGTYPE'))

    const rejection = (await answerResetRequest(deps, request()).catch(
      (error: unknown) => error
    )) as AuthException

    expect(rejection).toBeInstanceOf(AuthException)
    expect(rejection.getStatus()).toBe(500)
  })

  // Scenario: the cooldown is taken, then the store fails while issuing the code. Expected: the
  // 200 stands (it resolves), the cooldown is released, and the answer is the one an address that
  // does not exist gets.
  it('keeps the 200 when the store fails after the account is known', async () => {
    redis.setnx.mockResolvedValue(true)
    issue.mockRejectedValue(UNAVAILABLE)

    await expect(answerResetRequest(deps, request())).resolves.toBeUndefined()

    expect(redis.del).toHaveBeenCalledWith('cooldown:k')
  })
})
