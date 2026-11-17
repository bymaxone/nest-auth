/**
 * @fileoverview Filling the account-status cache never decides a request. The repository read has
 * already answered by the time the cache is written, so a store that cannot take the write must not
 * turn a decision that was made into an error; the next request simply reads the repository again.
 *
 * @layer Test
 */

import { Logger } from '@nestjs/common'

import { AccountStatusService } from './account-status.service'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'

const REF = { userId: 'u1', tenantId: 't1' } as const

/** The service over doubles: a cold cache, a repository holding `user`, and a store that fails writes. */
function build(
  user: { status: string; emailVerified: boolean } | null,
  required = false
): {
  service: AccountStatusService
  redis: { get: jest.Mock; set: jest.Mock }
  repo: { findById: jest.Mock }
} {
  const redis = {
    get: jest.fn().mockResolvedValue(null),
    set: jest.fn().mockRejectedValue(new Error('connection lost'))
  }
  const repo = { findById: jest.fn().mockResolvedValue(user) }
  const options = {
    hmacKey: 'k'.repeat(48),
    userStatusCacheTtlSeconds: 60,
    blockedStatuses: ['BANNED', 'SUSPENDED'],
    emailVerification: { required }
  }
  return {
    service: new AccountStatusService(redis as never, repo as never, options as never),
    redis,
    repo
  }
}

describe('AccountStatusService cache fill', () => {
  beforeEach(() => jest.spyOn(Logger.prototype, 'warn').mockImplementation())
  afterEach(() => jest.restoreAllMocks())

  // Scenario: the cache is cold, the repository says the account is active, and the cache write
  // fails. Expected: the account is usable. Why: the decision was made from the record just read.
  it('lets an active account through when the status write fails', async () => {
    const { service } = build({ status: 'ACTIVE', emailVerified: true })

    await expect(service.assertDashboardAccountUsable(REF)).resolves.toBeUndefined()
  })

  // Scenario: the same, for a blocked account. Expected: the account's own refusal, not the store's
  // error. Why: the caller must be told the account is blocked, and a blocked account must never be
  // answered with an outage that a client retries.
  it('refuses a blocked account with its own error when the status write fails', async () => {
    const { service } = build({ status: 'SUSPENDED', emailVerified: true })

    await expect(service.assertDashboardAccountUsable(REF)).rejects.toMatchObject({
      response: { error: { code: AUTH_ERROR_CODES.ACCOUNT_SUSPENDED } }
    })
  })

  // Scenario: email verification is required and the address is not verified. Expected: the
  // verification refusal, whichever of the two writes failed.
  it('refuses an unverified account with its own error when a write fails', async () => {
    const { service } = build({ status: 'ACTIVE', emailVerified: false }, true)

    await expect(service.assertDashboardAccountUsable(REF)).rejects.toMatchObject({
      response: { error: { code: AUTH_ERROR_CODES.EMAIL_NOT_VERIFIED } }
    })
  })

  // Scenario: verification is required, the status write succeeds and the verified-flag write fails.
  // Expected: a verified account is usable.
  it('lets a verified account through when only the verified-flag write fails', async () => {
    const { service, redis } = build({ status: 'ACTIVE', emailVerified: true }, true)
    redis.set.mockResolvedValueOnce(undefined)

    await expect(service.assertDashboardAccountUsable(REF)).resolves.toBeUndefined()
  })

  // Scenario: an account that does not exist. Expected: TOKEN_INVALID. Why: a missing repository
  // record is a refusal, and there is nothing to write to the cache.
  it('refuses a missing account with TOKEN_INVALID', async () => {
    const { service } = build(null)

    await expect(service.assertDashboardAccountUsable(REF)).rejects.toMatchObject({
      response: { error: { code: AUTH_ERROR_CODES.TOKEN_INVALID } }
    })
  })

  // Scenario: a failed write. Expected: one warning that says the next request reads the repository
  // again, and nothing from the store's text.
  it('logs one warning per failed write and keeps the store text out of it', async () => {
    const { service } = build({ status: 'ACTIVE', emailVerified: true })
    const warn = jest.spyOn(Logger.prototype, 'warn').mockImplementation()

    await service.assertDashboardAccountUsable(REF)

    expect(warn).toHaveBeenCalledTimes(1)
    expect(String(warn.mock.calls[0]?.[0])).toMatch(/reads the repository again/)
    expect(String(warn.mock.calls[0]?.[0])).not.toMatch(/connection lost/)
  })

  // Scenario: a cache read that fails (not a fill). Expected: the error propagates. Why: a store
  // that cannot answer a read is an outage, and only a write after the decision is best effort.
  it('fails when the cache READ fails', async () => {
    const { service, redis } = build({ status: 'ACTIVE', emailVerified: true })
    redis.get.mockRejectedValue(new Error('connection lost'))

    await expect(service.assertDashboardAccountUsable(REF)).rejects.toThrow('connection lost')
  })
})
