/**
 * @fileoverview Releasing the per-account MFA transition lock never changes what a transition
 * answers: once the record has been written the transition happened, and a store that cannot
 * answer the release must not turn it into an error. The lock expires on its own.
 *
 * @layer Test
 */

import { Logger } from '@nestjs/common'

import { MfaRecordService } from './mfa-record.service'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'

const OPTIONS = { hmacKey: 'k'.repeat(48), blockedStatuses: [] } as never
const USER = { id: 'u1', tenantId: 't1', status: 'active', mfaEnabled: false }
const WRITE = { mfaEnabled: true, mfaSecret: 'secret', mfaRecoveryCodes: ['a'] }

/** The service over doubles; `eval` is the lock release. */
function build(): {
  service: MfaRecordService
  repo: { findById: jest.Mock; updateMfa: jest.Mock }
  redis: { setIfAbsent: jest.Mock; eval: jest.Mock }
} {
  const repo = {
    findById: jest.fn().mockResolvedValue(USER),
    updateMfa: jest.fn().mockResolvedValue(undefined)
  }
  const redis = {
    setIfAbsent: jest.fn().mockResolvedValue(true),
    eval: jest.fn().mockResolvedValue(1)
  }
  return {
    service: new MfaRecordService(OPTIONS, repo as never, null, redis as never),
    repo,
    redis
  }
}

describe('MfaRecordService.transition lock release', () => {
  afterEach(() => {
    jest.useRealTimers()
    jest.restoreAllMocks()
  })

  // Scenario: the write commits and the store then fails the release. Expected: the transition
  // answers true, as it wrote. Why: an error here would tell the caller an MFA change that is in the
  // database did not happen, and a retry would then act on a state the caller does not expect.
  it('answers true when the release fails after the write committed', async () => {
    const { service, repo, redis } = build()
    redis.eval.mockRejectedValue(new Error('connection lost'))
    jest.spyOn(Logger.prototype, 'warn').mockImplementation()

    await expect(service.transition('dashboard', 'u1', 't1', () => WRITE)).resolves.toBe(true)

    expect(repo.updateMfa).toHaveBeenCalledTimes(1)
  })

  // Scenario: the caller abandons the transition and the release then fails. Expected: false.
  it('answers false when the transition is abandoned and the release fails', async () => {
    const { service, redis } = build()
    redis.eval.mockRejectedValue(new Error('connection lost'))
    jest.spyOn(Logger.prototype, 'warn').mockImplementation()

    await expect(service.transition('dashboard', 'u1', 't1', () => null)).resolves.toBe(false)
  })

  // Scenario: the transition itself fails and the release fails too. Expected: the transition's
  // own error is what the caller sees. Why: the release failure is the lesser fact and must not
  // hide the failure that matters.
  it('keeps the transition error when the release fails as well', async () => {
    const { service, repo, redis } = build()
    repo.updateMfa.mockRejectedValue(new Error('write failed'))
    redis.eval.mockRejectedValue(new Error('connection lost'))
    jest.spyOn(Logger.prototype, 'warn').mockImplementation()

    await expect(service.transition('dashboard', 'u1', 't1', () => WRITE)).rejects.toThrow(
      'write failed'
    )
  })

  // Scenario: a release that fails. Expected: a warning that says the lock will expire, and nothing
  // from the error's text beyond what the log helper allows. Why: the failure is not silent, and a
  // store's message may carry a host name.
  it('says in the log that the lock will expire on its own', async () => {
    const { service, redis } = build()
    redis.eval.mockRejectedValue(new Error('connection lost'))
    const warn = jest.spyOn(Logger.prototype, 'warn').mockImplementation()

    await service.transition('dashboard', 'u1', 't1', () => WRITE)

    expect(warn).toHaveBeenCalledTimes(1)
    expect(String(warn.mock.calls[0]?.[0])).toMatch(/expires on its own/)
  })

  // Scenario: an ordinary release. Expected: one compare-and-delete with this call's nonce and no
  // warning.
  it('releases with the nonce of the call and logs nothing when the store answers', async () => {
    const { service, redis } = build()
    const warn = jest.spyOn(Logger.prototype, 'warn').mockImplementation()

    await service.transition('dashboard', 'u1', 't1', () => WRITE)

    expect(redis.eval).toHaveBeenCalledTimes(1)
    const [, keys, args] = redis.eval.mock.calls[0] as [string, string[], string[]]
    expect(keys[0]).toMatch(/^mfalock:[0-9a-f]{64}$/)
    expect(args[0]).toMatch(/^[0-9a-f]{32}$/)
    expect(warn).not.toHaveBeenCalled()
  })
  // Scenario: a release failed, so the lock is still held, and a second transition on the same
  // account arrives; the store then honours the ten seconds the service asked for and a third arrives.
  // Expected: the second is refused with MFA_STATE_CONFLICT (try again) and still refused at nine
  // seconds, and the third succeeds after ten. Why: this is the cost of swallowing a failed release,
  // and it is bounded by the TTL the lock was taken with.
  it('refuses a second transition while the lock is held, until its ten seconds are over', async () => {
    jest.useFakeTimers()
    const { service, redis } = build()
    const expiries = new Map<string, number>()
    redis.setIfAbsent.mockImplementation((key: string, _value: string, ttl: number) => {
      const taken = (expiries.get(key) ?? 0) <= Date.now()
      if (taken) expiries.set(key, Date.now() + ttl * 1000)
      return Promise.resolve(taken)
    })
    redis.eval.mockRejectedValue(new Error('connection lost'))
    jest.spyOn(Logger.prototype, 'warn').mockImplementation()

    await expect(service.transition('dashboard', 'u1', 't1', () => WRITE)).resolves.toBe(true)
    const refused = { response: { error: { code: AUTH_ERROR_CODES.MFA_STATE_CONFLICT } } }
    await expect(service.transition('dashboard', 'u1', 't1', () => WRITE)).rejects.toMatchObject(
      refused
    )
    jest.advanceTimersByTime(9_000)
    await expect(service.transition('dashboard', 'u1', 't1', () => WRITE)).rejects.toMatchObject(
      refused
    )
    jest.advanceTimersByTime(1_000)
    await expect(service.transition('dashboard', 'u1', 't1', () => WRITE)).resolves.toBe(true)
    jest.useRealTimers()
  })
})
