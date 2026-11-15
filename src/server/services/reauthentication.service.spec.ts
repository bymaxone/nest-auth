/**
 * @fileoverview Tests for `ReauthenticationService`: the password check counted against the
 * `reauth` lockout, and the recent-sign-in requirement for an account with no password.
 */

import { Test } from '@nestjs/testing'

import { BruteForceService } from './brute-force.service'
import { MfaFlowLockoutService } from './mfa-flow-lockout.service'
import { PasswordService } from './password.service'
import { ReauthenticationService } from './reauthentication.service'
import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import { recentAuthKey } from '../constants/recent-auth'
import { userSubject } from '../constants/user-subject'
import { hmacSha256 } from '../crypto/secure-token'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthRedisService } from '../redis/auth-redis.service'

const HMAC_KEY = 'k'.repeat(48)
const SID = '11111111-2222-4333-8444-555555555555'
const OTHER_SID = '99999999-2222-4333-8444-555555555555'

/** Builds the service over mocks, returning the mocks the tests drive. */
async function build(): Promise<{
  service: ReauthenticationService
  redis: { get: jest.Mock }
  brute: { isLockedOut: jest.Mock; recordFailure: jest.Mock; resetFailures: jest.Mock }
  password: { compare: jest.Mock }
}> {
  const redis = { get: jest.fn().mockResolvedValue(null) }
  const brute = {
    isLockedOut: jest.fn().mockResolvedValue(false),
    recordFailure: jest.fn().mockResolvedValue(undefined),
    resetFailures: jest.fn().mockResolvedValue(undefined)
  }
  const password = { compare: jest.fn().mockResolvedValue(true) }
  const moduleRef = await Test.createTestingModule({
    providers: [
      ReauthenticationService,
      MfaFlowLockoutService,
      { provide: BYMAX_AUTH_OPTIONS, useValue: { hmacKey: HMAC_KEY } },
      { provide: AuthRedisService, useValue: redis },
      { provide: BruteForceService, useValue: brute },
      { provide: PasswordService, useValue: password }
    ]
  }).compile()
  return { service: moduleRef.get(ReauthenticationService), redis, brute, password }
}

/**
 * The counter id the `reauth` flow uses for a dashboard account, and the tenant-less one it must
 * never touch: two tenants' user `u1` share the latter and not the former.
 */
function reauthCounters(userId: string, tenantId: string): { scoped: string; tenantLess: string } {
  return {
    scoped: hmacSha256(`reauth:${userSubject('dashboard', userId, tenantId)}`, HMAC_KEY),
    tenantLess: hmacSha256(`reauth:dashboard:${userId}`, HMAC_KEY)
  }
}

describe('ReauthenticationService', () => {
  describe('an account with a password', () => {
    it('accepts the right password and clears the failure counters', async () => {
      const { service, brute } = await build()

      await expect(
        service.assertReauthenticated('dashboard', 'u1', 'hash', 'secret', 't1', undefined)
      ).resolves.toBeUndefined()

      const { scoped, tenantLess } = reauthCounters('u1', 't1')
      expect(brute.resetFailures.mock.calls).toEqual([[scoped]])
      expect(brute.resetFailures).not.toHaveBeenCalledWith(tenantLess)
      expect(brute.recordFailure).not.toHaveBeenCalled()
    })

    it('refuses a wrong password with INVALID_CREDENTIALS and counts the failure', async () => {
      const { service, brute, password } = await build()
      password.compare.mockResolvedValue(false)

      await expect(
        service.assertReauthenticated('dashboard', 'u1', 'hash', 'wrong', 't1', undefined)
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.INVALID_CREDENTIALS } }
      })

      const { scoped, tenantLess } = reauthCounters('u1', 't1')
      expect(brute.recordFailure.mock.calls).toEqual([[scoped]])
      expect(brute.recordFailure).not.toHaveBeenCalledWith(tenantLess)
      expect(brute.resetFailures).not.toHaveBeenCalled()
    })

    it('compares an absent password too, so the refusal costs the same as a wrong one', async () => {
      const { service, password } = await build()
      password.compare.mockResolvedValue(false)

      await expect(
        service.assertReauthenticated('dashboard', 'u1', 'hash', undefined, 't1', undefined)
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.INVALID_CREDENTIALS } }
      })

      expect(password.compare).toHaveBeenCalledWith('', 'hash')
    })

    it('refuses with ACCOUNT_LOCKED before comparing once the budget is spent', async () => {
      const { service, brute, password } = await build()
      brute.isLockedOut.mockResolvedValue(true)

      await expect(
        service.assertReauthenticated('platform', 'a1', 'hash', 'secret', undefined, undefined)
      ).rejects.toMatchObject({ response: { error: { code: AUTH_ERROR_CODES.ACCOUNT_LOCKED } } })

      expect(password.compare).not.toHaveBeenCalled()
      // The platform plane has no tenant, so the two ids coincide and are read once.
      expect(brute.isLockedOut.mock.calls).toEqual([
        [hmacSha256(`reauth:${userSubject('platform', 'a1', undefined)}`, HMAC_KEY)]
      ])
    })

    it('reads only the tenant-scoped counter on the dashboard plane before comparing', async () => {
      const { service, brute } = await build()

      await service.assertReauthenticated('dashboard', 'u1', 'hash', 'secret', 't1', undefined)

      const { scoped, tenantLess } = reauthCounters('u1', 't1')
      expect(brute.isLockedOut.mock.calls).toEqual([[scoped]])
      expect(brute.isLockedOut).not.toHaveBeenCalledWith(tenantLess)
    })
  })

  describe('an account with no password', () => {
    it('accepts a caller whose recent-authentication marker is present', async () => {
      const { service, redis } = await build()
      redis.get.mockResolvedValue('1')

      await expect(
        service.assertReauthenticated('dashboard', 'u1', null, undefined, 't1', SID)
      ).resolves.toBeUndefined()

      expect(redis.get).toHaveBeenCalledWith(recentAuthKey('dashboard', 'u1', HMAC_KEY, 't1', SID))
    })

    it('refuses with REAUTHENTICATION_REQUIRED when the marker is absent', async () => {
      const { service, password } = await build()

      await expect(
        service.assertReauthenticated('dashboard', 'u1', null, undefined, 't1', SID)
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.REAUTHENTICATION_REQUIRED } }
      })

      expect(password.compare).not.toHaveBeenCalled()
    })

    // Scenario: the proof was earned by another session of the same account (its key exists), and
    // the caller names its own session. Expected: refused, and only the caller's own key is read.
    // Why: the mark belongs to the session that earned it.
    it('does not accept a mark that another session earned', async () => {
      const { service, redis } = await build()
      redis.get.mockImplementation((key: string) =>
        Promise.resolve(
          key === recentAuthKey('dashboard', 'u1', HMAC_KEY, 't1', OTHER_SID) ? '1' : null
        )
      )

      await expect(
        service.assertReauthenticated('dashboard', 'u1', null, undefined, 't1', SID)
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.REAUTHENTICATION_REQUIRED } }
      })

      expect(redis.get.mock.calls).toEqual([
        [recentAuthKey('dashboard', 'u1', HMAC_KEY, 't1', SID)]
      ])
    })

    // Scenario: only a mark under the older, account-wide key exists. Expected: refused.
    // Why: a mark planted before an upgrade names no session, so it is not honoured after one.
    it('does not honour a mark under the old account-wide key', async () => {
      const { service, redis } = await build()
      const oldKey = `ra:${hmacSha256(userSubject('dashboard', 'u1', 't1'), HMAC_KEY)}`
      redis.get.mockImplementation((key: string) => Promise.resolve(key === oldKey ? '1' : null))

      await expect(
        service.assertReauthenticated('dashboard', 'u1', null, undefined, 't1', SID)
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.REAUTHENTICATION_REQUIRED } }
      })
    })

    // Scenario: a token with no `sid`, one minted before the claim, or one whose `sid` is not in the
    // contract's shape. Expected: refused without reading any key. Why: a token that names no
    // session cannot have earned a mark, and a caller-shaped value must not steer the key.
    it.each([undefined, '', 'not-a-session', `${SID}:x`, 'AAAAAAAA-2222-4333-8444-555555555555'])(
      'refuses a caller whose sid is %j without reading a mark',
      async (sid) => {
        const { service, redis } = await build()
        redis.get.mockResolvedValue('1')

        await expect(
          service.assertReauthenticated('dashboard', 'u1', null, undefined, 't1', sid)
        ).rejects.toMatchObject({
          response: { error: { code: AUTH_ERROR_CODES.REAUTHENTICATION_REQUIRED } }
        })

        expect(redis.get).not.toHaveBeenCalled()
      }
    )

    it('reads the marker under the tenant-scoped key, not another tenant’s', async () => {
      const { service, redis } = await build()

      await expect(
        service.assertReauthenticated('dashboard', 'u1', null, undefined, 't1', SID)
      ).rejects.toBeDefined()

      expect(redis.get).not.toHaveBeenCalledWith(
        recentAuthKey('dashboard', 'u1', HMAC_KEY, 't2', SID)
      )
    })
  })
})
