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
function reauthCounters(userId: string, tenantId: string): { scoped: string; legacy: string } {
  return {
    scoped: hmacSha256(`reauth:${userSubject('dashboard', userId, tenantId)}`, HMAC_KEY),
    legacy: hmacSha256(`reauth:dashboard:${userId}`, HMAC_KEY)
  }
}

describe('ReauthenticationService', () => {
  describe('an account with a password', () => {
    it('accepts the right password and clears the failure counters', async () => {
      const { service, brute } = await build()

      await expect(
        service.assertReauthenticated('dashboard', 'u1', 'hash', 'secret', 't1')
      ).resolves.toBeUndefined()

      const { scoped, legacy } = reauthCounters('u1', 't1')
      expect(brute.resetFailures.mock.calls).toEqual([[scoped]])
      expect(brute.resetFailures).not.toHaveBeenCalledWith(legacy)
      expect(brute.recordFailure).not.toHaveBeenCalled()
    })

    it('refuses a wrong password with INVALID_CREDENTIALS and counts the failure', async () => {
      const { service, brute, password } = await build()
      password.compare.mockResolvedValue(false)

      await expect(
        service.assertReauthenticated('dashboard', 'u1', 'hash', 'wrong', 't1')
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.INVALID_CREDENTIALS } }
      })

      const { scoped, legacy } = reauthCounters('u1', 't1')
      expect(brute.recordFailure.mock.calls).toEqual([[scoped]])
      expect(brute.recordFailure).not.toHaveBeenCalledWith(legacy)
      expect(brute.resetFailures).not.toHaveBeenCalled()
    })

    it('compares an absent password too, so the refusal costs the same as a wrong one', async () => {
      const { service, password } = await build()
      password.compare.mockResolvedValue(false)

      await expect(
        service.assertReauthenticated('dashboard', 'u1', 'hash', undefined, 't1')
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.INVALID_CREDENTIALS } }
      })

      expect(password.compare).toHaveBeenCalledWith('', 'hash')
    })

    it('refuses with ACCOUNT_LOCKED before comparing once the budget is spent', async () => {
      const { service, brute, password } = await build()
      brute.isLockedOut.mockResolvedValue(true)

      await expect(
        service.assertReauthenticated('platform', 'a1', 'hash', 'secret', undefined)
      ).rejects.toMatchObject({ response: { error: { code: AUTH_ERROR_CODES.ACCOUNT_LOCKED } } })

      expect(password.compare).not.toHaveBeenCalled()
      // The platform plane has no tenant, so the two ids coincide and are read once.
      expect(brute.isLockedOut.mock.calls).toEqual([
        [hmacSha256(`reauth:${userSubject('platform', 'a1', undefined)}`, HMAC_KEY)]
      ])
    })

    it('reads only the tenant-scoped counter on the dashboard plane before comparing', async () => {
      const { service, brute } = await build()

      await service.assertReauthenticated('dashboard', 'u1', 'hash', 'secret', 't1')

      const { scoped, legacy } = reauthCounters('u1', 't1')
      expect(brute.isLockedOut.mock.calls).toEqual([[scoped]])
      expect(brute.isLockedOut).not.toHaveBeenCalledWith(legacy)
    })
  })

  describe('an account with no password', () => {
    it('accepts a caller whose recent-authentication marker is present', async () => {
      const { service, redis } = await build()
      redis.get.mockResolvedValue('1')

      await expect(
        service.assertReauthenticated('dashboard', 'u1', null, undefined, 't1')
      ).resolves.toBeUndefined()

      expect(redis.get).toHaveBeenCalledWith(recentAuthKey('dashboard', 'u1', HMAC_KEY, 't1'))
    })

    it('refuses with REAUTHENTICATION_REQUIRED when the marker is absent', async () => {
      const { service, password } = await build()

      await expect(
        service.assertReauthenticated('dashboard', 'u1', null, undefined, 't1')
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.REAUTHENTICATION_REQUIRED } }
      })

      expect(password.compare).not.toHaveBeenCalled()
    })

    it('reads the marker under the tenant-scoped key, not another tenant’s', async () => {
      const { service, redis } = await build()

      await expect(
        service.assertReauthenticated('dashboard', 'u1', null, undefined, 't1')
      ).rejects.toBeDefined()

      expect(redis.get).not.toHaveBeenCalledWith(recentAuthKey('dashboard', 'u1', HMAC_KEY, 't2'))
    })
  })
})
