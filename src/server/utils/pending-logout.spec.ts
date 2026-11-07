/**
 * @fileoverview Tests for the retry marker helpers: writing it when a logout attempt fails and
 * settling it when a logout completes.
 */

import type { Logger } from '@nestjs/common'

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { AuthRedisService } from '../redis/auth-redis.service'
import { rememberPendingLogout, settlePendingLogout } from './pending-logout'

const KEY = 'lp:abc'
const OWNER = { userId: 'user-1', tenantId: 'tenant-1' }
const REFUSED = new Error('READONLY You can not write against a read only replica')

describe('pending logout marker', () => {
  const redis = { set: jest.fn(), del: jest.fn(), get: jest.fn() }
  const logger = { warn: jest.fn() }
  const asRedis = redis as unknown as AuthRedisService
  const asLogger = logger as unknown as Logger

  beforeEach(() => {
    jest.resetAllMocks()
    redis.set.mockResolvedValue(undefined)
    redis.del.mockResolvedValue(true)
  })

  describe('rememberPendingLogout', () => {
    // The record carries the owner and, when the session named one, the tenant; a record with no
    // tenant omits the field entirely rather than writing the string `undefined`.
    it.each([
      [
        'a tenant',
        { userId: 'user-1', tenantId: 'tenant-1' },
        '{"userId":"user-1","tenantId":"tenant-1"}'
      ],
      ['no tenant', { userId: 'admin-1', tenantId: undefined }, '{"userId":"admin-1"}']
    ])(
      'writes the owner with %s under the key and lifetime it was given',
      async (_name, owner, json) => {
        await rememberPendingLogout(asRedis, KEY, owner, 900, asLogger)

        expect(redis.set).toHaveBeenCalledWith(KEY, json, 900)
        expect(logger.warn).not.toHaveBeenCalled()
      }
    )

    // The write is best effort: a refused write is reported without the key or the owner, and never
    // thrown, because the logout is already failing and its own error is the one to raise.
    it('reports a refused write without throwing and without naming the key or the owner', async () => {
      redis.set.mockRejectedValue(REFUSED)

      await expect(
        rememberPendingLogout(
          asRedis,
          KEY,
          { userId: 'user-1', tenantId: 'tenant-1' },
          300,
          asLogger
        )
      ).resolves.toBeUndefined()

      expect(logger.warn).toHaveBeenCalledTimes(1)
      const logged = String(logger.warn.mock.calls[0]?.[0])
      expect(logged).toContain('the owner could not be kept for a retry')
      expect(logged).not.toContain(KEY)
      expect(logged).not.toContain('user-1')
    })
  })

  describe('settlePendingLogout', () => {
    // The marker is always removed; an owner read from the session announces regardless, and one
    // read from the marker announces only if this call removed it.
    it.each([
      ['the session, marker present', true, true, true],
      ['the session, marker absent', true, false, true],
      ['the marker, removed by this call', false, true, true],
      ['the marker, already removed by another', false, false, false]
    ])('announces for %s: %s', async (_name, fromSession, removed, announced) => {
      redis.del.mockResolvedValue(removed)

      await expect(
        settlePendingLogout(asRedis, KEY, fromSession, OWNER, 900, asLogger)
      ).resolves.toBe(announced)

      expect(redis.del).toHaveBeenCalledWith(KEY)
      expect(logger.warn).not.toHaveBeenCalled()
    })

    // An owner read from the marker whose claim the store refuses answers an error and announces
    // nothing: answering success would keep the client from retrying, and no later call would ever
    // announce this logout. The marker stays, so the retry claims it and announces once.
    it('answers an error when the claim of a marker-sourced owner is refused', async () => {
      redis.del.mockRejectedValue(REFUSED)

      const failure = await settlePendingLogout(asRedis, KEY, false, OWNER, 900, asLogger).catch(
        (err: unknown) => err
      )

      expect(failure).toBeInstanceOf(AuthException)
      expect((failure as AuthException).getResponse()).toMatchObject({
        error: { code: AUTH_ERROR_CODES.INTERNAL }
      })
      expect(logger.warn).toHaveBeenCalledTimes(1)
      const logged = String(logger.warn.mock.calls[0]?.[0])
      expect(logged).toContain('the retry marker could not be cleared')
      expect(logged).not.toContain(KEY)
      expect(redis.get).not.toHaveBeenCalled()
      expect(redis.set).not.toHaveBeenCalled()
    })

    describe('a stale marker whose removal the store refuses', () => {
      /** The code of the error a rejected settle carried. */
      async function refusedCode(): Promise<string | undefined> {
        const failure = await settlePendingLogout(asRedis, KEY, true, OWNER, 900, asLogger).catch(
          (err: unknown) => err
        )
        if (!(failure instanceof AuthException)) return undefined
        return (failure.getResponse() as { error?: { code?: string } }).error?.code
      }

      beforeEach(() => {
        redis.del.mockRejectedValue(REFUSED)
      })

      // A second read shows no marker is left, so no later retry can claim one and announce this
      // logout again: it is announced now.
      it('announces when a second read shows no marker is left', async () => {
        redis.get.mockResolvedValue(null)

        await expect(settlePendingLogout(asRedis, KEY, true, OWNER, 900, asLogger)).resolves.toBe(
          true
        )

        expect(redis.get).toHaveBeenCalledWith(KEY)
        expect(redis.set).not.toHaveBeenCalled()
      })

      // A marker still there would be claimed, and announced, by the retry; announcing now would
      // announce the same logout twice. The session is already gone, so the retry settles it.
      it('answers an error when a second read still finds the marker, and announces nothing', async () => {
        redis.get.mockResolvedValue('{"userId":"user-1","tenantId":"tenant-1"}')

        expect(await refusedCode()).toBe(AUTH_ERROR_CODES.INTERNAL)

        expect(redis.set).not.toHaveBeenCalled()
      })

      // Whether a marker is left is unknown, so the owner is recorded again, best effort, under
      // the lifetime it was given, and the logout answers an error for the retry to settle.
      it('records the owner again and answers an error when the second read also fails', async () => {
        redis.get.mockRejectedValue(REFUSED)

        expect(await refusedCode()).toBe(AUTH_ERROR_CODES.INTERNAL)

        expect(redis.set).toHaveBeenCalledWith(
          KEY,
          '{"userId":"user-1","tenantId":"tenant-1"}',
          900
        )
      })

      // The rewrite is best effort: a refused rewrite does not replace the error the logout answers.
      it('answers the error when the rewrite is refused too', async () => {
        redis.get.mockRejectedValue(REFUSED)
        redis.set.mockRejectedValue(REFUSED)

        expect(await refusedCode()).toBe(AUTH_ERROR_CODES.INTERNAL)
      })

      // The first refusal and the follow-up are reported without the key or the owner.
      it('reports the refusal without naming the key or the owner', async () => {
        redis.get.mockResolvedValue('{"userId":"user-1"}')

        await refusedCode()

        const logged = logger.warn.mock.calls.map((call) => String(call[0])).join('\n')
        expect(logged).toContain('the retry marker could not be cleared')
        expect(logged).not.toContain(KEY)
        expect(logged).not.toContain('user-1')
      })
    })
  })
})
