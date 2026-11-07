/**
 * @fileoverview Tests for the retry marker helpers: writing it when a logout attempt fails and
 * settling it when a logout completes.
 */

import type { Logger } from '@nestjs/common'

import type { AuthRedisService } from '../redis/auth-redis.service'
import { rememberPendingLogout, settlePendingLogout } from './pending-logout'

const KEY = 'lp:abc'
const REFUSED = new Error('READONLY You can not write against a read only replica')

describe('pending logout marker', () => {
  const redis = { set: jest.fn(), del: jest.fn() }
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

      await expect(settlePendingLogout(asRedis, KEY, fromSession, asLogger)).resolves.toBe(
        announced
      )

      expect(redis.del).toHaveBeenCalledWith(KEY)
      expect(logger.warn).not.toHaveBeenCalled()
    })

    // A removal the store refuses never turns a completed logout into a failure, and with no
    // removal there is no claim: from the session the logout still announces, from the marker not.
    it.each([
      ['the session', true],
      ['the marker', false]
    ])('reports a refused removal and answers %s', async (_name, fromSession) => {
      redis.del.mockRejectedValue(REFUSED)

      await expect(settlePendingLogout(asRedis, KEY, fromSession, asLogger)).resolves.toBe(
        fromSession
      )

      expect(logger.warn).toHaveBeenCalledTimes(1)
      const logged = String(logger.warn.mock.calls[0]?.[0])
      expect(logged).toContain('the retry marker could not be cleared')
      expect(logged).not.toContain(KEY)
    })
  })
})
