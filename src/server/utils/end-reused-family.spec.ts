/**
 * @fileoverview Unit tests for the revocation of a replayed refresh token's family.
 *
 * @layer Test
 */

import { Logger } from '@nestjs/common'

import { endReusedFamily } from './end-reused-family'
import { expectEvent } from '../__tests__/log-events'
import type { AuthRedisService } from '../redis/auth-redis.service'

const presented = { outcome: { familyId: 'f1' }, ip: '10.0.0.1', userAgent: 'agent' }

/** A store whose family belongs to `ownerId` in `tenantId`. */
function store(ownerId: string, tenantId?: string): AuthRedisService {
  return {
    revokeFamily: jest.fn(async () => ({ removed: 1, ownerId, tenantId }))
  } as unknown as AuthRedisService
}

describe('endReusedFamily', () => {
  let log: jest.SpyInstance

  beforeEach(() => {
    log = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
  })
  afterEach(() => jest.restoreAllMocks())

  // Scenario: a dashboard replay. Expected: the family is revoked, then both hooks are told.
  it('revokes the family and tells both hooks', async () => {
    const redis = store('u1', 't1')
    const hooks = { onSessionsRevoked: jest.fn(), onRefreshTokenReuseDetected: jest.fn() }

    await endReusedFamily(redis, hooks, new Logger(), { kind: 'dashboard', ...presented })

    expect((redis.revokeFamily as jest.Mock).mock.calls).toEqual([['f1']])
    expect(hooks.onSessionsRevoked.mock.calls).toStrictEqual([
      [{ userId: 'u1', tenantId: 't1', plane: 'dashboard', reason: 'refresh_reuse' }]
    ])
    expect(hooks.onRefreshTokenReuseDetected).toHaveBeenCalledWith(
      { userId: 'u1', familyId: 'f1' },
      { plane: 'dashboard', ip: '10.0.0.1', userAgent: 'agent', sanitizedHeaders: {} }
    )
  })

  // Scenario: a platform replay. Expected: the platform family, and an event with no tenant.
  it('revokes the platform family on the platform plane', async () => {
    const redis = store('a1')
    const onSessionsRevoked = jest.fn()

    await endReusedFamily(redis, { onSessionsRevoked }, new Logger(), {
      kind: 'platform',
      ...presented
    })

    expect(redis.revokeFamily).toHaveBeenCalledWith('f1', 'platform')
    expect(onSessionsRevoked.mock.calls[0]?.[0]).toStrictEqual({
      userId: 'a1',
      plane: 'platform',
      reason: 'refresh_reuse'
    })
    expect(Object.keys(onSessionsRevoked.mock.calls[0]?.[0] as object).includes('tenantId')).toBe(
      false
    )
  })

  // Scenario: no record names an owner. Expected: no hook, the family is still logged.
  it('tells no hook when no account can be named', async () => {
    const hooks = { onSessionsRevoked: jest.fn(), onRefreshTokenReuseDetected: jest.fn() }

    await endReusedFamily(store(''), hooks, new Logger(), { kind: 'dashboard', ...presented })

    expect(hooks.onSessionsRevoked).not.toHaveBeenCalled()
    expect(hooks.onRefreshTokenReuseDetected).not.toHaveBeenCalled()
    expectEvent(log, 'AUTH_REFRESH_FAMILY_REVOKED', { plane: 'dashboard', familyId: 'f1' })
  })

  // Scenario: no hooks at all. Expected: the revocation still happens.
  it('revokes with no hooks registered', async () => {
    const redis = store('u1', 't1')

    await endReusedFamily(redis, null, new Logger(), { kind: 'dashboard', ...presented })
    await endReusedFamily(redis, {}, new Logger(), { kind: 'dashboard', ...presented })

    expect(redis.revokeFamily).toHaveBeenCalledTimes(2)
  })
})
