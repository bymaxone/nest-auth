/**
 * @fileoverview Unit tests for the revocation of a replayed refresh token's family.
 *
 * @layer Test
 */

import { Logger } from '@nestjs/common'

import { endReusedFamily } from './end-reused-family'
import { expectEvent } from '../__tests__/log-events'
import type { AuthRedisService } from '../redis/auth-redis.service'

const familyId = '3f2b8c1e-9d4a-4f6b-8a2e-1c5d7e9f0a1b'
const presented = {
  outcome: { familyId },
  ip: '10.0.0.1',
  userAgent: 'agent'
}
const jwt = { accessExpiresIn: '15m' }

/** A store whose family belongs to `ownerId` in `tenantId`. */
function store(
  ownerId: string,
  tenantId?: string,
  sessionHashes: string[] = []
): Pick<AuthRedisService, 'revokeFamily' | 'set'> {
  return {
    revokeFamily: jest.fn(async () => ({
      removed: sessionHashes.length,
      sessionHashes,
      ownerId,
      tenantId
    })),
    set: jest.fn(async () => undefined)
  }
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

    await endReusedFamily(redis, hooks, new Logger(), jwt, { kind: 'dashboard', ...presented })

    expect((redis.revokeFamily as jest.Mock).mock.calls).toEqual([[familyId]])
    expect(hooks.onSessionsRevoked.mock.calls).toStrictEqual([
      [{ userId: 'u1', tenantId: 't1', plane: 'dashboard', reason: 'refresh_reuse' }]
    ])
    expect(hooks.onRefreshTokenReuseDetected).toHaveBeenCalledWith(
      { userId: 'u1', familyId },
      { plane: 'dashboard', ip: '10.0.0.1', userAgent: 'agent', sanitizedHeaders: {} }
    )
  })

  // Scenario: a platform replay. Expected: the platform family, and an event with no tenant.
  it('revokes the platform family on the platform plane', async () => {
    const redis = store('a1')
    const onSessionsRevoked = jest.fn()

    await endReusedFamily(redis, { onSessionsRevoked }, new Logger(), jwt, {
      kind: 'platform',
      ...presented
    })

    expect(redis.revokeFamily).toHaveBeenCalledWith(familyId, 'platform')
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

    await endReusedFamily(store(''), hooks, new Logger(), jwt, { kind: 'dashboard', ...presented })

    expect(hooks.onSessionsRevoked).not.toHaveBeenCalled()
    expect(hooks.onRefreshTokenReuseDetected).not.toHaveBeenCalled()
    expectEvent(log, 'AUTH_REFRESH_FAMILY_REVOKED', { plane: 'dashboard', familyId })
  })

  // Scenario: no hooks at all. Expected: the revocation still happens.
  it('revokes with no hooks registered', async () => {
    const redis = store('u1', 't1')

    await endReusedFamily(redis, null, new Logger(), jwt, { kind: 'dashboard', ...presented })
    await endReusedFamily(redis, {}, new Logger(), jwt, { kind: 'dashboard', ...presented })

    expect(redis.revokeFamily).toHaveBeenCalledTimes(2)
  })

  // Scenario: a replay of a family with a live session. Expected: its access tokens are ended under
  // the plane's own key, and the event names the sessions removed.
  it.each([
    ['dashboard' as const, 'rvs'],
    ['platform' as const, 'prvs']
  ])('ends the access tokens of the %s family and names its sessions', async (kind, prefix) => {
    const redis = store('u1', undefined, ['h1'])
    const onSessionsRevoked = jest.fn()

    await endReusedFamily(redis, { onSessionsRevoked }, new Logger(), jwt, { kind, ...presented })

    expect((redis.set as jest.Mock).mock.calls).toEqual([[`${prefix}:${familyId}`, '1', 960]])
    expect(onSessionsRevoked.mock.calls[0]?.[0]).toHaveProperty('sessionIds', ['h1'])
  })

  // Scenario: the entry cannot be written. Expected: the sessions are still revoked and announced,
  // the other hook still runs, and the failure reaches the caller.
  it('announces the revocation and then raises a refused write', async () => {
    const redis = store('u1', 't1', ['h1'])
    jest.mocked(redis.set).mockRejectedValue(new Error('refused'))
    const hooks = { onSessionsRevoked: jest.fn(), onRefreshTokenReuseDetected: jest.fn() }

    await expect(
      endReusedFamily(redis, hooks, new Logger(), jwt, { kind: 'dashboard', ...presented })
    ).rejects.toThrow('refused')

    expect(hooks.onSessionsRevoked).toHaveBeenCalledTimes(1)
    expect(hooks.onRefreshTokenReuseDetected).toHaveBeenCalledTimes(1)
  })
})
