/**
 * @fileoverview Unit tests for the announcement of a session revocation.
 *
 * @layer Test
 */

import { Logger } from '@nestjs/common'

import { announceSessionsRevoked, revokeEverySession } from './session-revocation'
import type { SessionsRevokedEvent } from '../interfaces/auth-hooks.interface'
import type { AuthRedisService } from '../redis/auth-redis.service'

const logger = new Logger('test')
const base: SessionsRevokedEvent = { userId: 'u1', plane: 'dashboard', reason: 'logout' }

/** A store whose two writes record the order they ran in. */
function store(
  calls: string[],
  fail?: 'delete' | 'epoch'
): Pick<AuthRedisService, 'invalidateUserSessions' | 'bumpUserTokenEpoch'> {
  const write = (name: 'delete' | 'epoch'): void => {
    calls.push(name)
    if (fail === name) throw new Error(`${name} refused`)
  }
  return {
    invalidateUserSessions: jest.fn(async () => write('delete')),
    bumpUserTokenEpoch: jest.fn(async () => {
      write('epoch')
      return 1
    })
  }
}

describe('announceSessionsRevoked', () => {
  // Scenario: every field is known. Expected: the host receives exactly them.
  it('passes the account, tenant, reason and sessions to the host', () => {
    const onSessionsRevoked = jest.fn()

    announceSessionsRevoked({ onSessionsRevoked }, logger, {
      ...base,
      tenantId: 't1',
      sessionIds: ['a']
    })

    expect(onSessionsRevoked.mock.calls).toStrictEqual([
      [{ userId: 'u1', plane: 'dashboard', reason: 'logout', tenantId: 't1', sessionIds: ['a'] }]
    ])
  })

  // Scenario: no tenant and no session list. Expected: neither key exists. Why: an absent field
  // says "not known"; a key holding undefined reads as a value.
  it('leaves out what is not known', () => {
    const onSessionsRevoked = jest.fn()

    announceSessionsRevoked({ onSessionsRevoked }, logger, base)

    expect(onSessionsRevoked.mock.calls[0]?.[0]).toStrictEqual({ ...base })
    expect(Object.keys(onSessionsRevoked.mock.calls[0]?.[0] as object)).toEqual([
      'userId',
      'plane',
      'reason'
    ])
  })

  // Scenario: a platform event handed a tenant. Expected: none reaches the host.
  it('never names a tenant on the platform plane', () => {
    const onSessionsRevoked = jest.fn()

    announceSessionsRevoked({ onSessionsRevoked }, logger, {
      ...base,
      plane: 'platform',
      tenantId: 't1'
    })

    expect(Object.keys(onSessionsRevoked.mock.calls[0]?.[0] as object)).not.toContain('tenantId')
  })

  // Scenario: no account, no hooks, or hooks without this one. Expected: nothing happens.
  it('says nothing without an account or a hook', () => {
    const onSessionsRevoked = jest.fn()

    announceSessionsRevoked({ onSessionsRevoked }, logger, { ...base, userId: '' })

    expect(onSessionsRevoked).not.toHaveBeenCalled()
    expect(() => announceSessionsRevoked(null, logger, base)).not.toThrow()
    expect(() => announceSessionsRevoked({}, logger, base)).not.toThrow()
  })

  // Scenario: the hook throws. Expected: the caller is not told, the log names the hook.
  it('logs a throwing hook without raising', async () => {
    const error = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
    const hooks = {
      onSessionsRevoked(): void {
        throw new Error('host failure')
      }
    }

    expect(() => announceSessionsRevoked(hooks, logger, base)).not.toThrow()
    await new Promise((resolve) => setImmediate(resolve))

    expect(error).toHaveBeenCalledWith(expect.objectContaining({ hook: 'onSessionsRevoked' }))
    error.mockRestore()
  })

  // Scenario: a hook that reads `this`. Expected: it is called on the hooks object.
  it('calls the hook on the object that declares it', () => {
    const hooks = {
      seen: [] as string[],
      onSessionsRevoked(event: SessionsRevokedEvent): void {
        this.seen.push(event.userId)
      }
    }

    announceSessionsRevoked(hooks, logger, base)

    expect(hooks.seen).toEqual(['u1'])
  })
})

describe('revokeEverySession', () => {
  const revocation = {
    userId: 'u1',
    tenantId: 't1',
    plane: 'dashboard',
    reason: 'password_reset'
  } as const

  // Scenario: both writes succeed. Expected: delete, then epoch, then the announcement.
  it('deletes, advances the epoch and then announces', async () => {
    const calls: string[] = []
    const redis = store(calls)
    const hooks = { onSessionsRevoked: jest.fn(() => void calls.push('hook')) }

    await revokeEverySession(redis, hooks, logger, revocation)

    expect(calls).toEqual(['delete', 'epoch', 'hook'])
    expect(redis.invalidateUserSessions).toHaveBeenCalledWith('u1', 't1', 'dashboard')
    expect(redis.bumpUserTokenEpoch).toHaveBeenCalledWith('u1', 't1', 'dashboard')
    expect(hooks.onSessionsRevoked).toHaveBeenCalledWith(revocation)
  })

  // Scenario: the epoch write is refused. Expected: announced, and the refusal reaches the caller.
  it('announces the deletion when the epoch write is refused', async () => {
    const onSessionsRevoked = jest.fn()

    await expect(
      revokeEverySession(store([], 'epoch'), { onSessionsRevoked }, logger, revocation)
    ).rejects.toThrow('epoch refused')

    expect(onSessionsRevoked).toHaveBeenCalledTimes(1)
  })

  // Scenario: the deletion is refused. Expected: no announcement. Why: nothing was revoked.
  it('announces nothing when the deletion is refused', async () => {
    const calls: string[] = []
    const onSessionsRevoked = jest.fn()

    await expect(
      revokeEverySession(store(calls, 'delete'), { onSessionsRevoked }, logger, revocation)
    ).rejects.toThrow('delete refused')

    expect(calls).toEqual(['delete'])
    expect(onSessionsRevoked).not.toHaveBeenCalled()
  })
})
