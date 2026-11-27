/**
 * @fileoverview What each flow that revokes sessions tells `onSessionsRevoked`.
 *
 * @layer Test
 */

import { Logger } from '@nestjs/common'

import { AuthService } from './auth.service'
import { MfaManagementService } from './mfa-management.service'
import { MfaService } from './mfa.service'
import { PasswordResetService } from './password-reset.service'
import { PlatformAuthService } from './platform-auth.service'
import { SessionService } from './session.service'
import { sha256 } from '../crypto/secure-token'
import type { SessionsRevokedEvent } from '../interfaces/auth-hooks.interface'

const kept = sha256('kept')
const other = sha256('other')
const account = { userId: 'u1', tenantId: 't1' }
const onSessionsRevoked = jest.fn<void, [SessionsRevokedEvent]>()
const hooks = { onSessionsRevoked }
const redis = {
  invalidateUserSessions: jest.fn(),
  bumpUserTokenEpoch: jest.fn(),
  eval: jest.fn(),
  smembers: jest.fn(),
  del: jest.fn(),
  srem: jest.fn()
}

/** Builds a service from positional collaborators the test does not need to type. */
function build<T>(Service: new (...args: never[]) => T, ...args: unknown[]): T {
  return new Service(...(args as never[]))
}

/** The events announced, in order. */
const events = (): SessionsRevokedEvent[] => onSessionsRevoked.mock.calls.map(([event]) => event)

beforeEach(() => {
  jest.resetAllMocks()
  redis.eval.mockResolvedValue(1)
  redis.smembers.mockResolvedValue([`rt:${kept}`, `rt:${other}`])
  jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
})
afterEach(() => jest.restoreAllMocks())

describe('SessionService', () => {
  const sessions = (): SessionService => build(SessionService, { hmacKey: 'k' }, {}, hooks, redis)
  const target = { ...account, sessionHash: other }
  const revoked = (reason: string, sessionIds: string[]) => ({
    userId: 'u1',
    tenantId: 't1',
    plane: 'dashboard',
    reason,
    sessionIds
  })

  // Scenario: one session revoked directly. Expected: one event naming it.
  it('announces a revoked session', async () => {
    await sessions().revokeSession(target)

    expect(events()).toEqual([revoked('session_revoked', [other])])
  })

  // Scenario: the epoch write after the removal is refused. Expected: announced all the same.
  it('announces another session even when the epoch write is refused', async () => {
    redis.bumpUserTokenEpoch.mockRejectedValue(new Error('refused'))

    await expect(sessions().revokeOtherSession(target)).rejects.toThrow('refused')

    expect(events()).toEqual([revoked('session_revoked', [other])])
  })

  // Scenario: every other session revoked, with and without a reason given.
  it('announces the others under the reason given', async () => {
    await sessions().revokeAllExceptCurrent({ ...account, currentSessionHash: kept })
    await sessions().revokeAllExceptCurrent({
      ...account,
      currentSessionHash: kept,
      reason: 'password_changed'
    })

    expect(events()).toEqual([
      revoked('other_sessions_revoked', [other]),
      revoked('password_changed', [other])
    ])
  })

  // Scenario: there is no other session. Expected: still announced. Why: the epoch advanced.
  it('announces a sweep that found no other session', async () => {
    redis.smembers.mockResolvedValue([`rt:${kept}`])

    await sessions().revokeAllExceptCurrent({ ...account, currentSessionHash: kept })

    expect(events()).toEqual([revoked('other_sessions_revoked', [])])
  })

  // Scenario: the sweep fails after deleting one session. Expected: that one is announced.
  it('announces what a failed sweep had already deleted', async () => {
    redis.bumpUserTokenEpoch.mockRejectedValue(new Error('refused'))

    await expect(
      sessions().revokeAllExceptCurrent({ ...account, currentSessionHash: kept })
    ).rejects.toThrow('refused')

    expect(events()).toEqual([revoked('other_sessions_revoked', [other])])
  })

  // Scenario: the sweep fails having deleted nothing. Expected: no event.
  it('announces nothing when a failed sweep deleted nothing', async () => {
    redis.eval.mockRejectedValue(new Error('refused'))

    await expect(
      sessions().revokeAllExceptCurrent({ ...account, currentSessionHash: kept })
    ).rejects.toThrow('refused')

    expect(events()).toEqual([])
  })
})

describe('the flows that end every session', () => {
  const reasons = (): string[] => events().map((event) => event.reason)

  /** An AuthService whose rotation answers for `account`. */
  function auth(user: unknown): AuthService {
    const tokenManager = { reissueTokens: async () => ({ session: account }) }
    const options = { blockedStatuses: ['BANNED'] }
    const repo = { findById: async () => user }
    return build(AuthService, options, repo, null, hooks, {}, tokenManager, {}, redis, {}, {}, {})
  }

  /** A PlatformAuthService whose rotation answers for administrator `a1`. */
  function platform(admin: unknown): PlatformAuthService {
    const tokenManager = { reissuePlatformTokens: async () => ({ session: { userId: 'a1' } }) }
    const options = { blockedStatuses: ['BANNED'] }
    const repo = { findById: async () => admin }
    return build(PlatformAuthService, repo, {}, tokenManager, {}, redis, options, hooks)
  }

  // Scenario: the programmatic call, and a refresh for an account that is gone or blocked.
  // Expected: the first says the sessions were revoked, the others that the account cannot be used.
  it('tells the dashboard reasons apart', async () => {
    await auth(null).revokeAllSessions(account)
    await expect(auth(null).refresh('t', 'ip', 'ua')).rejects.toThrow()
    await expect(auth({ id: 'u1', status: 'BANNED' }).refresh('t', 'ip', 'ua')).rejects.toThrow()

    expect(reasons()).toEqual([
      'all_sessions_revoked',
      'account_unavailable',
      'account_unavailable'
    ])
    expect(events()[0]).toMatchObject({ ...account, plane: 'dashboard' })
  })

  // Scenario: the same three on the platform plane. Expected: the same reasons, no tenant.
  it('tells the platform reasons apart', async () => {
    await platform(null).revokeAllPlatformSessions('a1')
    await expect(platform(null).refresh('t', 'ip', 'ua')).rejects.toThrow()
    await expect(
      platform({ id: 'a1', status: 'BANNED' }).refresh('t', 'ip', 'ua')
    ).rejects.toThrow()

    expect(events()).toStrictEqual(
      ['all_sessions_revoked', 'account_unavailable', 'account_unavailable'].map((reason) => ({
        userId: 'a1',
        plane: 'platform',
        reason
      }))
    )
  })

  // Scenario: a password change with no session to keep, and a completed reset.
  it('names a password change and a password reset', async () => {
    const reset = build(
      PasswordResetService,
      {},
      { updatePassword: async () => undefined, findById: async () => null },
      null,
      hooks,
      {},
      { hash: async () => 'hash' },
      redis,
      {},
      {}
    )

    await reset['endOtherSessions']('u1', 't1', undefined)
    await reset['applyPasswordReset']('u1', 't1', 'new-password')

    expect(events()).toMatchObject([
      { ...account, plane: 'dashboard', reason: 'password_changed' },
      { ...account, plane: 'dashboard', reason: 'password_reset' }
    ])
  })

  // Scenario: a second factor turned on and off, on each plane. Expected: the tenant is named on
  // the dashboard plane only.
  it('names a second factor turned on and off', async () => {
    const records = { transition: async () => undefined }
    const enable = build(MfaService, {}, {}, null, redis, {}, {}, {}, {}, {}, {}, {}, {}, hooks)
    const disable = build(MfaManagementService, {}, null, redis, {}, records, {}, hooks)

    await enable['endSessionsForNewFactor']('u1', 't1', 'dashboard')
    await enable['endSessionsForNewFactor']('a1', undefined, 'platform')
    await disable['clearFactor']({ userId: 'u1', tenantId: 't1', context: 'dashboard' })
    await disable['clearFactor']({ userId: 'a1', tenantId: undefined, context: 'platform' })

    expect(events()).toStrictEqual([
      { userId: 'u1', plane: 'dashboard', reason: 'mfa_enabled', tenantId: 't1' },
      { userId: 'a1', plane: 'platform', reason: 'mfa_enabled' },
      { userId: 'u1', plane: 'dashboard', reason: 'mfa_disabled', tenantId: 't1' },
      { userId: 'a1', plane: 'platform', reason: 'mfa_disabled' }
    ])
  })
})
