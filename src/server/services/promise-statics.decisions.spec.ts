/**
 * @fileoverview The decisions that wait for several reads, or for a deadline, when the statics of `Promise` are replaced after the
 * library loaded: the answer is the one the repositories gave. A replaced `Promise.all` or `Promise.race` used to answer a
 * membership the store never returned, a profile the plugin never fetched, an account that does not exist and the order sessions
 * are evicted in; and a monitor that wraps `then`, with fake timers on, must leave the clean path as it was.
 *
 * @layer Test
 */

import { Logger } from '@nestjs/common'
import { Test } from '@nestjs/testing'

import { resolveOptions } from '../config/resolved-options'
import {
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  GUARDED_USER_REPOSITORY
} from '../bymax-auth.constants'
import { sha256 } from '../crypto/secure-token'
import { withDeadline } from '../oauth/plugin-deadline'
import { AuthRedisService } from '../redis/auth-redis.service'
import { assertRootIsStandard, isRefusal } from '../utils/object-prototype-guard'
import { WorkspaceAccessService } from './workspace-access.service'
import { SessionService } from './session.service'
import { build, OWNER, sent, user } from './__tests__/workspace-invitation-harness'
import { CONTEXT, WORKSPACE_REF, workspaceRow } from './__tests__/workspace-service-harness'

/** Reads the answer of a helper: a failure is thrown by `.value`, not by the promise. */
async function unbox<T>(pending: Promise<{ readonly value: T }>): Promise<T> {
  return (await pending).value
}

const held = {
  all: Promise.all,
  race: Promise.race,
  allSettled: Promise.allSettled,
  any: Promise.any
}

/** Replaces the four statics after load by functions that answer `forged`, as a host's flaw could. */
function forge(forged: unknown): void {
  for (const name of Object.keys(held) as (keyof typeof held)[])
    Reflect.set(Promise, name, () => held.all.call(Promise, [forged]).then(([value]) => value))
}

afterEach(() => {
  for (const name of Object.keys(held) as (keyof typeof held)[])
    Reflect.set(Promise, name, held[name])
  jest.useRealTimers()
  jest.restoreAllMocks()
})

describe('the statics of Promise replaced after the library loaded', () => {
  // Scenario: the plugin's calls reject and `Promise.race` answers a profile. Expected: still rejected.
  // Why: the answer of the plugin is what the login is made from.
  it('does not turn a plugin that rejected into a profile', async () => {
    forge('FORGED PROFILE')

    await expect(
      unbox(withDeadline(() => Promise.reject(new Error('the exchange failed')), 50))
    ).rejects.toThrow('the exchange failed')
  })

  // Scenario: a plugin that never answers, `Promise.race` forged. Expected: the deadline still ends the wait.
  it('still ends the wait at the deadline', async () => {
    jest.useFakeTimers()
    forge('FORGED PROFILE')
    const waiting = withDeadline(() => new Promise<never>(() => undefined), 1000)
    const outcome = expect(unbox(waiting)).rejects.toThrow(
      'the plugin did not answer within 1000 ms'
    )

    await jest.advanceTimersByTimeAsync(1000)

    await outcome
  })

  // Scenario: a user who is not a member, `Promise.all` answering an owner. Expected: denied.
  it('keeps a non-member denied', async () => {
    const options = resolveOptions({
      jwt: { secret: 'xY9!kL2@mN5#pQ8$rS1%tU4^vW7&zA0B' },
      roles: { hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] } },
      rateLimit: { clientIpSource: 'peer' },
      workspaces: {
        enabled: true,
        roles: { hierarchy: { owner: ['editor'], editor: [] }, ownerRole: 'owner' },
        membershipCacheTtlSeconds: 0
      }
    })
    const service = new WorkspaceAccessService(
      { eval: jest.fn() } as never,
      {
        findById: jest.fn().mockResolvedValue(workspaceRow({ id: 'w1', tenantId: 't1' }))
      } as never,
      { find: jest.fn().mockResolvedValue(null) } as never,
      options
    )
    const ref = { tenantId: 't1', workspaceId: 'w1', userId: 'attacker' }
    forge([
      workspaceRow({ id: 'w1', tenantId: 't1' }),
      { ...ref, role: 'owner', status: 'active', createdAt: new Date(0), updatedAt: new Date(0) }
    ])

    expect(await service.resolveAccess(ref)).toEqual({ kind: 'denied' })
  })

  // Scenario: an invitation for an address with no account, `Promise.all` answering an account. Expected: false.
  it('keeps the answer of a preview about the account', async () => {
    const h = build()
    await h.service.invite(WORKSPACE_REF, OWNER, 'a@example.com', 'viewer', CONTEXT)
    const token = sent(h).data.inviteToken
    forge([workspaceRow({ name: 'FORGED' }), user('inviter'), user('existing')])

    const answer = await h.service.preview(token)

    expect(answer).toMatchObject({ workspaceName: 'Acme', accountExists: false })
  })

  async function sessions(): Promise<{
    service: SessionService
    redis: { get: jest.Mock; del: jest.Mock; smembers: jest.Mock }
  }> {
    jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
    const redis = {
      get: jest.fn(),
      del: jest.fn(),
      srem: jest.fn(),
      smembers: jest.fn(),
      pruneExpiredGraceMembers: jest.fn().mockResolvedValue(0),
      pruneDeadMembers: jest.fn().mockResolvedValue(0)
    }
    const options = {
      hmacKey: 'k',
      jwt: { secret: 's', refreshExpiresInDays: 7 },
      sessions: { enabled: true, defaultMaxSessions: 2, evictionStrategy: 'fifo' }
    }
    const module = await Test.createTestingModule({
      providers: [
        SessionService,
        { provide: AuthRedisService, useValue: redis },
        { provide: BYMAX_AUTH_OPTIONS, useValue: options },
        { provide: GUARDED_USER_REPOSITORY, useValue: { findById: jest.fn() } },
        { provide: BYMAX_AUTH_HOOKS, useValue: { onSessionEvicted: jest.fn() } }
      ]
    }).compile()
    return { service: module.get(SessionService), redis }
  }

  const detail = (createdAt: number): string =>
    JSON.stringify({ device: 'd', ip: '1.1.1.1', createdAt, lastActivityAt: createdAt })

  // Scenario: one stored session, `Promise.all` answering another. Expected: the stored one is listed.
  it('lists the sessions the store holds', async () => {
    const { service, redis } = await sessions()
    const hash = sha256('stored')
    redis.smembers.mockResolvedValue([`rt:${hash}`])
    redis.get.mockResolvedValue(detail(5))
    forge([{ kind: 'session', info: { sessionHash: 'FORGED', createdAt: 1 } }])

    const listed = await service.listSessions({ userId: 'u', tenantId: 't' })

    expect(listed.map((session) => session.sessionHash)).toEqual([hash])
  })

  // Scenario: three sessions over a limit of two, `Promise.all` giving the oldest a new age. Expected: the oldest is evicted.
  it('evicts the session that is the oldest in the store', async () => {
    const { service, redis } = await sessions()
    const [oldest, middle, fresh] = [sha256('a'), sha256('b'), sha256('new')]
    redis.smembers.mockResolvedValue([`rt:${oldest}`, `rt:${middle}`, `rt:${fresh}`])
    redis.get.mockImplementation((key: string) =>
      Promise.resolve(detail(key === `sd:${oldest}` ? 1 : key === `sd:${middle}` ? 2 : 3))
    )
    forge([
      { member: `rt:${oldest}`, memberHash: oldest, createdAt: 999 },
      { member: `rt:${middle}`, memberHash: middle, createdAt: 2 },
      { member: `rt:${fresh}`, memberHash: fresh, createdAt: 3 }
    ])

    await service['enforceSessionLimit']('u', 't', fresh, 'ip', 'ua')

    expect(redis.del.mock.calls.map(([key]) => key)).toEqual([`rt:${oldest}`, `sd:${oldest}`])
  })
})

describe('a monitor that wraps then, with fake timers on', () => {
  // Scenario: `then` replaced by a function that delegates, as an APM does, and the clock faked. Expected: a plugin that answers
  // is answered, and one that does not is ended at the deadline. Why: the library must not refuse or hang for what a host's tools do.
  it('leaves the deadline as it was', async () => {
    jest.useFakeTimers()
    const then = Promise.prototype.then
    Promise.prototype.then = function delegating(this: Promise<unknown>, ...args: unknown[]) {
      return (then as (...a: unknown[]) => unknown).apply(this, args)
    } as typeof then
    try {
      const answered = (await withDeadline(() => Promise.resolve('profile'), 1000)).value
      const silent = withDeadline(() => new Promise<never>(() => undefined), 1000)
      const ended = expect(unbox(silent)).rejects.toThrow('the plugin did not answer')
      await jest.advanceTimersByTimeAsync(1000)
      await ended

      expect(answered).toBe('profile')
      expect(jest.getTimerCount()).toBe(0)
    } finally {
      Promise.prototype.then = then
    }
  })

  // Scenario: the same wrapper while a membership is read from two repositories. Expected: the member is answered.
  it('leaves the reads of a membership as they were', async () => {
    jest.useFakeTimers()
    const then = Promise.prototype.then
    Promise.prototype.then = function delegating(this: Promise<unknown>, ...args: unknown[]) {
      return (then as (...a: unknown[]) => unknown).apply(this, args)
    } as typeof then
    try {
      const options = resolveOptions({
        jwt: { secret: 'xY9!kL2@mN5#pQ8$rS1%tU4^vW7&zA0B' },
        roles: { hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] } },
        rateLimit: { clientIpSource: 'peer' },
        workspaces: {
          enabled: true,
          roles: { hierarchy: { owner: ['editor'], editor: [] }, ownerRole: 'owner' },
          membershipCacheTtlSeconds: 0
        }
      })
      const ref = { tenantId: 't1', workspaceId: 'w1', userId: 'u1' }
      const service = new WorkspaceAccessService(
        { eval: jest.fn() } as never,
        {
          findById: jest.fn().mockResolvedValue(workspaceRow({ id: 'w1', tenantId: 't1' }))
        } as never,
        {
          find: jest.fn().mockResolvedValue({
            ...ref,
            role: 'editor',
            status: 'active',
            invitedByUserId: null,
            createdAt: new Date(0),
            updatedAt: new Date(0)
          })
        } as never,
        options
      )

      expect(await service.resolveAccess(ref)).toEqual({
        kind: 'member',
        member: { ...ref, role: 'editor' }
      })
    } finally {
      Promise.prototype.then = then
    }
  })
})

describe('the constructor of a promise replaced after the library loaded', () => {
  // Scenario: `Promise.prototype.constructor` replaced. Expected: the root guard refuses with the 500 `auth.internal`.
  // Why: `await` reads it to decide whether a value is a native promise, so a replaced one chooses what every wait yields.
  it('is refused by the guard', () => {
    const own = Object.getOwnPropertyDescriptor(
      Promise.prototype,
      'constructor'
    ) as PropertyDescriptor
    Object.defineProperty(Promise.prototype, 'constructor', { ...own, value: function Other() {} })
    try {
      let refusal: unknown
      try {
        assertRootIsStandard()
      } catch (error) {
        refusal = error
      }

      expect(isRefusal(refusal)).toBe(true)
    } finally {
      Object.defineProperty(Promise.prototype, 'constructor', own)
    }
    expect(() => {
      assertRootIsStandard()
    }).not.toThrow()
  })
})
