/**
 * @fileoverview Tests for the `access.denied` emitter: one event per refusal, bounded per account
 * by a window, with the suppressed count carried to the next event that is emitted.
 *
 * @layer Test
 */

import { Logger } from '@nestjs/common'

import { WorkspaceDeniedEventsService } from './workspace-denied-events.service'
import type { WorkspaceEventsService } from './workspace-events.service'
import type { ResolvedOptions } from '../config/resolved-options'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { WorkspaceAccessRefusal } from '../errors/workspace-access-refusal'
import type { WorkspaceRefusalReason } from '../errors/workspace-access-refusal'
import { assertWorkspaceAccess } from '../utils/workspace-access-decision'
import type { AuthRedisService } from '../redis/auth-redis.service'

const REF = { tenantId: 't1', userId: 'u1', workspaceId: 'w1', surface: 'http' as const }

/** A counter store with real window expiry, advanced by the test. */
class FakeRedis {
  now = 0
  fail = false
  private readonly values = new Map<string, { value: number; expiresAt: number }>()

  incrWithFixedTtl(key: string, ttl: number): Promise<number> {
    return this.run(() => {
      const live = this.live(key)
      const value = (live?.value ?? 0) + 1
      this.values.set(key, { value, expiresAt: live?.expiresAt ?? this.now + ttl * 1000 })
      return value
    })
  }

  getdel(key: string): Promise<string | null> {
    return this.run(() => {
      const live = this.live(key)
      this.values.delete(key)
      return live === undefined ? null : String(live.value)
    })
  }

  keys(): string[] {
    return [...this.values.keys()]
  }

  ttlOf(key: string): number {
    return Math.round(((this.values.get(key)?.expiresAt ?? 0) - this.now) / 1000)
  }

  private live(key: string): { value: number; expiresAt: number } | undefined {
    const entry = this.values.get(key)
    return entry !== undefined && entry.expiresAt > this.now ? entry : undefined
  }

  private run<T>(body: () => T): Promise<T> {
    return this.fail ? Promise.reject(new Error('redis down')) : Promise.resolve(body())
  }
}

function build(group: { max: number; windowSeconds: number } | undefined = undefined) {
  const redis = new FakeRedis()
  const emit = jest.fn()
  const options = Object.assign({} as ResolvedOptions, {
    hmacKey: 'k'.repeat(32),
    workspaces: { accessDeniedEvents: group ?? { max: 10, windowSeconds: 60 } }
  })
  const service = new WorkspaceDeniedEventsService(
    { emit } as Partial<WorkspaceEventsService> as WorkspaceEventsService,
    redis as Partial<AuthRedisService> as AuthRedisService,
    options
  )
  return { service, redis, emit }
}

/** Lets the detached emission finish. */
const settle = (): Promise<void> => new Promise((resolve) => setImmediate(resolve))

function refuse(
  code: ConstructorParameters<
    typeof WorkspaceAccessRefusal
  >[0] = AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND,
  reason: WorkspaceRefusalReason = 'not_member'
): () => never {
  return () => {
    throw new WorkspaceAccessRefusal(code, reason)
  }
}

async function deny(
  service: WorkspaceDeniedEventsService,
  ref: Parameters<WorkspaceDeniedEventsService['admit']>[0] = REF
): Promise<void> {
  expect(() => service.admit(ref, refuse())).toThrow(AuthException)
  await settle()
}

describe('WorkspaceDeniedEventsService', () => {
  let warn: jest.SpyInstance

  beforeEach(() => {
    warn = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
    jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  it('returns what the decision returns and touches nothing for an allowed request', async () => {
    const { service, redis, emit } = build()

    expect(service.admit(REF, () => 'member')).toBe('member')
    await settle()

    expect(emit).not.toHaveBeenCalled()
    expect(redis.keys()).toEqual([])
  })

  it('emits one access.denied with the public code, the surface and no suppression', async () => {
    const { service, emit } = build()

    await deny(service)

    expect(emit).toHaveBeenCalledTimes(1)
    expect(emit.mock.calls[0]?.[0]).toMatchObject({
      type: 'access.denied',
      tenantId: 't1',
      workspaceId: 'w1',
      actorUserId: 'u1',
      userId: 'u1',
      surface: 'http',
      code: AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND,
      reason: 'not_member',
      suppressedCount: 0
    })
    expect(emit.mock.calls[0]?.[1]).toEqual({
      userId: 'u1',
      tenantId: 't1',
      plane: 'dashboard',
      ip: '',
      userAgent: '',
      sanitizedHeaders: {}
    })
  })

  it('rethrows the very exception the decision raised', () => {
    const { service } = build()
    const raised = new AuthException(AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE)

    expect(() =>
      service.admit(REF, () => {
        throw raised
      })
    ).toThrow(raised)
  })

  it.each([
    [AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND, 'not_member'],
    [AUTH_ERROR_CODES.WORKSPACE_PENDING_DELETION, 'pending_deletion'],
    [AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE, 'insufficient_role']
  ] as const)('emits the %s refusal under its own code and the reason %s', async (code, reason) => {
    const { service, emit } = build()

    expect(() => service.admit(REF, refuse(code, reason))).toThrow(AuthException)
    await settle()

    expect(emit.mock.calls[0]?.[0]).toMatchObject({ code, reason })
  })

  // The host is told what the caller is not: a non-owner member of a workspace pending deletion is
  // answered not found, like a stranger, and the event says why.
  it('reports pending_deletion under the not-found code for a non-owner, from the real decision', async () => {
    const { service, emit } = build()
    const decide = (): unknown =>
      assertWorkspaceAccess(
        { kind: 'denied', pendingDeletion: true },
        ['viewer'],
        { viewer: [] },
        false
      )

    expect(() => service.admit(REF, decide)).toThrow(AuthException)
    await settle()

    expect(emit.mock.calls[0]?.[0]).toMatchObject({
      code: AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND,
      reason: 'pending_deletion'
    })
  })

  it('reports a stranger of the same workspace as not_member under the same code', async () => {
    const { service, emit } = build()
    const decide = (): unknown =>
      assertWorkspaceAccess({ kind: 'denied' }, ['viewer'], { viewer: [] }, false)

    expect(() => service.admit(REF, decide)).toThrow(AuthException)
    await settle()

    expect(emit.mock.calls[0]?.[0]).toMatchObject({
      code: AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND,
      reason: 'not_member'
    })
  })

  it('does not emit for an error that is not a refusal of access', async () => {
    const { service, emit } = build()

    expect(() =>
      service.admit(REF, () => {
        throw new TypeError('bug')
      })
    ).toThrow(TypeError)
    await settle()

    expect(emit).not.toHaveBeenCalled()
  })

  it('does not emit for an auth error that is not a refusal of workspace access', async () => {
    const { service, emit } = build()

    expect(() =>
      service.admit(REF, () => {
        throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
      })
    ).toThrow(AuthException)
    await settle()

    expect(emit).not.toHaveBeenCalled()
  })

  it('suppresses the denial after the K-th in a window', async () => {
    const { service, emit } = build({ max: 3, windowSeconds: 60 })

    for (let i = 0; i < 4; i++) await deny(service)

    expect(emit).toHaveBeenCalledTimes(3)
  })

  it('carries the suppressed count to the next window after silence', async () => {
    const { service, redis, emit } = build({ max: 3, windowSeconds: 60 })
    for (let i = 0; i < 3 + 5; i++) await deny(service)
    expect(emit).toHaveBeenCalledTimes(3)

    redis.now += 61_000
    await deny(service)

    expect(emit).toHaveBeenCalledTimes(4)
    expect(emit.mock.calls[3]?.[0]).toMatchObject({ suppressedCount: 5 })
  })

  it('reports the count once: the event after it starts from zero', async () => {
    const { service, redis, emit } = build({ max: 1, windowSeconds: 60 })
    await deny(service)
    await deny(service)
    await deny(service)
    redis.now += 61_000
    await deny(service)
    await deny(service)
    redis.now += 61_000
    await deny(service)

    expect(
      emit.mock.calls.map((call) => (call[0] as { suppressedCount: number }).suppressedCount)
    ).toEqual([0, 2, 1])
  })

  it('keeps the suppressed count long after the window has ended', async () => {
    const { service, redis } = build({ max: 1, windowSeconds: 60 })
    await deny(service)
    await deny(service)

    const [window, suppressed] = [redis.keys()[0] as string, redis.keys()[1] as string]
    expect(redis.ttlOf(window)).toBe(60)
    expect(redis.ttlOf(suppressed)).toBe(86_400)
    expect(window).not.toBe(suppressed)
  })

  it('does not put the account identifiers into the keys', async () => {
    const { service, redis } = build({ max: 1, windowSeconds: 60 })
    await deny(service)
    await deny(service)

    for (const key of redis.keys()) {
      expect(key).not.toContain('u1')
      expect(key).not.toContain('t1')
    }
  })

  it('gives each user, and each tenant, its own budget', async () => {
    const { service, emit } = build({ max: 1, windowSeconds: 60 })

    await deny(service)
    await deny(service, { ...REF, userId: 'u2' })
    await deny(service, { ...REF, tenantId: 't2' })

    expect(emit).toHaveBeenCalledTimes(3)
  })

  it('does not mix two accounts whose identifiers join to the same text', async () => {
    const { service, emit } = build({ max: 1, windowSeconds: 60 })

    await deny(service, { ...REF, tenantId: 'a', userId: 'b:c' })
    await deny(service, { ...REF, tenantId: 'a:b', userId: 'c' })

    expect(emit).toHaveBeenCalledTimes(2)
  })

  it('shares one budget across the surfaces of the same account', async () => {
    const { service, emit } = build({ max: 2, windowSeconds: 60 })

    await deny(service, { ...REF, surface: 'http' })
    await deny(service, { ...REF, surface: 'ws' })
    await deny(service, { ...REF, surface: 'verifier' })

    expect(emit).toHaveBeenCalledTimes(2)
    expect(emit.mock.calls.map((call) => (call[0] as { surface: string }).surface)).toEqual([
      'http',
      'ws'
    ])
  })

  it('still refuses, emits nothing and warns once per window when Redis is down', async () => {
    const { service, redis, emit } = build({ max: 3, windowSeconds: 60 })
    redis.fail = true

    await deny(service)
    await deny(service)

    expect(emit).not.toHaveBeenCalled()
    expect(warn).toHaveBeenCalledTimes(1)
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('access.denied'))
  })

  it('warns again once the window has passed, and says nothing about the account', async () => {
    jest.useFakeTimers({ doNotFake: ['setImmediate'] })
    try {
      const { service, redis } = build({ max: 3, windowSeconds: 60 })
      redis.fail = true

      await deny(service)
      jest.advanceTimersByTime(59_000)
      await deny(service)
      jest.advanceTimersByTime(2_000)
      await deny(service)

      expect(warn).toHaveBeenCalledTimes(2)
      expect(String(warn.mock.calls[0]?.[0])).not.toMatch(/u1|t1|w1/)
    } finally {
      jest.useRealTimers()
    }
  })

  it('warns again at exactly the end of the window and not a moment before', async () => {
    jest.useFakeTimers({ doNotFake: ['setImmediate'] })
    try {
      const { service, redis } = build({ max: 3, windowSeconds: 60 })
      redis.fail = true

      await deny(service)
      jest.advanceTimersByTime(59_999)
      await deny(service)
      expect(warn).toHaveBeenCalledTimes(1)
      jest.advanceTimersByTime(1)
      await deny(service)

      expect(warn).toHaveBeenCalledTimes(2)
    } finally {
      jest.useRealTimers()
    }
  })

  it('answers the same when the hook throws, and does not wait for it', async () => {
    const { service, emit } = build()
    emit.mockImplementation(() => {
      throw new Error('hook broke')
    })

    await expect(deny(service)).resolves.toBeUndefined()

    expect(jest.mocked(Logger.prototype.error)).toHaveBeenCalledWith(
      expect.stringMatching(/^access\.denied was not reported: /)
    )
  })

  it('survives a failure while reading the suppressed count', async () => {
    const { service, redis, emit } = build({ max: 1, windowSeconds: 60 })
    jest.spyOn(redis, 'getdel').mockRejectedValue(new Error('redis down'))

    await deny(service)

    expect(emit).not.toHaveBeenCalled()
    expect(warn).toHaveBeenCalledTimes(1)
  })

  it('counts a denial past the limit even though nothing is emitted for it', async () => {
    const { service, redis } = build({ max: 1, windowSeconds: 60 })
    await deny(service)
    await deny(service)
    await deny(service)

    redis.now += 61_000

    expect(await redis.getdel(redis.keys().find((key) => key.startsWith('wads:')) as string)).toBe(
      '2'
    )
  })
})

describe('WorkspaceDeniedEventsService construction', () => {
  it('refuses to exist without the workspace group', () => {
    expect(
      () =>
        new WorkspaceDeniedEventsService(
          {} as WorkspaceEventsService,
          {} as AuthRedisService,
          {} as ResolvedOptions
        )
    ).toThrow('[BymaxAuthModule] WorkspaceDeniedEventsService needs workspaces.enabled.')
  })
})
