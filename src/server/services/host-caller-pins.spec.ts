/**
 * @fileoverview What the host's own `await` and the library's detached work still answer when a store or repository call plants a
 * one-shot accessor on `Promise.prototype.constructor` (or makes `Promise[Symbol.species]` throw once) while the library waits.
 * The host awaits what an exported service returns after the last statement of the service ran, so every public method is pinned;
 * detached work is an `async` function around a pinned `await`, so a throwing species neither rejects a decision untyped nor leaves
 * a failure unhandled; a promise that refuses the pin is refused as `auth.internal`; the constructor of `Promise` is read by its
 * descriptor; and `checked` looks through the whole chain of prototypes for a `then`.
 *
 * @layer Test
 */

import { Logger } from '@nestjs/common'
import type { CallHandler } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { ExecutionContextHost } from '@nestjs/core/helpers/execution-context-host'
import { lastValueFrom, of } from 'rxjs'

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthMetricsTally } from '../observability/auth-metrics-tally'
import { AuthTracing } from '../observability/auth-tracing'
import { AuthObservabilityInterceptor, ObserveAuth } from '../observability/observe-auth'
import { isRefusal } from '../utils/object-prototype-guard'
import { checked, pinned } from '../utils/settle'
import { resolveOptions } from '../config/resolved-options'
import { AuthRedisService } from '../redis/auth-redis.service'
import { BruteForceService } from './brute-force.service'
import { MfaFlowLockoutService } from './mfa-flow-lockout.service'
import { PasswordService } from './password.service'
import { ReauthenticationService } from './reauthentication.service'
import { WsTicketService } from './ws-ticket.service'

const proto = Promise.prototype as unknown as Record<string, unknown>
const ownConstructor = Object.getOwnPropertyDescriptor(
  Promise.prototype,
  'constructor'
) as PropertyDescriptor
const ownThen = Promise.prototype.then
const ownSpecies = Object.getOwnPropertyDescriptor(Promise, Symbol.species) as PropertyDescriptor

afterEach(() => {
  Object.defineProperty(Promise.prototype, 'constructor', ownConstructor)
  Object.defineProperty(Promise.prototype, 'then', {
    value: ownThen,
    writable: true,
    configurable: true
  })
  Object.defineProperty(Promise, Symbol.species, ownSpecies)
  jest.restoreAllMocks()
})

/** Plants what a host store call could: the first read of the constructor installs a one-shot `then` that answers `forgedValue`. */
function plant(forgedValue: unknown): void {
  Object.defineProperty(Promise.prototype, 'constructor', {
    configurable: true,
    get() {
      Object.defineProperty(Promise.prototype, 'constructor', ownConstructor)
      Object.defineProperty(proto, 'then', {
        configurable: true,
        writable: true,
        value(this: Promise<unknown>, resolve: (value: unknown) => void) {
          Object.defineProperty(proto, 'then', {
            configurable: true,
            writable: true,
            value: ownThen
          })
          ownThen.call(
            this,
            () => undefined,
            () => undefined
          )
          resolve(forgedValue)
        }
      })
      return function NotPromise() {}
    }
  })
}

/** Makes the next read of `Promise[Symbol.species]` throw, once, and puts the language's own back. */
function throwSpeciesOnce(): void {
  Object.defineProperty(Promise, Symbol.species, {
    configurable: true,
    get() {
      Object.defineProperty(Promise, Symbol.species, ownSpecies)
      throw new Error('species')
    }
  })
}

describe('the host awaits what an exported service returns', () => {
  // Scenario: a store call plants the one-shot accessor while the lockout is read, and the plant answers `false`. Expected: the
  // account is still reported locked out. Why: the host's `await` of the method is the first read of the planted constructor, so
  // an unpinned method hands the decision to the plant (C1, "bruteforce").
  it('keeps a locked account locked out', async () => {
    const redis = {
      get: jest.fn(() => {
        plant(false)
        return Promise.resolve('999')
      })
    }
    const options = { bruteForce: { maxAttempts: 5, windowSeconds: 60 }, hmacKey: 'k' }
    const service = new BruteForceService(redis as never, options as never)

    expect(await service.isLockedOut('victim')).toBe(true)
  })
  /** The options and a store the host controls, whose first `call` plants the accessor with `forged`. */
  function hostStore(call: 'get' | 'eval', forged: unknown) {
    const options = resolveOptions({
      jwt: { secret: 'xY9!kL2@mN5#pQ8$rS1%tU4^vW7&zA0B' },
      roles: { hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] } },
      rateLimit: { clientIpSource: 'peer' },
      password: { costFactor: 16384 }
    })
    let armed = false
    const arm = (): void => {
      if (armed) return
      armed = true
      plant(forged)
    }
    const host = {
      get: () => {
        if (call === 'get') arm()
        return Promise.resolve(null)
      },
      eval: () => {
        if (call === 'eval') arm()
        return Promise.resolve(call === 'eval' ? null : 1)
      },
      del: () => Promise.resolve(1),
      incr: () => Promise.resolve(1),
      ttl: () => Promise.resolve(-1)
    }
    return { options, redis: new AuthRedisService(host as never, options) }
  }

  // Scenario: a wrong password is re-proved while a store call plants the accessor, and the plant answers `undefined`. Expected: the
  // call never resolves as if the password were right (C1, "reauth"): it refuses, with the typed failure or the guard's refusal.
  it('does not accept a wrong password for the re-proof', async () => {
    const { options, redis } = hostStore('get', undefined)
    const password = new PasswordService(options, {
      isBreached: () => Promise.resolve(false)
    } as never)
    const hash = await password.hash('correct horse battery staple')
    const lockout = new MfaFlowLockoutService(options, new BruteForceService(redis, options))
    const reauth = new ReauthenticationService(options, redis, password, lockout)

    let outcome: string
    try {
      await reauth.assertReauthenticated('dashboard', 'u1', hash, 'WRONG-password', 't1', 'sid-1')
      outcome = 'resolved'
    } catch {
      outcome = 'refused'
    }

    expect(outcome).toBe('refused')
  })

  // Scenario: a ticket that was never issued is redeemed while a store call plants the accessor with a forged snapshot. Expected: the
  // forged snapshot is not handed back (C1, "wsticket").
  it('does not redeem a ticket that was never issued', async () => {
    const forgedSnapshot = { sub: 'admin', tenantId: 't1', role: 'ADMIN', jti: 'x', epoch: 0 }
    const { options, redis } = hostStore('eval', forgedSnapshot)
    const service = new WsTicketService(redis, options, {} as never, {} as never)

    let outcome: unknown
    try {
      outcome = await service.redeem('never-issued-ticket')
    } catch {
      outcome = 'refused'
    }

    expect(outcome).not.toEqual(forgedSnapshot)
  })
})

describe('detached work under a throwing species', () => {
  // Scenario: the species getter throws once while a session is created, and the repository rejects. Expected: the answer of
  // `createSession` is the one it would have given, and nothing is left unhandled. Why: a `.then` chain read the species itself
  // (C2), so the chain threw before it attached a handler.
  it('leaves the rejection of a detached lookup handled and typed', async () => {
    jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
    jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
    const unhandled: unknown[] = []
    const listener = (reason: unknown): void => {
      unhandled.push(reason)
    }
    process.on('unhandledRejection', listener)
    const { SessionService } = await import('./session.service')
    const { guardRepository } = await import('../utils/host-read')
    const { USER_REPOSITORY_CONTRACT } = await import('../utils/repository-contracts')
    const users = guardRepository(
      {
        findById: () => {
          throwSpeciesOnce()
          return Promise.reject(new Error('db down'))
        }
      } as never,
      USER_REPOSITORY_CONTRACT
    )
    const options = {
      hmacKey: 'k',
      jwt: { secret: 's', refreshExpiresInDays: 7 },
      sessions: { enabled: false, defaultMaxSessions: 5, evictionStrategy: 'fifo' }
    }
    const redis = {
      eval: jest.fn().mockResolvedValue(0),
      set: jest.fn().mockResolvedValue('OK'),
      get: jest.fn().mockResolvedValue(null),
      sadd: jest.fn().mockResolvedValue(1),
      smembers: jest.fn().mockResolvedValue([]),
      expire: jest.fn().mockResolvedValue(1),
      pruneExpiredGraceMembers: jest.fn().mockResolvedValue(0),
      pruneDeadMembers: jest.fn().mockResolvedValue(0)
    }
    const service = new SessionService(
      options as never,
      users as never,
      { onNewSession: () => undefined } as never,
      redis as never
    )

    let outcome: unknown
    try {
      outcome = await service.createSession({
        userId: 'u1',
        tenantId: 't1',
        rawRefreshToken: 'r'.repeat(40),
        ip: '1.2.3.4',
        userAgent: 'ua'
      } as never)
    } catch (error) {
      outcome = error
    }
    await new Promise((resolve) => setTimeout(resolve, 50))
    // The getter is one-shot: a library that never reads the species leaves it armed, and the framework would trip on it.
    Object.defineProperty(Promise, Symbol.species, ownSpecies)
    process.off('unhandledRejection', listener)

    expect(unhandled).toEqual([])
    expect(outcome instanceof Error && !(outcome instanceof AuthException)).toBe(false)
  })
})

describe('a promise that refuses the pin', () => {
  // Scenario: a frozen promise. Expected: refused as the typed `auth.internal`, not the engine's raw TypeError (C4).
  it('is refused as auth.internal', () => {
    const frozen = Object.freeze(Promise.resolve(1))
    let refusal: unknown
    try {
      pinned(frozen)
    } catch (error) {
      refusal = error
    }

    expect(refusal instanceof AuthException || isRefusal(refusal)).toBe(true)
    expect((refusal as AuthException).getResponse()).toMatchObject({
      error: { code: AUTH_ERROR_CODES.INTERNAL }
    })
  })
})

describe('the seams around a decision', () => {
  // Scenario: the operation plants the accessor, then answers. Expected: the span answers what the operation did or refuses, and never the forged value (C5).
  it('returns what the traced operation answered', async () => {
    const tracing = new AuthTracing()

    let answer: unknown
    try {
      answer = await tracing.span('auth.login' as never, {}, () => {
        plant('FORGED')
        return Promise.resolve('real')
      })
    } catch (error) {
      answer = error
    }

    expect(answer).not.toBe('FORGED')
    expect(answer === 'real' || isRefusal(answer)).toBe(true)
  })

  // Scenario: the handler plants the accessor, then answers, and rxjs would read `then` of the promise it was given. Expected: the
  // subscriber receives the handler's answer (C6).
  it('hands the interceptor the answer of the handler', async () => {
    class Probe {
      handle(): void {}
    }
    const descriptor = Object.getOwnPropertyDescriptor(
      Probe.prototype,
      'handle'
    ) as PropertyDescriptor
    ObserveAuth('login', 'dashboard')(Probe.prototype, 'handle', descriptor)
    const interceptor = new AuthObservabilityInterceptor(
      new Reflector(),
      new AuthMetricsTally(),
      new AuthTracing()
    )
    const next: CallHandler = {
      handle: () => {
        plant('FORGED')
        return of('real')
      }
    }

    let answer: unknown
    try {
      answer = await lastValueFrom(
        interceptor.intercept(new ExecutionContextHost([{}], Probe, Probe.prototype.handle), next)
      )
    } catch (error) {
      answer = error
    }

    expect(answer).not.toBe('FORGED')
    expect(answer === 'real' || isRefusal(answer)).toBe(true)
  })
})

describe('the constructor of Promise, read by its descriptor', () => {
  // Scenario: the module loads while the slot is an accessor. Expected: it refuses to start, without running the getter (C7).
  it('refuses to load over an accessor', () => {
    let ran = false
    Object.defineProperty(Promise.prototype, 'constructor', {
      configurable: true,
      get() {
        ran = true
        return ownConstructor.value
      }
    })

    expect(() => {
      jest.isolateModules(() => {
        require('../utils/captured-builtins')
      })
    }).toThrow()
    expect(ran).toBe(false)
  })
})

describe('checked looks through the chain of prototypes', () => {
  // Scenario: a `then` on the prototype of a class, and on the prototype of that prototype. Expected: `checked` refuses both, and
  // answers a plain object (C9).
  it('refuses a then held anywhere on the chain', () => {
    class Base {}
    class Dto extends Base {}
    ;(Base.prototype as unknown as Record<string, unknown>)['then'] = () => undefined

    expect(() => checked(new Dto())).toThrow(AuthException)
    expect(checked({ a: 1 })).toEqual({ a: 1 })
  })
})
