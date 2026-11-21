/**
 * @fileoverview The boundary where the library reads what the host owns: the options factory and the records of
 * a repository. A failed read ends in the library's own error with the host's error as its `cause`, the copy of a
 * record keeps what the library reads by name and shows what a spread would have shown, and a guarded repository
 * keeps the host's own errors and lifecycle out of the way.
 *
 * @layer Test
 */

import { HttpException } from '@nestjs/common'

import {
  BYMAX_AUTH_API_KEY_REPOSITORY,
  BYMAX_AUTH_REDIS_CLIENT,
  BYMAX_AUTH_USER_REPOSITORY,
  GUARDED_API_KEY_REPOSITORY,
  GUARDED_USER_REPOSITORY
} from '../bymax-auth.constants'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { ErasedContract, ErasedRepositoryContract } from './repository-contracts'
import {
  callFactory,
  copyHostRecord,
  guardRepository,
  hostEntityOf,
  hostHasKey,
  readHostOptions,
  withGuardedViews
} from './host-read'

/** The host's own failure, with text a library error must never repeat. */
const fault = new Error('host-text-that-must-not-leak')

/** What the test repositories promise to answer: a record with an `id`, and nothing else. */
const RECORD: ErasedContract = { fields: { id: true }, nested: {} }

/** The promise of each method of the host fixture below. */
const ANSWERS: ErasedRepositoryContract = {
  find: RECORD,
  missing: RECORD,
  fail: 'value',
  typed: 'value',
  http: 'value',
  sync: 'value'
}

/** The code of an `AuthException`. */
const codeOf = (error: unknown): string =>
  ((error as AuthException).getResponse() as { error: { code: string } }).error.code

describe('readHostOptions', () => {
  // Scenario: a read that succeeds. Expected: its value. Why: the boundary adds nothing on the path with no failure.
  it('returns what the read returns', () => {
    expect(readHostOptions(() => 7)).toBe(7)
  })

  // Scenario: a getter of the host throws. Expected: the configuration error, the host's error as its cause, none of
  // its text in the message. Why: the host's error must not reach startup output as if the library wrote it.
  it('ends a host failure in the configuration error with the cause', () => {
    const attempt = (): void => {
      readHostOptions(() => {
        throw fault
      })
    }

    expect(attempt).toThrow(/^\[BymaxAuthModule\] the options could not be read/)
    try {
      attempt()
    } catch (error) {
      expect((error as Error).cause).toBe(fault)
      expect((error as Error).message).not.toContain(fault.message)
    }
  })

  // Scenario: the library's own refusal of a value, raised inside the read. Expected: the same error object. Why: the
  // refusals name the option and must reach the host as they are.
  it('passes the library refusals through untouched', () => {
    const refusal = new Error('[BymaxAuthModule] jwt.secret is too short')

    expect(() =>
      readHostOptions(() => {
        throw refusal
      })
    ).toThrow(refusal)
  })

  // Scenario: a thrown value that is not an Error. Expected: still the configuration error with it as the cause.
  it('wraps a thrown value that is not an Error', () => {
    try {
      readHostOptions(() => {
        throw 'plain'
      })
    } catch (error) {
      expect((error as Error).cause).toBe('plain')
      expect((error as Error).message).toMatch(/^\[BymaxAuthModule\]/)
    }
    expect.assertions(2)
  })
})

describe('callFactory', () => {
  // Scenario: a factory that answers. Expected: the answer inside a holder. Why: a promise resolved with a Proxy would
  // read its `then` once more outside the boundary, so the value travels in a plain object.
  it('returns the answer in a holder, for a sync and an async factory', async () => {
    await expect(callFactory(() => 1, [])).resolves.toEqual({ value: 1 })
    await expect(callFactory(async (a: number) => a + 1, [2] as never[])).resolves.toEqual({
      value: 3
    })
  })

  // Scenario: a factory that throws, rejects, or answers a thenable whose `then` throws. Expected: the configuration
  // error with the fault as the cause, for each.
  it.each([
    [
      'throws',
      () => {
        throw fault
      }
    ],
    ['rejects', async () => Promise.reject(fault)],
    [
      'answers a thenable that throws',
      () => ({
        then: () => {
          throw fault
        }
      })
    ]
  ])('ends a factory that %s in the configuration error', async (_label, factory) => {
    await expect(callFactory(factory as () => unknown, [])).rejects.toMatchObject({
      message: expect.stringMatching(
        /^\[BymaxAuthModule\] the options could not be read/
      ) as string,
      cause: fault
    })
  })

  // Scenario: a factory that raises the library's own refusal. Expected: that error, not a wrapper around it.
  it('passes a library refusal through', async () => {
    const refusal = new Error('[BymaxAuthModule] refused')

    await expect(callFactory(() => Promise.reject(refusal), [])).rejects.toBe(refusal)
  })
})

describe('hostHasKey', () => {
  // Scenario: an object with and without the key. Expected: true and false. A trap that throws is the configuration error.
  it('answers whether the key is there, inside the boundary', () => {
    expect(hostHasKey({ a: 1 }, 'a')).toBe(true)
    expect(hostHasKey({ a: 1 }, 'b')).toBe(false)
    const hostile = new Proxy(
      {},
      {
        has: () => {
          throw fault
        }
      }
    )
    expect(() => hostHasKey(hostile, 'a')).toThrow(/^\[BymaxAuthModule\]/)
  })
})

/** The typed errors a host repository throws on purpose, kept so a test can ask for those very instances. */
const typedErrors = {
  typed: new AuthException(AUTH_ERROR_CODES.EMAIL_ALREADY_EXISTS),
  http: new HttpException('conflict', 409)
}

describe('guardRepository', () => {
  const record = { id: 'u1' }
  const host = {
    note: 'plain member',
    calls: [] as string[],
    async find(id: string): Promise<unknown> {
      this.calls.push(id)
      return record
    },
    async missing(): Promise<null> {
      return null
    },
    async fail(): Promise<never> {
      throw fault
    },
    async typed(): Promise<never> {
      throw typedErrors.typed
    },
    http(): never {
      throw typedErrors.http
    },
    sync(): never {
      throw fault
    }
  }

  // Scenario: a method that answers a record. Expected: a copy, the call made on the host (its `this`), and members
  // that are not functions passed through. Why: the view must behave as the repository, only safer.
  it('answers a copy of the record from the host method, and passes plain members through', async () => {
    const guarded = guardRepository(host, ANSWERS)
    const answer = await guarded.find('a')

    expect(answer).toEqual(record)
    expect(answer).not.toBe(record)
    expect(host.calls).toEqual(['a'])
    expect(guarded.note).toBe('plain member')
    await expect(guarded.missing()).resolves.toBeNull()
  })

  // Scenario: a method whose contract is a plain value, a method the interface does not have, and a method promised to
  // answer a list that answers something else. Expected: the plain value comes back (a date as a copy), the extra
  // method's answer goes out as the host gave it, and the list that is no list ends in the internal error. Why: only
  // the answers of the methods of the interface are read, and one that breaks its promise is the host's failure.
  it('answers a value as a value, leaves an unpromised method alone and refuses a list that is no list', async () => {
    const when = new Date(5)
    const extra = { untouched: true }
    const guarded = guardRepository(
      {
        count: async (): Promise<unknown> => when,
        extra: async (): Promise<unknown> => extra,
        rows: async (): Promise<unknown> => ({ not: 'a list' })
      },
      { count: 'value', rows: { list: RECORD } }
    )

    const counted = (await guarded.count()) as Date

    expect(counted).not.toBe(when)
    expect(counted.getTime()).toBe(5)
    await expect(guarded.extra()).resolves.toBe(extra)
    await expect(guarded.rows()).rejects.toBeInstanceOf(AuthException)
  })

  // Scenario: the host rejects with an error that is a Proxy whose prototype read throws, so the test for a typed error
  // is itself a failed read of the host. Expected: the internal error with that error as its cause. Why: the check of
  // the error sits in the catch, where a throw would otherwise let the host's own error out.
  it('ends a rejection whose type cannot be read in the internal error with the cause', async () => {
    const hostile = new Proxy(new Error('hostile'), {
      getPrototypeOf: () => {
        throw fault
      }
    })
    const guarded = guardRepository(
      {
        async find(): Promise<never> {
          throw hostile
        }
      },
      { find: RECORD }
    )

    const error = (await guarded.find().catch((caught: unknown) => caught)) as AuthException

    expect(error).toBeInstanceOf(AuthException)
    expect(Object.is(error.cause, hostile)).toBe(true)
  })

  // Scenario: a method that rejects, or throws before it answers. Expected: the internal error with the cause.
  it.each([['fail'], ['sync']] as const)(
    'ends %s in the internal error with the cause',
    async (name) => {
      const guarded = guardRepository(host, ANSWERS)

      await expect(guarded[name]()).rejects.toMatchObject({ cause: fault })
      await expect(guarded[name]()).rejects.toBeInstanceOf(AuthException)
    }
  )

  // Scenario: the host throws a typed error on purpose (a conflict it maps). Expected: that very error.
  it.each([['typed'], ['http']] as const)(
    'lets the typed error of %s through, as the same instance',
    async (name) => {
      const guarded = guardRepository(host, ANSWERS)

      await expect(guarded[name]()).rejects.toBe(typedErrors[name])
    }
  )
})

describe('guardRepository against a hostile repository', () => {
  // Scenario: the repository is itself a Proxy and reading a method throws. Expected: the read does not throw; calling
  // the method rejects with the internal error and the fault as its cause. Why: the property read happens in the
  // service, outside any try, so a throwing read must become a rejection the service already handles.
  it('turns a throwing read of a method into an internal rejection with the cause', async () => {
    const hostile = new Proxy(
      {},
      {
        get: () => {
          throw fault
        }
      }
    )
    const guarded = guardRepository(hostile as { find(): Promise<unknown> }, ANSWERS)

    const read = (): Promise<unknown> => guarded.find()

    expect(() => guarded.find).not.toThrow()
    await expect(read()).rejects.toMatchObject({ cause: fault })
    await expect(read()).rejects.toBeInstanceOf(AuthException)
  })

  // Scenario: a repository whose methods are frozen own properties. Expected: the view still answers, with a copy. Why:
  // a proxy over the frozen object itself must return the exact original member for a non-configurable read-only
  // property, so the view is built over a separate target.
  it('wraps a repository whose own methods are frozen', async () => {
    const user = { id: 'u1' }
    const frozen = Object.freeze({ findById: async (): Promise<unknown> => user })
    const guarded = guardRepository(frozen, { findById: RECORD })

    const answer = await guarded.findById()

    expect(answer).toEqual(user)
    expect(answer).not.toBe(user)
  })

  // Scenario: a list answer that is a Proxy counting every trap, read through the guarded view and through the copy
  // alone. Expected: the same number of traps, and none after the copy finished. Why: a read of the host's list made
  // after the copy, such as one that links each copy to its entity, would sit outside the boundary that turns a host
  // failure into the internal error.
  it('reads the host list no more than the copy does', async () => {
    const counted = (): { rows: unknown[]; reads: () => number } => {
      let reads = 0
      const rows = new Proxy([{ id: 'u1' }, { id: 'u2' }], {
        get(target, key, receiver): unknown {
          reads += 1
          return Reflect.get(target, key, receiver)
        },
        has(target, key): boolean {
          reads += 1
          return Reflect.has(target, key)
        }
      })
      return { rows, reads: () => reads }
    }
    const alone = counted()
    copyHostRecord(await (async (): Promise<unknown> => alone.rows)(), { list: RECORD })
    const through = counted()
    const guarded = guardRepository(
      { find: async (): Promise<unknown> => through.rows },
      { find: { list: RECORD } }
    )

    await guarded.find()

    expect(through.reads()).toBe(alone.reads())
  })

  // Scenario: a hostile repository that throws for every key, awaited the way Nest awaits a factory result. Expected: the
  // await settles with the view. Why: `then` read as a function that never settles would hang startup.
  it('settles when the view of a repository that throws on every read is awaited', async () => {
    const hostile = new Proxy(
      {},
      {
        get: () => {
          throw fault
        }
      }
    )
    const view = guardRepository(hostile as { find(): Promise<unknown> }, ANSWERS)

    await expect(Promise.resolve(view)).resolves.toBe(view)
  })

  // Scenario: a repository with Nest lifecycle hooks. Expected: the view exposes none of them. Why: Nest calls a hook
  // on every provider instance it finds, and the guarded view is a second provider over the same repository, so
  // the host's hook would run twice.
  it.each([
    'onModuleInit',
    'onApplicationBootstrap',
    'onModuleDestroy',
    'beforeApplicationShutdown',
    'onApplicationShutdown'
  ])('does not expose the %s hook of the repository', (hook) => {
    const hooks = { [hook]: jest.fn(), find: jest.fn() }
    const guarded = guardRepository(hooks, ANSWERS) as Record<string, unknown>

    expect(guarded[hook]).toBeUndefined()
    expect(typeof guarded['find']).toBe('function')
  })
})

describe('hostEntityOf', () => {
  // Scenario: records the guarded view answered, and values it did not. Expected: the entity the host returned comes
  // back for the answer and for each record of a list; anything else comes back as it is. Why: code of the host (a
  // callback) is handed its own object, with its prototype getters and methods, while the library reads the copy.
  it('returns the entity behind an answer of the guarded view, and anything else as it is', async () => {
    class Entity {
      id = 'u1'
      get plan(): string {
        return 'pro'
      }
      isPro(): boolean {
        return true
      }
    }
    const entity = new Entity()
    const other = new Entity()
    const guarded = guardRepository(
      {
        one: async (): Promise<unknown> => entity,
        many: async (): Promise<unknown> => [entity, other],
        none: async (): Promise<unknown> => null
      },
      { one: RECORD, many: { list: RECORD }, none: RECORD }
    )

    const one = (await guarded.one()) as Entity
    const many = (await guarded.many()) as Entity[]
    const stranger = { id: 'x' }

    expect(one).not.toBe(entity)
    expect(hostEntityOf(one)).toBe(entity)
    expect(hostEntityOf(one).plan).toBe('pro')
    expect(hostEntityOf(one).isPro()).toBe(true)
    expect(hostEntityOf(many[0])).toBe(entity)
    expect(hostEntityOf(many[1])).toBe(other)
    expect(hostEntityOf(stranger)).toBe(stranger)
    expect(hostEntityOf(await guarded.none())).toBeNull()
    expect(hostEntityOf('text')).toBe('text')
  })
})

describe('withGuardedViews', () => {
  // Scenario: the host supplies the user and the API-key repositories and the Redis client. Expected: one guarded
  // provider per repository, on the internal token, built from the host's token; nothing for the client.
  it('adds a guarded provider for each repository the host supplied, and no other', () => {
    const plain = class Plain {}
    const host = [
      { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: {} },
      { provide: BYMAX_AUTH_API_KEY_REPOSITORY, useValue: {} },
      { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: {} },
      plain
    ]
    const providers = withGuardedViews(host)
    const added = providers.slice(host.length) as {
      provide: symbol
      inject: symbol[]
      useFactory: (h: object) => object
    }[]

    expect(providers.slice(0, host.length)).toEqual(host)
    expect(new Set(added.map((provider) => provider.provide))).toEqual(
      new Set([GUARDED_USER_REPOSITORY, GUARDED_API_KEY_REPOSITORY])
    )
    const user = added.find((provider) => provider.provide === GUARDED_USER_REPOSITORY)
    expect(user?.inject).toEqual([BYMAX_AUTH_USER_REPOSITORY])
    const repository = { find: async (): Promise<unknown> => ({ id: 1 }) }
    expect(user?.useFactory(repository)).not.toBe(repository)
  })

  // Scenario: the host supplies no repository. Expected: nothing.
  it('adds nothing when the host supplied no repository', () => {
    expect(withGuardedViews([])).toEqual([])
  })
})
