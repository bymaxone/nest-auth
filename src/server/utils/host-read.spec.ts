import { runInNewContext } from 'node:vm'

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
import type { ApiKeyPrincipal, AuthApiKey } from '../interfaces/api-key-repository.interface'
import type { MembershipWithWorkspace } from '../interfaces/membership-repository.interface'
import type { AuthPlatformUser } from '../interfaces/platform-user-repository.interface'
import type { AuthUser } from '../interfaces/user-repository.interface'
import type { AuthWorkspace } from '../interfaces/workspace-repository.interface'
import {
  callFactory,
  copyHostRecord,
  withGuardedViews,
  guardRepository,
  hostHasKey,
  readHostOptions,
  RECORD_FIELDS
} from './host-read'

/** The host's own failure, with text a library error must never repeat. */
const fault = new Error('host-text-that-must-not-leak')

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

describe('copyHostRecord', () => {
  // Scenario: values that are not objects. Expected: returned as they are.
  it.each([[null], [undefined], [3], ['text'], [true]])('returns %p as it is', (value) => {
    expect(copyHostRecord(value)).toBe(value)
  })

  // Scenario: a record with nested data. Expected: an equal copy sharing nothing mutable with the original.
  it('copies a record, its nested objects and its arrays', () => {
    const record = { id: 'u', nested: { list: ['a', { b: 1 }] }, at: new Date(5) }
    const copy = copyHostRecord(record) as typeof record

    expect(copy).toEqual(record)
    expect(copy).not.toBe(record)
    expect(copy.nested).not.toBe(record.nested)
    expect(copy.nested.list).not.toBe(record.nested.list)
    expect(copy.nested.list[1]).not.toBe(record.nested.list[1])
    expect(copy.at).not.toBe(record.at)
    expect(copy.at.getTime()).toBe(5)
  })

  // Scenario: an entity class with a getter on its prototype. Expected: the getter's value is in the copy. Why: a
  // spread would lose it, and the library reads the field by name.
  it('keeps the value of an accessor a class defines on its prototype', () => {
    class Entity {
      id = 'e1'
      get label(): string {
        return 'computed'
      }
    }

    expect(copyHostRecord(new Entity())).toEqual({ id: 'e1', label: 'computed' })
  })

  // Scenario: an accessor inherited from a base class and an own property shadowing nothing. Expected: both read.
  it('reads accessors up the prototype chain', () => {
    class Base {
      get kind(): string {
        return 'base'
      }
    }
    class Derived extends Base {
      id = 'd1'
    }

    expect(copyHostRecord(new Derived())).toEqual({ id: 'd1', kind: 'base' })
  })

  // Scenario: values that are not data. Expected: passed on as they are, not copied into plain objects.
  it('passes opaque values through by reference', () => {
    const map = new Map([['k', 1]])
    const bytes = new Uint8Array([1, 2])
    const url = new URL('https://a.example')
    const record = copyHostRecord({ map, bytes, url, fn: copyHostRecord }) as Record<
      string,
      unknown
    >

    expect(record['map']).toBe(map)
    expect(record['bytes']).toBe(bytes)
    expect(record['url']).toBe(url)
    expect(record['fn']).toBe(copyHostRecord)
  })

  // Scenario: the fields an auth decision reads, held as non-enumerable own properties, one as a getter. Expected: each
  // survives the copy with its value. Why: a copy that lists only enumerable keys would drop `status` or
  // `mfaEnabled`, and the decision would read undefined.
  it('keeps non-enumerable own fields, data and getter alike', () => {
    const record = { id: 'u1' }
    Object.defineProperty(record, 'passwordHash', { value: 'hash', enumerable: false })
    Object.defineProperty(record, 'status', { get: () => 'ACTIVE', enumerable: false })
    Object.defineProperty(record, 'mfaEnabled', { value: true, enumerable: false })

    const copy = copyHostRecord(record) as Record<string, unknown>

    expect(copy['passwordHash']).toBe('hash')
    expect(copy['status']).toBe('ACTIVE')
    expect(copy['mfaEnabled']).toBe(true)
    expect(copy['id']).toBe('u1')
  })

  // Scenario: values made in another realm (a vm context, which is what a test runner or a driver bundle can hand
  // over). Expected: a date is still a date, a map stays a map by reference, and a plain object from there is copied
  // without an own __proto__ key. Why: `instanceof` is false across realms, so such a date was copied as an object that
  // holds the prototype of its realm, and the response that carried it failed to serialize.
  it('treats values from another realm as the kinds they are', () => {
    const foreign = <T>(source: string): T => runInNewContext(source) as T
    const date = foreign<Date>('new Date(5)')
    const map = foreign<Map<string, number>>('new Map([["a", 1]])')
    const plain = foreign<Record<string, number>>('({ a: 1 })')

    const copy = copyHostRecord({ date, map, plain }) as {
      date: Date
      map: unknown
      plain: Record<string, number>
    }

    expect(JSON.stringify(copy.date)).toBe(JSON.stringify(new Date(5)))
    expect(copy.date.getTime()).toBe(5)
    expect(copy.map).toBe(map)
    expect(Object.getOwnPropertyNames(copy.plain)).toEqual(['a'])
    expect(JSON.stringify(copy)).toContain('"a":1')
  })

  // Scenario: a record whose auth state lives on its prototype, as a class default or an Object.create base does.
  // Expected: the inherited data fields survive the copy, an own field shadows an inherited one, and the inherited
  // methods are not copied. Why: dropping `mfaEnabled` would let a login skip the challenge.
  it('keeps inherited data fields, lets an own field shadow them, and leaves methods behind', () => {
    class Base {
      mfaEnabled = true
      status = 'ACTIVE'
      describe(): string {
        return 'method'
      }
    }
    const proto = { role: 'admin', mfaEnabled: true, helper: (): string => 'fn' }
    const record = Object.assign(Object.create(proto) as Record<string, unknown>, {
      id: 'u1',
      role: 'user'
    })
    Object.defineProperty(Base.prototype, 'tenantId', { value: 't1', enumerable: false })

    const fromClass = copyHostRecord(new Base()) as Record<string, unknown>
    const copy = copyHostRecord(record) as Record<string, unknown>

    expect(copy['mfaEnabled']).toBe(true)
    expect(copy['role']).toBe('user')
    expect(copy['id']).toBe('u1')
    expect(copy['helper']).toBeUndefined()
    expect(fromClass['tenantId']).toBe('t1')
    expect(fromClass['describe']).toBeUndefined()
  })

  // Scenario: a record that answers by name and lists nothing (a lazy entity or a Proxy with only a get trap). Expected:
  // every field of the record interfaces is still read by name, and the list covers each interface. Why: no
  // enumeration can find a field the object never lists, and the services read `user.mfaEnabled`, not a key list.
  it('reads the fields of the record interfaces by name from an object that lists none', () => {
    const answers: Record<string, unknown> = {
      mfaEnabled: true,
      status: 'ACTIVE',
      passwordHash: 'h'
    }
    const lazy = new Proxy({}, { get: (_target, key) => answers[String(key)] })

    const copy = copyHostRecord(lazy) as Record<string, unknown>

    expect(copy['mfaEnabled']).toBe(true)
    expect(copy['status']).toBe('ACTIVE')
    expect(copy['passwordHash']).toBe('h')
    expect(Object.keys(copy).sort()).toEqual(['mfaEnabled', 'passwordHash', 'status'])
  })

  it('covers every field of every record interface in the by-name list', () => {
    type Declared =
      | keyof AuthUser
      | keyof AuthPlatformUser
      | keyof AuthApiKey
      | keyof ApiKeyPrincipal
      | keyof AuthWorkspace
      | keyof MembershipWithWorkspace
    const covered: Exclude<Declared, (typeof RECORD_FIELDS)[number]> extends never ? true : never =
      true

    expect(covered).toBe(true)
    expect(new Set(RECORD_FIELDS).size).toBe(RECORD_FIELDS.length)
  })

  // Scenario: a record with an own key named __proto__ (what JSON.parse of user input produces). Expected: it stays an
  // own key of the copy and the copy's prototype is untouched. Why: assigning it would swap the copy's prototype for the
  // copied value, and the copy would inherit names the original did not own.
  it('keeps a __proto__ key an own property and does not change the prototype of the copy', () => {
    const record = JSON.parse('{"meta":{"__proto__":{"role":"ADMIN"},"a":1}}') as object
    const copy = copyHostRecord(record) as { meta: Record<string, unknown> }

    expect(Object.getPrototypeOf(copy.meta)).toBe(Object.prototype)
    expect(Object.keys(copy.meta)).toContain('__proto__')
    expect(copy.meta['role']).toBeUndefined()
  })

  // Scenario: a record that holds itself. Expected: one copy that holds itself, not a stack overflow.
  it('copies a cycle once', () => {
    const record: { self?: unknown } = {}
    record.self = record
    const copy = copyHostRecord(record) as { self?: unknown }

    expect(copy.self).toBe(copy)
    expect(copy).not.toBe(record)
  })

  // Scenario: a record nested deeper than the library follows. Expected: the internal error, not a crash.
  it('refuses a record nested past the limit as an internal error', () => {
    let deep: Record<string, unknown> = {}
    for (let level = 0; level < 20; level += 1) deep = { next: deep }

    expect.assertions(2)
    try {
      copyHostRecord(deep)
    } catch (error) {
      expect(codeOf(error)).toBe(AUTH_ERROR_CODES.INTERNAL)
      expect((error as Error).cause).toBeInstanceOf(Error)
    }
  })

  // Scenario: a getter that throws. Expected: the internal error with the fault as the cause and none of its text.
  it('ends a getter that throws in the internal error with the cause', () => {
    const record = {
      get id(): string {
        throw fault
      }
    }

    expect.assertions(3)
    try {
      copyHostRecord(record)
    } catch (error) {
      expect(codeOf(error)).toBe(AUTH_ERROR_CODES.INTERNAL)
      expect((error as Error).cause).toBe(fault)
      expect(JSON.stringify((error as AuthException).getResponse())).not.toContain(fault.message)
    }
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
    const guarded = guardRepository(host)
    const answer = await guarded.find('a')

    expect(answer).toEqual(record)
    expect(answer).not.toBe(record)
    expect(host.calls).toEqual(['a'])
    expect(guarded.note).toBe('plain member')
    await expect(guarded.missing()).resolves.toBeNull()
  })

  // Scenario: a method that rejects, or throws before it answers. Expected: the internal error with the cause.
  it.each([['fail'], ['sync']] as const)(
    'ends %s in the internal error with the cause',
    async (name) => {
      const guarded = guardRepository(host)

      await expect(guarded[name]()).rejects.toMatchObject({ cause: fault })
      await expect(guarded[name]()).rejects.toBeInstanceOf(AuthException)
    }
  )

  // Scenario: the host throws a typed error on purpose (a conflict it maps). Expected: that very error.
  it.each([['typed'], ['http']] as const)(
    'lets the typed error of %s through, as the same instance',
    async (name) => {
      const guarded = guardRepository(host)

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
    const guarded = guardRepository(hostile as { find(): Promise<unknown> })

    const read = (): Promise<unknown> => guarded.find()

    expect(() => guarded.find).not.toThrow()
    await expect(read()).rejects.toMatchObject({ cause: fault })
    await expect(read()).rejects.toBeInstanceOf(AuthException)
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
    const view = guardRepository(hostile as { find(): Promise<unknown> })

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
    const guarded = guardRepository(hooks) as Record<string, unknown>

    expect(guarded[hook]).toBeUndefined()
    expect(typeof guarded['find']).toBe('function')
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
