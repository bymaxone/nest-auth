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
import {
  callFactory,
  copyHostRecord,
  withGuardedViews,
  guardRepository,
  hostHasKey,
  readHostOptions
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
      throw new AuthException(AUTH_ERROR_CODES.EMAIL_ALREADY_EXISTS)
    },
    http(): never {
      throw new HttpException('x', 409)
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
  it.each([['typed'], ['http']] as const)('lets the typed error of %s through', async (name) => {
    const guarded = guardRepository(host)

    await expect(guarded[name]()).rejects.toBeInstanceOf(HttpException)
    await expect(guarded[name]()).rejects.not.toHaveProperty('cause', fault)
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
