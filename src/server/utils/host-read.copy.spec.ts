/**
 * @fileoverview The copy of a record a repository returned: what a spread of the record shows, the fields the
 * library reads by name, the kinds passed on by reference, the bounds of the copy and the guarantees that a hidden
 * field stays hidden and a getter nobody asked for is never evaluated.
 *
 * @layer Test
 */

import { runInNewContext } from 'node:vm'

import { BYMAX_AUTH_REDIS_CLIENT, BYMAX_AUTH_USER_REPOSITORY } from '../bymax-auth.constants'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { ApiKeyPrincipal, AuthApiKey } from '../interfaces/api-key-repository.interface'
import type {
  MembershipPage,
  MembershipWithWorkspace,
  RemoveAllMembershipsResult
} from '../interfaces/membership-repository.interface'
import type { AuthPlatformUser } from '../interfaces/platform-user-repository.interface'
import type { AuthUser } from '../interfaces/user-repository.interface'
import type {
  AuthWorkspace,
  CreateWorkspaceResult
} from '../interfaces/workspace-repository.interface'
import { copyHostRecord, guardRepository, RECORD_FIELDS, withGuardedViews } from './host-read'

/** The host's own failure, with text a library error must never repeat. */
const fault = new Error('host-text-that-must-not-leak')

/** The code of an `AuthException`. */
const codeOf = (error: unknown): string =>
  ((error as AuthException).getResponse() as { error: { code: string } }).error.code

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

  // Scenario: an entity class with a getter on its prototype. Expected: the getter's value is readable by name on the
  // copy and is not enumerable. Why: a spread would lose it, and the library reads the field by name.
  it('keeps the value of an accessor a class defines on its prototype', () => {
    class Entity {
      id = 'e1'
      get label(): string {
        return 'computed'
      }
    }

    const copy = copyHostRecord(new Entity()) as Record<string, unknown>

    expect(copy['label']).toBe('computed')
    expect(copy).toEqual({ id: 'e1' })
  })

  // Scenario: an accessor inherited from a base class and an own property shadowing nothing. Expected: both read.
  it('reads accessors up the prototype chain', () => {
    class Base {
      get role(): string {
        return 'base'
      }
    }
    class Derived extends Base {
      id = 'd1'
    }

    const copy = copyHostRecord(new Derived()) as Record<string, unknown>

    expect(copy['role']).toBe('base')
    expect(copy['id']).toBe('d1')
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
  // without an own __proto__ key. Why: `instanceof` is false across realms, so a date from another realm has to be told
  // by its internal slot to keep its date semantics and its serialization.
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
    expect(Object.keys(copy)).toEqual([])
  })

  // Scenario: the result envelopes of the repositories (a page, the outcome of removing a user's memberships, of creating
  // a workspace) held on a prototype. Expected: every envelope field is found by name. Why: the services read
  // `page.items` and `outcome.result` the way they read a record's fields.
  it('finds the fields of the result envelopes by name when they live on a prototype', () => {
    const page = Object.create({ items: [{ id: 'w1' }], nextCursor: null }) as Record<
      string,
      unknown
    >
    const outcome = Object.create({ result: 'ok', removed: [], workspaceIds: ['w2'] }) as Record<
      string,
      unknown
    >

    const copied = copyHostRecord({ page, outcome }) as {
      page: Record<string, unknown>
      outcome: Record<string, unknown>
    }

    expect(copied.page['items']).toEqual([{ id: 'w1' }])
    expect(copied.page['nextCursor']).toBeNull()
    expect(copied.outcome['result']).toBe('ok')
    expect(copied.outcome['removed']).toEqual([])
    expect(copied.outcome['workspaceIds']).toEqual(['w2'])
  })

  it('covers every field of every record interface and result envelope in the by-name list', () => {
    type KeysOfUnion<T> = T extends unknown ? keyof T : never
    type Declared =
      | keyof AuthUser
      | keyof AuthPlatformUser
      | keyof AuthApiKey
      | keyof ApiKeyPrincipal
      | keyof AuthWorkspace
      | keyof MembershipWithWorkspace
      | keyof MembershipPage<unknown>
      | KeysOfUnion<RemoveAllMembershipsResult>
      | KeysOfUnion<CreateWorkspaceResult>
    const covered: Exclude<Declared, (typeof RECORD_FIELDS)[number]> extends never ? true : never =
      true

    expect(covered).toBe(true)
    expect(new Set(RECORD_FIELDS).size).toBe(RECORD_FIELDS.length)
  })

  // Scenario: a class whose prototype holds a shared handle (a model's connection, a class-level client) nested deeper
  // than the copy follows. Expected: the record is copied, the handle is left behind, and the listed fields that live
  // on the prototype still arrive. Why: copying the prototype's data would walk a connection graph per record and could
  // turn a valid lookup into an internal error.
  it('does not walk shared data held on a prototype, and still finds its listed fields', () => {
    let deep: Record<string, unknown> = { leaf: true }
    for (let level = 0; level < 20; level += 1) deep = { next: deep }
    class Doc {
      id = 'u1'
    }
    Object.assign(Doc.prototype, { connection: deep, mfaEnabled: true })

    const copy = copyHostRecord(new Doc()) as Record<string, unknown>

    expect(copy['id']).toBe('u1')
    expect(copy['mfaEnabled']).toBe(true)
    expect(copy['connection']).toBeUndefined()
  })

  // Scenario: the limits and shapes of the copy, each one a bound a mutant could move. Expected: a record nested exactly
  // at the limit is copied and one level deeper is refused with the library's text; arrays follow the same limit, are
  // copied to their length, and a cyclic array is copied once; a record with no prototype is copied; the descriptor of
  // a copied __proto__ key is a plain data property; a listed name that is a method is left behind; a getter of a
  // listed name is read once; a listed field nested past the limit is refused.
  describe('bounds of the copy', () => {
    const nest = (levels: number): Record<string, unknown> => {
      let value: Record<string, unknown> = { leaf: true }
      for (let level = 0; level < levels; level += 1) value = { next: value }
      return value
    }
    const causeOf = (thunk: () => unknown): unknown => {
      try {
        thunk()
      } catch (error) {
        return (error as { cause?: Error }).cause?.message
      }
      return undefined
    }

    it('copies a record nested exactly at the limit and refuses one level deeper, saying why', () => {
      expect(() => copyHostRecord(nest(16))).not.toThrow()
      expect(causeOf(() => copyHostRecord(nest(17)))).toBe(
        'the record nests deeper than the library follows'
      )
    })

    it('applies the limit to arrays, copies exactly their length and copies a cyclic array once', () => {
      let deep: unknown[] = [1]
      for (let level = 0; level < 20; level += 1) deep = [deep]
      const cyclic: unknown[] = [1, 2]
      cyclic.push(cyclic)

      const copy = copyHostRecord({ list: [1, 2], cyclic }) as {
        list: unknown[]
        cyclic: unknown[]
      }

      expect(causeOf(() => copyHostRecord({ deep }))).toBeDefined()
      expect(copy.list).toEqual([1, 2])
      expect(copy.list).toHaveLength(2)
      expect(copy.cyclic[2]).toBe(copy.cyclic)
    })

    it('copies a record that has no prototype', () => {
      const bare = Object.create(null) as Record<string, unknown>
      bare['id'] = 'u1'

      expect((copyHostRecord(bare) as Record<string, unknown>)['id']).toBe('u1')
    })

    it('defines a copied __proto__ key as a plain data property', () => {
      const copy = copyHostRecord(JSON.parse('{"meta":{"__proto__":1}}')) as { meta: object }

      expect(Object.getOwnPropertyDescriptor(copy.meta, '__proto__')).toEqual({
        value: 1,
        writable: true,
        enumerable: true,
        configurable: true
      })
    })

    it('keeps a field whose name is a setter on Object.prototype, own and listed alike', () => {
      Object.defineProperty(Object.prototype, 'zz', { set(): void {}, configurable: true })
      Object.defineProperty(Object.prototype, 'status', { set(): void {}, configurable: true })
      try {
        const copy = copyHostRecord({ zz: 1, id: 'u1', name: 'n' }) as Record<string, unknown>
        const lazy = copyHostRecord(
          new Proxy({}, { get: (_t, key) => (key === 'status' ? 'ACTIVE' : undefined) })
        ) as Record<string, unknown>

        expect(Object.hasOwn(copy, 'zz')).toBe(true)
        expect(Object.hasOwn(lazy, 'status')).toBe(true)
      } finally {
        Reflect.deleteProperty(Object.prototype, 'zz')
        Reflect.deleteProperty(Object.prototype, 'status')
      }
    })

    it('leaves a method behind even when it carries the name of a listed field', () => {
      class Doc {
        status(): string {
          return 'method'
        }
      }

      expect((copyHostRecord(new Doc()) as Record<string, unknown>)['status']).toBeUndefined()
    })

    it('reads the getter of a listed field once', () => {
      let reads = 0
      const record = {}
      Object.defineProperty(record, 'status', {
        get: () => {
          reads += 1
          return 'ACTIVE'
        },
        enumerable: true
      })

      copyHostRecord(record)

      expect(reads).toBe(1)
    })

    it('applies the limit to a listed field answered by name', () => {
      const lazy = new Proxy(
        {},
        { get: (_target, key) => (key === 'workspace' ? nest(16) : undefined) }
      )

      expect(causeOf(() => copyHostRecord(lazy))).toBe(
        'the record nests deeper than the library follows'
      )
    })

    it('answers undefined to a symbol read of a repository whose reads throw', () => {
      const hostile = new Proxy(
        {},
        {
          get: () => {
            throw fault
          }
        }
      )
      const view = guardRepository(hostile as { find(): Promise<unknown> })

      expect(Reflect.get(view, Symbol.iterator)).toBeUndefined()
    })

    it('does not take a class with a static provide for a token provider', () => {
      class Weird {
        static provide = BYMAX_AUTH_USER_REPOSITORY
      }

      expect(withGuardedViews([Weird as never])).toEqual([Weird])
    })

    it('adds no view when only unrelated providers are present', () => {
      const providers = [{ provide: BYMAX_AUTH_REDIS_CLIENT, useValue: {} }]

      expect(withGuardedViews(providers)).toEqual(providers)
    })
  })

  // Scenario: an entity with getters the library never reads (an unloaded relation, a computed view), one on the
  // prototype and one hidden on the instance, beside the fields it does read. Expected: the copy is made, the getters
  // are never evaluated, and the contract fields arrive. Why: evaluating a getter nobody asked for would fail every
  // lookup of an entity whose relation is not loaded.
  it('never evaluates a getter the library does not read', () => {
    let evaluated = 0
    class Entity {
      id = 'u1'
      get status(): string {
        return 'ACTIVE'
      }
      get unloadedRelation(): string {
        evaluated += 1
        throw new Error('relation not loaded')
      }
    }
    const entity = new Entity()
    Object.defineProperty(entity, 'hiddenRelation', {
      get: () => {
        evaluated += 1
        throw new Error('relation not loaded')
      },
      enumerable: false
    })

    const copy = copyHostRecord(entity) as Record<string, unknown>

    expect(copy['id']).toBe('u1')
    expect(copy['status']).toBe('ACTIVE')
    expect(evaluated).toBe(0)
  })

  // Scenario: a record whose hidden fields must stay hidden: a non-enumerable backing object, a non-enumerable auth
  // field and an inherited accessor of a contract field. Expected: the contract fields are readable by name, the backing
  // object is not copied at all, and none is enumerable, so a spread, Object.keys or JSON.stringify of the copy shows
  // what the host's record showed. Why: the services strip a few credential fields from a spread of the record, and a
  // hidden field made visible would reach the response.
  it('keeps hidden fields hidden from a spread while still readable by name', () => {
    class Doc {
      id = 'u1'
      get role(): string {
        return 'user'
      }
    }
    const record = new Doc()
    Object.defineProperty(record, '_credentials', {
      value: { passwordHash: 'hash', mfaSecret: 'enc' },
      enumerable: false
    })
    Object.defineProperty(record, 'status', { value: 'ACTIVE', enumerable: false })

    const copy = copyHostRecord(record) as Record<string, unknown>

    expect(copy['status']).toBe('ACTIVE')
    expect(copy['role']).toBe('user')
    expect(copy['_credentials']).toBeUndefined()
    expect(Object.keys(copy)).toEqual(['id'])
    expect(Object.keys({ ...copy })).toEqual(['id'])
    expect(JSON.stringify(copy)).toBe('{"id":"u1"}')
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
