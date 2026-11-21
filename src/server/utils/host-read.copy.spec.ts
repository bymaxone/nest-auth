/**
 * @fileoverview The copy of an answer a repository returned: what a spread of the record shows, the fields its
 * contract names read by name, the kinds passed on by reference, the bounds of the copy and the guarantees that a hidden
 * field stays hidden and a field the contract does not name is never read.
 *
 * @layer Test
 */

import { runInNewContext } from 'node:vm'

import { BYMAX_AUTH_REDIS_CLIENT, BYMAX_AUTH_USER_REPOSITORY } from '../bymax-auth.constants'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { copyHostRecord, guardRepository, withGuardedViews } from './host-read'
import {
  API_KEY_REPOSITORY_CONTRACT,
  MEMBERSHIP_REPOSITORY_CONTRACT,
  USER_REPOSITORY_CONTRACT,
  WORKSPACE_REPOSITORY_CONTRACT
} from './repository-contracts'

/** The host's own failure, with text a library error must never repeat. */
const fault = new Error('host-text-that-must-not-leak')

/** The code of an `AuthException`. */
const codeOf = (error: unknown): string =>
  ((error as AuthException).getResponse() as { error: { code: string } }).error.code

/** What a record of the user repository is read for. */
const USER = USER_REPOSITORY_CONTRACT.findById

/** What a page of the memberships of a user, each with its workspace, is read for. */
const PAGE = MEMBERSHIP_REPOSITORY_CONTRACT.listForUser

describe('copyHostRecord', () => {
  // Scenario: values that are not objects. Expected: returned as they are.
  it.each([[null], [undefined], [3], ['text'], [true]])('returns %p as it is', (value) => {
    expect(copyHostRecord(value, USER)).toBe(value)
  })

  // Scenario: a page of memberships with their workspaces, the nested records and the dates among its fields.
  // Expected: an equal copy sharing nothing mutable with the original. Why: the library reads these fields, so what
  // it reads must not change under it.
  it('copies a record, its nested records and its arrays', () => {
    const membership = {
      tenantId: 't1',
      workspaceId: 'w1',
      userId: 'u1',
      role: 'ADMIN',
      status: 'ACTIVE',
      invitedByUserId: null,
      createdAt: new Date(6),
      updatedAt: new Date(7),
      workspace: {
        id: 'w1',
        tenantId: 't1',
        name: 'W',
        status: 'ACTIVE',
        createdAt: new Date(5),
        deletionScheduledAt: null
      }
    }
    const page = { items: [membership], nextCursor: null }
    const copy = copyHostRecord(page, PAGE) as typeof page

    expect(copy).toEqual(page)
    expect(copy).not.toBe(page)
    expect(copy.items).not.toBe(page.items)
    expect(copy.items[0]).not.toBe(membership)
    expect(copy.items[0]?.workspace).not.toBe(membership.workspace)
    expect(copy.items[0]?.workspace.createdAt).not.toBe(membership.workspace.createdAt)
    expect(copy.items[0]?.workspace.createdAt.getTime()).toBe(5)
  })

  // Scenario: an entity class with a getter on its prototype. Expected: the getter's value is readable by name on the
  // copy and is not enumerable. Why: a spread would lose it, and the library reads the field by name.
  it('keeps the value of an accessor a class defines on its prototype', () => {
    class Entity {
      id = 'e1'
      get email(): string {
        return 'computed'
      }
    }

    const copy = copyHostRecord(new Entity(), USER) as Record<string, unknown>

    expect(copy['email']).toBe('computed')
    expect(copy).toEqual({ id: 'e1', email: 'computed' })
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

    const copy = copyHostRecord(new Derived(), USER) as Record<string, unknown>

    expect(copy['role']).toBe('base')
    expect(copy['id']).toBe('d1')
  })

  // Scenario: values that are not data, held by fields of the contract and by a field of the host's own. Expected:
  // passed on as they are, not copied into plain objects.
  it('passes opaque values through by reference', () => {
    const map = new Map([['k', 1]])
    const bytes = new Uint8Array([1, 2])
    const url = new URL('https://a.example')
    const record = copyHostRecord(
      { lastLoginAt: map, mfaRecoveryCodes: bytes, oauthProvider: url, fn: copyHostRecord },
      USER
    ) as Record<string, unknown>

    expect(record['lastLoginAt']).toBe(map)
    expect(record['mfaRecoveryCodes']).toBe(bytes)
    expect(record['oauthProvider']).toBe(url)
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

    const copy = copyHostRecord(record, USER) as Record<string, unknown>

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

    const copy = copyHostRecord({ createdAt: date, lastLoginAt: map, name: plain }, USER) as {
      createdAt: Date
      lastLoginAt: unknown
      name: Record<string, number>
    }

    expect(JSON.stringify(copy.createdAt)).toBe(JSON.stringify(new Date(5)))
    expect(copy.createdAt.getTime()).toBe(5)
    expect(copy.lastLoginAt).toBe(map)
    expect(Object.getOwnPropertyNames(copy.name)).toEqual(['a'])
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

    const fromClass = copyHostRecord(new Base(), USER) as Record<string, unknown>
    const copy = copyHostRecord(record, USER) as Record<string, unknown>

    expect(copy['mfaEnabled']).toBe(true)
    expect(copy['role']).toBe('user')
    expect(copy['id']).toBe('u1')
    expect(copy['helper']).toBeUndefined()
    expect(fromClass['tenantId']).toBe('t1')
    expect(fromClass['describe']).toBeUndefined()
  })

  // Scenario: a record that answers by name and lists nothing (a lazy entity or a Proxy with only a get trap). Expected:
  // every field of the contract is still read by name. Why: no enumeration can find a field the object never lists,
  // and the services read `user.mfaEnabled`, not a key list.
  it('reads the fields of the contract by name from an object that lists none', () => {
    const answers: Record<string, unknown> = {
      mfaEnabled: true,
      status: 'ACTIVE',
      passwordHash: 'h'
    }
    const lazy = new Proxy({}, { get: (_target, key) => answers[String(key)] })

    const copy = copyHostRecord(lazy, USER) as Record<string, unknown>

    expect(copy['mfaEnabled']).toBe(true)
    expect(copy['status']).toBe('ACTIVE')
    expect(copy['passwordHash']).toBe('h')
    expect(Object.keys(copy)).toEqual(['status', 'mfaEnabled'])
  })

  // Scenario: the result envelopes of the repositories (a page, the outcome of removing a user's memberships) held on
  // a prototype. Expected: every envelope field of the contract is found by name, and the records among them are
  // copied by their own contract. Why: the services read `page.items` and `outcome.result` the way they read a
  // record's fields.
  it('finds the fields of the result envelopes by name when they live on a prototype', () => {
    const page = Object.create({ items: [], nextCursor: 'c' }) as object
    const outcome = Object.create({
      result: 'ok',
      removed: [{ workspaceId: 'w1', role: 'MEMBER' }],
      workspaceIds: ['w2']
    }) as object

    const pageCopy = copyHostRecord(page, PAGE) as Record<string, unknown>
    const outcomeCopy = copyHostRecord(
      outcome,
      MEMBERSHIP_REPOSITORY_CONTRACT.removeAllForUser
    ) as Record<string, unknown>

    expect(pageCopy['items']).toEqual([])
    expect(pageCopy['nextCursor']).toBe('c')
    expect(outcomeCopy['result']).toBe('ok')
    expect(outcomeCopy['removed']).toEqual([{ workspaceId: 'w1', role: 'MEMBER' }])
    expect(outcomeCopy['workspaceIds']).toEqual(['w2'])
  })

  // Scenario: a class whose prototype holds a shared handle (a model's connection, a class-level client) nested deeper
  // than the copy follows. Expected: the record is copied, the handle is left behind, and the fields of the contract
  // that live on the prototype still arrive. Why: copying the prototype's data would walk a connection graph per record
  // and could turn a valid lookup into an internal error.
  it('does not walk shared data held on a prototype, and still finds the fields of the contract', () => {
    let deep: Record<string, unknown> = { leaf: true }
    for (let level = 0; level < 20; level += 1) deep = { next: deep }
    class Doc {
      id = 'u1'
    }
    Object.assign(Doc.prototype, { connection: deep, mfaEnabled: true })

    const copy = copyHostRecord(new Doc(), USER) as Record<string, unknown>

    expect(copy['id']).toBe('u1')
    expect(copy['mfaEnabled']).toBe(true)
    expect(copy['connection']).toBeUndefined()
  })

  // Scenario: the limits and shapes of the copy, each one a bound a mutant could move. Expected: a value nested exactly
  // at the limit is copied and one level deeper is refused with the library's text; arrays follow the same limit, are
  // copied to their length, and a cyclic array is copied once; a record with no prototype is copied; the descriptor of
  // a copied __proto__ key is a plain data property; a name of the contract that is a method is left behind; a getter
  // of a field of the contract is read once; a field of the contract nested past the limit is refused.
  describe('bounds of the copy', () => {
    const timeAs = (answer: unknown): Date =>
      new Proxy(new Date(0), {
        get: (target, key) => {
          if (key === 'getTime') return () => answer
          const member: unknown = Reflect.get(target, key, target)
          return typeof member === 'function' ? member.bind(target) : member
        }
      })
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
      expect(() => copyHostRecord({ name: nest(15) }, USER)).not.toThrow()
      expect(causeOf(() => copyHostRecord({ name: nest(16) }, USER))).toBe(
        'the record nests deeper than the library follows'
      )
    })

    it('applies the limit to arrays, copies exactly their length and copies a cyclic array once', () => {
      let deep: unknown[] = [1]
      for (let level = 0; level < 20; level += 1) deep = [deep]
      const cyclic: unknown[] = [1, 2]
      cyclic.push(cyclic)

      const copy = copyHostRecord({ mfaRecoveryCodes: cyclic, oauthProvider: [1, 2] }, USER) as {
        oauthProvider: unknown[]
        mfaRecoveryCodes: unknown[]
      }

      expect(causeOf(() => copyHostRecord({ mfaRecoveryCodes: deep }, USER))).toBeDefined()
      expect(copy.oauthProvider).toEqual([1, 2])
      expect(copy.oauthProvider).toHaveLength(2)
      expect(copy.mfaRecoveryCodes[2]).toBe(copy.mfaRecoveryCodes)
    })

    // The path of a page is four contract levels deep before the data starts, so the limit applies to what is left.
    it('applies the limit along the path of a page, down to a value of its workspace', () => {
      const pageWith = (levels: number): unknown => ({
        items: [{ workspace: { name: nest(levels) } }],
        nextCursor: null
      })

      expect(() => copyHostRecord(pageWith(12), PAGE)).not.toThrow()
      expect(causeOf(() => copyHostRecord(pageWith(13), PAGE))).toBe(
        'the record nests deeper than the library follows'
      )
    })

    it('copies a list of records to exactly its length, and what is reached twice under one contract once', () => {
      const row = { id: 'a' }
      const inner = [row]
      const rows = [row, { id: 'b' }, row]

      const copy = copyHostRecord(rows, { list: USER }) as unknown[]
      const nested = copyHostRecord([inner, inner], { list: { list: USER } }) as unknown[][]

      expect(copy).toEqual(rows)
      expect(copy).toHaveLength(3)
      expect(copy[2]).toBe(copy[0])
      expect(nested[1]).toBe(nested[0])
      expect(nested[0]?.[0]).not.toBe(row)
    })

    it('refuses a list that is offered where a record is promised, saying why', () => {
      const loop: unknown[] = []
      loop.push(loop)
      const items: unknown[] = []
      items.push({ workspace: items })
      const reason = 'the answer is not the record its method promises'

      expect(causeOf(() => copyHostRecord(loop, { list: USER }))).toBe(reason)
      expect(causeOf(() => copyHostRecord({ items, nextCursor: null }, PAGE))).toBe(reason)
    })

    it('copies a plain object that holds itself once, inside a field of the contract', () => {
      const own: Record<string, unknown> = {}
      own['self'] = own

      const copy = copyHostRecord({ name: own }, USER) as { name: { self: unknown } }

      expect(copy.name.self).toBe(copy.name)
      expect(copy.name).not.toBe(own)
    })

    it('defines no field for a name of the contract that is undefined or absent', () => {
      const copy = copyHostRecord({ id: 'u1', name: undefined }, USER) as Record<string, unknown>

      expect(Object.hasOwn(copy, 'name')).toBe(false)
      expect(Object.hasOwn(copy, 'email')).toBe(false)
      expect(copy['id']).toBe('u1')
    })

    it('refuses an answer that is no list where its method promises one, saying why', () => {
      expect(causeOf(() => copyHostRecord({ not: 'a list' }, { list: USER }))).toBe(
        'the answer is not the list its method promises'
      )
    })

    it('refuses an array or an object that holds more than the library follows', () => {
      const many = (size: number): unknown[] => Array.from({ length: size }, () => 0)
      const keyed = (size: number): Record<string, number> =>
        Object.fromEntries(Array.from({ length: size }, (_, index) => [`k${index}`, 1]))
      const refusal = 'the answer holds more than the library follows'

      expect(() => copyHostRecord({ mfaRecoveryCodes: many(100_000) }, USER)).not.toThrow()
      expect(causeOf(() => copyHostRecord({ mfaRecoveryCodes: many(100_001) }, USER))).toBe(refusal)
      expect(() => copyHostRecord({ name: keyed(100_000) }, USER)).not.toThrow()
      expect(causeOf(() => copyHostRecord({ name: keyed(100_001) }, USER))).toBe(refusal)
      expect(() => copyHostRecord(many(100_000), { list: 'value' })).not.toThrow()
      expect(causeOf(() => copyHostRecord(many(100_001), { list: 'value' }))).toBe(refusal)
      expect(() => copyHostRecord(keyed(100_000), USER)).not.toThrow()
      expect(causeOf(() => copyHostRecord(keyed(100_001), USER))).toBe(refusal)
    })

    it('refuses an array where its method promises a record, saying why', () => {
      expect(causeOf(() => copyHostRecord([{ id: 'u1' }], USER))).toBe(
        'the answer is not the record its method promises'
      )
    })

    it('keeps what was copied as data apart from what is copied as a record', () => {
      const workspace = { id: 'w1', name: 'W', createdAt: new Date(5) }
      Object.defineProperty(workspace, 'status', { value: 'ACTIVE', enumerable: false })
      const membership = { role: workspace, workspace }

      const copy = copyHostRecord({ items: [membership], nextCursor: null }, PAGE) as {
        items: { workspace: Record<string, unknown> }[]
      }

      expect(copy.items[0]?.workspace['status']).toBe('ACTIVE')
    })

    it('finds the fields of the contract on an ancestor that has no prototype of its own', () => {
      const root = Object.assign(Object.create(null) as object, {
        passwordHash: 'x',
        email: 'a@b.c'
      })
      const record = Object.assign(Object.create(root) as Record<string, unknown>, { id: 'u1' })

      const copy = copyHostRecord(record, USER) as Record<string, unknown>

      expect(copy['passwordHash']).toBe('x')
      expect(copy['email']).toBe('a@b.c')
      expect(Object.keys(copy)).toEqual(['id', 'email'])
    })

    it('copies a record that has no prototype', () => {
      const bare = Object.create(null) as Record<string, unknown>
      bare['id'] = 'u1'

      expect((copyHostRecord(bare, USER) as Record<string, unknown>)['id']).toBe('u1')
    })

    it('defines a copied __proto__ key as a plain data property', () => {
      const copy = copyHostRecord(JSON.parse('{"name":{"__proto__":1}}'), USER) as { name: object }

      expect(Object.getOwnPropertyDescriptor(copy.name, '__proto__')).toEqual({
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
        const copy = copyHostRecord({ zz: 1, id: 'u1', name: 'n' }, USER) as Record<string, unknown>
        const lazy = copyHostRecord(
          new Proxy({}, { get: (_t, key) => (key === 'status' ? 'ACTIVE' : undefined) }),
          USER
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

      expect(causeOf(() => copyHostRecord(new Doc(), USER))).toBe(
        'the answer holds a function where its method promises data'
      )
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

      copyHostRecord(record, USER)

      expect(reads).toBe(1)
    })

    it('applies the limit to a listed field answered by name', () => {
      const lazy = new Proxy(
        {},
        { get: (_target, key) => (key === 'mfaSecret' ? nest(16) : undefined) }
      )

      expect(causeOf(() => copyHostRecord(lazy, USER))).toBe(
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
      const view = guardRepository(hostile as { find(): Promise<unknown> }, {})

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

  // Scenario: a field the library does not read that nests far past the limit of the copy. Expected: the copy is made
  // and hands that field on by reference. Why: a host record carries state of its own that the library never reads,
  // and following it would fail every lookup of a record whose state is deep.
  it('hands a field the library does not read on by reference, however deep it nests', () => {
    let state: Record<string, unknown> = { leaf: true }
    for (let level = 0; level < 60; level += 1) state = { next: state }

    const copy = copyHostRecord({ id: 'u1', state }, USER) as { id: string; state: unknown }

    expect(copy.id).toBe('u1')
    expect(copy.state).toBe(state)
    expect(Object.keys(copy)).toEqual(['id', 'state'])
  })

  // Scenario: an entity shaped like a hydrated ORM instance (the own fields of a Sequelize model with two levels of
  // included relations measured 16 levels deep, a third level goes past the limit): its state, its options and its
  // relations hang off enumerable own fields, the values the library reads sit behind prototype getters. Expected:
  // the copy is made, the getters answer by name, the state stays the host's own object. Why: this is the shape that
  // would otherwise turn every lookup into the internal error once a relation is loaded.
  it('copies a hydrated entity whose own state is deeper than the limit and holds itself', () => {
    const chain = (levels: number): Record<string, unknown> => {
      let node: Record<string, unknown> = { model: 'Tag' }
      for (let level = 0; level < levels; level += 1) node = { include: [node], model: 'Post' }
      return node
    }
    class Hydrated {
      dataValues: Record<string, unknown> = { email: 'a@b.c', passwordHash: 'h' }
      _previousDataValues: Record<string, unknown> = { email: 'a@b.c' }
      _options: Record<string, unknown> = { include: [chain(40)] }
      _self: unknown = this
      get email(): unknown {
        return this.dataValues['email']
      }
      get passwordHash(): unknown {
        return this.dataValues['passwordHash']
      }
    }
    const entity = new Hydrated()

    const copy = copyHostRecord(entity, USER) as Record<string, unknown>

    expect(copy['email']).toBe('a@b.c')
    expect(copy['passwordHash']).toBe('h')
    expect(copy['dataValues']).toBe(entity.dataValues)
    expect(copy['_options']).toBe(entity._options)
  })

  // Scenario: an entity with getters the contract does not name (an unloaded relation, a computed view), one on the
  // prototype, one hidden on the instance and one own and enumerable, beside the fields it does read. Expected: the
  // copy is made, none of the getters is evaluated, and the fields of the contract arrive. Why: evaluating a getter
  // nobody asked for would fail every lookup of an entity whose relation is not loaded.
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
    Object.defineProperty(entity, 'ownRelation', {
      get: () => {
        evaluated += 1
        throw new Error('relation not loaded')
      },
      enumerable: true
    })

    const copy = copyHostRecord(entity, USER) as Record<string, unknown>

    expect(copy['id']).toBe('u1')
    expect(copy['status']).toBe('ACTIVE')
    expect(copy['ownRelation']).toBeUndefined()
    expect(evaluated).toBe(0)
  })

  // Scenario: a record that serves fields of the contract through its prototype or as non-enumerable properties, with
  // the credentials among them. Expected: every field the contract names is readable by name and visible to a spread,
  // Object.keys and JSON.stringify of the copy, except the credentials (`passwordHash`, `mfaSecret`), which stay as
  // hidden as the host's record made them; a non-enumerable backing object is not copied at all. Why: the copy is what
  // the services spread into a token payload, so `role`, `tenantId` and `status` have to be visible, while a credential
  // made visible would reach a response.
  it('keeps hidden fields hidden from a spread while still readable by name', () => {
    class Doc {
      id = 'u1'
      get role(): string {
        return 'user'
      }
      get passwordHash(): string {
        return 'hash'
      }
      get mfaSecret(): string {
        return 'enc'
      }
    }
    const record = new Doc()
    Object.defineProperty(record, '_credentials', {
      value: { passwordHash: 'hash', mfaSecret: 'enc' },
      enumerable: false
    })
    Object.defineProperty(record, 'status', { value: 'ACTIVE', enumerable: false })

    const copy = copyHostRecord(record, USER) as Record<string, unknown>

    expect(copy['status']).toBe('ACTIVE')
    expect(copy['role']).toBe('user')
    expect(copy['passwordHash']).toBe('hash')
    expect(copy['mfaSecret']).toBe('enc')
    expect(copy['_credentials']).toBeUndefined()
    expect(Object.keys(copy)).toEqual(['id', 'role', 'status'])
    expect(Object.keys({ ...copy })).toEqual(['id', 'role', 'status'])
    expect(JSON.stringify(copy)).toBe('{"id":"u1","role":"user","status":"ACTIVE"}')
  })

  // Scenario: a record with an own key named __proto__ (what JSON.parse of user input produces). Expected: it stays an
  // own key of the copy and the copy's prototype is untouched. Why: assigning it would swap the copy's prototype for the
  // copied value, and the copy would inherit names the original did not own.
  it('keeps a __proto__ key an own property and does not change the prototype of the copy', () => {
    const record = JSON.parse('{"name":{"__proto__":{"role":"ADMIN"},"a":1}}') as object
    const copy = copyHostRecord(record, USER) as { name: Record<string, unknown> }

    expect(Object.getPrototypeOf(copy.name)).toBe(Object.prototype)
    expect(Object.keys(copy.name)).toContain('__proto__')
    expect(copy.name['role']).toBeUndefined()
  })

  // Scenario: an object that is both a membership of a page and its own workspace. Expected: each is a copy made by the
  // contract of its own place and neither is the other, while a field the workspace contract does not name (its own
  // `workspace`) is handed on by reference. Why: the same object copied under another contract is another copy, and
  // a copy reused across contracts would hand one place the fields of the other.
  it('copies an object reached under two contracts once under each', () => {
    const both: Record<string, unknown> = {
      tenantId: 't1',
      workspaceId: 'w1',
      userId: 'u1',
      role: 'ADMIN',
      status: 'ACTIVE',
      invitedByUserId: null,
      createdAt: new Date(1),
      updatedAt: new Date(2),
      id: 'w1',
      name: 'W',
      deletionScheduledAt: null
    }
    both['workspace'] = both

    const copy = copyHostRecord({ items: [both], nextCursor: null }, PAGE) as {
      items: { role: string; workspace: Record<string, unknown> }[]
    }
    const item = copy.items[0]

    expect(item?.role).toBe('ADMIN')
    expect(item?.workspace).not.toBe(item)
    expect(item?.workspace['name']).toBe('W')
    expect(item?.workspace['workspace']).toBe(both)
  })

  // Scenario: a value of the contract nested deeper than the library follows. Expected: the internal error, not a
  // crash.
  it('refuses a value nested past the limit as an internal error', () => {
    let deep: Record<string, unknown> = {}
    for (let level = 0; level < 20; level += 1) deep = { next: deep }

    expect.assertions(2)
    try {
      copyHostRecord({ name: deep }, USER)
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
      copyHostRecord(record, USER)
    } catch (error) {
      expect(codeOf(error)).toBe(AUTH_ERROR_CODES.INTERNAL)
      expect((error as Error).cause).toBe(fault)
      expect(JSON.stringify((error as AuthException).getResponse())).not.toContain(fault.message)
    }
  })
})
