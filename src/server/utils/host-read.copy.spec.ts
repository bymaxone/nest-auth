/**
 * @fileoverview The copy of an answer a repository returned: what the copy keeps of a record, which of its fields a
 * spread shows, the fields it hands on without reading, the bounds of the copy and the memo that keeps one object
 * copied once under one contract.
 *
 * @layer Test
 */

import { runInNewContext } from 'node:vm'

import { BYMAX_AUTH_REDIS_CLIENT, BYMAX_AUTH_USER_REPOSITORY } from '../bymax-auth.constants'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import {
  membershipRecord,
  membershipWithWorkspace,
  onPrototype,
  userRecord,
  workspaceRecord
} from './__tests__/host-records'
import { copyHostRecord, guardRepository, withGuardedViews } from './host-read'
import { MEMBERSHIP_REPOSITORY_CONTRACT, USER_REPOSITORY_CONTRACT } from './repository-contracts'

/** The host's own failure, with text a library error must never repeat. */
const fault = new Error('host-text-that-must-not-leak')

/** The code of an `AuthException`. */
const codeOf = (error: unknown): string =>
  ((error as AuthException).getResponse() as { error: { code: string } }).error.code

/** The reason a copy ended in, or undefined when it ended in none. */
const causeOf = (thunk: () => unknown): unknown => {
  try {
    thunk()
  } catch (error) {
    return (error as { cause?: Error }).cause?.message
  }
  return undefined
}

/** What a record of the user repository is read for. */
const USER = USER_REPOSITORY_CONTRACT.findById

/** What a page of the memberships of a user, each with its workspace, is read for. */
const PAGE = MEMBERSHIP_REPOSITORY_CONTRACT.listForUser

/** The fields of a user that are credentials. */
const CREDENTIALS = ['passwordHash', 'mfaSecret', 'mfaRecoveryCodes']

/** The fields of a user a spread of its copy shows, in the order of its contract. */
const VISIBLE = Object.keys(userRecord()).filter((key) => !CREDENTIALS.includes(key))

describe('copyHostRecord', () => {
  // Scenario: an answer that is no record. Expected: a record that was not found comes back as it is; anything else is
  // refused with the library's reason. Why: a method that finds nothing answers null or undefined, and a number where a
  // record is promised is the host's failure.
  it.each([[null], [undefined]])('returns %p, a record that was not found, as it is', (value) => {
    expect(copyHostRecord(value, USER)).toBe(value)
  })

  it.each([[3], ['text'], [true]])('refuses %p where a record is promised', (value) => {
    expect(causeOf(() => copyHostRecord(value, USER))).toBe(
      'the answer holds a value that is not the kind its method promises'
    )
  })

  // Scenario: a page of memberships with their workspaces. Expected: an equal copy sharing nothing mutable with the
  // original. Why: the library reads these fields, so what it reads must not change under it.
  it('copies a record, its nested records, its lists and its dates', () => {
    const membership = membershipWithWorkspace({
      workspace: workspaceRecord({ createdAt: new Date(5) })
    })
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

  // Scenario: an entity that serves every field through its prototype, the credentials among them. Expected: every
  // field is readable by name, a spread, Object.keys and JSON.stringify of the copy show the fields that are not
  // credentials, and the credentials stay as hidden as the host's record made them. Why: the copy is what the services
  // spread into a token payload, so `role`, `tenantId` and `status` have to be visible, while a credential made visible
  // would reach a response.
  it('keeps what an entity serves through its prototype, visible except the credentials', () => {
    const entity = onPrototype(userRecord({ mfaSecret: 'enc', mfaRecoveryCodes: ['c1'] }))

    const copy = copyHostRecord(entity, USER) as Record<string, unknown>

    expect(copy['role']).toBe('MEMBER')
    expect(copy['passwordHash']).toBe('hash')
    expect(copy['mfaSecret']).toBe('enc')
    expect(copy['mfaRecoveryCodes']).toEqual(['c1'])
    expect(Object.keys(copy)).toEqual(VISIBLE)
    expect(Object.keys({ ...copy })).toEqual(VISIBLE)
    expect(JSON.stringify(copy)).not.toContain('hash')
    expect(JSON.stringify(copy)).not.toContain('enc')
  })

  // Scenario: an accessor inherited from a base class beside own fields. Expected: both are read.
  it('reads accessors up the prototype chain', () => {
    class Base {
      get role(): string {
        return 'base'
      }
    }
    class Derived extends Base {}
    const { role: _served, ...rest } = userRecord()
    const entity = Object.assign(new Derived(), rest)

    const copy = copyHostRecord(entity, USER) as Record<string, unknown>

    expect(copy['role']).toBe('base')
    expect(copy['id']).toBe('u1')
  })

  // Scenario: the fields an auth decision reads, held as non-enumerable own properties, one as a getter. Expected: each
  // survives the copy with its value, and the credential among them stays hidden. Why: a copy that lists only
  // enumerable keys would drop `status` or `mfaEnabled`, and the decision would read undefined.
  it('keeps non-enumerable own fields, data and getter alike', () => {
    const record = userRecord()
    Object.defineProperty(record, 'passwordHash', { value: 'hash', enumerable: false })
    Object.defineProperty(record, 'status', { get: () => 'ACTIVE', enumerable: false })
    Object.defineProperty(record, 'mfaEnabled', { value: true, enumerable: false })

    const copy = copyHostRecord(record, USER) as Record<string, unknown>

    expect(copy['passwordHash']).toBe('hash')
    expect(copy['status']).toBe('ACTIVE')
    expect(copy['mfaEnabled']).toBe(true)
    expect(Object.keys(copy)).toContain('status')
    expect(Object.keys(copy)).not.toContain('passwordHash')
  })

  // Scenario: values made in another realm (a vm context, which is what a test runner or a driver bundle can hand
  // over). Expected: a date is still a date, and a plain object from there that the contract does not name is handed on
  // as it is. Why: `instanceof` is false across realms, so a date from another realm has to be told by its internal slot.
  it('treats values from another realm as the kinds they are', () => {
    const foreign = <T>(source: string): T => runInNewContext(source) as T
    const date = foreign<Date>('new Date(5)')
    const extra = foreign<Record<string, number>>('({ a: 1 })')

    const copy = copyHostRecord({ ...userRecord(), createdAt: date, extra }, USER) as {
      createdAt: Date
      extra: unknown
    }

    expect(JSON.stringify(copy.createdAt)).toBe(JSON.stringify(new Date(5)))
    expect(copy.createdAt.getTime()).toBe(5)
    expect(copy.createdAt).not.toBe(date)
    expect(copy.extra).toBe(extra)
  })

  // Scenario: a record whose auth state lives on its prototype, as a class default or an Object.create base does.
  // Expected: the inherited fields survive the copy, an own field shadows an inherited one, and the inherited methods
  // are not copied. Why: dropping `mfaEnabled` would let a login skip the challenge.
  it('keeps inherited data fields, lets an own field shadow them, and leaves methods behind', () => {
    const { role: _own, mfaEnabled: _inherited, ...rest } = userRecord()
    const proto = { role: 'admin', mfaEnabled: true, helper: (): string => 'fn' }
    const record = Object.assign(Object.create(proto) as Record<string, unknown>, rest, {
      role: 'user'
    })

    const copy = copyHostRecord(record, USER) as Record<string, unknown>

    expect(copy['mfaEnabled']).toBe(true)
    expect(copy['role']).toBe('user')
    expect(copy['id']).toBe('u1')
    expect(copy['helper']).toBeUndefined()
  })

  // Scenario: a record that answers by name and lists nothing (a lazy entity or a Proxy with only a get trap). Expected:
  // every field of the contract is still read by name. Why: no enumeration can find a field the object never lists,
  // and the services read `user.mfaEnabled`, not a key list.
  it('reads the fields of the contract by name from an object that lists none', () => {
    const answers: Record<string, unknown> = { ...userRecord({ mfaEnabled: true }) }
    const lazy = new Proxy({}, { get: (_target, key) => answers[String(key)] })

    const copy = copyHostRecord(lazy, USER) as Record<string, unknown>

    expect(copy['mfaEnabled']).toBe(true)
    expect(copy['status']).toBe('active')
    expect(Object.keys(copy)).toEqual(VISIBLE)
  })

  // Scenario: the result envelopes of the repositories (a page, the outcome of removing a user's memberships) held on
  // a prototype. Expected: every envelope field of the contract is found by name, and the records among them are
  // copied by their own contract. Why: the services read `page.items` and `outcome.result` the way they read a
  // record's fields.
  it('finds the fields of the result envelopes by name when they live on a prototype', () => {
    const page = onPrototype({ items: [], nextCursor: 'c' })
    const outcome = onPrototype({
      result: 'ok',
      removed: [{ workspaceId: 'w1', role: 'MEMBER' }],
      workspaceIds: ['w2']
    })

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

  // Scenario: a class whose prototype holds a shared handle (a model's connection, a class-level client) nested deep.
  // Expected: the record is copied and the handle is left behind. Why: copying the prototype's data would walk a
  // connection graph per record.
  it('does not walk shared data held on a prototype, and still finds the fields of the contract', () => {
    let deep: Record<string, unknown> = { leaf: true }
    for (let level = 0; level < 20; level += 1) deep = { next: deep }
    class Doc {
      constructor() {
        Object.assign(this, userRecord())
      }
    }
    Object.assign(Doc.prototype, { connection: deep })

    const copy = copyHostRecord(new Doc(), USER) as Record<string, unknown>

    expect(copy['id']).toBe('u1')
    expect(copy['connection']).toBeUndefined()
  })

  // Scenario: fields of the contract held only by an ancestor that has no prototype of its own, which is how the root object
  // of a runtime looks. Expected: they are not read, and a strict one is refused as absent. Why: the root of a realm cannot
  // be told from such an ancestor, and a key found there is not something the host's record or its class holds.
  it('does not read a field held only by an ancestor that has no prototype of its own', () => {
    const { passwordHash, email, ...rest } = userRecord({ email: 'x@y.z' })
    const root = Object.assign(Object.create(null) as object, { passwordHash, email })
    const record = Object.assign(Object.create(root) as Record<string, unknown>, rest)

    expect(() => copyHostRecord(record, USER)).toThrow(AuthException)
  })

  // Scenario: a record with no prototype, and one with an own key named __proto__. Expected: both are copied, the key
  // stays an own property and the prototype of the copy is untouched. Why: assigning it would swap the prototype of the
  // copy for the copied value, and the copy would inherit names the original did not own.
  it('copies a record without a prototype and keeps a __proto__ key an own property', () => {
    const bare = Object.assign(Object.create(null) as object, userRecord())
    const forged = userRecord()
    Object.defineProperty(forged, '__proto__', {
      value: { role: 'ADMIN' },
      enumerable: true,
      configurable: true,
      writable: true
    })

    const fromBare = copyHostRecord(bare, USER) as Record<string, unknown>
    const fromForged = copyHostRecord(forged, USER) as Record<string, unknown>

    expect(fromBare['id']).toBe('u1')
    expect(Object.getPrototypeOf(fromForged)).toBeNull()
    expect(Object.getOwnPropertyDescriptor(fromForged, '__proto__')).toEqual({
      value: { role: 'ADMIN' },
      writable: true,
      enumerable: true,
      configurable: true
    })
    expect(fromForged['role']).toBe('MEMBER')
  })

  // Scenario: names that are setters on Object.prototype, as an own field the contract does not name and as a field it
  // does. Expected: both stay own properties of the copy. Why: assigning them would call the setter and drop the value.
  it('keeps a field whose name is a setter on Object.prototype, own and listed alike', () => {
    Object.defineProperty(Object.prototype, 'zz', { set(): void {}, configurable: true })
    Object.defineProperty(Object.prototype, 'status', { set(): void {}, configurable: true })
    try {
      const own = copyHostRecord({ ...userRecord(), zz: 1 }, USER) as Record<string, unknown>
      const served = copyHostRecord(onPrototype(userRecord()), USER) as Record<string, unknown>

      expect(Object.hasOwn(own, 'zz')).toBe(true)
      expect(Object.hasOwn(served, 'status')).toBe(true)
      expect(served['status']).toBe('active')
    } finally {
      Reflect.deleteProperty(Object.prototype, 'zz')
      Reflect.deleteProperty(Object.prototype, 'status')
    }
  })

  // Scenario: an own getter of a field of the contract. Expected: it is read once.
  it('reads the getter of a field of the contract once', () => {
    let reads = 0
    const record = userRecord()
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

  // Scenario: a getter of a field the contract names that throws. Expected: the internal error with the fault as the
  // cause and none of its text.
  it('ends a getter that throws in the internal error with the cause', () => {
    const record = userRecord()
    Object.defineProperty(record, 'name', {
      get: () => {
        throw fault
      },
      enumerable: true
    })

    expect.assertions(3)
    try {
      copyHostRecord(record, USER)
    } catch (error) {
      expect(codeOf(error)).toBe(AUTH_ERROR_CODES.INTERNAL)
      expect((error as Error).cause).toBe(fault)
      expect(JSON.stringify((error as AuthException).getResponse())).not.toContain(fault.message)
    }
  })

  // Scenario: fields the contract does not name: an own field that nests far past any limit, an entity shaped like a
  // hydrated ORM instance (its state, options and relations in enumerable own fields, one holding the entity itself).
  // Expected: the copy is made, the fields stay the host's own objects and stay visible to a spread, and the values the
  // library reads sit behind prototype getters. Why: following such state would fail every lookup of a record whose
  // state is deep.
  it('hands the fields the contract does not name on by reference, however deep they nest', () => {
    let state: Record<string, unknown> = { leaf: true }
    for (let level = 0; level < 60; level += 1) state = { next: state }
    class Hydrated {
      constructor(readonly dataValues: Record<string, unknown>) {}
      _options: Record<string, unknown> = { include: [state] }
      _self: unknown = this
    }
    for (const key of Object.keys(userRecord()))
      Object.defineProperty(Hydrated.prototype, key, {
        get(this: Hydrated): unknown {
          return this.dataValues[key]
        }
      })
    const entity = new Hydrated({ ...userRecord() })

    const copy = copyHostRecord(entity, USER) as Record<string, unknown>

    expect(copy['email']).toBe('a@b.c')
    expect(copy['dataValues']).toBe(entity.dataValues)
    expect(copy['_options']).toBe(entity._options)
    expect(copy['_self']).toBe(entity)
    expect(Object.keys(copy)).toEqual(expect.arrayContaining(['dataValues', '_options', '_self']))
  })

  // Scenario: an entity with getters the contract does not name (an unloaded relation, a computed view): one on the
  // prototype, one hidden on the instance and one own and enumerable. Expected: the copy is made, none is evaluated.
  // Why: evaluating a getter nobody asked for would fail every lookup of an entity whose relation is not loaded.
  it('never evaluates a getter the contract does not name', () => {
    let evaluated = 0
    class Entity {
      constructor() {
        Object.assign(this, userRecord())
      }
      get unloadedRelation(): string {
        evaluated += 1
        throw new Error('relation not loaded')
      }
    }
    const entity = new Entity()
    for (const [name, enumerable] of [
      ['hiddenRelation', false],
      ['ownRelation', true]
    ] as const)
      Object.defineProperty(entity, name, {
        get: () => {
          evaluated += 1
          throw new Error('relation not loaded')
        },
        enumerable
      })

    const copy = copyHostRecord(entity, USER) as Record<string, unknown>

    expect(copy['id']).toBe('u1')
    expect(copy['ownRelation']).toBeUndefined()
    expect(evaluated).toBe(0)
  })

  // Scenario: a hostile repository whose reads all throw, read for a symbol; a class with a static provide; providers
  // that are not repositories. Expected: undefined for the symbol, no view for the others.
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

  describe('bounds of the copy', () => {
    const many = (size: number): string[] => Array.from({ length: size }, () => 'x')
    const keyed = (size: number): Record<string, number> =>
      Object.fromEntries(Array.from({ length: size }, (_, index) => [`k${index}`, 1]))
    const refusal = 'the answer holds more than the library follows'

    // Scenario: a list of strings, a list of records, a record with many keys, at exactly the bound and one past it.
    // Expected: the first is copied and the second refused with the library's reason.
    it('refuses an array or an object that holds more than the library follows', () => {
      const user = userRecord()
      const keys = Object.keys(user).length

      expect(() => copyHostRecord({ ...user, mfaRecoveryCodes: many(100_000) }, USER)).not.toThrow()
      expect(
        causeOf(() => copyHostRecord({ ...user, mfaRecoveryCodes: many(100_001) }, USER))
      ).toBe(refusal)
      expect(() => copyHostRecord({ ...user, ...keyed(100_000 - keys) }, USER)).not.toThrow()
      expect(causeOf(() => copyHostRecord({ ...user, ...keyed(100_001 - keys) }, USER))).toBe(
        refusal
      )
      expect(() => copyHostRecord(Array(100_000).fill(user), { list: USER })).not.toThrow()
      expect(causeOf(() => copyHostRecord(Array(100_001).fill(user), { list: USER }))).toBe(refusal)
    })

    // Scenario: the shapes a list and a record promise. Expected: a list that is no list and an array that is no record
    // are refused with the library's reason.
    it('refuses an answer of the wrong shape, saying why', () => {
      expect(causeOf(() => copyHostRecord({ not: 'a list' }, { list: USER }))).toBe(
        'the answer is not the list its method promises'
      )
      expect(causeOf(() => copyHostRecord([userRecord()], USER))).toBe(
        'the answer is not the record its method promises'
      )
    })

    // Scenario: a list of records copied to exactly its length, an object reached twice under one contract, and the
    // same inner list reached twice. Expected: one copy each. Why: a value reached twice is one value.
    it('copies a list to exactly its length, and what is reached twice under one contract once', () => {
      const row = userRecord()
      const inner = [row]
      const rows = [row, userRecord({ id: 'u2' }), row]

      const copy = copyHostRecord(rows, { list: USER }) as unknown[]
      const nested = copyHostRecord([inner, inner], { list: { list: USER } }) as unknown[][]

      expect(copy).toEqual(rows)
      expect(copy).toHaveLength(3)
      expect(copy[2]).toBe(copy[0])
      expect(nested[1]).toBe(nested[0])
      expect(nested[0]?.[0]).not.toBe(row)
    })

    // Scenario: a list offered where a record is promised, as a list that holds itself and as an items array that a
    // membership's workspace points back to. Expected: refused, never answered from the copy of the list. Why: a copy
    // made under one contract is not the copy for another.
    it('refuses a list that is offered where a record is promised, saying why', () => {
      const loop: unknown[] = []
      loop.push(loop)
      const items: unknown[] = []
      items.push({ ...membershipRecord(), workspace: items })
      const reason = 'the answer is not the record its method promises'

      expect(causeOf(() => copyHostRecord(loop, { list: USER }))).toBe(reason)
      expect(causeOf(() => copyHostRecord({ items, nextCursor: null }, PAGE))).toBe(reason)
    })

    // Scenario: an object that is both a membership of a page and its own workspace. Expected: each is a copy made by
    // the contract of its own place and neither is the other, while a field the workspace contract does not name (its
    // own `workspace`) is handed on by reference. Why: the same object copied under another contract is another copy.
    it('copies an object reached under two contracts once under each', () => {
      const both: Record<string, unknown> = {
        ...membershipWithWorkspace(),
        id: 'w1',
        name: 'W',
        deletionScheduledAt: null
      }
      both['workspace'] = both

      const copy = copyHostRecord({ items: [both], nextCursor: null }, PAGE) as {
        items: { role: string; workspace: Record<string, unknown> }[]
      }
      const item = copy.items[0]

      expect(item?.role).toBe('MEMBER')
      expect(item?.workspace).not.toBe(item)
      expect(item?.workspace['name']).toBe('W')
      expect(item?.workspace['workspace']).toBe(both)
    })
  })
})
