/**
 * @fileoverview What the copy does with the values a contract names: dates (a Proxy of one, a date that is not a time),
 * a field promised as data that is served as a function, and the instances of classes of the host.
 *
 * @layer Test
 */

import { copyHostRecord } from './host-read'
import {
  API_KEY_REPOSITORY_CONTRACT,
  USER_REPOSITORY_CONTRACT,
  WORKSPACE_REPOSITORY_CONTRACT
} from './repository-contracts'

/** What a record of the user repository is read for. */
const USER = USER_REPOSITORY_CONTRACT.findById

/** The reason of the failure a copy ends in, or undefined when it ends in none. */
const causeOf = (thunk: () => unknown): unknown => {
  try {
    thunk()
  } catch (error) {
    return (error as { cause?: Error }).cause?.message
  }
  return undefined
}

/** A Proxy of a date whose `getTime` answers `answer`, and whose other methods run on the date. */
const timeAs = (answer: unknown): Date =>
  new Proxy(new Date(0), {
    get: (target, key) => {
      if (key === 'getTime') return () => answer
      const member: unknown = Reflect.get(target, key, target)
      return typeof member === 'function' ? member.bind(target) : member
    }
  })

describe('the values of the contract', () => {
  it('copies a date a Proxy of the host answers as, and nothing else a Proxy wraps', () => {
    const moment = new Proxy(new Date(5), {
      get: (target, key) => {
        const member: unknown = Reflect.get(target, key, target)
        return typeof member === 'function' ? member.bind(target) : member
      }
    })
    const plain = new Proxy({ a: 1 }, {})

    const copy = copyHostRecord({ createdAt: moment, name: plain }, USER) as {
      createdAt: Date
      name: unknown
    }

    expect(copy.createdAt).toBeInstanceOf(Date)
    expect(copy.createdAt.getTime()).toBe(5)
    expect(copy.name).toEqual({ a: 1 })
    expect(copy.name).not.toBeInstanceOf(Date)
  })

  // Scenario: a date that is not a time, as a real Invalid Date and as a Proxy whose `getTime` answers a NaN, a string
  // or an infinity, in a deadline of an API key and of a workspace. Expected: each is refused with the library's
  // reason. Why: such a date compares false with every instant, so a deadline read from it would never be due.
  it.each([
    ['a real Invalid Date', (): Date => new Date(Number.NaN)],
    ['a Proxy answering NaN', (): Date => timeAs(Number.NaN)],
    ['a Proxy answering a string', (): Date => timeAs('x')],
    ['a Proxy answering an infinity', (): Date => timeAs(Number.POSITIVE_INFINITY)]
  ])('refuses %s as a deadline', (_name, make) => {
    const reason = 'the answer holds a date that is not a time'

    expect(
      causeOf(() => copyHostRecord({ expiresAt: make() }, API_KEY_REPOSITORY_CONTRACT.findById))
    ).toBe(reason)
    expect(
      causeOf(() =>
        copyHostRecord({ deletionScheduledAt: make() }, WORKSPACE_REPOSITORY_CONTRACT.findById)
      )
    ).toBe(reason)
  })

  it('does not take an object that only has the methods of a date for one, even behind a Proxy', () => {
    const lookalike = { getTime: (): number => 5, toISOString: (): string => 'x', own: true }
    const wrapped = new Proxy(lookalike, {})
    const forged = new Proxy(Object.create(Date.prototype) as object, {})

    const copy = copyHostRecord({ createdAt: wrapped }, USER) as { createdAt: unknown }

    expect(copy.createdAt).not.toBeInstanceOf(Date)
    expect((copy.createdAt as typeof lookalike).own).toBe(true)
    expect(causeOf(() => copyHostRecord({ createdAt: forged }, USER))).toBeDefined()
  })

  // Scenario: a field the contract promises as data, served as a function or as a getter that answers one, for the
  // fields that decide an admission. Expected: refused with the library's reason. Why: a field that is dropped reads as
  // the default of its type, so `mfaEnabled` as a function would skip the second factor.
  it.each([
    ['mfaEnabled', USER],
    ['status', USER],
    ['emailVerified', USER],
    ['revokedAt', API_KEY_REPOSITORY_CONTRACT.findById],
    ['expiresAt', API_KEY_REPOSITORY_CONTRACT.findById]
  ] as const)(
    'refuses %s served as a function, or as a getter answering one',
    (field, contract) => {
      const reason = 'the answer holds a function where its method promises data'
      const own = { [field]: (): boolean => true }
      const getter = Object.defineProperty({}, field, { get: () => (): boolean => true })
      const inherited = Object.create({
        get [field](): () => boolean {
          return (): boolean => true
        }
      }) as object

      expect(causeOf(() => copyHostRecord(own, contract))).toBe(reason)
      expect(causeOf(() => copyHostRecord(getter, contract))).toBe(reason)
      expect(causeOf(() => copyHostRecord(inherited, contract))).toBe(reason)
    }
  )

  // Scenario: an id type of a database driver and the date of a date library in fields of the contract. Expected: each
  // is the host's own object, so `String(id)` is the real id, two users never share an id and the date keeps its
  // methods; a plain object in the same place is still copied. Why: a plain copy of such an instance has the fields
  // and none of the behavior, and every id would print as "[object Object]".
  // Scenario: a plain object with no prototype in a field of the contract, and the kinds of object whose state is not in
  // their fields (a Map, a Set, a Promise, a buffer, an Error, a URL). Expected: the plain object is copied, each of the
  // kinds is the host's own object. Why: a copy of a Map would be an empty object that answers to nothing.
  it('copies a plain object without a prototype and keeps the kinds that hold their state apart', () => {
    const bare = Object.assign(Object.create(null) as object, { a: 1 })
    const kinds = [
      new Map([['k', 1]]),
      new Set([1]),
      new WeakMap(),
      Promise.resolve(1),
      /x/u,
      new Error('e'),
      new Uint8Array([1]),
      new ArrayBuffer(1),
      new URL('https://a.example')
    ]

    const copy = copyHostRecord({ name: bare, mfaRecoveryCodes: kinds }, USER) as {
      name: object
      mfaRecoveryCodes: unknown[]
    }

    expect(copy.name).toEqual({ a: 1 })
    expect(copy.name).not.toBe(bare)
    kinds.forEach((kind, index) => expect(copy.mfaRecoveryCodes[index]).toBe(kind))
  })

  it('keeps the instance of a class of the host in a field of the contract by reference', () => {
    class ObjectIdLike {
      constructor(private readonly hex: string) {}
      toString(): string {
        return this.hex
      }
    }
    class MomentLike {
      format(): string {
        return 'formatted'
      }
    }
    const first = new ObjectIdLike('64b0000000000000000000a1')
    const second = new ObjectIdLike('64b0000000000000000000a2')
    const moment = new MomentLike()
    const plain = { kept: 'copied' }

    const one = copyHostRecord({ id: first, tenantId: second, name: plain }, USER) as Record<
      string,
      unknown
    >
    const two = copyHostRecord({ id: second, createdAt: moment }, USER) as Record<string, unknown>

    expect(one['id']).toBe(first)
    expect(String(one['id'])).toBe('64b0000000000000000000a1')
    expect(String(two['id'])).toBe('64b0000000000000000000a2')
    expect(String(one['id'])).not.toBe(String(two['id']))
    expect(one['tenantId']).toBe(second)
    expect((two['createdAt'] as MomentLike).format()).toBe('formatted')
    expect(one['name']).toEqual(plain)
    expect(one['name']).not.toBe(plain)
  })
})
