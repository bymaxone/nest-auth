/**
 * @fileoverview What the copy accepts as each kind a contract names: a boolean is a boolean and no wrapper of one, a
 * date has a real time, an id may be an instance of a class of the host, a field the interface requires is not absent,
 * and a function is no value at all.
 *
 * @layer Test
 */

import {
  apiKeyRecord,
  membershipRecord,
  onPrototype,
  platformRecord,
  userRecord,
  workspaceRecord
} from './__tests__/host-records'
import { copyHostRecord } from './host-read'
import {
  API_KEY_REPOSITORY_CONTRACT,
  MEMBERSHIP_REPOSITORY_CONTRACT,
  PLATFORM_USER_REPOSITORY_CONTRACT,
  USER_REPOSITORY_CONTRACT,
  WORKSPACE_REPOSITORY_CONTRACT
} from './repository-contracts'

const USER = USER_REPOSITORY_CONTRACT.findById
const PLATFORM = PLATFORM_USER_REPOSITORY_CONTRACT.findById
const KEY = API_KEY_REPOSITORY_CONTRACT.findById
const WORKSPACE = WORKSPACE_REPOSITORY_CONTRACT.findById
const MEMBERSHIP = MEMBERSHIP_REPOSITORY_CONTRACT.find

const WRONG_KIND = 'the answer holds a value that is not the kind its method promises'
const ABSENT = 'the answer lacks a field its method promises'
const NOT_A_TIME = 'the answer holds a date that is not a time'

/** The reason a copy ended in, or undefined when it ended in none. */
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

/** What a host serves that is no boolean, no string and no number, in the spellings a wrapper or a coercion hides. */
const GARBAGE: [string, unknown][] = [
  ['a Boolean wrapper', new Boolean(false)],
  ['a String wrapper', new String('x')],
  ['a Number wrapper', new Number(1)],
  ['a symbol', Symbol('s')],
  ['a bigint', 0n],
  ['an empty object', {}],
  ['an array', []],
  ['a function', (): boolean => true]
]

describe('the kinds of the contract', () => {
  // Scenario: a field of a user, a platform user and an API key that decides an admission, served as each spelling of
  // garbage. Expected: refused with the library's reason, never read as a value. Why: `new Boolean(false)` is truthy, so
  // `!user.emailVerified` would be false and an unverified account would pass; a symbol or `0n` would pass the same way.
  it.each([
    ['mfaEnabled', USER, userRecord],
    ['emailVerified', USER, userRecord],
    ['mfaEnabled', PLATFORM, platformRecord]
  ] as const)('refuses a %s that is no boolean', (field, contract, make) => {
    for (const [, garbage] of [...GARBAGE, ['a string', 'true'], ['a number', 1]] as const)
      expect(causeOf(() => copyHostRecord({ ...make(), [field]: garbage }, contract))).toBe(
        WRONG_KIND
      )
    expect(() => copyHostRecord({ ...make(), [field]: true }, contract)).not.toThrow()
    expect(() => copyHostRecord({ ...make(), [field]: false }, contract)).not.toThrow()
  })

  it.each([
    ['status', USER, userRecord],
    ['role', USER, userRecord],
    ['email', USER, userRecord],
    ['status', PLATFORM, platformRecord],
    ['label', KEY, apiKeyRecord]
  ] as const)('refuses a %s that is no string', (field, contract, make) => {
    for (const [, garbage] of [...GARBAGE, ['a number', 1]] as const)
      expect(causeOf(() => copyHostRecord({ ...make(), [field]: garbage }, contract))).toBe(
        WRONG_KIND
      )
    expect(() => copyHostRecord({ ...make(), [field]: 'ok' }, contract)).not.toThrow()
  })

  // Scenario: the ids of the contracts, served as an instance of a class of the host, as a wrapper and as garbage.
  // Expected: the instance is the host's own object (`String(id)` is the real id, two users never share one), the rest
  // is refused. Why: an id type of a driver prints through its own `toString`, and a plain copy of it would print as
  // `[object Object]` for every user.
  it('keeps an id that is an instance of a class of the host and refuses the other objects', () => {
    class ObjectIdLike {
      constructor(private readonly hex: string) {}
      toString(): string {
        return this.hex
      }
    }
    const first = new ObjectIdLike('64b0000000000000000000a1')
    const second = new ObjectIdLike('64b0000000000000000000a2')

    const one = copyHostRecord(
      userRecord({ id: first as never, tenantId: second as never }),
      USER
    ) as Record<string, unknown>
    const two = copyHostRecord(userRecord({ id: second as never }), USER) as Record<string, unknown>

    expect(one['id']).toBe(first)
    expect(one['tenantId']).toBe(second)
    expect(String(one['id'])).toBe('64b0000000000000000000a1')
    expect(String(one['id'])).not.toBe(String(two['id']))
    for (const [, garbage] of [
      ...GARBAGE.filter(([name]) => name !== 'a function'),
      ['a function', (): void => undefined],
      ['a number', 5],
      ['a plain object', { hex: 'x' }]
    ] as const)
      expect(causeOf(() => copyHostRecord(userRecord({ id: garbage as never }), USER))).toBe(
        WRONG_KIND
      )
  })

  // Scenario: a number promised by a method, served as NaN, an infinity, a string and a wrapper. Expected: refused.
  it('refuses a count that is no finite number', () => {
    const count = MEMBERSHIP_REPOSITORY_CONTRACT.countOwned

    for (const garbage of [
      Number.NaN,
      Number.POSITIVE_INFINITY,
      '5',
      new Number(5),
      undefined,
      null
    ])
      expect(causeOf(() => copyHostRecord(garbage, count))).toBe(WRONG_KIND)
    expect(copyHostRecord(5, count)).toBe(5)
  })

  // Scenario: a deadline served as a date whose time is a NaN, an infinity, a string, a coerced empty value, a time past
  // the range of a date, a real Invalid Date, and as a Proxy whose `getTime` answers each. Expected: refused. Why: a
  // date that compares false with every instant makes a deadline look over, and `Number('')` is 0: a deadline of 1970.
  it.each([
    ['an API key expiresAt', (value: unknown) => ({ ...apiKeyRecord(), expiresAt: value }), KEY],
    [
      'a workspace deadline',
      (value: unknown) => ({ ...workspaceRecord(), deletionScheduledAt: value }),
      WORKSPACE
    ],
    ['a user createdAt', (value: unknown) => ({ ...userRecord(), createdAt: value }), USER]
  ] as const)('refuses %s that is not a time', (_name, make, contract) => {
    const spellings = [
      Number.NaN,
      Number.POSITIVE_INFINITY,
      'x',
      '5',
      '',
      null,
      false,
      true,
      [],
      {},
      1e20
    ]
    for (const answer of spellings)
      expect(causeOf(() => copyHostRecord(make(timeAs(answer)), contract))).toBe(NOT_A_TIME)
    expect(causeOf(() => copyHostRecord(make(new Date(Number.NaN)), contract))).toBe(NOT_A_TIME)
    expect(copyHostRecord(make(timeAs(5)), contract)).toEqual(make(new Date(5)))
  })

  // Scenario: a date a Proxy of the host answers as, an object that only has the methods of a date, and a Proxy over an
  // object with the chain of a date and none of its state. Expected: the first is copied as the date it answers as, the
  // others are refused. Why: a Proxy has no internal slot, so the chain is what tells it; the methods alone tell nothing.
  it('copies a Proxy of a date and refuses what only looks like one', () => {
    const lookalike = new Proxy({ getTime: (): number => 5, toISOString: (): string => 'x' }, {})
    const forged = new Proxy(Object.create(Date.prototype) as object, {})

    const copy = copyHostRecord({ ...userRecord(), createdAt: timeAs(5) }, USER) as {
      createdAt: Date
    }

    expect(copy.createdAt).toBeInstanceOf(Date)
    expect(copy.createdAt.getTime()).toBe(5)
    expect(causeOf(() => copyHostRecord({ ...userRecord(), createdAt: lookalike }, USER))).toBe(
      WRONG_KIND
    )
    expect(
      causeOf(() => copyHostRecord({ ...userRecord(), createdAt: forged }, USER))
    ).toBeDefined()
  })

  // Scenario: a list of strings served with an element that is no string, as a wrapper and as a non-array. Expected:
  // refused. Why: the scopes of an API key and the recovery codes of an account are compared as strings.
  it('refuses a list of strings that holds anything else, and an answer that is no list', () => {
    for (const garbage of [new String('x'), 1, Symbol('s'), {}, null])
      expect(
        causeOf(() => copyHostRecord({ ...apiKeyRecord(), scopes: ['a', garbage] }, KEY))
      ).toBe(WRONG_KIND)
    expect(causeOf(() => copyHostRecord({ ...apiKeyRecord(), scopes: 'read' }, KEY))).toBe(
      WRONG_KIND
    )
    expect(
      causeOf(() => copyHostRecord({ ...apiKeyRecord(), scopes: new String('read') }, KEY))
    ).toBe(WRONG_KIND)
    const copy = copyHostRecord({ ...apiKeyRecord(), scopes: ['a', 'b'] }, KEY) as {
      scopes: string[]
    }
    expect(copy.scopes).toEqual(['a', 'b'])
  })

  // Scenario: a field the interface requires, absent and served as undefined, and a field it allows to be absent.
  // Expected: the required one is refused, the optional one is simply not there. Why: absent reads as the default of its
  // type, so `mfaEnabled` absent is a user without a second factor.
  it.each([
    ['id', USER, userRecord],
    ['email', USER, userRecord],
    ['name', USER, userRecord],
    ['passwordHash', USER, userRecord],
    ['role', USER, userRecord],
    ['status', USER, userRecord],
    ['tenantId', USER, userRecord],
    ['emailVerified', USER, userRecord],
    ['mfaEnabled', USER, userRecord],
    ['lastLoginAt', USER, userRecord],
    ['createdAt', USER, userRecord],
    ['mfaEnabled', PLATFORM, platformRecord],
    ['passwordHash', PLATFORM, platformRecord],
    ['expiresAt', KEY, apiKeyRecord],
    ['scopes', KEY, apiKeyRecord],
    ['role', MEMBERSHIP, membershipRecord],
    ['status', MEMBERSHIP, membershipRecord]
  ] as const)('refuses a %s that is absent', (field, contract, make) => {
    const absent: Record<string, unknown> = { ...make() }
    Reflect.deleteProperty(absent, field)

    expect(causeOf(() => copyHostRecord(absent, contract))).toBe(ABSENT)
    expect(causeOf(() => copyHostRecord({ ...absent, [field]: undefined }, contract))).toBe(ABSENT)
    expect(
      causeOf(() => copyHostRecord(new Proxy({ ...absent }, { get: () => undefined }), contract))
    ).toBe(ABSENT)
  })

  it('lets a field the interface makes optional be absent, and null where null is promised', () => {
    const user: Record<string, unknown> = { ...userRecord() }

    const copy = copyHostRecord({ ...user, passwordHash: null }, USER) as Record<string, unknown>

    const columns = copyHostRecord(
      { ...user, mfaSecret: null, mfaRecoveryCodes: null, oauthProvider: null },
      USER
    ) as Record<string, unknown>

    expect(Object.hasOwn(copy, 'mfaSecret')).toBe(false)
    expect(Object.hasOwn(copy, 'mfaRecoveryCodes')).toBe(false)
    expect(copy['passwordHash']).toBeNull()
    expect(columns['mfaSecret']).toBeNull()
    expect(columns['mfaRecoveryCodes']).toBeNull()
    expect(columns['oauthProvider']).toBeNull()
    expect(causeOf(() => copyHostRecord({ ...user, status: null }, USER))).toBe(WRONG_KIND)
    expect(causeOf(() => copyHostRecord({ ...user, mfaEnabled: null }, USER))).toBe(WRONG_KIND)
  })

  // Scenario: a field promised as data, served as a function and as a getter that answers one (an own getter and an
  // inherited one), for the fields that decide an admission. Expected: refused. Why: a field that is dropped reads as
  // absent, and `mfaEnabled` absent is a user without a second factor.
  it.each([
    ['mfaEnabled', USER, userRecord],
    ['status', USER, userRecord],
    ['emailVerified', USER, userRecord],
    ['revokedAt', KEY, apiKeyRecord],
    ['expiresAt', KEY, apiKeyRecord]
  ] as const)(
    'refuses %s served as a function, or as a getter answering one',
    (field, contract, make) => {
      const own = { ...make(), [field]: (): boolean => true }
      const getter = Object.defineProperty({ ...make() }, field, {
        get: () => (): boolean => true,
        enumerable: true
      })
      const { [field]: _served, ...rest }: Record<string, unknown> = { ...make() }
      const inherited = Object.assign(
        Object.create({
          get [field](): () => boolean {
            return (): boolean => true
          }
        }) as object,
        rest
      )

      expect(causeOf(() => copyHostRecord(own, contract))).toBe(WRONG_KIND)
      expect(causeOf(() => copyHostRecord(getter, contract))).toBe(WRONG_KIND)
      expect(causeOf(() => copyHostRecord(inherited, contract))).toBe(WRONG_KIND)
    }
  )

  // Scenario: what a method answers that is no record: a boolean, a string, nothing. Expected: a boolean and a string
  // are read as their kind (a wrapper or a missing answer is refused), and what a method that answers nothing returns
  // is dropped. Why: `markRevoked` answering `new Boolean(false)` would be truthy.
  it('reads the plain answers of a method as their kind', () => {
    const revoked = API_KEY_REPOSITORY_CONTRACT.markRevoked
    const renamed = WORKSPACE_REPOSITORY_CONTRACT.rename
    const last = MEMBERSHIP_REPOSITORY_CONTRACT.getLastActiveWorkspaceId
    const touched = API_KEY_REPOSITORY_CONTRACT.touchLastUsed

    expect(copyHostRecord(true, revoked)).toBe(true)
    expect(copyHostRecord('ok', renamed)).toBe('ok')
    expect(copyHostRecord(null, last)).toBeNull()
    expect(copyHostRecord('w1', last)).toBe('w1')
    expect(copyHostRecord({ ignored: true }, touched)).toBeUndefined()
    expect(copyHostRecord(null, touched)).toBeUndefined()
    for (const garbage of [new Boolean(false), undefined, null, 'true', 1])
      expect(causeOf(() => copyHostRecord(garbage, revoked))).toBe(WRONG_KIND)
    for (const garbage of [new String('ok'), undefined, null, 1])
      expect(causeOf(() => copyHostRecord(garbage, renamed))).toBe(WRONG_KIND)
    expect(causeOf(() => copyHostRecord(undefined, last))).toBe(WRONG_KIND)
  })

  // Scenario: a user whose every field is served through its prototype, with a wrapper where a boolean is promised.
  // Expected: refused as for an own field.
  it('applies the kinds to a field served through a prototype', () => {
    const served = onPrototype({ ...userRecord(), emailVerified: new Boolean(false) })

    expect(causeOf(() => copyHostRecord(served, USER))).toBe(WRONG_KIND)
  })
})
