/**
 * @fileoverview What an id that only informs may be: a value that names one row and cannot name two, since an id
 * reaches claims, keys and the scope of a query, and an object that prints the same as another would merge two rows.
 *
 * @layer Test
 */

import { runInNewContext } from 'node:vm'

import { membershipRecord, userRecord, workspaceRecord } from './__tests__/host-records'
import { copyHostRecord } from './host-read'
import {
  MEMBERSHIP_REPOSITORY_CONTRACT,
  USER_REPOSITORY_CONTRACT,
  WORKSPACE_REPOSITORY_CONTRACT
} from './repository-contracts'

const WRONG_KIND = 'the answer holds a value that is not the kind its method promises'

const USER = USER_REPOSITORY_CONTRACT.findById
const WORKSPACE = WORKSPACE_REPOSITORY_CONTRACT.findById
const MEMBERSHIP = MEMBERSHIP_REPOSITORY_CONTRACT.find

/** An id type of a driver: an object that prints as the id it holds. */
class ObjectIdLike {
  constructor(private readonly hex: string) {}
  toString(): string {
    return this.hex
  }
}

/** What prints as nothing, or as the same text for every value of its kind. */
class PrintsEmpty {
  toString(): string {
    return ''
  }
}

/** An object that prints as the text it was given. */
class PrintsText {
  constructor(private readonly text: string) {}
  toString(): string {
    return this.text
  }
}

class PrintsAsAnObject {
  toString(): string {
    return '[object Anything]'
  }
}

const NOT_AN_ID: readonly (readonly [string, unknown])[] = [
  ['an empty string', ''],
  ['a Date', new Date(0)],
  ['a Map', new Map()],
  ['a Set', new Set()],
  ['a RegExp', /id/u],
  ['a Promise', Promise.resolve('id')],
  ['a function', () => 'id'],
  ['a boolean', true],
  ['a NaN', Number.NaN],
  ['an infinity', Number.POSITIVE_INFINITY],
  ['a fraction', 1.5],
  ['an unsafe integer', Number.MAX_SAFE_INTEGER + 1],
  ['an array', ['id']],
  ['a plain object', {}],
  ['an object that prints as nothing', new PrintsEmpty()],
  ['an object that prints as an object', new PrintsAsAnObject()],
  ['a blank string', '   '],
  ['a string of line breaks and tabs', '\t\n'],
  ['the text undefined', 'undefined'],
  ['the text null', 'null'],
  ['an object that prints as blank', new PrintsText(' ')],
  ['an object that prints as undefined', new PrintsText('undefined')],
  ['an object that prints as null', new PrintsText('null')],
  ['an Error', new Error('id')],
  ['a Buffer', Buffer.from('id')],
  ['a typed array', new Uint8Array([1, 2])],
  ['a symbol', Symbol('id')],
  ['a bigint', 1n],
  ['a Proxy of an Error', new Proxy(new Error('id'), {})],
  ['an object made from Error.prototype', Object.create(Error.prototype) as object],
  ['an instance of a subclass of Error', new (class DriverError extends Error {})('id')],
  ['a Proxy of a Date', new Proxy(new Date(0), {})],
  ['an object made from Date.prototype', Object.create(Date.prototype) as object],
  ['a Proxy of a RegExp', new Proxy(/id/u, {})],
  ['an object made from RegExp.prototype', Object.create(RegExp.prototype) as object],
  ['a Proxy of a Buffer', new Proxy(Buffer.from('id'), {})],
  ['an object made from Uint8Array.prototype', Object.create(Uint8Array.prototype) as object],
  ['a Date of another realm', runInNewContext('new Date(0)') as object],
  ['a RegExp of another realm', runInNewContext('/id/u') as object],
  ['an Error of another realm', runInNewContext("new Error('id')") as object],
  ['a Uint8Array of another realm', runInNewContext('new Uint8Array([1])') as object]
]

/** The reason a copy ended in, or undefined when it ended in none. */
const causeOf = (thunk: () => unknown): unknown => {
  try {
    thunk()
  } catch (error) {
    return (error as { cause?: Error }).cause?.message
  }
  return undefined
}

describe('an id that only informs', () => {
  // Scenario: the id of a user, a workspace and the workspace of a membership served as each value that would print the
  // same for two rows or as nothing: an empty string, a Date, a Map, a Set, a RegExp, a Promise, a function, a boolean,
  // a NaN, an infinity, a fraction, an integer past the safe range, an array, a plain object, an object that prints as
  // nothing or as `[object ...]`, a symbol and a bigint. Expected: each is refused with the library's reason. Why: two
  // workspaces whose ids are Maps are both `{}` in a claim and in a key, and would be one workspace to whoever scopes by it.
  it.each(NOT_AN_ID)('refuses %s as an id', (_name, id) => {
    const asked = [
      () => copyHostRecord(userRecord({ id: id as never }), USER),
      () => copyHostRecord(workspaceRecord({ id: id as never }), WORKSPACE),
      () => copyHostRecord(membershipRecord({ workspaceId: id as never }), MEMBERSHIP)
    ]

    for (const ask of asked) expect(causeOf(ask)).toBe(WRONG_KIND)
  })

  // Scenario: the ids a driver serves: a string, a safe integer, zero, a negative integer, and an object that prints as
  // its hex. Expected: each is kept as the string it prints as. Why: numeric and ObjectId-like ids are how the databases
  // the library supports key their rows, and a claim, a key and a comparison all take a string, as the interface says.
  it('keeps a string, a safe integer and an object that prints as its id, as a string', () => {
    const objectId = new ObjectIdLike('64b0000000000000000000a1')
    const ids = [
      'w1',
      42,
      0,
      -7,
      objectId,
      '[object custom]',
      ' padded ',
      'nullable',
      'undefined-1'
    ]

    for (const id of ids) {
      const copy = copyHostRecord(workspaceRecord({ id: id as never }), WORKSPACE) as {
        id: unknown
      }

      expect(copy.id).toBe(String(id))
    }
  })

  // Scenario: two workspaces whose ids are Maps, and two whose ids are objects that print as different hex. Expected:
  // the Maps are refused, the objects are kept apart. Why: the Maps would merge, the objects never do.
  it('refuses two workspaces with Map ids and keeps two ObjectId-like ones apart', () => {
    const one = new ObjectIdLike('64b0000000000000000000a1')
    const two = new ObjectIdLike('64b0000000000000000000a2')

    const copies = [one, two].map(
      (id) =>
        copyHostRecord(workspaceRecord({ id: id as never }), WORKSPACE) as { id: ObjectIdLike }
    )

    expect(
      causeOf(() => copyHostRecord(workspaceRecord({ id: new Map() as never }), WORKSPACE))
    ).toBe(WRONG_KIND)
    expect(String(copies[0]?.id)).not.toBe(String(copies[1]?.id))
  })

  // Scenario: an id whose toString throws and one whose toString answers a different text each time. Expected: the throw
  // ends in the internal error with the host's error as its cause; the id is printed once and its first text decides.
  // Why: what is checked is what is kept, and a failure of the host is its failure, not the library's.
  it('prints an object id once, and a toString that throws ends in the internal error', () => {
    let prints = 0
    const flipping = {
      toString: (): string => {
        prints += 1
        return prints === 1 ? 'first' : ''
      }
    }
    class Throws {
      toString(): string {
        throw new Error('host failure')
      }
    }

    const copy = copyHostRecord(
      workspaceRecord({ id: Object.assign(new ObjectIdLike('x'), flipping) as never }),
      WORKSPACE
    )

    expect((copy as { id: unknown }).id).toBe('first')
    expect(prints).toBe(1)
    expect(
      causeOf(() => copyHostRecord(workspaceRecord({ id: new Throws() as never }), WORKSPACE))
    ).toBe('host failure')
  })
})
