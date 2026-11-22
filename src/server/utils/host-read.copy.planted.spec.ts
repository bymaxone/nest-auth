/**
 * @fileoverview A field a record lacks is absent, however the runtime's own object is dressed: a key planted on
 * `Object.prototype` is not a field of the host's record. A strict field the record lacks is refused as absent, an optional
 * one is left out of the copy, a field the record holds or the class of the record serves is kept, and the copy holds
 * no prototype for a planted key to fall through to.
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
import { RECORD_CONTRACTS } from './repository-contracts'

const ABSENT = 'the answer lacks a field its method promises'

/** The record of each contract, complete. */
const RECORDS = {
  user: userRecord,
  platformUser: platformRecord,
  apiKey: apiKeyRecord,
  workspace: workspaceRecord,
  membership: membershipRecord,
  removedMembership: () => ({ workspaceId: 'ws-1', role: 'MEMBER' })
} as const

/** A value of the kind of a field that would pass its reader, and differs from the one the records hold. */
function plantedFor(spec: string, held?: unknown): unknown {
  const base = spec.replace(/[~|?].*$/u, '').replace(/^~/u, '')
  if (base === 'boolean') return held === true ? false : true
  if (base === 'date') return new Date(0)
  if (base === 'strings') return ['planted']
  return 'planted-value'
}

/** Runs `body` with `key` planted on the root object of the process and always takes it away again. */
function withPlanted<T>(key: string, value: unknown, body: () => T): T {
  const held = Object.getOwnPropertyDescriptor(Object.prototype, key)
  Object.defineProperty(Object.prototype, key, {
    value,
    configurable: true,
    enumerable: false,
    writable: true
  })
  try {
    return body()
  } finally {
    if (held === undefined) Reflect.deleteProperty(Object.prototype, key)
    else Object.defineProperty(Object.prototype, key, held)
  }
}

/** The reason a copy ended in, or undefined when it ended in none. */
const causeOf = (thunk: () => unknown): unknown => {
  try {
    thunk()
  } catch (error) {
    return (error as { cause?: Error }).cause?.message
  }
  return undefined
}

const FIELDS = (Object.keys(RECORDS) as (keyof typeof RECORDS)[]).flatMap((kind) =>
  Object.entries(RECORD_CONTRACTS[kind].fields).map(
    ([field, spec]) => [kind, field, spec as string] as const
  )
)

describe('a field the record lacks, with its name planted on Object.prototype', () => {
  // Scenario: every field of every record contract, deleted from a complete record, with its name planted on the root
  // object. Expected: a field the contract requires is refused as absent, and a field the contract allows to be absent is
  // not on the copy. Why: absent must refuse (`mfaEnabled` absent is not off, `role` absent is not an admin), and a planted
  // key is not what the record holds.
  it.each(FIELDS)('%s.%s is absent, not the planted value', (kind, field, spec) => {
    const record: Record<string, unknown> = { ...RECORDS[kind]() }
    Reflect.deleteProperty(record, field)
    const optional = spec.endsWith('?') || spec.startsWith('~')

    const cause = withPlanted(field, plantedFor(spec), () =>
      causeOf(() => copyHostRecord(record, RECORD_CONTRACTS[kind]))
    )
    const copy = optional
      ? withPlanted(field, plantedFor(spec), () => copyHostRecord(record, RECORD_CONTRACTS[kind]))
      : undefined

    if (optional) expect(Reflect.get(copy as object, field)).toBeUndefined()
    else expect(cause).toBe(ABSENT)
  })

  // Scenario: every field of every record contract, held by the record itself, and served by the class the record is an
  // instance of, with a different value planted on the root object. Expected: the copy holds the value of the record. Why:
  // what the host's record or its class serves is the field, and the planted key beside it is not.
  it.each(FIELDS)('%s.%s keeps the value the record or its class holds', (kind, field, spec) => {
    const complete = RECORDS[kind]()
    const own = Reflect.get(complete, field)
    if (own === undefined) return

    const fromOwn = withPlanted(field, plantedFor(spec, own), () =>
      copyHostRecord(complete, RECORD_CONTRACTS[kind])
    )
    const fromClass = withPlanted(field, plantedFor(spec, own), () =>
      copyHostRecord(onPrototype(complete), RECORD_CONTRACTS[kind])
    )

    expect(Reflect.get(fromOwn as object, field)).toEqual(own)
    expect(Reflect.get(fromClass as object, field)).toEqual(own)
  })

  // Scenario: a copy of each record. Expected: it has no prototype. Why: a field the copy does not hold must read as
  // nothing, not as what the root object holds.
  it.each(Object.keys(RECORDS) as (keyof typeof RECORDS)[])(
    'the copy of a %s holds no prototype',
    (kind) => {
      const copy = copyHostRecord(RECORDS[kind](), RECORD_CONTRACTS[kind])

      expect(Object.getPrototypeOf(copy)).toBeNull()
    }
  )
})
