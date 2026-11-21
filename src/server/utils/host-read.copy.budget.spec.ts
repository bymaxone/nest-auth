/**
 * @fileoverview A read follows a bounded number of nodes in all, not only a bounded number in each container: a list
 * of records that each stay under the cap of a container could still hold more than a copy should walk.
 *
 * @layer Test
 */

import { apiKeyRecord } from './__tests__/host-records'
import { copyHostRecord } from './host-read'
import { API_KEY_REPOSITORY_CONTRACT } from './repository-contracts'

const LIST = API_KEY_REPOSITORY_CONTRACT.listByLabel
const TOO_MUCH = 'the answer holds more than the library follows'

/** The nodes a read follows: the elements of lists, the own keys of records and the strings of a list of strings. */
const BUDGET = 1_000_000

/** The keys of an API key record, and its list of scopes of one string. */
const OWN_KEYS = 8
const SCOPES = 1

/** The reason a copy ended in, or undefined when it ended in none. */
const causeOf = (thunk: () => unknown): unknown => {
  try {
    thunk()
  } catch (error) {
    return (error as { cause?: Error }).cause?.message
  }
  return undefined
}

/** `count` API key records, `filler` own keys more on each, each key inside the cap of a container. */
const keysWith = (count: number, filler: number): object[] =>
  Array.from({ length: count }, () => {
    const record: Record<string, unknown> = { ...apiKeyRecord({ scopes: ['a'] }) }
    for (let index = 0; index < filler; index += 1) record[`extra${index}`] = index
    return record
  })

/** The filler of each of `count` records that makes a read follow exactly `nodes` nodes. */
const fillerFor = (count: number, nodes: number): number => nodes / count - 1 - OWN_KEYS - SCOPES

describe('the nodes of a read', () => {
  // Scenario: ten records of a list whose keys and strings add up to exactly the budget, and the same with one key more.
  // Expected: the first is copied whole and the second is refused with the library's reason. Why: each record is inside
  // the cap of a container, and a list of them would otherwise walk as many nodes as a host cared to serve.
  it('copies a read of exactly the budget and refuses one key more', () => {
    const filler = fillerFor(10, BUDGET)
    const exact = keysWith(10, filler)
    const over = keysWith(10, filler)
    ;(over[0] as Record<string, unknown>)['one more'] = 1

    expect(copyHostRecord(exact, LIST)).toHaveLength(10)
    expect(causeOf(() => copyHostRecord(over, LIST))).toBe(TOO_MUCH)
  })

  // Scenario: eleven records whose scopes hold 100000 strings each, a list of strings that is inside the cap of a
  // container. Expected: refused. Why: the strings of a list count as nodes, so they cannot be the way around the budget.
  it('counts the strings of a list of strings', () => {
    const records = Array.from({ length: 11 }, () => ({
      ...apiKeyRecord({ scopes: Array.from({ length: 100_000 }, () => 's') })
    }))

    expect(causeOf(() => copyHostRecord(records, LIST))).toBe(TOO_MUCH)
  })
})
