/**
 * @fileoverview The walk of `assertNoThenOnChain` over the chain of an answer: what it refuses, what it lets through, how far it reads and
 * what the refusal carries.
 *
 * @layer Test
 */

import { assertNoThenOnChain, isRefusal } from './object-prototype-guard'

/** What `assertNoThenOnChain` throws for `value`, or `undefined` when it returns. */
function refusalOf(value: unknown): unknown {
  try {
    assertNoThenOnChain(value)
  } catch (error) {
    return error
  }
  return undefined
}

describe('assertNoThenOnChain', () => {
  // Scenario: a function that holds an own `then`. Expected: the refusal. Why: awaiting a function with a `then` calls it, as it does an object.
  it('refuses a function that holds a then', () => {
    const answer = Object.assign(() => undefined, { then: () => undefined })

    expect(isRefusal(refusalOf(answer))).toBe(true)
  })

  // Scenario: what a promise is never resolved with an object: null and the primitives. Expected: each passes.
  it.each([[null], [undefined], [0], ['then'], [true], [Symbol('then')]])(
    'lets %p through',
    (value) => {
      expect(refusalOf(value)).toBeUndefined()
    }
  )

  // Scenario: an object that holds a `then`, and one that inherits it. Expected: the refusal names what held it and carries no value of the answer.
  it('says on the cause of the refusal that a then was held', () => {
    const inherited = Object.create({ then: () => undefined }) as object

    const refusal = refusalOf(inherited) as { cause: Error }

    expect(isRefusal(refusal)).toBe(true)
    expect(refusal.cause.message).toBe('an answer, or a prototype it inherits from, holds a then')
  })

  // Scenario: a chain that is a cycle, as a proxy whose prototype is itself. Expected: the walk reads exactly 256 levels, stops, and the
  // answer passes. Why: the bound keeps a cycle a host built from looping, and a bound of 257 or none reads more than the contract names.
  it('reads a cycle for exactly 256 levels and then lets the answer pass', () => {
    let reads = 0
    const cycle: object = new Proxy(
      {},
      {
        getPrototypeOf: (): object | null => {
          reads += 1
          if (reads > 1000) throw new Error('the walk did not stop')
          return cycle
        }
      }
    )

    expect(refusalOf(cycle)).toBeUndefined()
    expect(reads).toBe(256)
  })
})
