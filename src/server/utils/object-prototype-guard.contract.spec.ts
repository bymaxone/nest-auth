/**
 * @fileoverview The words and the shape of the refusal of the library, and the two kinds of built-in the baseline reads that a
 * plain function does not exercise: the iterator of a type, which is keyed by a symbol, and an accessor.
 *
 * @layer Test
 */

import { AUTH_ERROR_CODES, AUTH_ERROR_MESSAGES } from '../errors/auth-error-codes'
import { replacedBuiltins } from './builtin-baseline'
import {
  RootNotStandardException,
  assertRootIsStandard,
  assertRootIsStandardAtBoot
} from './object-prototype-guard'

// The test's own copies: the windows below replace built-ins, so nothing inside one may call a live one.
const define = Object.defineProperty
const getOwn = Object.getOwnPropertyDescriptor
const remove = Reflect.deleteProperty
const PLANTED = 'bymaxPlantedForTheContractSpec'

/** Runs `run` with `key` of `holder` replaced by `stub`, planting a key on the root too when `plant` is set. */
function withReplaced<T>(
  holder: object,
  key: PropertyKey,
  stub: PropertyDescriptor,
  plant: boolean,
  run: () => T
): T {
  const held = getOwn(holder, key) as PropertyDescriptor
  define(holder, key, { ...held, ...stub })
  if (plant) define(Object.prototype, PLANTED, { value: 1, configurable: true })
  try {
    return run()
  } finally {
    if (plant) remove(Object.prototype, PLANTED)
    define(holder, key, held)
  }
}

/** The failure of `run`, or `undefined` when it did not fail. */
function failureOf(run: () => void): unknown {
  try {
    run()
  } catch (error) {
    return error
  }
  return undefined
}

const EVERY = { value: () => true }

describe('the refusal of the library while the runtime differs', () => {
  // Scenario: a key planted on the root and a built-in replaced at once. Expected: the cause names both counts, entries first.
  // Why: each kind is counted on its own and a report that names one hides the other.
  it('reports both counts when a key is planted and a built-in is replaced', () => {
    const refusal = withReplaced(Array.prototype, 'every', EVERY, true, () =>
      failureOf(assertRootIsStandard)
    ) as RootNotStandardException

    expect((refusal.cause as Error).message).toBe(
      "Object.prototype holds 1 entries that are not the runtime's own; 1 built-ins are not the runtime's own"
    )
  })

  // Scenario: the refusal read for its message, its name and the attributes of its fields. Expected: the generic message of
  // `auth.internal`, the name of the class, and fields that are writable and configurable like those of any error.
  // Why: the message is what a client sees, and a field a caller cannot set or delete breaks the code that handles errors.
  it('carries the generic message, its name and ordinary fields', () => {
    const refusal = withReplaced(Array.prototype, 'every', EVERY, false, () =>
      failureOf(assertRootIsStandard)
    ) as RootNotStandardException

    expect(refusal.message).toBe(AUTH_ERROR_MESSAGES[AUTH_ERROR_CODES.INTERNAL])
    expect(refusal.name).toBe('RootNotStandardException')
    for (const field of ['response', 'status', 'message', 'name', 'cause']) {
      expect(getOwn(refusal, field)).toMatchObject({ configurable: true, writable: true })
    }
  })

  // Scenario: the module booted while a built-in is replaced, and while a key is planted too. Expected: it does not start, and
  // the message names what differs. Why: an operator reads it to find the cause.
  it('does not boot while a built-in differs, and says so', () => {
    const builtinOnly = withReplaced(Array.prototype, 'every', EVERY, false, () =>
      failureOf(assertRootIsStandardAtBoot)
    ) as Error
    const both = withReplaced(Array.prototype, 'every', EVERY, true, () =>
      failureOf(assertRootIsStandardAtBoot)
    ) as Error

    expect(builtinOnly.message).toBe(
      "[BymaxAuthModule] 1 built-ins are not the runtime's own; the module does not start while a built-in differs."
    )
    expect(both.message).toBe(
      "[BymaxAuthModule] Object.prototype holds 1 entries that are not the runtime's own; 1 built-ins are not the runtime's own; the module does not start while a built-in differs."
    )
  })
})

describe('what the baseline of built-ins reads beyond a plain function', () => {
  // Scenario: the iterator of arrays replaced. Expected: one built-in is counted. Why: the iterator is keyed by a symbol, so the
  // list names it by a marker, and a list that lost the marker would drop every iterator from the baseline.
  it('counts a replaced iterator', () => {
    const count = withReplaced(
      Array.prototype,
      Symbol.iterator,
      { value: () => undefined },
      false,
      replacedBuiltins
    )

    expect(count).toBe(1)
  })

  // Scenario: the getter of an accessor replaced (`RegExp.prototype.global`). Expected: one built-in is counted. Why: an accessor
  // has no `writable` field and is configurable, and the baseline must still hold it.
  it('counts a replaced getter', () => {
    const count = withReplaced(
      RegExp.prototype,
      'global',
      { get: () => true },
      false,
      replacedBuiltins
    )

    expect(count).toBe(1)
  })
})
