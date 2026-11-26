/**
 * @fileoverview The walk over the recorded built-ins reads each entry's descriptor and then its field directly. Each row below
 * is a way the entry can be wrong, or a way the root can answer for it, and the count must stay one for each.
 *
 * @layer Test
 */

import { replacedBuiltins } from './builtin-baseline'

// The test's own copies: a window replaces built-ins, so nothing inside one may call a live one.
const define = Object.defineProperty
const getOwn = Object.getOwnPropertyDescriptor
const remove = Reflect.deleteProperty

interface Window {
  /** The count taken while the window is open, or the error the walk threw. */
  counted: number | undefined
  thrown: unknown
}

/** Opens a window on one entry, takes the count inside it, and puts everything back. */
function within(
  holder: object,
  key: PropertyKey,
  change: () => void,
  plantOnRoot?: [string, unknown]
): Window {
  const original = getOwn(holder, key) as PropertyDescriptor
  const result: Window = { counted: undefined, thrown: undefined }
  try {
    change()
    if (plantOnRoot !== undefined)
      define(Object.prototype, plantOnRoot[0], {
        value: plantOnRoot[1],
        configurable: true,
        writable: true,
        enumerable: false
      })
    try {
      result.counted = replacedBuiltins()
    } catch (error) {
      result.thrown = error
    }
  } finally {
    if (plantOnRoot !== undefined) remove(Object.prototype, plantOnRoot[0])
    remove(holder, key)
    define(holder, key, original)
  }
  return result
}

const METHOD = 'some'
const ACCESSOR_HOLDER = Map.prototype
const ACCESSOR = 'size'

describe('the walk over the recorded built-ins reads descriptors without trusting the root', () => {
  // Scenario: nothing is changed. Expected: no built-in is counted. Why: the baseline is the runtime's own.
  it('counts nothing in a clean process', () => {
    expect(replacedBuiltins()).toBe(0)
  })

  // Scenario: a method is replaced by another function. Expected: one. Why: the function read is not the one recorded.
  it('counts a method replaced by another function', () => {
    const held: unknown = Reflect.get(Array.prototype, METHOD)
    const window = within(Array.prototype, METHOD, () =>
      define(Array.prototype, METHOD, { value: () => held, writable: true, configurable: true })
    )

    expect(window.thrown).toBeUndefined()
    expect(window.counted).toBe(1)
  })

  // Scenario: a method is replaced by an accessor that answers the original function. Expected: one, and the accessor is not run.
  // Why: an accessor has no own `value`, so the entry is not what it was even though a read would find the original.
  it('counts an accessor in place of a method', () => {
    const held: unknown = Reflect.get(Array.prototype, METHOD)
    let ran = false
    const window = within(Array.prototype, METHOD, () =>
      define(Array.prototype, METHOD, {
        get: () => {
          ran = true
          return held
        },
        configurable: true
      })
    )

    expect(ran).toBe(false)
    expect(window.counted).toBe(1)
  })

  // Scenario: a method is replaced by an accessor, and the original function is planted as `value` on Object.prototype. Expected:
  // one. Why: the descriptor has no own `value`, and a read of `value` finds the planted one through the root; only the own-field
  // test keeps the root from answering for it.
  it('counts an accessor in place of a method while the original is planted as value on the root', () => {
    const held: unknown = Reflect.get(Array.prototype, METHOD)
    const window = within(
      Array.prototype,
      METHOD,
      () => define(Array.prototype, METHOD, { get: () => 0, configurable: true }),
      ['value', held]
    )

    expect(window.counted).toBe(1)
  })

  // Scenario: an accessor is replaced by a data property, and the original getter is planted as `get` on Object.prototype.
  // Expected: one. Why: the same, for the field `get`.
  it('counts a data property in place of an accessor while the original getter is planted as get on the root', () => {
    const getter = (getOwn(ACCESSOR_HOLDER, ACCESSOR) as PropertyDescriptor).get
    const window = within(
      ACCESSOR_HOLDER,
      ACCESSOR,
      () => define(ACCESSOR_HOLDER, ACCESSOR, { value: 3, configurable: true, writable: true }),
      ['get', getter]
    )

    expect(window.counted).toBe(1)
  })

  // Scenario: a recorded method is deleted. Expected: one, and the walk does not throw. Why: a deleted entry has no descriptor, and
  // reading a field of it would throw instead of counting.
  it('counts a deleted entry without throwing', () => {
    const window = within(Array.prototype, METHOD, () => {
      remove(Array.prototype, METHOD)
    })

    expect(window.thrown).toBeUndefined()
    expect(window.counted).toBe(1)
  })

  // Scenario: a recorded accessor is deleted. Expected: one, and the walk does not throw. Why: the same, for the loop over accessors.
  it('counts a deleted accessor without throwing', () => {
    const window = within(ACCESSOR_HOLDER, ACCESSOR, () => {
      remove(ACCESSOR_HOLDER, ACCESSOR)
    })

    expect(window.thrown).toBeUndefined()
    expect(window.counted).toBe(1)
  })
})
