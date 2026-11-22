/**
 * @fileoverview The guard is not blinded by a built-in replaced after it loaded: each built-in a check could call, replaced by
 * one that answers nothing, leaves a planted key counted and refused, and leaves a standard root accepted.
 *
 * @layer Test
 */

import {
  RootNotStandardException,
  assertRootIsStandard,
  plantedOnRoot
} from './object-prototype-guard'

// The test's own copies: the window below replaces built-ins, so nothing inside it may call a live one.
const define = Object.defineProperty
const getOwn = Object.getOwnPropertyDescriptor
const remove = Reflect.deleteProperty

const empty = (): undefined => undefined
const iteratorOfNothing = function (): { next: () => { done: boolean; value: undefined } } {
  return { next: () => ({ done: true, value: undefined }) }
}

/** Each built-in the guard, the verification and the signature could call, with a replacement that answers nothing. */
const REPLACED: readonly (readonly [string, object, PropertyKey, unknown])[] = [
  ['Object.hasOwn', Object, 'hasOwn', () => true],
  ['Object.hasOwn answering no', Object, 'hasOwn', () => false],
  ['Object.getPrototypeOf', Object, 'getPrototypeOf', () => null],
  ['Object.getOwnPropertyDescriptor', Object, 'getOwnPropertyDescriptor', empty],
  ['Object.getOwnPropertyDescriptors', Object, 'getOwnPropertyDescriptors', () => ({})],
  ['Object.getOwnPropertyNames', Object, 'getOwnPropertyNames', () => []],
  ['Object.keys', Object, 'keys', () => []],
  ['Object.entries', Object, 'entries', () => []],
  ['Object.create', Object, 'create', () => ({})],
  ['Object.assign', Object, 'assign', () => ({})],
  ['Object.freeze', Object, 'freeze', empty],
  ['Reflect.ownKeys', Reflect, 'ownKeys', () => []],
  ['Reflect.get', Reflect, 'get', empty],
  ['Reflect.has', Reflect, 'has', () => false],
  ['the iterator of an array', Array.prototype, Symbol.iterator, iteratorOfNothing],
  ['Array.prototype.every', Array.prototype, 'every', () => true],
  ['Array.prototype.some', Array.prototype, 'some', () => false],
  ['Array.prototype.forEach', Array.prototype, 'forEach', empty],
  ['Array.prototype.map', Array.prototype, 'map', () => []],
  ['Array.prototype.filter', Array.prototype, 'filter', () => []],
  ['Array.prototype.includes', Array.prototype, 'includes', () => true],
  ['Array.prototype.indexOf', Array.prototype, 'indexOf', () => 0],
  ['Map.prototype.get', Map.prototype, 'get', empty],
  ['Map.prototype.has', Map.prototype, 'has', () => true],
  ['Map.prototype.set', Map.prototype, 'set', empty],
  ['Set.prototype.add', Set.prototype, 'add', empty],
  ['Set.prototype.has', Set.prototype, 'has', () => true],
  ['Function.prototype.call', Function.prototype, 'call', empty],
  ['Function.prototype.apply', Function.prototype, 'apply', empty],
  ['Function.prototype.bind', Function.prototype, 'bind', () => empty],
  ['String.prototype.startsWith', String.prototype, 'startsWith', () => true]
]

/** Runs `run` with `key` of `holder` replaced by `stub`, and puts it back. */
function replaced(holder: object, key: PropertyKey, stub: unknown, run: () => void): void {
  const held = getOwn(holder, key) as PropertyDescriptor
  define(holder, key, { value: stub, configurable: true, writable: true })
  try {
    run()
  } finally {
    define(holder, key, held)
  }
}

describe('the guard with a built-in replaced after it loaded', () => {
  // Scenario: each built-in replaced, then a key planted on the root. Expected: the planted entry is counted once and the guard
  // refuses with its own refusal. Why: a check that calls a live built-in is blinded by a flaw that replaces it first.
  it.each(REPLACED)('still refuses a planted key with %s replaced', (_name, holder, key, stub) => {
    let counted = -1
    let refusal: unknown
    replaced(holder, key, stub, () => {
      define(Object.prototype, 'sessions', {
        value: 1,
        configurable: true,
        enumerable: true,
        writable: true
      })
      try {
        counted = plantedOnRoot()
        try {
          assertRootIsStandard()
        } catch (error) {
          refusal = error
        }
      } finally {
        remove(Object.prototype, 'sessions')
      }
    })

    expect(counted).toBe(1)
    expect(refusal).toBeInstanceOf(RootNotStandardException)
  })

  // Scenario: the same replacements with nothing planted. Expected: the root is standard and the guard lets the call through.
  // Why: a replaced built-in must not make a clean process refuse everything either.
  it.each(REPLACED)(
    'still accepts a standard root with %s replaced',
    (_name, holder, key, stub) => {
      let counted = -1
      let refusal: unknown
      replaced(holder, key, stub, () => {
        counted = plantedOnRoot()
        try {
          assertRootIsStandard()
        } catch (error) {
          refusal = error
        }
      })

      expect(counted).toBe(0)
      expect(refusal).toBeUndefined()
    }
  )
})
