/**
 * @fileoverview The guard is not blinded by a built-in replaced after it loaded: each built-in a check could call, replaced by
 * one that answers nothing, leaves a planted key counted and refused, and leaves a standard root accepted.
 *
 * @layer Test
 */

import { replacedBuiltins } from './builtin-baseline'
import {
  RootNotStandardException,
  assertRootIsStandard,
  plantedOnRoot
} from './object-prototype-guard'

// Loading a module in isolation loads another copy of `reflect-metadata`, which redefines `Reflect.getMetadata`; the baseline of
// the modules under test holds the function the first copy defined, so each case puts it back.
const GET_METADATA = Object.getOwnPropertyDescriptor(Reflect, 'getMetadata') as PropertyDescriptor
afterEach(() => {
  Object.defineProperty(Reflect, 'getMetadata', GET_METADATA)
})

// The test's own copies: the window below replaces built-ins, so nothing inside it may call a live one.
const define = Object.defineProperty
const getOwn = Object.getOwnPropertyDescriptor
const remove = Reflect.deleteProperty
const rootObject = Object.prototype

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

  // Scenario: the same replacements with nothing planted. Expected: the judgement of the root still counts nothing planted, and
  // the guard refuses exactly when the replaced function is one the library baselines, with the reason that names built-ins and
  // not planted entries. Why: a replaced built-in must neither blind the judgement of the root nor make it invent a planted key.
  it.each(REPLACED)(
    'counts no planted key, and a replaced built-in, with %s replaced',
    (_name, holder, key, stub) => {
      let planted = -1
      let swapped = -1
      let refusal: unknown
      replaced(holder, key, stub, () => {
        planted = plantedOnRoot()
        swapped = replacedBuiltins()
        try {
          assertRootIsStandard()
        } catch (error) {
          refusal = error
        }
      })

      expect(planted).toBe(0)
      expect(refusal === undefined).toBe(swapped === 0)
      if (swapped > 0) {
        expect(refusal).toBeInstanceOf(RootNotStandardException)
        expect(((refusal as { cause: Error }).cause as Error).message).toBe(
          `${swapped} built-ins are not the runtime's own`
        )
      }
    }
  )
})

/** The global bindings a check could reach through, each replaced by a binding that answers nothing. */
const GLOBALS = ['Object', 'Reflect', 'Array', 'JSON', 'Map', 'Set', 'Error', 'Symbol'] as const

describe('the guard with a global binding replaced after it loaded', () => {
  // Scenario: each global binding the guard's source names, replaced after the module loaded by one that answers nothing, then a
  // key planted. Expected: the planted entry is still counted and the guard still refuses. Why: the guard calls the copies it
  // took at load, never the binding by name, so replacing the binding cannot blind it.
  it.each(GLOBALS)('still refuses a planted key with the global %s replaced', (name) => {
    const holder = globalThis as Record<string, unknown>
    const held = getOwn(globalThis, name) as PropertyDescriptor
    let counted = -1
    let refusal: unknown
    define(globalThis, name, { value: undefined, configurable: true, writable: true })
    define(rootObject, 'sessions', {
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
      remove(rootObject, 'sessions')
      define(globalThis, name, held)
    }

    expect(holder[name]).toBe(held.value)
    expect(counted).toBe(1)
    expect(refusal).toBeInstanceOf(RootNotStandardException)
  })
})

describe('the guard loaded over a root that already holds an accessor under a name an exception assigns', () => {
  // Scenario: an accessor with no setter planted under each such name before the module loads. Expected: the import does not
  // throw, the guard counts the entry and refuses with the library's refusal (500, auth.internal), and the helper a
  // verification's catch uses passes it through. Why: the guard promises never to throw from the import and to refuse on use.
  // `options` is not a row: with it planted, `@nestjs/common` throws while it builds its own logger, before this module loads.
  it.each(['response', 'status', 'message', 'name', 'cause'] as const)(
    'loads, and refuses on use, with an accessor planted as %s',
    (name) => {
      let loaded: typeof import('./object-prototype-guard') | undefined
      let thrown: unknown
      define(Object.prototype, name, { get: (): number => 1, configurable: true })
      try {
        jest.isolateModules(() => {
          try {
            loaded = jest.requireActual<typeof import('./object-prototype-guard')>(
              './object-prototype-guard'
            )
          } catch (error) {
            thrown = error
          }
        })
        let refusal: unknown
        try {
          loaded?.assertRootIsStandard()
        } catch (error) {
          refusal = error
        }
        expect(thrown).toBeUndefined()
        expect(refusal).toBeInstanceOf(loaded?.RootNotStandardException)
        expect(loaded?.refusedOr(refusal, 'auth.token_invalid')).toBe(refusal)
        expect((refusal as { getStatus(): number }).getStatus()).toBe(500)
        expect((refusal as { getResponse(): unknown }).getResponse()).toEqual({
          error: { code: 'auth.internal', message: expect.any(String), details: null }
        })
        expect(((refusal as { cause: Error }).cause as Error).message).toMatch(/holds \d+ entries/)
      } finally {
        remove(Object.prototype, name)
      }
    }
  )
})
