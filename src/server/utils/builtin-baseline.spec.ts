/**
 * @fileoverview The built-ins the decisions of the library are made with are compared with what they were at load: a function
 * replaced, turned into an accessor or deleted, and a global binding that names another value, are each counted, and the
 * guard refuses while one is.
 *
 * @layer Test
 */

import { BASELINED_GLOBALS, BASELINED_STATICS, replacedBuiltins } from './builtin-baseline'

// The test's own copies: the windows below replace built-ins, so nothing inside one may call a live one.
const define = Object.defineProperty
const getOwn = Object.getOwnPropertyDescriptor
const keysOf = Reflect.ownKeys
const world = globalThis as Record<string, unknown>

/** The prototypes the module records whole, found the same way it finds them. */
const PROTOTYPES: [string, object][] = [
  ['Array.prototype', Array.prototype],
  ['String.prototype', String.prototype],
  ['Map.prototype', Map.prototype],
  ['Set.prototype', Set.prototype],
  ['WeakMap.prototype', WeakMap.prototype],
  ['RegExp.prototype', RegExp.prototype],
  ['Function.prototype', Function.prototype],
  ['ArrayIterator.prototype', Object.getPrototypeOf([][Symbol.iterator]()) as object],
  ['MapIterator.prototype', Object.getPrototypeOf(new Map()[Symbol.iterator]()) as object],
  ['SetIterator.prototype', Object.getPrototypeOf(new Set()[Symbol.iterator]()) as object],
  ['StringIterator.prototype', Object.getPrototypeOf(''[Symbol.iterator]()) as object]
]

/** Every `[label, holder, key]` the module records on a function. */
function entries(): [string, object, PropertyKey][] {
  const found: [string, object, PropertyKey][] = []
  for (const [name, holder] of PROTOTYPES)
    for (const key of keysOf(holder)) {
      const descriptor = getOwn(holder, key)
      if (
        key !== 'constructor' &&
        typeof descriptor?.value === 'function' &&
        (descriptor.configurable === true || descriptor.writable === true)
      )
        found.push([`${name}.${String(key)}`, holder, key])
    }
  for (const [namespace, list] of Object.entries(BASELINED_STATICS))
    for (const name of list) found.push([`${namespace}.${name}`, world[namespace] as object, name])
  return found
}

/** Runs `run` with `key` of `holder` changed to `descriptor`, and puts it back. */
function changed(
  holder: object,
  key: PropertyKey,
  descriptor: PropertyDescriptor,
  run: () => void
): void {
  const held = getOwn(holder, key) as PropertyDescriptor
  define(holder, key, { configurable: true, ...descriptor })
  try {
    run()
  } finally {
    define(holder, key, held)
  }
}

describe('the built-ins the library baselines', () => {
  // Scenario: nothing replaced. Expected: none counted. Why: a clean process must never be refused.
  it("counts none in a process whose built-ins are the runtime's own", () => {
    expect(replacedBuiltins()).toBe(0)
  })

  // Scenario: the list of entries the module records, enumerated here independently. Expected: it holds the functions the
  // services decide with. Why: a list that quietly lost its prototypes would count nothing and refuse nothing.
  it('records the functions that decisions are made with', () => {
    const labels = entries().map(([label]) => label)

    expect(labels).toEqual(
      expect.arrayContaining([
        'Array.prototype.some',
        'Array.prototype.includes',
        'Set.prototype.has',
        'Map.prototype.get',
        'String.prototype.startsWith',
        'Object.keys',
        'Reflect.get',
        'JSON.parse'
      ])
    )
    expect(labels.length).toBeGreaterThan(150)
  })

  // Scenario: each recorded function replaced, in turn, by another function. Expected: exactly one built-in is counted while it
  // is replaced and none once it is put back. Why: a decision made with a replaced `some` or `has` must be refused.
  it.each(entries())('counts %s when it is replaced', (_label, holder, key) => {
    let counted = -1
    changed(holder, key, { value: () => undefined, writable: true }, () => {
      counted = replacedBuiltins()
    })

    expect(counted).toBe(1)
    expect(replacedBuiltins()).toBe(0)
  })

  // Scenario: a recorded function deleted. Expected: counted. Why: a missing built-in is not the runtime's own either.
  it.each([
    ['Array.prototype', Array.prototype, 'some'],
    ['Set.prototype', Set.prototype, 'has'],
    ['Object', Object, 'keys']
  ] as const)('counts %s.%s when it is deleted', (_name, holder, key) => {
    const held = getOwn(holder, key) as PropertyDescriptor
    let counted = -1
    Reflect.deleteProperty(holder, key)
    try {
      counted = replacedBuiltins()
    } finally {
      define(holder, key, held)
    }

    expect(counted).toBe(1)
  })

  // Scenario: a recorded function turned into an accessor that records whether it ran. Expected: counted, and the accessor
  // never runs. Why: the comparison must not hand control to code the flaw wrote.
  it('counts an accessor in place of a function without running it', () => {
    let ran = false
    let counted = -1
    changed(
      Array.prototype,
      'includes',
      {
        get: (): undefined => {
          ran = true
          return undefined
        }
      },
      () => {
        counted = replacedBuiltins()
      }
    )

    expect(counted).toBe(1)
    expect(ran).toBe(false)
  })

  // Scenario: each global binding the module names pointed at another value. Expected: exactly one counted, and none once it is
  // put back. Why: the sources name these bindings, so a replaced one is what a call reaches.
  it.each(BASELINED_GLOBALS)('counts the global %s when it names another value', (name) => {
    const held = world[name]
    let counted = -1
    world[name] = (): undefined => undefined
    try {
      counted = replacedBuiltins()
    } finally {
      world[name] = held
    }

    expect(counted).toBe(1)
    expect(replacedBuiltins()).toBe(0)
  })
})
