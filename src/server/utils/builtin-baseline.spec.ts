/**
 * @fileoverview The built-ins the decisions of the library are made with are compared with what they were at load: a function
 * replaced, turned into an accessor or deleted, and a global binding that names another value, are each counted, and the
 * guard refuses while one is.
 *
 * @layer Test
 */

import {
  BASELINED_GLOBALS,
  BASELINED_HOLDERS,
  BASELINED_ITERATORS,
  BASELINED_PROTOTYPES,
  BASELINED_STATICS,
  ITERATOR,
  replacedBuiltins
} from './builtin-baseline'

// The test's own copies: the windows below replace built-ins, so nothing inside one may call a live one.
const define = Object.defineProperty
const getOwn = Object.getOwnPropertyDescriptor
const keysOf = Reflect.ownKeys
const world = globalThis as Record<string, unknown>

/** Every `[label, holder, key]` the module records, enumerated from its lists. */
function entries(): [string, object, PropertyKey][] {
  const found: [string, object, PropertyKey][] = []
  for (const lists of [BASELINED_PROTOTYPES, BASELINED_ITERATORS] as Record<
    string,
    readonly string[]
  >[])
    for (const [name, list] of Object.entries(lists))
      for (const key of list) {
        const holder = BASELINED_HOLDERS[name] as object
        const at = key === ITERATOR ? Symbol.iterator : key
        const descriptor = getOwn(holder, at)
        if (
          descriptor !== undefined &&
          (descriptor.configurable === true || descriptor.writable === true)
        )
          found.push([`${name}.${key}`, holder, at])
      }
  for (const [namespace, list] of Object.entries(BASELINED_STATICS))
    for (const name of list) found.push([`${namespace}.${name}`, world[namespace] as object, name])
  return found
}

/** What replaces the entry: a function for a method, an accessor with a different getter for an accessor. */
function replacementFor(holder: object, key: PropertyKey): PropertyDescriptor {
  const held = getOwn(holder, key) as PropertyDescriptor
  return typeof held.value === 'function'
    ? { value: () => undefined, writable: true }
    : { get: () => undefined }
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
        'URLSearchParams.prototype.set',
        'URL.prototype.origin',
        'Buffer.prototype.readUInt8'
      ])
    )
    expect(labels.length).toBeGreaterThan(150)
    expect(labels.length).toBeLessThan(260)
  })

  // Scenario: each recorded function replaced, in turn, by another function. Expected: exactly one built-in is counted while it
  // is replaced and none once it is put back. Why: a decision made with a replaced `some` or `has` must be refused.
  it.each(entries())('counts %s when it is replaced', (_label, holder, key) => {
    let counted = -1
    changed(holder, key, replacementFor(holder, key), () => {
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

  // Scenario: functions that no source calls (a method a polyfill adds or patches, an HTML string method, the whole of `JSON`
  // which the library captures) replaced. Expected: none counted. Why: a built-in nothing calls must never make a healthy
  // process refuse, and what is captured needs no comparison.
  it.each([
    ['Array.prototype', Array.prototype, 'copyWithin'],
    ['String.prototype', String.prototype, 'anchor'],
    ['Map.prototype', Map.prototype, 'clear'],
    ['Object', Object, 'getOwnPropertyNames'],
    ['JSON', JSON, 'stringify'],
    ['JSON', JSON, 'parse']
  ] as const)(
    'counts nothing when %s.%s, which no source calls, is replaced',
    (_name, holder, key) => {
      let counted = -1
      changed(holder, key, { value: () => undefined, writable: true }, () => {
        counted = replacedBuiltins()
      })

      expect(counted).toBe(0)
    }
  )

  // Scenario: an accessor of a prototype that the sources read (`Map.prototype.size`, `URL.prototype.origin`) given another
  // getter. Expected: counted. Why: a replaced `size` or `origin` answers a decision just as a replaced method does.
  it.each([
    ['Map.prototype.size', () => Map.prototype, 'size'],
    ['URL.prototype.origin', () => URL.prototype, 'origin'],
    [
      'TypedArray.prototype.length',
      () => Object.getPrototypeOf(Uint8Array.prototype) as object,
      'length'
    ]
  ] as const)('counts the accessor %s when its getter is replaced', (_label, holderOf, key) => {
    let counted = -1
    changed(holderOf(), key, { get: () => 0 }, () => {
      counted = replacedBuiltins()
    })

    expect(counted).toBe(1)
  })
})
