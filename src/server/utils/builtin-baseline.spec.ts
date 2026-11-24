/**
 * @fileoverview The built-ins the decisions of the library are made with are compared with what they were at load: a function
 * replaced, turned into an accessor or deleted, and a global binding that names another value, are each counted, and the
 * guard refuses while one is.
 *
 * @layer Test
 */

import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { buildSync } from 'esbuild'

import {
  BASELINED_DEPENDENCIES,
  BASELINED_GLOBALS,
  BASELINED_HOLDERS,
  BASELINED_ITERATORS,
  BASELINED_PROTOTYPES,
  BASELINED_STATICS,
  BASELINED_CONSTRUCTORS,
  BASELINED_REGEXP_ACCESSORS,
  ITERATOR,
  PROTOCOL_HOLDERS,
  rebaselinePolyfills,
  replacedBuiltins,
  SPECIES_CONSTRUCTORS
} from './builtin-baseline'
import { IntrinsicPromise } from './captured-builtins'
import { assertRootIsStandard, assertRootIsStandardAtBoot } from './object-prototype-guard'

// The test's own copies: the windows below replace built-ins, so nothing inside one may call a live one.
const define = Object.defineProperty
const getOwn = Object.getOwnPropertyDescriptor
const keysOf = Reflect.ownKeys
const world = globalThis as Record<string, unknown>

/** Every `[label, holder, key]` the module records, enumerated from its lists. */
function entries(): [string, object, PropertyKey][] {
  const found: [string, object, PropertyKey][] = []
  for (const lists of [BASELINED_PROTOTYPES, BASELINED_ITERATORS, BASELINED_DEPENDENCIES] as Record<
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
        'Buffer.prototype.readUInt8',
        'Date.prototype.getTime',
        'node:crypto.timingSafeEqual',
        'node:crypto.createHmac',
        'JwtService.prototype.verify'
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

  // Scenario: functions that neither the sources nor the JWT libraries call (a method a polyfill adds or patches, an HTML string
  // method) replaced. Expected: none counted. Why: a built-in nothing calls must never make a healthy process refuse.
  it.each([
    ['Array.prototype', Array.prototype, 'copyWithin'],
    ['String.prototype', String.prototype, 'anchor'],
    ['Map.prototype', Map.prototype, 'clear'],
    ['Object', Object, 'getOwnPropertyNames']
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

  // Scenario: a plain Node process, where `Buffer` is an accessor of the global object, loads the module and assigns `Buffer`
  // another value. Expected: the getter is the same function and one built-in is counted, and none once it is put back. Why:
  // assigning to an accessor binding changes what its getter answers without changing the getter, so the comparison reads the
  // resolved value. Run in a process of its own because the sandbox of the test runner makes such a binding a plain property
  // the first time it is read.
  it('counts an accessor binding whose value was assigned, though its getter is unchanged', () => {
    const bundle = buildSync({
      entryPoints: [join(__dirname, 'builtin-baseline.ts')],
      bundle: true,
      platform: 'node',
      format: 'cjs',
      packages: 'external',
      write: false
    }).outputFiles[0]?.text as string
    const directory = mkdtempSync(join(tmpdir(), 'builtin-baseline-'))
    const file = join(directory, 'baseline.cjs')
    writeFileSync(file, bundle)
    const script = [
      `const baseline = require(${JSON.stringify(file)})`,
      "const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'Buffer')",
      'const out = { accessor: typeof descriptor.get === "function", clean: baseline.replacedBuiltins() }',
      'const held = globalThis.Buffer',
      'globalThis.Buffer = function () {}',
      "out.sameGetter = Object.getOwnPropertyDescriptor(globalThis, 'Buffer').get === descriptor.get",
      'out.assigned = baseline.replacedBuiltins()',
      'globalThis.Buffer = held',
      'out.restored = baseline.replacedBuiltins()',
      'process.stdout.write(JSON.stringify(out))'
    ].join('\n')
    let result = ''
    try {
      result = execFileSync(process.execPath, ['-e', script], {
        encoding: 'utf8',
        env: { ...process.env, NODE_PATH: join(process.cwd(), 'node_modules') }
      })
    } finally {
      rmSync(directory, { recursive: true, force: true })
    }

    expect(JSON.parse(result)).toEqual({
      accessor: true,
      clean: 0,
      sameGetter: true,
      assigned: 1,
      restored: 0
    })
  })

  describe('the functions of the polyfill that decorators load', () => {
    const GET_METADATA = getOwn(Reflect, 'getMetadata') as PropertyDescriptor

    /** Puts the polyfill back as the first copy defined it and records it again, so no case leaves its stub as the baseline. */
    afterEach(() => {
      define(Reflect, 'getMetadata', GET_METADATA)
      rebaselinePolyfills()
    })

    // Scenario: a second copy of `reflect-metadata` redefines `Reflect.getMetadata` while the imports of the application run, then
    // the module boots, then a third copy replaces it again. Expected: counted before the boot, accepted after it, counted again
    // after the later replacement. Why: a host with two copies must not be refused for the copy that loaded last, and a change
    // after the boot is exactly what the baseline is for.
    it('takes the function again at boot and counts a change after it', () => {
      define(Reflect, 'getMetadata', { ...GET_METADATA, value: () => 'second copy' })
      const before = replacedBuiltins()
      assertRootIsStandardAtBoot()
      const after = replacedBuiltins()
      define(Reflect, 'getMetadata', { ...GET_METADATA, value: () => 'third copy' })
      const later = replacedBuiltins()

      expect({ before, after, later }).toEqual({ before: 1, after: 0, later: 1 })
    })

    // Scenario: `Reflect.get` replaced before the module boots, then the boot. Expected: still counted after it. Why: only the
    // function the polyfill defines is taken again; any other function of `Reflect` that differs at the boot is a replacement.
    it('does not take any other function of Reflect again at boot', () => {
      const get = getOwn(Reflect, 'get') as PropertyDescriptor
      define(Reflect, 'get', { ...get, value: () => undefined })
      let counted = -1
      try {
        assertRootIsStandardAtBoot()
      } catch {
        counted = replacedBuiltins()
      } finally {
        define(Reflect, 'get', get)
      }

      expect(counted).toBe(1)
    })

    // Scenario: the function deleted, then an accessor put in its place, each time with the module booting. Expected: still counted.
    // Why: a function that is gone, or one that answers through a getter, is not a copy of the polyfill to take again.
    it.each([
      ['deleted', undefined],
      ['an accessor', { get: () => undefined, configurable: true }]
    ] as const)('does not take the function again when it is %s', (_how, replacement) => {
      if (replacement === undefined) Reflect.deleteProperty(Reflect, 'getMetadata')
      else define(Reflect, 'getMetadata', replacement)
      rebaselinePolyfills()

      expect(replacedBuiltins()).toBe(1)
    })
  })
})

describe('the protocol the language dispatches through', () => {
  /** Every symbol-keyed function of a protocol holder, found from the holder itself and not from a list. */
  const protocol = PROTOCOL_HOLDERS.flatMap((name): [string, () => object, symbol][] => {
    const holder = BASELINED_HOLDERS[name] as object
    return keysOf(holder)
      .filter((key): key is symbol => typeof key === 'symbol')
      .filter((key) => {
        const descriptor = getOwn(holder, key)
        return (
          typeof descriptor?.value === 'function' &&
          (descriptor.configurable === true || descriptor.writable === true)
        )
      })
      .map((key): [string, () => object, symbol] => [`${name}[${String(key)}]`, () => holder, key])
  })

  it('finds the functions a regular expression and an iteration run', () => {
    const labels = protocol.map(([label]) => label)

    expect(labels).toEqual(
      expect.arrayContaining([
        'RegExp.prototype[Symbol(Symbol.replace)]',
        'RegExp.prototype[Symbol(Symbol.split)]',
        'RegExp.prototype[Symbol(Symbol.match)]',
        'Array.prototype[Symbol(Symbol.iterator)]'
      ])
    )
  })

  // Scenario: each symbol-keyed function of a protocol holder replaced, in turn. Expected: counted once, and none once put back.
  // Why: `'a=b'.replace(/=/g, '')` runs `RegExp.prototype[Symbol.replace]`, which no source names, so a replaced one decides what
  // `jwa` makes of every digest.
  it.each(protocol)('counts %s when it is replaced', (_label, holderOf, key) => {
    let counted = -1
    changed(holderOf(), key, { value: () => undefined, writable: true }, () => {
      counted = replacedBuiltins()
    })

    expect(counted).toBe(1)
    expect(replacedBuiltins()).toBe(0)
  })

  // Scenario: a symbol key added to each protocol holder (`String.prototype[Symbol.split]`, which every `split` with a string
  // separator consults). Expected: counted. Why: an added key replaces no recorded function, so only a comparison of the keys sees it.
  it.each(PROTOCOL_HOLDERS)('counts a symbol key added to %s', (name) => {
    const holder = BASELINED_HOLDERS[name] as object
    const added = Symbol('added')
    define(holder, added, { value: () => undefined, configurable: true })
    let counted = -1
    try {
      counted = replacedBuiltins()
    } finally {
      Reflect.deleteProperty(holder, added)
    }

    expect(counted).toBe(1)
    expect(replacedBuiltins()).toBe(0)
  })

  // Scenario: each accessor the regular expression algorithms read, given another getter. Expected: counted.
  it.each(BASELINED_REGEXP_ACCESSORS)(
    'counts RegExp.prototype.%s when its getter is replaced',
    (name) => {
      let counted = -1
      changed(RegExp.prototype, name, { get: () => false }, () => {
        counted = replacedBuiltins()
      })

      expect(counted).toBe(1)
    }
  )
})

describe('the constructor an instance names, which the species lookup reads first', () => {
  // Scenario: the `constructor` property of the prototype of each constructor whose methods consult the species, replaced by a
  // function. Expected: counted once, and none once restored. Why: `[a, b].map(...)` reads `array.constructor` and then
  // `constructor[Symbol.species]`, so a replaced `Array.prototype.constructor` chooses what every `map` builds, and it is a key of
  // a prototype that no list names and the root snapshot does not cover.
  it.each(SPECIES_CONSTRUCTORS)('counts %s.prototype.constructor when it is replaced', (name) => {
    const prototype = (BASELINED_CONSTRUCTORS[name] as { prototype: object }).prototype
    let counted = -1
    changed(prototype, 'constructor', { value: function Other() {}, writable: true }, () => {
      counted = replacedBuiltins()
    })

    expect(counted).toBe(1)
    expect(replacedBuiltins()).toBe(0)
  })
})

describe('the constructor the buffers name', () => {
  // Scenario: the `constructor` property of `Buffer.prototype` and of `Uint8Array.prototype` replaced. Expected: counted once.
  // Why: `buffer.slice()` reads `constructor` and then the species it inherits from the typed arrays, so a replaced one chooses
  // what the slice of a buffer builds.
  it.each([
    ['Buffer.prototype', () => Buffer.prototype],
    ['Uint8Array.prototype', () => Uint8Array.prototype]
  ] as const)('counts %s.constructor when it is replaced', (_name, holderOf) => {
    let counted = -1
    changed(holderOf(), 'constructor', { value: function Other() {}, writable: true }, () => {
      counted = replacedBuiltins()
    })

    expect(counted).toBe(1)
    expect(replacedBuiltins()).toBe(0)
  })
})

describe('the constructor a promise names', () => {
  // Scenario: the `constructor` property of `Promise.prototype` replaced. Expected: counted once, and none once restored.
  // Why: `await` reads `constructor` of a promise to decide whether it is native, so a replaced one chooses what every wait yields.
  it('counts Promise.prototype.constructor when it is replaced', () => {
    let counted = -1
    changed(
      Promise.prototype,
      'constructor',
      { value: function Other() {}, writable: true },
      () => {
        counted = replacedBuiltins()
      }
    )

    expect(counted).toBe(1)
    expect(replacedBuiltins()).toBe(0)
  })

  // Scenario: the statics and `then` of `Promise` replaced, as the monitors and the test doubles of a host do. Expected: none
  // counted. Why: no source reads them (the sources wait with `await` alone), so the guard must not refuse for them.
  it.each(['all', 'race', 'allSettled', 'any', 'resolve', 'reject'])(
    'does not count Promise.%s when it is replaced',
    (name) => {
      let counted = -1
      changed(Promise, name, { value: function Other() {}, writable: true }, () => {
        counted = replacedBuiltins()
      })

      expect(counted).toBe(0)
    }
  )

  it('does not count Promise.prototype.then when it is replaced', () => {
    let counted = -1
    changed(Promise.prototype, 'then', { value: Promise.prototype.then, writable: true }, () => {
      counted = replacedBuiltins()
    })

    expect(counted).toBe(0)
  })

  // Scenario: a `then` planted on a prototype a value resolves through, then removed. Expected: counted once, none after.
  // Why: resolving a promise with an object asks it for `then`, so a planted one answers for every decision that resolves with one.
  it.each([
    ['Array.prototype', Array.prototype],
    ['Function.prototype', Function.prototype]
  ])('counts a then planted on %s', (_name, holder) => {
    let counted = -1
    Object.defineProperty(holder, 'then', { value: () => undefined, configurable: true })
    try {
      counted = replacedBuiltins()
    } finally {
      Reflect.deleteProperty(holder, 'then')
    }

    expect(counted).toBe(1)
    expect(replacedBuiltins()).toBe(0)
  })

  // Scenario: a `then` planted on the root object, then removed. Expected: the guard refuses while it is there, and not after.
  it('refuses while a then is planted on Object.prototype', () => {
    let refused = false
    Object.defineProperty(Object.prototype, 'then', { value: () => undefined, configurable: true })
    try {
      assertRootIsStandard()
    } catch {
      refused = true
    } finally {
      Reflect.deleteProperty(Object.prototype, 'then')
    }

    expect(refused).toBe(true)
    expect(() => {
      assertRootIsStandard()
    }).not.toThrow()
  })

  // Scenario: the global `Promise` binding replaced by another constructor, as a host's test double does. Expected: none counted,
  // and the helpers still build from the language's own constructor. Why: the binding is not what `await` reads.
  it('builds from the intrinsic constructor when the global binding is replaced', () => {
    const intrinsic = Object.getPrototypeOf(Promise.resolve()).constructor as unknown
    const held = Object.getOwnPropertyDescriptor(globalThis, 'Promise') as PropertyDescriptor
    Object.defineProperty(globalThis, 'Promise', { ...held, value: function Other() {} })
    try {
      expect(replacedBuiltins()).toBe(0)
      expect(IntrinsicPromise).toBe(intrinsic)
    } finally {
      Object.defineProperty(globalThis, 'Promise', held)
    }
  })
})

describe('the species of the constructors', () => {
  // Scenario: the `Symbol.species` accessor of each constructor given another getter, then put back. Expected: counted once, and
  // none once restored. Why: `[a, b].filter(...).map(...)` reads `Array[Symbol.species]` to choose what it builds, so a replaced
  // one decides what the code destructures, and no source names it.
  it.each(SPECIES_CONSTRUCTORS)('counts the species of %s when its getter is replaced', (name) => {
    let counted = -1
    changed(BASELINED_CONSTRUCTORS[name], Symbol.species, { get: () => Array }, () => {
      counted = replacedBuiltins()
    })

    expect(counted).toBe(1)
    expect(replacedBuiltins()).toBe(0)
  })
})
