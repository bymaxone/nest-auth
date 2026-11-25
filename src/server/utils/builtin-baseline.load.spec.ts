/**
 * @fileoverview The baseline module loads over a runtime that does not have every built-in on its lists in the usual form: one
 * missing, one that is not a function, and one that cannot be replaced. The import never throws, the entry is left out, and
 * the other entries are compared as usual.
 *
 * Runs in a file of its own: one case makes a built-in permanently non-writable, which the other specs must not inherit.
 *
 * @layer Test
 */

type Baseline = typeof import('./builtin-baseline')

// The test's own copies: nothing here may depend on a built-in the cases below change.
const define = Object.defineProperty
const getOwn = Object.getOwnPropertyDescriptor
const remove = Reflect.deleteProperty

/** Loads a fresh copy of the module, so its record is taken over the runtime as it is now. */
function loadFresh(): Baseline {
  let loaded: Baseline | undefined
  jest.isolateModules(() => {
    loaded = jest.requireActual<Baseline>('./builtin-baseline')
  })
  return loaded as Baseline
}

describe('the baseline loaded over a runtime that differs from the usual one', () => {
  // Scenario: a built-in on the list is missing when the module loads. Expected: the import does not throw, nothing is counted
  // and the entry is not compared. Why: a runtime that lacks a function must not stop the library from loading.
  it('loads with a listed built-in missing', () => {
    const held = getOwn(Set.prototype, 'has') as PropertyDescriptor
    remove(Set.prototype, 'has')
    let counted = -1
    try {
      counted = loadFresh().replacedBuiltins()
    } finally {
      define(Set.prototype, 'has', held)
    }

    expect(counted).toBe(0)
  })

  // Scenario: a listed built-in is a plain value and not a function when the module loads, and is a function again when the count
  // is taken. Expected: the import does not throw, nothing is counted and the entry is not compared. Why: the record holds
  // functions only, so a value that was never one has no original to differ from.
  it('loads with a listed built-in that is not a function', () => {
    const held = getOwn(Number.prototype, 'toFixed') as PropertyDescriptor
    define(Number.prototype, 'toFixed', { ...held, value: 5 })
    let loaded: Baseline
    try {
      loaded = loadFresh()
    } finally {
      define(Number.prototype, 'toFixed', held)
    }

    expect(loaded.replacedBuiltins()).toBe(0)
  })

  // Scenario: a function is planted as `value` on the root when the module loads, and later the getter of a listed accessor is replaced.
  // Expected: the replacement is counted. Why: a descriptor is an ordinary object, so a `value` it inherits from the root must not make
  // the load read an accessor as a method and leave it out of the record.
  it('records an accessor although the root holds a value', () => {
    let loaded: Baseline | undefined
    jest.isolateModules(() => {
      // The imports first, outside the planting: the libraries define their own accessors, and a `value` the root holds would be read
      // into every descriptor they pass to `defineProperty`.
      jest.requireActual('@nestjs/core')
      jest.requireActual('@nestjs/jwt')
      jest.requireActual('../crypto/captured-crypto')
      jest.requireActual('./captured-builtins')
      define(Object.prototype, 'value', { value: () => 0, configurable: true, writable: true })
      try {
        loaded = jest.requireActual<Baseline>('./builtin-baseline')
      } finally {
        remove(Object.prototype, 'value')
      }
    })
    const held = getOwn(Map.prototype, 'size') as PropertyDescriptor
    define(Map.prototype, 'size', { ...held, get: () => 7 })
    let counted = -1
    try {
      counted = (loaded as Baseline).replacedBuiltins()
    } finally {
      define(Map.prototype, 'size', held)
    }

    expect(counted).toBe(1)
  })

  // Scenario: a listed built-in that can be neither assigned nor redefined when the module loads. Expected: the import does not
  // throw, nothing is counted and the entry is not compared, since nothing can replace it. The change it makes to
  // `WeakMap.prototype.set` is permanent for this file.
  it('loads with a listed built-in that cannot be replaced', () => {
    const held = getOwn(WeakMap.prototype, 'set') as PropertyDescriptor
    define(WeakMap.prototype, 'set', { ...held, writable: false, configurable: false })

    expect(loadFresh().replacedBuiltins()).toBe(0)
  })

  // Scenario: `Object.getOwnPropertySymbols` is replaced before the module loads with a function that lists nothing. Then a symbol
  // function is added to a protocol holder, and one the holder had is replaced. Expected: each is counted. Why: a reader that hides
  // symbols must not hide the protocol the language runs from every later decision.
  it.each([
    ['answers an empty list', (): symbol[] => []],
    ['answers nothing', (): undefined => undefined]
  ])('counts protocol symbols while the replaced symbol reader %s', (_label, reader) => {
    const held = getOwn(Object, 'getOwnPropertySymbols') as PropertyDescriptor
    const replace = getOwn(RegExp.prototype, Symbol.replace) as PropertyDescriptor
    const added = Symbol('added-protocol')
    let loaded: Baseline
    define(Object, 'getOwnPropertySymbols', { ...held, value: reader })
    try {
      loaded = loadFresh()
    } finally {
      define(Object, 'getOwnPropertySymbols', held)
    }
    const before = loaded.replacedBuiltins()
    let afterAdded = -1
    let afterReplaced = -1
    try {
      define(RegExp.prototype, added, { value: (): void => {}, configurable: true })
      afterAdded = loaded.replacedBuiltins()
      remove(RegExp.prototype, added)
      define(RegExp.prototype, Symbol.replace, { ...replace, value: (): string => '' })
      afterReplaced = loaded.replacedBuiltins()
    } finally {
      remove(RegExp.prototype, added)
      define(RegExp.prototype, Symbol.replace, replace)
    }

    expect([afterAdded - before, afterReplaced - before]).toEqual([1, 1])
  })

  // Scenario: `Object.getOwnPropertySymbols` is replaced before the module loads with a function that lists another symbol where
  // `RegExp.prototype` has `Symbol.match`, so the count is the same. Then `Symbol.match` is replaced. Expected: it is counted.
  // Why: the symbols are compared one by one, not by how many there are.
  it('counts a replaced protocol function whose key the symbol reader swaps for another', () => {
    const native = Object.getOwnPropertySymbols
    const held = getOwn(Object, 'getOwnPropertySymbols') as PropertyDescriptor
    const match = getOwn(RegExp.prototype, Symbol.match) as PropertyDescriptor
    const other = Symbol('listed-instead')
    const swap = (value: object): symbol[] =>
      native(value).map((key) => (value === RegExp.prototype && key === Symbol.match ? other : key))
    let baseline: Baseline
    define(Object, 'getOwnPropertySymbols', { ...held, value: swap })
    try {
      baseline = loadFresh()
    } finally {
      define(Object, 'getOwnPropertySymbols', held)
    }
    const before = baseline.replacedBuiltins()
    try {
      define(RegExp.prototype, Symbol.match, { ...match, value: (): null => null })

      expect(baseline.replacedBuiltins() - before).toBe(1)
    } finally {
      define(RegExp.prototype, Symbol.match, match)
    }
  })

  // Scenario: `Object.getOwnPropertySymbols` is replaced before the module loads with a function that answers nothing for
  // `Number.prototype`, which has no symbol key, and the real list for every other holder. Expected: the module loads and
  // counts nothing. Why: an answer that is no list is not used, whatever the holder has.
  it('loads when the symbol reader answers nothing for a holder without symbol keys', () => {
    const native = Object.getOwnPropertySymbols
    const held = getOwn(Object, 'getOwnPropertySymbols') as PropertyDescriptor
    const silent = (value: object): symbol[] | undefined =>
      value === Number.prototype ? undefined : native(value)
    let baseline: Baseline
    define(Object, 'getOwnPropertySymbols', { ...held, value: silent })
    try {
      baseline = loadFresh()
    } finally {
      define(Object, 'getOwnPropertySymbols', held)
    }

    expect(baseline.replacedBuiltins()).toBe(0)
  })

  // Scenario: `Object.getOwnPropertySymbols` is replaced before the module loads with a function that counts its calls and
  // answers as the native one. Expected: the comparison calls it. Why: the cheaper reader is used when it lists every symbol.
  it('reads the symbol keys with the symbol reader when it lists every one', () => {
    const native = Object.getOwnPropertySymbols
    const held = getOwn(Object, 'getOwnPropertySymbols') as PropertyDescriptor
    const spy = jest.fn((value: object): symbol[] => native(value))
    let baseline: Baseline
    define(Object, 'getOwnPropertySymbols', { ...held, value: spy })
    try {
      baseline = loadFresh()
    } finally {
      define(Object, 'getOwnPropertySymbols', held)
    }
    spy.mockClear()
    baseline.replacedBuiltins()

    expect(spy).toHaveBeenCalled()
  })

  // Scenario: `Object.getOwnPropertySymbols` is replaced before the module loads with a function that lists one symbol more
  // than `RegExp.prototype` has. Expected: the comparison calls it. Why: it lists every symbol the holder has, so it is used.
  it('keeps a symbol reader that lists a symbol beyond those the holder has', () => {
    const native = Object.getOwnPropertySymbols
    const held = getOwn(Object, 'getOwnPropertySymbols') as PropertyDescriptor
    const extra = Symbol('beyond')
    const spy = jest.fn((value: object): symbol[] =>
      value === RegExp.prototype ? [...native(value), extra] : native(value)
    )
    let baseline: Baseline
    define(Object, 'getOwnPropertySymbols', { ...held, value: spy })
    try {
      baseline = loadFresh()
    } finally {
      define(Object, 'getOwnPropertySymbols', held)
    }
    spy.mockClear()
    baseline.replacedBuiltins()

    expect(spy).toHaveBeenCalled()
  })

  // Scenario: `Reflect.ownKeys` is replaced before the module loads with a function that lists nothing, then a symbol function is
  // added to a protocol holder. Expected: it is counted. Why: a key reader that lists no symbol gives nothing to hold the
  // symbol reader to, so the symbol reader stays in use.
  it('counts an added protocol symbol while the replaced key reader lists nothing', () => {
    const held = getOwn(Reflect, 'ownKeys') as PropertyDescriptor
    const added = Symbol('added-protocol')
    let loaded: Baseline
    define(Reflect, 'ownKeys', { ...held, value: (): (string | symbol)[] => [] })
    try {
      loaded = loadFresh()
    } finally {
      define(Reflect, 'ownKeys', held)
    }
    const before = loaded.replacedBuiltins()
    let after = -1
    try {
      define(RegExp.prototype, added, { value: (): void => {}, configurable: true })
      after = loaded.replacedBuiltins()
    } finally {
      remove(RegExp.prototype, added)
    }

    expect(after - before).toBe(1)
  })
})
