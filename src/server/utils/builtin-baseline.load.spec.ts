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

  // Scenario: a listed built-in is a plain value and not a function when the module loads. Expected: the import does not throw,
  // nothing is counted and the entry is not compared.
  it('loads with a listed built-in that is not a function', () => {
    const held = getOwn(Map.prototype, 'get') as PropertyDescriptor
    define(Map.prototype, 'get', { ...held, value: 5 })
    let counted = -1
    try {
      counted = loadFresh().replacedBuiltins()
    } finally {
      define(Map.prototype, 'get', held)
    }

    expect(counted).toBe(0)
  })

  // Scenario: a listed built-in that can be neither assigned nor redefined when the module loads. Expected: the import does not
  // throw, nothing is counted and the entry is not compared, since nothing can replace it. This case is the last, and the change
  // it makes to `WeakMap.prototype.set` is permanent for this file.
  it('loads with a listed built-in that cannot be replaced', () => {
    const held = getOwn(WeakMap.prototype, 'set') as PropertyDescriptor
    define(WeakMap.prototype, 'set', { ...held, writable: false, configurable: false })

    expect(loadFresh().replacedBuiltins()).toBe(0)
  })
})
