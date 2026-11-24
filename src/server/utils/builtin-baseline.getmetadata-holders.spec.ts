/**
 * @fileoverview A function named like the one the polyfill defines, planted on a holder other than `Reflect` before the module
 * loads: the baseline records none of them, so taking the polyfill again at boot never touches one.
 *
 * @layer Test
 */

export {}

const define = Object.defineProperty
const getOwn = Object.getOwnPropertyDescriptor
const world = globalThis as Record<string, unknown>

type Baseline = typeof import('./builtin-baseline')

// Loading the module loads the polyfill, so the function is read after that.
jest.requireActual<Baseline>('./builtin-baseline')
const GET_METADATA = getOwn(Reflect, 'getMetadata') as PropertyDescriptor

/** Every holder the lists name, but `Reflect`, found from the lists themselves, with the root added: a holder the baseline could record. */
function holders(): [string, () => object][] {
  const baseline = jest.requireActual<Baseline>('./builtin-baseline')
  const found: [string, () => object][] = [['Object.prototype', () => Object.prototype]]
  for (const name of Object.keys(baseline.BASELINED_HOLDERS))
    if (name !== 'Reflect') found.push([name, () => baseline.BASELINED_HOLDERS[name] as object])
  for (const namespace of Object.keys(baseline.BASELINED_STATICS))
    if (namespace !== 'Reflect') found.push([namespace, () => world[namespace] as object])
  return found
}

/**
 * Plants `key` on `holder` as a function, loads a copy of the module, replaces the function as an import would, and returns the
 * count before and after the module takes the polyfill again.
 */
function replaceAfterLoad(holder: object, key: PropertyKey): [number, number] {
  const planted = { value: () => 'planted', configurable: true, writable: true }
  define(holder, key, planted)
  let result: [number, number] = [-1, -1]
  try {
    jest.isolateModules(() => {
      const copy = jest.requireActual<Baseline>('./builtin-baseline')
      define(holder, key, { ...planted, value: () => 'replaced by an import' })
      const before = copy.replacedBuiltins()
      copy.rebaselinePolyfills()
      result = [before, copy.replacedBuiltins()]
    })
  } finally {
    Reflect.deleteProperty(holder, key)
    // A copy loaded in isolation loads another copy of the polyfill, which redefines the function.
    define(Reflect, 'getMetadata', GET_METADATA)
  }
  return result
}

describe('a function named getMetadata on a holder that is not Reflect', () => {
  // Scenario: the function planted on the root under a string key and under a symbol of that name, the module loads, an import
  // replaces it, and the module takes the polyfill again. Expected: nothing is counted before or after.
  // Why: the baseline holds the functions its lists name, and the root is not one of the holders they name for this key.
  it.each([
    ['a string key', 'getMetadata'],
    ['a symbol key', Symbol('getMetadata')]
  ] as const)('the root records none of it under %s', (_label, key) => {
    expect(replaceAfterLoad(Object.prototype, key)).toEqual([0, 0])
  })

  // Scenario: the same on every holder the lists name and every namespace of the statics. Expected: nothing is counted before or
  // after, for each. Why: taking the polyfill again is for `Reflect.getMetadata` alone, so a table that records this key on
  // another holder would have its replacement absorbed there; this case fails first, and says which holder.
  it.each(holders())('%s records none of it', (_name, holder) => {
    expect(replaceAfterLoad(holder(), 'getMetadata')).toEqual([0, 0])
  })
})
