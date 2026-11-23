/**
 * @fileoverview A key of the root named like the value of a read past the end of a list: the baseline reads the entries of the
 * root that the language defines, never a name that is not on its list.
 *
 * @layer Test
 */

const define = Object.defineProperty
const remove = Reflect.deleteProperty

describe('the baseline of the root when it loads with an entry named undefined', () => {
  // Scenario: the root already holds an entry named `undefined` when the module loads. Expected: it is counted as one entry that
  // is not the runtime's own, because the baseline holds only the names the runtime defines.
  // Why: a baseline that read one name past its list would record that entry as standard and the check would count none.
  it('counts that entry as not the runtime own', () => {
    define(Object.prototype, 'undefined', { value: 1, configurable: true })
    try {
      let counted = -1
      jest.isolateModules(() => {
        const guard = jest.requireActual<typeof import('./object-prototype-guard')>(
          './object-prototype-guard'
        )
        counted = guard.plantedOnRoot()
      })
      expect(counted).toBe(1)
    } finally {
      remove(Object.prototype, 'undefined')
    }
  })
})
