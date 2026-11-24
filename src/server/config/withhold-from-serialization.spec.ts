/**
 * @fileoverview The withholding of a key reads the descriptor of the property for its own fields only.
 *
 * @layer Test
 */

import { withholdFromSerialization } from './resolved-options'

describe('withholdFromSerialization', () => {
  // Scenario: a property that is an accessor. Expected: the withheld getter answers `undefined`, as the descriptor of an accessor holds
  // no `value` of its own. A `value` planted on `Object.prototype` cannot be tried here: `Object.defineProperty` reads its own
  // descriptor argument through the root, so the plant would end the call before the read this row is about.
  it('answers undefined for an accessor, which has no value of its own', () => {
    const target = {}
    Object.defineProperty(target, 'key', { get: () => 'real', configurable: true })

    withholdFromSerialization(target, 'key')

    expect(Reflect.get(target, 'key')).toBeUndefined()
  })

  // Scenario: a data property. Expected: the value is kept and the key no longer enumerates.
  it('keeps the value of a data property and hides it from enumeration', () => {
    const target = { key: 'secret' }

    withholdFromSerialization(target, 'key')

    expect({ value: Reflect.get(target, 'key'), keys: Object.keys(target) }).toEqual({
      value: 'secret',
      keys: []
    })
  })
})
