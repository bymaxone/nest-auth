/**
 * @fileoverview Whose a key is, is judged with the built-ins as they were when the module loaded: replacing them afterwards does
 * not change the answer.
 *
 * @layer Test
 */

import { readOwnOrClass } from './own-or-class'

class Served {
  get served(): string {
    return 'class'
  }
}

describe('readOwnOrClass after the built-ins it uses are replaced', () => {
  // Scenario: `Object.hasOwn`, `Object.getPrototypeOf` and `Reflect.get` replaced by functions that answer wrongly, then the reads of
  // an own key, a key of the class and a key only the root object holds. Expected: the same answers as before the replacement. Why:
  // a flaw that can plant a key can replace a built-in, and the judgement of what the host wrote cannot depend on either.
  it('answers as it did', () => {
    const own = { written: 'own' }
    const instance = Object.assign(new Served(), { extra: 1 })
    const held = { hasOwn: Object.hasOwn, prototypeOf: Object.getPrototypeOf, get: Reflect.get }
    Object.defineProperty(Object.prototype, 'planted', { value: 'root', configurable: true })
    ;(Object as { hasOwn: unknown }).hasOwn = (): boolean => true
    ;(Object as { getPrototypeOf: unknown }).getPrototypeOf = (): null => null
    ;(Reflect as { get: unknown }).get = (): string => 'replaced'
    let answers: unknown[]
    try {
      answers = [
        readOwnOrClass(own, 'written'),
        readOwnOrClass(instance, 'served'),
        readOwnOrClass(own, 'planted')
      ]
    } finally {
      Object.hasOwn = held.hasOwn
      Object.getPrototypeOf = held.prototypeOf
      Reflect.get = held.get
      Reflect.deleteProperty(Object.prototype, 'planted')
    }

    expect(answers).toEqual(['own', 'class', undefined])
  })
})
