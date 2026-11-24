/**
 * @fileoverview The load of the captured built-ins when the constructor slot of promises was replaced before it. The language takes its
 * own constructor from that slot, so the load fails instead of building every pin and wait from the host's function.
 *
 * @layer Test
 */

describe('the load of the captured built-ins', () => {
  // Scenario: the slot holds another function when the module loads. Expected: the load throws and names the cause.
  it('fails when the constructor of Promise was replaced before it', () => {
    const own = Object.getOwnPropertyDescriptor(
      Promise.prototype,
      'constructor'
    ) as PropertyDescriptor
    Object.defineProperty(Promise.prototype, 'constructor', { ...own, value: Object })
    try {
      jest.isolateModules(() => {
        expect(() => require('./captured-builtins')).toThrow('constructor of Promise was replaced')
      })
    } finally {
      Object.defineProperty(Promise.prototype, 'constructor', own)
    }
  })

  // Scenario: nothing replaced. Expected: the language's constructor is the one exported.
  it('exports the constructor whose prototype is the promises own', () => {
    jest.isolateModules(() => {
      const loaded = require('./captured-builtins') as typeof import('./captured-builtins')

      expect(loaded.IntrinsicPromise.prototype).toBe(loaded.intrinsicPromisePrototype)
    })
  })
})
