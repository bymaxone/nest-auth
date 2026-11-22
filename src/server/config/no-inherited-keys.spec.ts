/**
 * @fileoverview The copy that holds no prototype keeps what the original held, and nothing falls through for what it
 * did not.
 *
 * @layer Test
 */

import { runInNewContext } from 'node:vm'

import { withoutInheritedKeys } from './no-inherited-keys'

describe('withoutInheritedKeys', () => {
  // Scenario: a plain object holding a group, a list, a function and a class instance. Expected: the objects that are
  // plain have no prototype, at every level, and the list, the function and the instance are the same values. Why: only
  // what a literal or a spread made falls through to the runtime's root object.
  it('removes the prototype of the plain objects and leaves every other value alone', () => {
    class Held {}
    const list = ['a']
    const fn = (): string => 'a'
    const held = new Held()

    const copy = withoutInheritedKeys({ group: { inner: { x: 1 } }, list, fn, held })

    expect(Object.getPrototypeOf(copy)).toBeNull()
    expect(Object.getPrototypeOf(copy.group)).toBeNull()
    expect(Object.getPrototypeOf(copy.group.inner)).toBeNull()
    expect([copy.list, copy.fn, copy.held]).toEqual([list, fn, held])
    expect(copy.list).toBe(list)
    expect(copy.held).toBe(held)
  })

  // Scenario: a key withheld from serialization and a getter, in the original. Expected: the copy keeps the key
  // non-enumerable and the getter a getter. Why: the secrets of the resolved options are withheld that way, and the copy
  // must not make one visible.
  it('keeps the descriptor of each property', () => {
    const original: Record<string, unknown> = { shown: 1 }
    Object.defineProperty(original, 'secret', { value: 's', enumerable: false })
    Object.defineProperty(original, 'live', { get: () => 'now', enumerable: true })

    const copy = withoutInheritedKeys(original)

    expect(Object.keys(copy)).toEqual(['shown', 'live'])
    expect(Object.getOwnPropertyDescriptor(copy, 'secret')?.enumerable).toBe(false)
    expect(Object.getOwnPropertyDescriptor(copy, 'live')?.get).toBeDefined()
    expect(copy['secret']).toBe('s')
  })

  // Scenario: a tree nested deeper than the options ever are. Expected: the levels past the bound are left as they were.
  // Why: the copy is bounded, so a cyclic or hostile tree cannot make it run without end.
  it('stops at its depth bound', () => {
    const deep = { a: { b: { c: { d: { e: 1 } } } } }

    const copy = withoutInheritedKeys(deep)

    expect(Object.getPrototypeOf(copy.a.b.c)).toBeNull()
    expect(Object.getPrototypeOf(copy.a.b.c.d)).toBe(Object.prototype)
  })

  // Scenario: an object from another realm, whose root is not this realm's Object.prototype, and a value that is no object.
  // Expected: the first is copied like a plain object, and a primitive comes back as it is. Why: a plain object is judged
  // by its root having no prototype, not by being this realm's.
  it('copies a plain object of another realm and returns a primitive as it is', () => {
    const foreign: object = runInNewContext('({ a: 1 })') as object

    expect(Object.getPrototypeOf(withoutInheritedKeys(foreign))).toBeNull()
    expect(withoutInheritedKeys('text')).toBe('text')
    expect(withoutInheritedKeys(null)).toBeNull()
  })
})
