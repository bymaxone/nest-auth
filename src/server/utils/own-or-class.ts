/**
 * @fileoverview Reading a key of an object the host wrote: from the object itself or from the class it is an instance of,
 * and never from the root object of the runtime.
 *
 * @layer Utility
 */

// Captured at load, so a later replacement of these built-ins cannot change whose a key is judged to be.
const hasOwn = Object.hasOwn
const prototypeOf = Object.getPrototypeOf
const getKey = Reflect.get

/**
 * Reads one key of an object as the host wrote it: from the object itself or from the class it is an instance of, and
 * never from the runtime's root object. A key planted on `Object.prototype` is not something the host wrote, so it must not reach an
 * option or a field the host left unwritten; a Proxy answers for itself.
 *
 * @param group - The object, of any prototype.
 * @param key - The key to read.
 * @returns The value the host gave, or `undefined` when the host wrote none.
 */
export function readOwnOrClass(group: object, key: string): unknown {
  for (let holder: object | null = group; holder !== null; holder = prototypeOf(holder)) {
    if (!hasOwn(holder, key)) continue
    // The first holder decides, and the root object is never read: a getter planted there does not run.
    return holder !== group && prototypeOf(holder) === null ? undefined : getKey(group, key)
  }
  return getKey(group, key)
}
