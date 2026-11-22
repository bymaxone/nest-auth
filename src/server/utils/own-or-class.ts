/**
 * @fileoverview Reading a key of an object the host wrote: from the object itself or from the class it is an instance of,
 * and never from the root object of the runtime.
 *
 * @layer Utility
 */

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
  const value: unknown = Reflect.get(group, key)
  if (Object.hasOwn(group, key)) return value
  let root = group
  for (let next = Object.getPrototypeOf(root); next !== null; next = Object.getPrototypeOf(root)) {
    if (Object.getPrototypeOf(next) !== null && Object.hasOwn(next, key)) return value
    root = next
  }
  return Object.hasOwn(root, key) ? undefined : value
}
