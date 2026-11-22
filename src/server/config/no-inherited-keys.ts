/**
 * @fileoverview The resolved options hold only what the host wrote and what the library defaulted, and answer nothing
 * else.
 *
 * Every option an auth decision reads is read by property from the resolved options (`options.sessions`,
 * `options.invitations?.enabled`, `group.maxSessionsResolver`). On an object that inherits from `Object.prototype` an
 * option nobody wrote falls through to that prototype, so a key planted there by a library with a prototype-pollution
 * flaw would switch on a feature or weaken a check from outside the configuration. An object with no prototype answers
 * `undefined` for what it does not hold.
 *
 * @layer Config
 */

/** How deep the groups of the options go: the options, a group, a sub-group and a map inside it. */
const MAX_DEPTH = 4

/** Whether `value` is a plain object: one a literal or a spread made, with the runtime's own root as its prototype. */
function isPlain(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null) return false
  const prototype: unknown = Object.getPrototypeOf(value)
  return prototype === null || Object.getPrototypeOf(prototype) === null
}

/**
 * Copies the plain objects of a tree into objects with no prototype, keeping each property's descriptor (a key withheld
 * from serialization stays withheld, a getter stays a getter). Arrays, functions, class instances and every other
 * value are kept as they are.
 *
 * @param value - The resolved options, or a group of them.
 * @param depth - How many levels are already copied.
 * @returns The same tree with no prototype to fall through to.
 */
export function withoutInheritedKeys<T>(value: T, depth = 0): T {
  if (depth >= MAX_DEPTH || !isPlain(value)) return value
  const copy: Record<string, unknown> = Object.create(null) as Record<string, unknown>
  for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
    if ('value' in descriptor) descriptor.value = withoutInheritedKeys(descriptor.value, depth + 1)
    Object.defineProperty(copy, key, descriptor)
  }
  return copy as T
}
