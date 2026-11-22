/**
 * @fileoverview Named refusals for an option that must be an object or an array and is something
 * else, so a `null` or a scalar is reported by option name instead of as a raw `TypeError`.
 *
 * @layer Config
 */

import { describeReceived } from './describe-received'

/**
 * Requires `value` to be an object that holds settings: not an array and not a function, which a spread
 * and a key read both see as empty.
 *
 * @param label - The option's dotted path.
 * @param value - What the host passed.
 * @throws {Error} Naming the option and the type received, never the content.
 */
export function assertObject(label: string, value: unknown): void {
  if (Object(value) === value && typeof value !== 'function' && !Array.isArray(value)) return
  throw new Error(
    `[BymaxAuthModule] ${label} must be an object (received ${describeReceived(value)}).`
  )
}

/**
 * Requires `value` to be an array.
 *
 * @param label - The option's dotted path.
 * @param value - What the host passed.
 * @throws {Error} Naming the option and the type received, never the content.
 */
export function assertArray(label: string, value: unknown): void {
  if (Array.isArray(value)) return
  throw new Error(
    `[BymaxAuthModule] ${label} must be an array (received ${describeReceived(value)}).`
  )
}

/**
 * Requires every child of a role in a hierarchy to be the name of a role the hierarchy declares.
 *
 * The kind is checked before the value is printed: a child that is not a string is named by what it is, so a
 * `toString` the host wrote never runs and a symbol never throws from a template.
 *
 * @param label - The role's dotted path, such as `roles.hierarchy['ADMIN']`.
 * @param children - The array of children the role lists.
 * @param declared - The role names the hierarchy declares as keys.
 * @throws {Error} Naming the path, and the position and kind of a child that is not a string, or the unknown role.
 */
export function assertKnownChildren(
  label: string,
  children: readonly unknown[],
  declared: ReadonlySet<string>
): void {
  children.forEach((child, position) => {
    if (typeof child !== 'string') {
      throw new Error(
        `[BymaxAuthModule] ${label} must name roles as strings ` +
          `(received ${describeReceived(child)} at position ${position}).`
      )
    }
    if (!declared.has(child)) {
      throw new Error(
        `[BymaxAuthModule] ${label} references unknown role '${child}'. ` +
          `All roles referenced as children must be declared as keys in the hierarchy.`
      )
    }
  })
}
