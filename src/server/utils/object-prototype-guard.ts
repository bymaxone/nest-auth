/**
 * @fileoverview The root object of the runtime holds what the runtime defines and nothing else, and the library refuses to
 * sign, verify, hash or write a cookie while it holds more.
 *
 * Every plain object inherits from `Object.prototype`, so a key planted there (by a flaw elsewhere in the process, in a JSON
 * the flaw can write) is read as an option, a claim or a cookie attribute by every dependency that copies an object into a
 * new one. The own keys the library puts on what it hands to its dependencies shadow the names it knows; this guard covers
 * the names it does not know. The standard entries are listed by name and each is compared with the descriptor it had when
 * this module loaded, so an entry that is overwritten (`hasOwnProperty`, `toString`, `constructor`) is counted like a new one.
 * A root that already differed from the standard kinds at load is counted too: the guard refuses on use and never throws
 * from the import.
 *
 * @layer Utility
 */

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'

/** What the runtime defines on `Object.prototype`. */
const STANDARD = [
  'constructor',
  '__defineGetter__',
  '__defineSetter__',
  'hasOwnProperty',
  '__lookupGetter__',
  '__lookupSetter__',
  'isPrototypeOf',
  'propertyIsEnumerable',
  'toString',
  'valueOf',
  '__proto__',
  'toLocaleString'
] as const

// Captured at load, so a later overwrite of these built-ins cannot change how the root is judged.
const ownKeys = Reflect.ownKeys
const describe = Object.getOwnPropertyDescriptor
const root = Object.prototype

/** The descriptor each standard entry had at load. */
const BASELINE = new Map<string, PropertyDescriptor | undefined>(
  STANDARD.map((name) => [name, describe(root, name)])
)

/** Whether an entry is the kind the runtime defines: a function that is not enumerable, or the accessor of `__proto__`. */
function isStandardKind(name: string, descriptor: PropertyDescriptor | undefined): boolean {
  if (descriptor === undefined || descriptor.enumerable === true) return false
  return name === '__proto__'
    ? typeof descriptor.get === 'function' && typeof descriptor.set === 'function'
    : typeof descriptor.value === 'function'
}

/** Whether the root was already unlike the runtime's own when this module loaded. */
const LOADED_STANDARD = STANDARD.every((name) => isStandardKind(name, BASELINE.get(name)))

/** Whether two descriptors describe the same entry. */
function same(
  left: PropertyDescriptor | undefined,
  right: PropertyDescriptor | undefined
): boolean {
  return (
    left !== undefined &&
    right !== undefined &&
    left.value === right.value &&
    left.get === right.get &&
    left.set === right.set &&
    left.enumerable === right.enumerable &&
    left.writable === right.writable &&
    left.configurable === right.configurable
  )
}

/**
 * Counts the entries of `Object.prototype` that are not the runtime's own: a string key outside the standard set, a standard
 * entry that differs from what it was at load or is gone, and one for a root that was already unlike the runtime's at load.
 *
 * @returns The number of such entries, zero for a standard root.
 */
export function plantedOnRoot(): number {
  let count = LOADED_STANDARD ? 0 : 1
  for (const key of ownKeys(root))
    if (typeof key === 'string' && !same(describe(root, key), BASELINE.get(key))) count += 1
  for (const name of STANDARD) if (describe(root, name) === undefined) count += 1
  return count
}

/**
 * Refuses while `Object.prototype` holds an entry that is not the runtime's own.
 *
 * @throws {AuthException} `auth.internal`, whose cause reports the count and nothing else.
 */
export function assertRootIsStandard(): void {
  const planted = plantedOnRoot()
  if (planted > 0)
    throw new AuthException(AUTH_ERROR_CODES.INTERNAL, undefined, {
      cause: new Error(`Object.prototype holds ${planted} entries that are not the runtime's own`)
    })
}

/**
 * Refuses to start while `Object.prototype` holds an entry that is not the runtime's own.
 *
 * @throws {Error} Naming the module and reporting the count, and no name.
 */
export function assertRootIsStandardAtBoot(): void {
  const planted = plantedOnRoot()
  if (planted > 0)
    throw new Error(
      `[BymaxAuthModule] Object.prototype holds ${planted} entries that are not the runtime's own; ` +
        'the module does not start while a key is planted there.'
    )
}
