/**
 * @fileoverview The root object of the runtime holds what the runtime defines and nothing else, and the library refuses to
 * sign, verify, hash or write a cookie while it holds more.
 *
 * Every plain object inherits from `Object.prototype`, so a key planted there (by a flaw elsewhere in the process, in a JSON
 * the flaw can write) is read as an option, a claim or a cookie attribute by every dependency that copies an object into a
 * new one. The own keys the library puts on what it hands to its dependencies shadow the names it knows; this guard covers
 * the names it does not know. The standard entries are listed by name and each is compared, by value, accessors and
 * enumerability, with what it was when this module loaded, so an entry that is overwritten (`hasOwnProperty`, `toString`, `constructor`) is counted like a new one.
 * A root that already differed from the standard kinds at load is counted too: the guard refuses on use and never throws
 * from the import.
 *
 * @layer Utility
 */

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import type { AuthErrorCode } from '../errors/auth-error-codes'
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
const hasOwn = Object.hasOwn
const getDescriptor = Object.getOwnPropertyDescriptor
const root = Object.prototype

/** The fields of a descriptor, each read only when the descriptor holds it: a descriptor inherits from the root too. */
interface Held {
  readonly value: unknown
  readonly get: unknown
  readonly set: unknown
  readonly enumerable: boolean
}

/** The descriptor of an entry of the root as a record that holds no prototype, or `undefined` when the entry is not there. */
function describe(name: string): Held | undefined {
  const descriptor = getDescriptor(root, name) as Record<string, unknown> | undefined
  if (descriptor === undefined) return undefined
  const field = (key: string): unknown => (hasOwn(descriptor, key) ? descriptor[key] : undefined)
  return Object.assign(Object.create(null) as Held, {
    value: field('value'),
    get: field('get'),
    set: field('set'),
    enumerable: field('enumerable') === true
  })
}

/** The descriptor each standard entry had at load. */
const BASELINE = new Map<string, Held | undefined>(STANDARD.map((name) => [name, describe(name)]))

/** Whether an entry is the kind the runtime defines: a function that is not enumerable, or the accessor of `__proto__`. */
function isStandardKind(name: string, descriptor: Held | undefined): boolean {
  // A runtime started with `--disable-proto=delete` has no `__proto__` at all, which is as standard as having one.
  if (name === '__proto__' && descriptor === undefined) return true
  if (descriptor === undefined || descriptor.enumerable) return false
  return name === '__proto__'
    ? typeof descriptor.get === 'function' && typeof descriptor.set === 'function'
    : typeof descriptor.value === 'function'
}

/** Whether the root was already unlike the runtime's own when this module loaded. */
const LOADED_STANDARD = STANDARD.every((name) => isStandardKind(name, BASELINE.get(name)))

/** Whether two descriptors describe the same entry. */
function same(left: Held | undefined, right: Held | undefined): boolean {
  return (
    left !== undefined &&
    right !== undefined &&
    left.value === right.value &&
    left.get === right.get &&
    left.set === right.set &&
    left.enumerable === right.enumerable
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
    if (typeof key === 'string' && !same(describe(key), BASELINE.get(key))) count += 1
  for (const name of STANDARD)
    if (describe(name) === undefined && BASELINE.get(name) !== undefined) count += 1
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
    throw new RootNotStandardException({
      cause: new Error(`Object.prototype holds ${planted} entries that are not the runtime's own`)
    })
}

/** The refusal of the library while the root object holds a planted entry: `auth.internal`, which no caller turns into another answer. */
export class RootNotStandardException extends AuthException {
  constructor(options: { cause: Error }) {
    super(AUTH_ERROR_CODES.INTERNAL, undefined, options)
  }
}

/**
 * The failure a verification reports: the library's own refusal passes through, so a polluted process answers 500 and does not
 * look like every token being invalid, and anything else is the code the caller gives for a token that did not verify.
 *
 * @param error - What the verification threw.
 * @param code - The code of the failure of a token.
 * @returns The refusal itself, or an `AuthException` with `code`.
 */
export function refusedOr(error: unknown, code: AuthErrorCode): AuthException {
  return error instanceof RootNotStandardException ? error : new AuthException(code)
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
