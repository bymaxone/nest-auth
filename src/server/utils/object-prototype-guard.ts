/**
 * @fileoverview The root object of the runtime holds what the runtime defines and nothing else, and the library refuses to
 * sign, verify, hash or write a cookie while it holds more.
 *
 * Every plain object inherits from `Object.prototype`, so a key planted there (by a flaw elsewhere in the process, in a JSON
 * the flaw can write) is read as an option, a claim or a cookie attribute by every dependency that copies an object into a
 * new one. The own keys the library puts on what it hands to its dependencies shadow the names it knows; this guard covers
 * the names it does not know. The standard entries are listed by name and each is compared, by value, accessors and
 * enumerability, with what it was when this module loaded, so an entry that is overwritten (`hasOwnProperty`, `toString`, `constructor`) is counted like a new one.
 * The built-ins the decisions are made with (`some`, `includes`, `has`, `get`, the string methods, `Object.keys`) are compared with
 * what they were at load by `builtin-baseline`, and a replaced one refuses the call with a reason of its own.
 * A root that already differed from the standard kinds at load is counted too: the guard refuses on use and never throws
 * from the import.
 *
 * @layer Utility
 */

import { rebaselinePolyfills, replacedBuiltins } from './builtin-baseline'
import {
  ErrorOf,
  captureStack,
  createObject,
  defineKey,
  getDescriptor,
  getKey,
  hasOwn,
  ownKeys
} from './captured-builtins'
import {
  AUTH_ERROR_CODES,
  AUTH_ERROR_MESSAGES,
  AUTH_ERROR_STATUS
} from '../errors/auth-error-codes'
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

const root = Object.prototype

/** The fields of a descriptor, each read only when the descriptor holds it: a descriptor inherits from the root too. */
interface Held {
  value: unknown
  get: unknown
  set: unknown
  enumerable: boolean
}

/** The descriptor of an entry of the root as a record that holds no prototype, or `undefined` when the entry is not there. */
function describe(name: string): Held | undefined {
  const descriptor = getDescriptor(root, name) as Record<string, unknown> | undefined
  if (descriptor === undefined) return undefined
  const held = createObject(null) as Held
  held.value = hasOwn(descriptor, 'value') ? descriptor['value'] : undefined
  held.get = hasOwn(descriptor, 'get') ? descriptor['get'] : undefined
  held.set = hasOwn(descriptor, 'set') ? descriptor['set'] : undefined
  held.enumerable = hasOwn(descriptor, 'enumerable') && descriptor['enumerable'] === true
  return held
}

/** The descriptor each standard entry had at load, by name, in a record that holds no prototype. */
const BASELINE = createObject(null) as Record<string, Held | undefined>
for (let index = 0; index < STANDARD.length; index += 1)
  BASELINE[STANDARD[index] as string] = describe(STANDARD[index] as string)

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
let LOADED_STANDARD = true
for (let index = 0; index < STANDARD.length; index += 1) {
  const name = STANDARD[index] as string
  if (!isStandardKind(name, BASELINE[name])) LOADED_STANDARD = false
}

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
  const keys = ownKeys(root)
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index]
    if (typeof key === 'string' && !same(describe(key), BASELINE[key])) count += 1
  }
  for (let index = 0; index < STANDARD.length; index += 1) {
    const name = STANDARD[index] as string
    if (describe(name) === undefined && BASELINE[name] !== undefined) count += 1
  }
  return count
}

/**
 * Refuses while `Object.prototype` holds an entry, or a built-in is a function, that is not the runtime's own.
 *
 * @throws {AuthException} `auth.internal`, whose cause reports the counts and nothing else.
 */
export function assertRootIsStandard(): void {
  const planted = plantedOnRoot()
  const replaced = replacedBuiltins()
  if (planted > 0 || replaced > 0) throw refusalOf(reasonOf(planted, replaced))
}

/** What the refusal reports: the counts and nothing else, a reason for each of the two ways the runtime can differ. */
function reasonOf(planted: number, replaced: number): string {
  const entries = `Object.prototype holds ${planted} entries that are not the runtime's own`
  const builtins = `${replaced} built-ins are not the runtime's own`
  if (replaced === 0) return entries
  return planted === 0 ? builtins : `${entries}; ${builtins}`
}

/** The mark the refusal carries, so it is recognised without `instanceof`, which calls a live built-in. */
const REFUSAL = Symbol('root-not-standard')

/**
 * The refusal of the library while the runtime differs from its own: `auth.internal`, which no caller turns into another answer.
 * It is never constructed: `refusalOf` makes the object, so no accessor planted on the root can run in a constructor.
 */
export class RootNotStandardException extends AuthException {}

/** A data descriptor, with no prototype: defining a property reads `get`, `set` and `enumerable` through it. */
function dataOf(value: unknown): PropertyDescriptor {
  const descriptor = createObject(null) as PropertyDescriptor
  descriptor.value = value
  descriptor.configurable = true
  descriptor.writable = true
  return descriptor
}

const CODE = AUTH_ERROR_CODES.INTERNAL
const MESSAGE = AUTH_ERROR_MESSAGES[CODE]
const STATUS = AUTH_ERROR_STATUS[CODE]

/**
 * Makes a fresh refusal for `reason`, from references taken when the module loaded. Constructing an exception assigns
 * `response`, `status`, `options`, `message`, `name` and `cause` to the new object, and an accessor planted on the root under one
 * of those names turns the assignment into a `TypeError`, so the object is made with the prototype of the exception and
 * its fields defined as own data. Each refusal is its own object: two requests refused at the same time never see each other's
 * cause, and nothing a caller does to one reaches another.
 */
function refusalOf(reason: string): RootNotStandardException {
  const refusal = createObject(RootNotStandardException.prototype) as RootNotStandardException
  defineKey(refusal, 'response', dataOf({ error: { code: CODE, message: MESSAGE, details: null } }))
  defineKey(refusal, 'status', dataOf(STATUS))
  defineKey(refusal, 'message', dataOf(MESSAGE))
  defineKey(refusal, 'name', dataOf('RootNotStandardException'))
  defineKey(refusal, 'cause', dataOf(new ErrorOf(reason)))
  defineKey(refusal, REFUSAL, dataOf(true))
  captureStack(refusal, refusalOf)
  return refusal
}

/** Whether `error` is the refusal of the guard. */
function isRefusal(error: unknown): error is RootNotStandardException {
  return typeof error === 'object' && error !== null && getKey(error, REFUSAL) === true
}

/**
 * Rethrows `error` when it is the refusal of the guard, and returns for anything else. A `catch` that turns a failure into
 * another answer (a token that did not verify becomes "nothing to blacklist") calls this first, so the refusal is never
 * swallowed into a pass.
 *
 * @param error - What the `try` threw.
 * @throws The refusal itself, when `error` is one.
 */
export function rethrowRefusal(error: unknown): void {
  if (isRefusal(error)) throw error
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
  return isRefusal(error) ? error : new AuthException(code)
}

/**
 * Refuses to start while `Object.prototype` holds an entry, or a built-in is a function, that is not the runtime's own.
 *
 * @throws {Error} Naming the module and reporting the counts, and no name.
 */
export function assertRootIsStandardAtBoot(): void {
  rebaselinePolyfills()
  const planted = plantedOnRoot()
  const replaced = replacedBuiltins()
  if (planted > 0 || replaced > 0)
    throw new ErrorOf(
      `[BymaxAuthModule] ${reasonOf(planted, replaced)}; the module does not start while ` +
        (replaced === 0 ? 'a key is planted there.' : 'a built-in differs.')
    )
}
