/**
 * @fileoverview The built-ins the decisions of the library are made with, as they were when this module loaded.
 *
 * A role check is `Array.prototype.some`, a revocation lookup is `Map.prototype.get`, a tenant match is a string method, and a
 * flaw that can run code in the process can replace any of them after the library loaded. A replaced `some` that answers
 * `true` is a privilege escalation and a replaced `has` is a revoked token that is accepted. The library cannot call a copy
 * of every built-in its services use, so it compares them instead: each function listed here is read again whenever the
 * root guard runs, at the entry of every verification, signature, hash and cookie, and the guard refuses while one is not
 * the function that was there at load.
 *
 * The prototypes are recorded whole (every function an instance of the type inherits), the namespaces by the names the
 * sources call (a spec reads the sources and fails for a name that is not listed), and the global bindings by name.
 * `Promise`, `Date` and `Intl` are not listed: a decision never depends on them, and the test doubles of a host replace all
 * three (a fake clock replaces `Intl` together with `Date`).
 *
 * @layer Utility
 */

import { getDescriptor, getKey, hasOwn, ownKeys, prototypeOf } from './captured-builtins'

/** The functions of the namespaces the sources call, by namespace; a source that calls another name must add it here. */
export const BASELINED_STATICS = {
  Object: [
    'assign',
    'create',
    'defineProperty',
    'entries',
    'freeze',
    'fromEntries',
    'getOwnPropertyDescriptor',
    'getOwnPropertyDescriptors',
    'getPrototypeOf',
    'hasOwn',
    'keys',
    'values'
  ],
  Reflect: ['apply', 'deleteProperty', 'get', 'ownKeys', 'set'],
  Array: ['from', 'isArray'],
  Number: ['isFinite', 'isInteger', 'isNaN', 'isSafeInteger', 'parseFloat'],
  Math: ['ceil', 'floor', 'log2', 'max', 'min'],
  JSON: ['parse', 'stringify'],
  Buffer: ['alloc', 'allocUnsafe', 'byteLength', 'concat', 'from']
} as const satisfies Record<string, readonly string[]>

/** The global bindings the sources name, whose identity is compared. */
export const BASELINED_GLOBALS = [
  'Array',
  'Boolean',
  'Buffer',
  'DataView',
  'Error',
  'Function',
  'JSON',
  'Map',
  'Math',
  'Number',
  'Object',
  'Proxy',
  'RangeError',
  'Reflect',
  'RegExp',
  'Set',
  'String',
  'Symbol',
  'TypeError',
  'Uint8Array',
  'URL',
  'URLSearchParams',
  'WeakMap',
  'isNaN',
  'parseFloat',
  'parseInt',
  'structuredClone'
] as const

const world = globalThis as Record<string, unknown>

/** The instances whose whole prototype is recorded, with the object that holds it. */
const PROTOTYPES: readonly object[] = [
  Array.prototype,
  String.prototype,
  Map.prototype,
  Set.prototype,
  WeakMap.prototype,
  RegExp.prototype,
  Function.prototype,
  prototypeOf([][Symbol.iterator]()) as object,
  prototypeOf(new Map()[Symbol.iterator]()) as object,
  prototypeOf(new Set()[Symbol.iterator]()) as object,
  prototypeOf(''[Symbol.iterator]()) as object
]

// Parallel lists, filled once: the holder, the key and the function each entry held at load.
const holders: object[] = []
const names: PropertyKey[] = []
const originals: unknown[] = []

function record(holder: object, key: PropertyKey): void {
  const descriptor = getDescriptor(holder, key)
  if (descriptor === undefined || typeof descriptor.value !== 'function') return
  // A function that can neither be assigned nor redefined (`Function.prototype[Symbol.hasInstance]`) cannot be replaced.
  if (descriptor.configurable !== true && descriptor.writable !== true) return
  holders[holders.length] = holder
  names[names.length] = key
  originals[originals.length] = descriptor.value
}

for (let index = 0; index < PROTOTYPES.length; index += 1) {
  const holder = PROTOTYPES[index] as object
  const keys = ownKeys(holder)
  for (let at = 0; at < keys.length; at += 1) {
    const key = keys[at] as PropertyKey
    if (key !== 'constructor') record(holder, key)
  }
}
for (const [namespace, list] of Object.entries(BASELINED_STATICS)) {
  const holder = world[namespace] as object
  for (let at = 0; at < list.length; at += 1) record(holder, list[at] as string)
}

const globalOriginals: unknown[] = []
for (let index = 0; index < BASELINED_GLOBALS.length; index += 1)
  globalOriginals[index] = world[BASELINED_GLOBALS[index] as string]

/**
 * Counts the built-ins that are not what they were when this module loaded: a function replaced, turned into an accessor or
 * deleted, and a global binding that names another value.
 *
 * The functions are read through descriptors, so an accessor planted in place of one is counted without being run.
 *
 * @returns The number of such built-ins, zero when every one is the runtime's own.
 */
export function replacedBuiltins(): number {
  let count = 0
  for (let index = 0; index < holders.length; index += 1) {
    const descriptor = getDescriptor(holders[index] as object, names[index] as PropertyKey)
    if (
      descriptor === undefined ||
      !hasOwn(descriptor, 'value') ||
      descriptor['value'] !== originals[index]
    )
      count += 1
  }
  // Read by `Reflect.get` and not through a descriptor: the global object of a `vm` context answers a descriptor through a native
  // interceptor that reads the root, and a planted `get` or `value` there aborts the process.
  for (let index = 0; index < BASELINED_GLOBALS.length; index += 1)
    if (getKey(world, BASELINED_GLOBALS[index] as string) !== globalOriginals[index]) count += 1
  return count
}
