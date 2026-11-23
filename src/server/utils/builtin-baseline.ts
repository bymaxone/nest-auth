/**
 * @fileoverview The built-ins the decisions of the library are made with, as they were when this module loaded.
 *
 * A role check is `Array.prototype.some`, a revocation lookup is `Map.prototype.get`, a tenant match is a string method, the
 * PKCE parameters are written with `URLSearchParams.prototype.set`, and a flaw that can run code in the process can replace any
 * of them after the library loaded. A replaced `some` that answers `true` is a privilege escalation and a replaced `has` is a
 * revoked token that is accepted. The library cannot call a copy of every built-in its sources use, so it compares them
 * instead: each function listed here is read again whenever the root guard runs, and the guard refuses while one is not the
 * function that was there at load. The guard runs at the entry of every verification, signature, hash and cookie, at the
 * start of each guard that decides, and again after each lookup that a guard or a service waits for before it decides.
 *
 * Only what the sources call or read is listed, and a spec reads the sources as syntax and fails in both directions: for a
 * function or accessor they use that is not listed, and for one that is listed and nothing uses. A built-in that a polyfill or a
 * monitor of the host patches and no source calls is therefore never compared. What the library serialises and parses
 * (`JSON`) and what it hashes and compares secrets with (`node:crypto`) is not compared but captured, in
 * `captured-builtins` and `captured-crypto`, so no replacement reaches it. The clock source (the `Date` binding, `Date.now`
 * and `Date.parse`), `Promise` and `Intl` are not compared: the test doubles of a host replace them (a fake clock replaces
 * `Date` and `Intl` together). The methods of the dates themselves (`getTime`, `toISOString`), which the expiry of a key and the
 * reading of a cursor are decided with, are compared.
 *
 * @layer Utility
 */

import { Reflector } from '@nestjs/core'
import { JwtService } from '@nestjs/jwt'

import { getDescriptor, getKey, hasOwn, prototypeOf } from './captured-builtins'
import { nodeCrypto } from '../crypto/captured-crypto'

/** The name under which the iterator function of a type is listed: the key is the well-known symbol. */
export const ITERATOR = '@@iterator'

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
  Reflect: ['apply', 'deleteProperty', 'get', 'set'],
  Array: ['from', 'isArray'],
  Number: ['isFinite', 'isInteger', 'isNaN', 'isSafeInteger', 'parseFloat'],
  Math: ['abs', 'ceil', 'floor', 'log2', 'max', 'min', 'round'],
  JSON: ['parse', 'stringify'],
  Buffer: ['alloc', 'allocUnsafe', 'allocUnsafeSlow', 'byteLength', 'concat', 'from', 'isBuffer']
} as const satisfies Record<string, readonly string[]>

/**
 * The functions and accessors of the prototypes that the sources call or read, by prototype. The iterator functions, which
 * `for...of`, spreads and destructuring call without naming them, are listed apart, in `BASELINED_ITERATORS`.
 */
export const BASELINED_PROTOTYPES = {
  'Array.prototype': [
    'at',
    'concat',
    'fill',
    'find',
    'findIndex',
    'lastIndexOf',
    'push',
    'reverse',
    'slice',
    'sort',
    'splice',
    'includes',
    'indexOf',
    'join',
    'keys',
    'entries',
    'values',
    'forEach',
    'filter',
    'flat',
    'flatMap',
    'map',
    'every',
    'some',
    'reduce',
    'toString'
  ],
  'String.prototype': [
    'at',
    'charAt',
    'charCodeAt',
    'concat',
    'endsWith',
    'includes',
    'indexOf',
    'lastIndexOf',
    'localeCompare',
    'match',
    'padStart',
    'repeat',
    'replace',
    'replaceAll',
    'search',
    'slice',
    'split',
    'sub',
    'substring',
    'startsWith',
    'toString',
    'trim',
    'toLowerCase',
    'toUpperCase',
    'valueOf'
  ],
  'Map.prototype': ['get', 'set', 'has', 'entries', 'forEach', 'keys', 'size', 'values'],
  'Set.prototype': ['has', 'add', 'entries', 'forEach', 'size', 'values', 'keys'],
  'WeakMap.prototype': ['get', 'set', 'has'],
  'RegExp.prototype': ['exec', 'flags', 'source', 'toString', 'test'],
  'Function.prototype': ['apply', 'bind', 'call', 'toString'],
  'Number.prototype': ['toFixed', 'toString', 'valueOf'],
  'URL.prototype': [
    'toString',
    'origin',
    'password',
    'host',
    'hostname',
    'port',
    'pathname',
    'search',
    'searchParams',
    'hash'
  ],
  'URLSearchParams.prototype': [
    'size',
    'get',
    'getAll',
    'has',
    'set',
    'sort',
    'entries',
    'forEach',
    'keys',
    'values',
    'toString'
  ],
  'Buffer.prototype': [
    'readUInt8',
    'writeUInt32BE',
    'copy',
    'toString',
    'compare',
    'indexOf',
    'lastIndexOf',
    'includes',
    'fill',
    'write',
    'slice'
  ],
  'TypedArray.prototype': [
    'buffer',
    'byteLength',
    'length',
    'entries',
    'keys',
    'values',
    'at',
    'every',
    'fill',
    'filter',
    'find',
    'findIndex',
    'forEach',
    'includes',
    'indexOf',
    'join',
    'lastIndexOf',
    'map',
    'reverse',
    'reduce',
    'set',
    'slice',
    'some',
    'sort',
    'toString'
  ],
  'DataView.prototype': ['buffer', 'byteLength'],
  'Date.prototype': ['toString', 'toISOString', 'getTime', 'valueOf']
} as const satisfies Record<string, readonly string[]>

/**
 * The functions the libraries the decisions go through read at each call, by holder. `jwa` calls `crypto.timingSafeEqual` and
 * `crypto.createHmac` inside `verify`, and then `update` and `digest` on the `Hmac` it gets back, and the library's own digests are `createHash` and `createHmac` followed by `update` and
 * `digest`, so a replaced one verifies a forged token, makes a wrong secret hash to the stored digest, or stores another; `Reflector` reads `Reflect.getMetadata`, so a
 * replaced one answers `@Public()` or `@SkipMfa()` for any route. A spec reads the installed `jsonwebtoken`, `jws`, `jwa` and
 * `Reflector` and fails for a name they read that is not listed, and for a method of `JwtService` or `Reflector` that the
 * sources call.
 */
export const BASELINED_DEPENDENCIES = {
  'node:crypto': [
    'KeyObject',
    'createHmac',
    'createPrivateKey',
    'createPublicKey',
    'createSecretKey',
    'createSign',
    'createVerify',
    'timingSafeEqual'
  ],
  'JwtService.prototype': ['sign', 'verify'],
  Reflect: ['getMetadata'],
  'Reflector.prototype': ['get', 'getAllAndOverride'],
  'Cipheriv.prototype': ['final', 'getAuthTag', 'update'],
  'Decipheriv.prototype': ['final', 'setAuthTag', 'update'],
  'Hash.prototype': ['digest', 'update'],
  'Hmac.prototype': ['digest', 'update'],
  'Sign.prototype': ['sign', 'update'],
  'Verify.prototype': ['update', 'verify']
} as const satisfies Record<string, readonly string[]>

/** The iterator protocol the language calls without the sources naming it, by holder: the function that makes the iterator. */
export const BASELINED_ITERATORS = {
  'Array.prototype': [ITERATOR],
  'String.prototype': [ITERATOR],
  'Map.prototype': [ITERATOR],
  'Set.prototype': [ITERATOR],
  'ArrayIterator.prototype': ['next'],
  'StringIterator.prototype': ['next'],
  'MapIterator.prototype': ['next'],
  'SetIterator.prototype': ['next']
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
  'isFinite',
  'isNaN',
  'parseFloat',
  'parseInt',
  'structuredClone'
] as const

const world = globalThis as Record<string, unknown>

/** The prototypes the lists name, by name. */
export const BASELINED_HOLDERS: Record<string, object> = {
  'Array.prototype': Array.prototype,
  'String.prototype': String.prototype,
  'Map.prototype': Map.prototype,
  'Set.prototype': Set.prototype,
  'WeakMap.prototype': WeakMap.prototype,
  'RegExp.prototype': RegExp.prototype,
  'Function.prototype': Function.prototype,
  'Number.prototype': Number.prototype,
  'URL.prototype': URL.prototype,
  'URLSearchParams.prototype': URLSearchParams.prototype,
  'Buffer.prototype': Buffer.prototype,
  'TypedArray.prototype': prototypeOf(Uint8Array.prototype) as object,
  'DataView.prototype': DataView.prototype,
  'Date.prototype': Date.prototype,
  'ArrayIterator.prototype': prototypeOf([][Symbol.iterator]()) as object,
  'MapIterator.prototype': prototypeOf(new Map()[Symbol.iterator]()) as object,
  'SetIterator.prototype': prototypeOf(new Set()[Symbol.iterator]()) as object,
  'StringIterator.prototype': prototypeOf(''[Symbol.iterator]()) as object,
  'node:crypto': nodeCrypto,
  'JwtService.prototype': JwtService.prototype,
  Reflect,
  'Reflector.prototype': Reflector.prototype,
  'Cipheriv.prototype': nodeCrypto.Cipheriv.prototype,
  'Decipheriv.prototype': nodeCrypto.Decipheriv.prototype,
  'Hash.prototype': nodeCrypto.Hash.prototype,
  'Hmac.prototype': nodeCrypto.Hmac.prototype,
  'Sign.prototype': nodeCrypto.Sign.prototype,
  'Verify.prototype': nodeCrypto.Verify.prototype
}

// Parallel lists, filled once: the holder, the key, the field of the descriptor that holds the function (`value` for a method,
// `get` for an accessor) and the function each entry held at load.
const holders: object[] = []
const keys: PropertyKey[] = []
const fields: string[] = []
const originals: unknown[] = []

function record(holder: object, key: PropertyKey): void {
  const descriptor = getDescriptor(holder, key)
  if (descriptor === undefined) return
  // A function that can neither be assigned nor redefined (`Function.prototype[Symbol.hasInstance]`) cannot be replaced.
  if (descriptor.configurable !== true && descriptor.writable !== true) return
  const field = typeof descriptor.value === 'function' ? 'value' : 'get'
  const held = field === 'value' ? descriptor.value : descriptor.get
  if (typeof held !== 'function') return
  holders[holders.length] = holder
  keys[keys.length] = key
  fields[fields.length] = field
  originals[originals.length] = held
}

/** Records the entries of `lists`, each name read from the holder named by its key. */
function recordAll(lists: Record<string, readonly string[]>): void {
  for (const [name, list] of Object.entries(lists))
    for (let at = 0; at < list.length; at += 1) {
      const key = list[at] === ITERATOR ? Symbol.iterator : (list[at] as string)
      record(BASELINED_HOLDERS[name] as object, key)
    }
}

recordAll(BASELINED_PROTOTYPES)
recordAll(BASELINED_ITERATORS)
recordAll(BASELINED_DEPENDENCIES)
for (const [namespace, list] of Object.entries(BASELINED_STATICS))
  for (let at = 0; at < list.length; at += 1) record(world[namespace] as object, list[at] as string)

const globalOriginals: unknown[] = []
for (let index = 0; index < BASELINED_GLOBALS.length; index += 1)
  globalOriginals[index] = world[BASELINED_GLOBALS[index] as string]

/**
 * Takes again the function of the polyfill that decorators load (`Reflect.getMetadata`, and no other function of `Reflect`), which a second copy of
 * `reflect-metadata` replaces while the imports of the application run. Called when the module boots, after those imports,
 * so a host with two copies is not refused for the copy that loaded last; a change after the boot is counted as ever.
 */
export function rebaselinePolyfills(): void {
  for (let index = 0; index < holders.length; index += 1) {
    if (holders[index] !== Reflect || keys[index] !== 'getMetadata') continue
    const descriptor = getDescriptor(holders[index] as object, keys[index] as PropertyKey)
    if (descriptor !== undefined && hasOwn(descriptor, fields[index] as string))
      originals[index] = getKey(descriptor, fields[index] as string)
  }
}

/**
 * Counts the built-ins that are not what they were when this module loaded: a function replaced, turned into an accessor or
 * deleted, an accessor whose getter was replaced, and a global binding that names another value.
 *
 * The functions are read through descriptors, so an accessor planted in place of one is counted without being run.
 *
 * @returns The number of such built-ins, zero when every one is the runtime's own.
 */
export function replacedBuiltins(): number {
  let count = 0
  for (let index = 0; index < holders.length; index += 1) {
    const descriptor = getDescriptor(holders[index] as object, keys[index] as PropertyKey)
    const field = fields[index] as string
    if (
      descriptor === undefined ||
      !hasOwn(descriptor, field) ||
      getKey(descriptor, field) !== originals[index]
    )
      count += 1
  }
  // Read by `Reflect.get` and not through a descriptor: the global object of a `vm` context answers a descriptor through a native
  // interceptor that reads the root, and a planted `get` or `value` there aborts the process.
  for (let index = 0; index < BASELINED_GLOBALS.length; index += 1)
    if (getKey(world, BASELINED_GLOBALS[index] as string) !== globalOriginals[index]) count += 1
  return count
}
