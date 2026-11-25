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
 * and `Date.parse`) and `Intl` are not compared: the test doubles of a host replace them (a fake clock replaces `Date` and
 * `Intl` together). Of `Promise` only `Promise.prototype.constructor` is compared, because `await` reads it; the statics
 * (`all`, `race`) and `then` are not, since the monitors of a host wrap them, so no decision of the library calls one: they
 * wait with `await` on promises they pinned (`utils/settle`), which attaches a handler without reading `then`, and a spec fails on a
 * static of `Promise` in the sources. The methods of the dates themselves (`getTime`, `toISOString`), which the expiry of a key and the
 * reading of a cursor are decided with, are compared.
 *
 * @layer Utility
 */

import { Reflector } from '@nestjs/core'
import { JwtService } from '@nestjs/jwt'

import {
  IntrinsicPromise,
  getDescriptor,
  getKey,
  hasOwn,
  ownKeys,
  prototypeOf
} from './captured-builtins'
import { nodeCrypto } from '../crypto/captured-crypto'

/** The name under which the iterator function of a type is listed: the key is the well-known symbol. */
// Stryker disable next-line StringLiteral: the marker is read only by `recordAll`, and every holder that names it is a protocol holder, whose symbol keys (the iterator among them) are recorded by the protocol loop, so a marker that matches nothing records the same entries
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

/**
 * The prototypes the language dispatches through without a source naming the function: a regular expression given to `replace`,
 * `split`, `match` or `search` runs `RegExp.prototype[Symbol.replace]` and the rest, `for...of` runs the iterator of its operand,
 * and a primitive is turned into a value through `Symbol.toPrimitive`. Every symbol-keyed function of these is recorded, and a
 * symbol key added to one is counted; a name-based scan of the sources cannot see either.
 */
export const PROTOCOL_HOLDERS = [
  'Array.prototype',
  'Date.prototype',
  'Map.prototype',
  'Number.prototype',
  'RegExp.prototype',
  'Set.prototype',
  'String.prototype',
  'TypedArray.prototype'
] as const

/**
 * The constructors whose `Symbol.species` accessor `map`, `filter`, `slice`, `concat` and `flatMap` of an array, the methods of a
 * typed array, a regular expression's `split` and the copies of a map and a set read to choose what they build. It is an own
 * accessor of the constructor, which neither a prototype nor a namespace list holds, and a replaced one makes every such call
 * build, and the code destructure, what the attacker chose. The lookup reads the `constructor` of the instance first, an own key of
 * its prototype, so that is recorded too.
 */
export const SPECIES_CONSTRUCTORS = [
  'Array',
  'ArrayBuffer',
  'Map',
  'Promise',
  'RegExp',
  'Set',
  'TypedArray'
] as const

/**
 * The classes of the buffers and the byte arrays, whose prototype names the constructor that `buffer.slice()` and the methods of a
 * typed array read first; their species is inherited from `TypedArray`, which `SPECIES_CONSTRUCTORS` records.
 */
export const BUFFER_CONSTRUCTORS = ['Buffer', 'Uint8Array'] as const

/** The constructors named by `SPECIES_CONSTRUCTORS`, by name. */
export const BASELINED_CONSTRUCTORS: Record<(typeof SPECIES_CONSTRUCTORS)[number], object> = {
  Array,
  ArrayBuffer,
  Map,
  Promise: IntrinsicPromise,
  RegExp,
  Set,
  TypedArray: prototypeOf(Uint8Array) as object
}

/** The accessors of `RegExp.prototype` the algorithms of `replace`, `split`, `match` and `search` read for every regular expression. */
export const BASELINED_REGEXP_ACCESSORS = [
  'dotAll',
  'flags',
  'global',
  'hasIndices',
  'ignoreCase',
  'multiline',
  'source',
  'sticky',
  'unicode',
  'unicodeSets'
] as const

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
  // An entry the lists and the protocol both name is recorded once, so a replacement is counted once.
  // Stryker disable next-line EqualityOperator: a read one past the end of the list is `undefined`, which equals no holder
  for (let index = 0; index < holders.length; index += 1)
    if (holders[index] === holder && keys[index] === key) return
  const descriptor = getDescriptor(holder, key)
  if (descriptor === undefined) return
  // Own fields only: a descriptor is an ordinary object, and a `value` or a `get` planted on the root would answer for an accessor.
  const field = hasOwn(descriptor, 'value') ? 'value' : 'get'
  const held = hasOwn(descriptor, field) ? descriptor[field] : undefined
  if (typeof held !== 'function') return
  holders[holders.length] = holder
  keys[keys.length] = key
  fields[fields.length] = field
  originals[originals.length] = held
}

/** Records the entries of `lists`, each name read from the holder named by its key. */
function recordAll(lists: Record<string, readonly string[]>): void {
  for (const [name, list] of Object.entries(lists))
    // Stryker disable next-line EqualityOperator: a read one past the end of the list is `undefined`, which names no property, so `record` finds no descriptor and returns
    for (let at = 0; at < list.length; at += 1) {
      // Stryker disable next-line ConditionalExpression: every holder that names the iterator marker is a protocol holder, whose symbol keys the protocol loop records, so reading the marker as a name records the same entries
      const key = list[at] === ITERATOR ? Symbol.iterator : (list[at] as string)
      record(BASELINED_HOLDERS[name] as object, key)
    }
}

recordAll(BASELINED_PROTOTYPES)
recordAll(BASELINED_ITERATORS)
recordAll(BASELINED_DEPENDENCIES)

// The protocol: each symbol-keyed function of a protocol holder, and the symbols the holder had, to count one that is added.
const protocolHolders: object[] = []
const protocolSymbols: symbol[][] = []
for (let index = 0; index < PROTOCOL_HOLDERS.length; index += 1) {
  const holder = BASELINED_HOLDERS[PROTOCOL_HOLDERS[index] as string] as object
  const known: symbol[] = []
  const present = ownKeys(holder)
  // Stryker disable next-line EqualityOperator: a read one past the end of the list is `undefined`, which is not a symbol and is skipped
  for (let at = 0; at < present.length; at += 1) {
    const key = present[at] as string | symbol
    if (typeof key !== 'symbol') continue
    known[known.length] = key
    record(holder, key)
  }
  protocolHolders[protocolHolders.length] = holder
  protocolSymbols[protocolSymbols.length] = known
}
// Stryker disable next-line EqualityOperator: a read one past the end of the list is `undefined`, which names no property, so `record` finds no descriptor and returns
for (let index = 0; index < BASELINED_REGEXP_ACCESSORS.length; index += 1)
  record(RegExp.prototype, BASELINED_REGEXP_ACCESSORS[index] as string)
for (let index = 0; index < SPECIES_CONSTRUCTORS.length; index += 1) {
  // The lookup reads the `constructor` of the instance (an own key of its prototype) and only then the species of that constructor.
  const constructor =
    BASELINED_CONSTRUCTORS[SPECIES_CONSTRUCTORS[index] as (typeof SPECIES_CONSTRUCTORS)[number]]
  record(constructor, Symbol.species)
  record((constructor as { prototype: object }).prototype, 'constructor')
}
record(Buffer.prototype, 'constructor')
record(Uint8Array.prototype, 'constructor')
// `await` reads `constructor` of a promise to decide whether it is a native one (recorded above with the species of `Promise`); the statics of `Promise` are not read anywhere.
for (const [namespace, list] of Object.entries(BASELINED_STATICS))
  // Stryker disable next-line EqualityOperator: a read one past the end of the list is `undefined`, which names no property, so `record` finds no descriptor and returns
  for (let at = 0; at < list.length; at += 1) record(world[namespace] as object, list[at] as string)

// Stryker disable next-line ArrayDeclaration: the loop below assigns every index of the list from zero, so a seeded element is overwritten
const globalOriginals: unknown[] = []
// Stryker disable next-line EqualityOperator: a read one past the end of the list is `undefined`, and the global named `undefined` is `undefined` when it is stored and when it is compared, so the extra pass counts nothing
for (let index = 0; index < BASELINED_GLOBALS.length; index += 1)
  globalOriginals[index] = world[BASELINED_GLOBALS[index] as string]

/**
 * The holders an awaited value can inherit from: a value an `await` or a `resolve` receives is asked for `then` first, so a `then`
 * planted on one of these prototypes (the root is counted by the root guard) answers for every value that inherits it.
 */
const thenHolders: object[] = []
const holderNames = ownKeys(BASELINED_HOLDERS)
// Stryker disable next-line EqualityOperator: a read one past the end of the list is `undefined`, which is not a name of the table
for (let index = 0; index < holderNames.length; index += 1)
  thenHolders[thenHolders.length] = BASELINED_HOLDERS[holderNames[index] as string] as object

/** Counts the holders that carry an own `then`, which none of them has. */
function plantedThens(): number {
  let planted = 0
  for (let index = 0; index < thenHolders.length; index += 1)
    if (hasOwn(thenHolders[index] as object, 'then')) planted += 1
  return planted
}

/** Counts the symbol keys a protocol holder has now that it did not have when this module loaded. */
function addedProtocolSymbols(): number {
  let added = 0
  for (let index = 0; index < protocolHolders.length; index += 1) {
    const present = ownKeys(protocolHolders[index] as object)
    const known = protocolSymbols[index] as symbol[]
    // Stryker disable next-line EqualityOperator: a read one past the end of the list is `undefined`, which is not a symbol and is skipped
    for (let at = 0; at < present.length; at += 1) {
      const key = present[at] as string | symbol
      if (typeof key !== 'symbol') continue
      let found = false
      // Stryker disable next-line EqualityOperator: a read one past the end of the list is `undefined`, which is never the symbol compared
      for (let seen = 0; seen < known.length; seen += 1)
        if (known[seen] === key) {
          found = true
          break
        }
      if (!found) added += 1
    }
  }
  return added
}

/**
 * Takes again the function of the polyfill that decorators load (`Reflect.getMetadata`, and no other function of `Reflect`), which a second copy of
 * `reflect-metadata` replaces while the imports of the application run. Called when the module boots, after those imports,
 * so a host with two copies is not refused for the copy that loaded last; a change after the boot is counted as ever.
 */
export function rebaselinePolyfills(): void {
  // Stryker disable next-line EqualityOperator: a read one past the end of the list is `undefined`, which is not `Reflect`, so the pass continues
  for (let index = 0; index < holders.length; index += 1) {
    if (keys[index] !== 'getMetadata') continue
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
  count += addedProtocolSymbols()
  count += plantedThens()
  // Read by `Reflect.get` and not through a descriptor: the global object of a `vm` context answers a descriptor through a native
  // interceptor that reads the root, and a planted `get` or `value` there aborts the process.
  // Stryker disable next-line EqualityOperator: a read one past the end of the list is `undefined`, and the global named `undefined` is `undefined` when it is stored and when it is compared, so the extra pass counts nothing
  for (let index = 0; index < BASELINED_GLOBALS.length; index += 1)
    if (getKey(world, BASELINED_GLOBALS[index] as string) !== globalOriginals[index]) count += 1
  return count
}
