/**
 * @fileoverview The built-ins the root guard, the verification and the signature call, taken when the module loads.
 *
 * A flaw that can plant a key on `Object.prototype` can also replace a built-in, and a check that calls the live one is blinded
 * by the replacement. These are the copies the checks call, so replacing `Object.hasOwn` or `Reflect.get` afterwards changes
 * nothing they decide. The array iterator, `Map`, `Set` and the array methods are not here because the checks do not use
 * them: they are written with indexed loops and null-prototype records.
 *
 * @layer Utility
 */

import net from 'node:net'

/** `Object.hasOwn` as it was when the module loaded: whether a key is an own key of an object, never a read through the prototype. */
export const hasOwn = Object.hasOwn

/** `Object.getPrototypeOf` as it was when the module loaded. */
export const prototypeOf = Object.getPrototypeOf

/**
 * The promise a native `async` function returns, taken from one: its prototype is the language's own `Promise.prototype`, not
 * whatever a host library (Bluebird, a zone) bound to the global `Promise` before this module loaded.
 */
export const intrinsicPromisePrototype: Promise<unknown> = prototypeOf(
  (async (): Promise<void> => undefined)()
)

/** The constructor of that prototype, which `await` compares with the promise it is given. */
const constructorSlot = Object.getOwnPropertyDescriptor(intrinsicPromisePrototype, 'constructor')

// Read by its descriptor, not by value: a `get` a host planted on the slot would run here and answer, and what a plain read returns
// is whatever that getter chose. Only a data property is the language's own.
if (constructorSlot === undefined || !hasOwn(constructorSlot, 'value'))
  throw new Error(
    "[BymaxAuthModule] the constructor of Promise is an accessor; the module does not start while the runtime's promises are not its own."
  )

/** The language-native `Promise` constructor, captured from the prototype's own data slot, not the replaceable global binding. */
export const IntrinsicPromise = constructorSlot.value as PromiseConstructor

// The constructor is read from a slot a host can have replaced before this module loaded. The language's own constructor and its prototype
// point at each other, so a slot that holds another function is caught here and the load fails, instead of every pin and every wait
// being made with the host's function.
if ((IntrinsicPromise as { prototype?: unknown }).prototype !== intrinsicPromisePrototype)
  throw new Error(
    "[BymaxAuthModule] the constructor of Promise was replaced before the module loaded; the module does not start while the runtime's promises are not its own."
  )

/** The `then` of the language's own promises, taken once: a host that replaces `Promise.prototype.then` later does not change it. */
export const intrinsicThen = intrinsicPromisePrototype.then

/** `Reflect.apply` as it was when the module loaded, so a function is called without reading `call` or `apply` off it. */
export const applyFunction = Reflect.apply

/** `Reflect.get` as it was when the module loaded: a read of a key that honours the receiver, taken once. */
export const getKey = Reflect.get

/** `Reflect.ownKeys` as it was when the module loaded: the own keys of an object, strings and symbols. */
export const ownKeys = Reflect.ownKeys

/** `Object.getOwnPropertyDescriptor` as it was when the module loaded. */
export const getDescriptor = Object.getOwnPropertyDescriptor

/** `Object.create` as it was when the module loaded: used to make objects that hold no prototype. */
export const createObject = Object.create

/** `Object.assign` as it was when the module loaded. */
export const assign = Object.assign

/** `Object.defineProperty` as it was when the module loaded: defines own data, never through a setter on the prototype. */
export const defineKey = Object.defineProperty

/** `Object.freeze` as it was when the module loaded: seals an object nothing may change after it is shared. */
export const freezeObject = Object.freeze

/** The `Error` constructor as it was when the module loaded. */
export const ErrorOf = Error

/** `Error.captureStackTrace` as it was when the module loaded: gives a made object the stack of its caller. */
export const captureStack = Error.captureStackTrace

/** `JSON.parse` as it was when the module loaded: what the library reads from its stores goes through this copy. */
export const parseJson: (text: string) => unknown = JSON.parse
/** `JSON.stringify` as it was when the module loaded: what the library writes to its stores goes through this copy. */
export const stringifyJson: (value: unknown) => string = JSON.stringify

/** `net.isIP` as it was when the module loaded: the family of an address (4, 6 or 0), which keys the rate limit and the client address. */
export const isIP: (input: string) => number = net.isIP

/** `net.isIPv6` as it was when the module loaded: whether an address is IPv6, which decides how the rate limit groups it. */
export const isIPv6: (input: string) => boolean = net.isIPv6
