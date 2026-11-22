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

export const hasOwn = Object.hasOwn
export const prototypeOf = Object.getPrototypeOf
export const getKey = Reflect.get
export const ownKeys = Reflect.ownKeys
export const getDescriptor = Object.getOwnPropertyDescriptor
export const createObject = Object.create
export const assign = Object.assign
export const defineKey = Object.defineProperty
export const ErrorOf = Error
