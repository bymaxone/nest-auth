/**
 * @fileoverview The `node:crypto` primitives the library compares, hashes and generates secrets and identifiers with, taken when the module
 * loads.
 *
 * A flaw that can run code in the process can also replace a method of `node:crypto` after the library loaded, and a
 * compare that reads `timingSafeEqual` at the call answers whatever the replacement answers. The copies below are what the
 * secret comparisons, the digests, the HMACs, the random bytes, the random integers and the random identifiers, the ciphers and the key derivation of the library
 * call, so a later replacement changes nothing they compute. Every other file under `src/server` takes them from here
 * and imports nothing but types from `node:crypto`.
 *
 * @layer Crypto
 */

import nodeCrypto from 'node:crypto'

/** The module object itself, which the JWT libraries read their primitives from at each call (`crypto.timingSafeEqual`). */
export { nodeCrypto }

/** `crypto.createCipheriv` as it was when the module loaded: the cipher of the encrypted secrets. */
export const createCipheriv = nodeCrypto.createCipheriv

/** `crypto.createDecipheriv` as it was when the module loaded: the decipher of the encrypted secrets. */
export const createDecipheriv = nodeCrypto.createDecipheriv

/** `crypto.createHash` as it was when the module loaded: the digests of tokens, keys and codes. */
export const createHash = nodeCrypto.createHash

/** `crypto.createHmac` as it was when the module loaded: the keyed digests (TOTP, recovery codes, derived keys). */
export const createHmac = nodeCrypto.createHmac

/** `crypto.randomBytes` as it was when the module loaded: the source of every secret and token. */
export const randomBytes = nodeCrypto.randomBytes

/** `crypto.randomInt` as it was when the module loaded: the source of the numeric codes. */
export const randomInt = nodeCrypto.randomInt

/** `crypto.randomUUID` as it was when the module loaded: the source of identifiers. */
export const randomUUID = nodeCrypto.randomUUID

/** `crypto.scrypt` as it was when the module loaded: the key derivation of the password hash. */
export const scrypt = nodeCrypto.scrypt

/** `crypto.timingSafeEqual` as it was when the module loaded: the comparison of every secret. */
export const timingSafeEqual = nodeCrypto.timingSafeEqual
