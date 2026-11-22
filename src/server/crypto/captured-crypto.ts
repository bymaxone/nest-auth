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

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  randomInt,
  randomUUID,
  scrypt,
  timingSafeEqual
} from 'node:crypto'

const capturedCreateCipheriv = createCipheriv
const capturedCreateDecipheriv = createDecipheriv
const capturedCreateHash = createHash
const capturedCreateHmac = createHmac
const capturedRandomBytes = randomBytes
const capturedRandomInt = randomInt
const capturedRandomUUID = randomUUID
const capturedScrypt = scrypt
const capturedTimingSafeEqual = timingSafeEqual

export {
  capturedCreateCipheriv as createCipheriv,
  capturedCreateDecipheriv as createDecipheriv,
  capturedCreateHash as createHash,
  capturedCreateHmac as createHmac,
  capturedRandomBytes as randomBytes,
  capturedRandomInt as randomInt,
  capturedRandomUUID as randomUUID,
  capturedScrypt as scrypt,
  capturedTimingSafeEqual as timingSafeEqual
}
