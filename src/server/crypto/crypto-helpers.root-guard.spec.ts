/**
 * @fileoverview Each helper that hashes, compares or derives from a secret checks the built-ins at its entry, so a call made while
 * a built-in is replaced is refused by the helper itself and not only by the caller above it.
 *
 * @layer Test
 */

import nodeCryptoModule from 'node:crypto'

import { digestRecoveryCode, verifyRecoveryCode } from '../utils/mfa-recovery-codes'
import { apiKeyDigest, digestsMatch } from './api-key'
import { hmacSha256, sha256, timingSafeCompare } from './secure-token'
import { generateHotp, generateTotp, generateTotpSecret, verifyTotp } from './totp'

// The test's own copies: the window below replaces a built-in, so nothing inside it may call a live one.
const nodeCrypto = nodeCryptoModule
const define = Object.defineProperty
const getOwn = Object.getOwnPropertyDescriptor

const SECRET = generateTotpSecret().base32
const DIGEST = apiKeyDigest('a', 'p')
const OTHER = apiKeyDigest('b', 'p')

/** The helpers, each as a call that is valid on a standard runtime. */
const HELPERS: readonly (readonly [string, () => unknown])[] = [
  ['sha256', () => sha256('abc')],
  ['hmacSha256', () => hmacSha256('message', 'secret')],
  ['timingSafeCompare', () => timingSafeCompare('a', 'b')],
  ['apiKeyDigest', () => apiKeyDigest('a', 'p')],
  ['digestsMatch', () => digestsMatch(DIGEST, OTHER)],
  ['generateHotp', () => generateHotp(SECRET, 1)],
  ['generateTotp', () => generateTotp(SECRET)],
  ['verifyTotp', () => verifyTotp(SECRET, '000000')],
  ['digestRecoveryCode', () => digestRecoveryCode('code', 'key')],
  ['verifyRecoveryCode', () => verifyRecoveryCode('code', [], 'key', [])]
]

describe('the helpers that hash, compare or derive from a secret', () => {
  it.each(HELPERS)('%s answers on a standard runtime', async (_name, call) => {
    await expect(Promise.resolve(call())).resolves.toBeDefined()
  })

  // Scenario: each helper called while `Array.prototype.includes` is replaced by a function that answers true. Expected: the
  // library's refusal (500), whatever the helper itself calls. Why: the check at the entry is what stops a helper from answering
  // with a replaced runtime, and it is the helper's own, so a caller that forgets it is still safe.
  it.each(HELPERS)('%s is refused while a built-in is replaced', async (_name, call) => {
    const held = getOwn(Array.prototype, 'includes') as PropertyDescriptor
    define(Array.prototype, 'includes', { ...held, value: () => true })
    let status: number | undefined
    try {
      await call()
    } catch (error) {
      status = (error as { getStatus?: () => number }).getStatus?.()
    } finally {
      define(Array.prototype, 'includes', held)
    }

    expect(status).toBe(500)
  })

  // Scenario: the `update` or the `digest` of the objects `createHash` and `createHmac` return, replaced (before a value is hashed
  // or compared) by functions that make every input compute the same digest, then each helper called with a wrong secret.
  // Expected: the library's refusal for every helper, never a digest. Why: those methods are read at each call, so a replaced one
  // makes a wrong secret compute the digest that was stored, and the helper's own check at its entry is what refuses it.
  it.each(
    HELPERS.flatMap(([helper, call]) =>
      (['Hash', 'Hmac'] as const).flatMap((kind) =>
        (['update', 'digest'] as const).map((method) => [helper, call, kind, method] as const)
      )
    )
  )('%s is refused while %s.prototype.%s is replaced', async (_helper, call, kind, method) => {
    const prototype = (nodeCrypto[kind] as { prototype: object }).prototype
    const held = getOwn(prototype, method) as PropertyDescriptor
    define(prototype, method, {
      ...held,
      value: function (this: unknown): unknown {
        return method === 'digest' ? Buffer.from('same') : this
      }
    })
    let status: number | undefined
    try {
      await call()
    } catch (error) {
      status = (error as { getStatus?: () => number }).getStatus?.()
    } finally {
      define(prototype, method, held)
    }

    expect(status).toBe(500)
  })
})
