/**
 * @fileoverview Each helper that hashes, compares or derives from a secret checks the built-ins at its entry, so a call made while
 * a built-in is replaced is refused by the helper itself and not only by the caller above it.
 *
 * @layer Test
 */

import nodeCryptoModule from 'node:crypto'

import { decrypt, encrypt } from './aes-gcm'
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
const AES_KEY = Buffer.alloc(32, 7).toString('base64')
const SEALED = encrypt('secret', AES_KEY)

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
  ['verifyRecoveryCode', () => verifyRecoveryCode('code', [], 'key', [])],
  ['encrypt', () => encrypt('secret', AES_KEY)],
  ['decrypt', () => decrypt(SEALED, AES_KEY)]
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

  // Scenario: `Decipheriv.prototype.final`, which is where a ciphertext with the wrong tag is refused, replaced by a function that
  // answers nothing, then a ciphertext whose tag was altered decrypted. Expected: the library's refusal, never the plaintext.
  // Why: with `final` replaced a tampered ciphertext is accepted, so the secret it carries is the attacker's.
  it('decrypt refuses a tampered ciphertext while Decipheriv.prototype.final is replaced', () => {
    const [iv, tag, body] = SEALED.split(':') as [string, string, string]
    const tampered = [iv, Buffer.alloc(16, 1).toString('base64'), body].join(':')
    const prototype = (nodeCrypto['Decipheriv'] as { prototype: object }).prototype
    const held = getOwn(prototype, 'final') as PropertyDescriptor
    define(prototype, 'final', { ...held, value: () => Buffer.alloc(0) })
    let status: number | undefined
    let plain: unknown
    try {
      plain = decrypt(tampered, AES_KEY)
    } catch (error) {
      status = (error as { getStatus?: () => number }).getStatus?.()
    } finally {
      define(prototype, 'final', held)
    }

    expect(tag).toBeDefined()
    expect(plain).toBeUndefined()
    expect(status).toBe(500)
  })
})
