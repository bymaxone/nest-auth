/**
 * @fileoverview The option objects the library hands to its dependencies name every option the dependency reads.
 *
 * `@nestjs/jwt`, `jsonwebtoken`, `express` and `node:crypto` copy the options they are given into a new `{}` and then
 * read option names the library never set. A `{}` inherits from `Object.prototype`, so a key planted there by a flaw
 * elsewhere in the process (`secretOrPrivateKey`, `clockTolerance`, `noTimestamp`, `domain`, `cost`) would be read as if
 * the library had written it. An own key shadows the planted one, so each object below carries an own key, with a
 * neutral value, for every name the pinned dependency reads and the library does not choose. The test beside this file
 * reads the sources of the pinned versions and fails when one reads a name that is in none of these lists.
 *
 * @layer Utility
 */

import type { JwtModuleOptions, JwtSignOptions } from '@nestjs/jwt'
import type { CookieOptions } from 'express'

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'

/** The module options of `@nestjs/jwt` that pick the key or merge more options in; the library gives only `secret` and `signOptions`. */
export const JWT_MODULE_SHADOWS = Object.freeze({
  secretOrPrivateKey: undefined,
  secretOrKeyProvider: undefined,
  publicKey: undefined,
  privateKey: undefined,
  verifyOptions: undefined
})

/** The options of `jsonwebtoken.verify` the library does not choose, each neutral: no tolerance, no age bound, no nonce, no extra claim to match. */
export const JWT_VERIFY_SHADOWS = Object.freeze({
  complete: false,
  clockTimestamp: undefined,
  clockTolerance: undefined,
  ignoreNotBefore: false,
  maxAge: undefined,
  nonce: undefined,
  subject: undefined,
  jwtid: undefined,
  allowInvalidAsymmetricKeyTypes: false
})

/** The options of `jsonwebtoken.sign` whose schema accepts a neutral value that changes nothing in the token. */
export const JWT_SIGN_SHADOWS = Object.freeze({
  noTimestamp: false,
  mutatePayload: false,
  header: Object.freeze({}),
  encoding: 'utf8',
  allowInsecureKeySizes: false,
  allowInvalidAsymmetricKeyTypes: false
})

/**
 * The options of `jsonwebtoken.sign` that have no neutral value: each one that is present adds a claim or a header field,
 * and the schema refuses `undefined`. A signature is refused while the process carries one of them on `Object.prototype`.
 */
export const JWT_SIGN_UNSHADOWABLE = [
  'keyid',
  'notBefore',
  'jwtid',
  'subject',
  'issuer',
  'audience'
] as const

/** The aliases of `crypto.scrypt` options; one given next to `N`, `r` or `p` throws, so the library's own values must not meet a planted one. */
export const SCRYPT_SHADOWS = Object.freeze({
  cost: undefined,
  blockSize: undefined,
  parallelization: undefined
})

/** The options of `res.cookie` and `res.clearCookie` the library does not choose; `express` and `cookie` read them from a copy. */
export const COOKIE_SHADOWS: Readonly<CookieOptions> = Object.freeze(
  Object.assign<CookieOptions, object>(
    {},
    {
      domain: undefined,
      expires: undefined,
      encode: undefined,
      partitioned: false,
      priority: undefined,
      signed: false
    }
  )
)

/**
 * Refuses to sign while the root object of the process carries an option name that cannot be shadowed.
 *
 * @param names - The option names that have no neutral own value.
 * @throws {AuthException} `auth.internal` when `Object.prototype` holds one of them.
 */
export function assertRootCarries(names: readonly string[]): void {
  if (names.some((name) => Object.hasOwn(Object.prototype, name)))
    throw new AuthException(AUTH_ERROR_CODES.INTERNAL)
}

/**
 * The module options the library registers `@nestjs/jwt` with: the secret and the algorithm it signs under, and an own
 * key for every option that would pick another key or merge more options in.
 *
 * @param secret - The resolved signing secret.
 * @returns The options for `JwtModule`.
 */
export function jwtModuleOptions(secret: string): JwtModuleOptions {
  return Object.assign<JwtModuleOptions, object>(
    { secret, signOptions: { algorithm: 'HS256' } },
    JWT_MODULE_SHADOWS
  )
}

/**
 * The options of one `sign` call: what the library chose, over the neutral value of every option it did not.
 *
 * @param chosen - The options the call sets (`expiresIn`, the secret, the algorithm, the issuer and the audience).
 * @returns The options to hand to `JwtService.sign`.
 * @throws {AuthException} `auth.internal` when `Object.prototype` holds an option that has no neutral value.
 */
export function jwtSignOptions(chosen: object): JwtSignOptions {
  assertRootCarries(JWT_SIGN_UNSHADOWABLE)
  return Object.assign({} as JwtSignOptions, JWT_SIGN_SHADOWS, chosen)
}
