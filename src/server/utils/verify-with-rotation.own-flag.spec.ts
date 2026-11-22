/**
 * @fileoverview Whether a verification may ignore the expiry is read from the flag the caller wrote, by own key, and never from
 * the root object: the default of the parameter is read before the guard of the function runs, so the guard is not what closes
 * it. The guard is replaced by a no-op here to prove that.
 *
 * @layer Test
 */

import { JwtService } from '@nestjs/jwt'

import type { ResolvedOptions } from '../config/resolved-options'
import { jwtModuleOptions } from './dependency-options'
import { verifyWithRotation } from './verify-with-rotation'

jest.mock('./object-prototype-guard', () => ({ assertRootIsStandard: (): void => undefined }))

const SECRET = 'real-secret-real-secret-real-secret-1234'
const options = Object.assign({} as ResolvedOptions, {
  jwt: { secret: SECRET, algorithm: 'HS256', previousSecrets: [] }
})
const service = new JwtService(jwtModuleOptions(SECRET))
const expired = service.sign(
  { sub: 'user', exp: Math.floor(Date.now() / 1000) - 3600 },
  { noTimestamp: true }
)

describe('the flag that lets a verification ignore the expiry', () => {
  // Scenario: an expired token, verified with no flag, while `ignoreExpiration` is planted on Object.prototype as true.
  // Expected: the token is refused. Why: nothing the caller did asked for the expiry to be ignored.
  it('is not read from the root object', () => {
    Object.defineProperty(Object.prototype, 'ignoreExpiration', {
      value: true,
      configurable: true,
      enumerable: true,
      writable: true
    })
    try {
      expect(() => verifyWithRotation(service, options, expired)).toThrow('jwt expired')
      expect(() => verifyWithRotation(service, options, expired, {})).toThrow('jwt expired')
    } finally {
      Reflect.deleteProperty(Object.prototype, 'ignoreExpiration')
    }
  })

  // Scenario: the same planted flag, with `Object.hasOwn` replaced by a function that answers yes for every key after the module
  // loaded. Expected: the token is still refused. Why: the own-key read cannot depend on a live built-in, or replacing it
  // brings the planted flag back.
  it('is not read from the root object when Object.hasOwn is replaced', () => {
    const held = Object.getOwnPropertyDescriptor(Object, 'hasOwn') as PropertyDescriptor
    let refusal = ''
    Object.defineProperty(Object.prototype, 'ignoreExpiration', {
      value: true,
      configurable: true,
      enumerable: true,
      writable: true
    })
    Object.defineProperty(Object, 'hasOwn', { ...held, value: (): boolean => true })
    try {
      verifyWithRotation(service, options, expired)
    } catch (error) {
      refusal = (error as Error).message
    } finally {
      Object.defineProperty(Object, 'hasOwn', held)
      Reflect.deleteProperty(Object.prototype, 'ignoreExpiration')
    }

    expect(refusal).toBe('jwt expired')
  })

  // Scenario: the same token, verified by the caller that writes the flag. Expected: it is accepted. Why: logout needs it.
  it('is read from the flag the caller wrote', () => {
    expect(
      verifyWithRotation<{ sub: string }>(service, options, expired, { ignoreExpiration: true }).sub
    ).toBe('user')
  })
})
