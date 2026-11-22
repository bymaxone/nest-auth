/**
 * @fileoverview A sweep over the built-ins: every function of the globals the language offers, replaced in turn by a spy that
 * records who called it, while the root guard, the judgement of whose a key is, the options handed to the dependencies and
 * the verification run. The modules that decide those answers call no live built-in, so the record of calls that came from
 * them is empty.
 *
 * Only calls whose immediate caller is one of the modules named below count: the dependencies those modules call
 * (`jsonwebtoken`, `cookie`, NestJS) use the built-ins freely, and what they decide is not decided here.
 *
 * @layer Test
 */

import { JwtService } from '@nestjs/jwt'

import type { ResolvedOptions } from '../config/resolved-options'
import { cookieOptions, jwtModuleOptions, jwtSignOptions } from './dependency-options'
import { assertRootIsStandard, plantedOnRoot, refusedOr } from './object-prototype-guard'
import { readOwnOrClass } from './own-or-class'
import { verifyWithRotation } from './verify-with-rotation'

/** The modules whose calls to a built-in are recorded: a frame of the stack that names one of them. */
const WATCHED = [
  'utils/object-prototype-guard',
  'utils/own-or-class',
  'utils/dependency-options',
  'utils/verify-with-rotation',
  'utils/captured-builtins',
  'crypto/captured-crypto'
]

// The sweep's own copies: nothing inside the window may call a live built-in, or the spy would record itself.
const ownKeys = Reflect.ownKeys
const apply = Reflect.apply
const getDescriptor = Object.getOwnPropertyDescriptor
const define = Object.defineProperty
const getPrototype = Object.getPrototypeOf
const ErrorOf = Error
const stringIndexOf = String.prototype.indexOf
const stringSlice = String.prototype.slice
const push = Array.prototype.push
const describeKey = (key: PropertyKey): string =>
  typeof key === 'symbol' ? key.toString() : String(key)

const SECRET = 'real-secret-real-secret-real-secret-1234'
const options = Object.assign({} as ResolvedOptions, {
  jwt: {
    secret: SECRET,
    algorithm: 'HS256',
    previousSecrets: ['old-secret-old-secret-old-secret-1234']
  }
})

/**
 * The holders whose own functions are replaced: the globals, their prototypes and the prototypes of the iterators. Not
 * `Object.prototype`: the guard refuses a root whose standard entries were replaced, which is the point of it.
 */
function holders(): [string, object][] {
  const iteratorPrototype = (value: object): object => getPrototype(value) as object
  return [
    ['Object', Object],
    ['Reflect', Reflect],
    ['Array', Array],
    ['Array.prototype', Array.prototype],
    ['String', String],
    ['String.prototype', String.prototype],
    ['Number', Number],
    ['Function.prototype', Function.prototype],
    ['Map', Map],
    ['Map.prototype', Map.prototype],
    ['Set', Set],
    ['Set.prototype', Set.prototype],
    ['JSON', JSON],
    ['Symbol', Symbol],
    ['Promise.prototype', Promise.prototype],
    ['ArrayIterator.prototype', iteratorPrototype([][Symbol.iterator]())],
    ['MapIterator.prototype', iteratorPrototype(new Map()[Symbol.iterator]())],
    ['SetIterator.prototype', iteratorPrototype(new Set()[Symbol.iterator]())],
    ['StringIterator.prototype', iteratorPrototype(''[Symbol.iterator]())]
  ]
}

/** Runs `scenario` with every function of every holder replaced by a spy; returns the calls that came from a watched module. */
function sweep(scenario: () => void): string[] {
  const calls: string[] = []
  const restore: (() => void)[] = []
  let busy = false
  for (const [holderName, holder] of holders()) {
    for (const key of ownKeys(holder)) {
      const descriptor = getDescriptor(holder, key)
      if (descriptor === undefined || typeof descriptor.value !== 'function') continue
      if (descriptor.configurable !== true) continue
      if (key === 'constructor') continue
      const original = descriptor.value as (...args: unknown[]) => unknown
      const spy = function (this: unknown, ...args: unknown[]): unknown {
        if (!busy) {
          busy = true
          const stack = String(new ErrorOf().stack)
          const caller = apply(stringSlice, stack, [
            apply(stringIndexOf, stack, ['\n']) + 1
          ]) as string
          const frames = apply(stringSlice, caller, [
            apply(stringIndexOf, caller, ['\n']) + 1,
            apply(stringIndexOf, caller, ['\n', apply(stringIndexOf, caller, ['\n']) + 1])
          ]) as string
          for (const watched of WATCHED)
            if (apply(stringIndexOf, frames, [watched]) !== -1) {
              apply(push, calls, [`${holderName}.${describeKey(key)} <- ${watched}`])
              break
            }
          busy = false
        }
        return apply(original, this, args)
      }
      define(holder, key, { ...descriptor, value: spy })
      apply(push, restore, [(): void => void define(holder, key, descriptor)])
    }
  }
  try {
    scenario()
  } finally {
    busy = true
    for (let index = restore.length - 1; index >= 0; index -= 1) (restore[index] as () => void)()
    busy = false
  }
  return calls
}

describe('the modules that decide the root guard, the ownership of a key, the dependency options and the verification', () => {
  const service = new JwtService(jwtModuleOptions(SECRET))
  const token = service.sign({ sub: 'user' }, { noTimestamp: true })
  const expired = service.sign({ sub: 'user', exp: 1 }, { noTimestamp: true })
  const planted = (): never => {
    throw new ErrorOf('not reached')
  }

  // Scenario: every function of every global replaced by a recording spy, then a clean-root judgement, a judgement over a root
  // holding a planted key and the refusal passed through, the reading of an own key, a class key and a root-only key, the
  // options for a signature, a cookie and the module, and a verification (current secret, previous secret, ignoring the
  // expiry, and refused). Expected: no recorded call came from one of the modules. Why: a call to a live built-in is a
  // call a replacement can answer for, and these modules decide the answers.
  it('call no live built-in', () => {
    class Holder {
      get viaClass(): string {
        return 'class'
      }
    }
    const own = { viaOwn: 'own' }
    const calls = sweep(() => {
      plantedOnRoot()
      assertRootIsStandard()
      readOwnOrClass(own, 'viaOwn')
      readOwnOrClass(new Holder(), 'viaClass')
      readOwnOrClass(own, 'absent')
      jwtSignOptions({ expiresIn: '10m' })
      jwtModuleOptions(SECRET)
      cookieOptions()
      cookieOptions({ httpOnly: true, path: '/', maxAge: 1 })
      verifyWithRotation(service, options, token)
      verifyWithRotation(service, options, expired, { ignoreExpiration: true })
      try {
        verifyWithRotation(service, options, 'not-a-token')
      } catch (error) {
        refusedOr(error, 'auth.token_invalid')
      }
      planted
    })

    expect(calls).toEqual([])
  })
})
