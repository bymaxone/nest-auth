/**
 * @fileoverview The library refuses to sign, verify, hash, write a cookie or start while `Object.prototype` holds an entry
 * that is not the runtime's own: a key planted there, a standard entry overwritten, or a root that already differed when the
 * guard loaded. The refusal reports a count and no name.
 *
 * @layer Test
 */

import { Module } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { Test } from '@nestjs/testing'

import { BYMAX_AUTH_BREACH_CHECKER, BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import { BYMAX_AUTH_REDIS_CLIENT, BYMAX_AUTH_USER_REPOSITORY } from '../bymax-auth.constants'
import { BymaxAuthModule } from '../bymax-auth.module'
import type { ResolvedOptions } from '../config/resolved-options'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { PasswordService } from '../services/password.service'
import { cookieOptions, jwtModuleOptions, jwtSignOptions } from './dependency-options'
import {
  RootNotStandardException,
  assertRootIsStandard,
  plantedOnRoot,
  refusedOr
} from './object-prototype-guard'
import { verifyWithRotation } from './verify-with-rotation'

const SECRET = 'real-secret-real-secret-real-secret-1234'

/** Runs `body` with `descriptor` defined on the root object of the process and puts back what was there. */
function withRoot<T>(key: string, descriptor: PropertyDescriptor | undefined, body: () => T): T {
  const held = Object.getOwnPropertyDescriptor(Object.prototype, key)
  if (descriptor === undefined) Reflect.deleteProperty(Object.prototype, key)
  else Object.defineProperty(Object.prototype, key, { configurable: true, ...descriptor })
  try {
    return body()
  } finally {
    if (held === undefined) Reflect.deleteProperty(Object.prototype, key)
    else Object.defineProperty(Object.prototype, key, held)
  }
}

/** The failure of a call, or `undefined` when it did not fail. */
function failureOf(call: () => unknown): unknown {
  try {
    call()
  } catch (error) {
    return error
  }
  return undefined
}

const PLANTED = { value: 'planted', writable: true, enumerable: false }

describe('the root object of the runtime', () => {
  // Scenario: nothing planted. Expected: no entry is counted and the guard lets the call through. Why: the standard root is
  // what every process has, and the guard must not refuse a clean one.
  it('is standard when nothing is planted', () => {
    expect(plantedOnRoot()).toBe(0)
    expect(() => assertRootIsStandard()).not.toThrow()
  })

  // Scenario: a key planted as data, as a getter and as an enumerable entry, and a standard name overwritten with a number,
  // with a function of the attacker and as an accessor, and one deleted. Expected: each is counted once, and the refusal is
  // `auth.internal` with a cause that reports the count and none of the names. Why: a name list alone is evaded by
  // overwriting a standard name, and a name in an error would tell an attacker what the guard looks at.
  it.each([
    ['a key planted as data', 'sessions', PLANTED],
    ['a key planted as a getter', 'enabled', { get: (): boolean => false }],
    ['a key planted as an enumerable entry', 'domain', { ...PLANTED, enumerable: true }],
    ['hasOwnProperty overwritten with a number', 'hasOwnProperty', { value: 1, writable: true }],
    ['toString overwritten with a number', 'toString', { value: 1, writable: true }],
    [
      'constructor overwritten with a function',
      'constructor',
      { value: function Impostor() {}, writable: true }
    ],
    ['valueOf overwritten as an accessor', 'valueOf', { get: (): number => 1 }],
    ['isPrototypeOf deleted', 'isPrototypeOf', undefined],
    ['toString made enumerable', 'toString', { enumerable: true }],
    ['the getter of __proto__ replaced', '__proto__', { get: (): number => 1 }],
    ['the setter of __proto__ replaced', '__proto__', { set: (): void => undefined }]
  ] as const)('is counted when %s', (_what, key, descriptor) => {
    const planted = withRoot(key, descriptor, plantedOnRoot)
    const refusal = withRoot(key, descriptor, () => failureOf(assertRootIsStandard))

    expect(planted).toBe(1)
    expect(refusal).toBeInstanceOf(AuthException)
    expect((refusal as AuthException).getResponse()).toMatchObject({
      error: { code: AUTH_ERROR_CODES.INTERNAL }
    })
    expect(((refusal as AuthException).cause as Error).message).toBe(
      "Object.prototype holds 1 entries that are not the runtime's own"
    )
    expect(JSON.stringify(refusal)).not.toContain(key)
  })

  // Scenario: an accessor that throws, planted under each name a property descriptor is read by (`get`, `set`, `value`,
  // `enumerable`, `writable` and `configurable`). Expected: the root is counted once, the accessor is never run, and the
  // refusal is the library's. Why: a descriptor is an object that inherits from the root too, so reading a field it does not
  // hold would run what is planted under that name.
  it.each(['get', 'set', 'value', 'enumerable', 'writable', 'configurable'] as const)(
    'never runs an accessor planted as %s while it judges the root',
    (name) => {
      let calls = 0
      const accessor = {
        get: (): never => {
          calls += 1
          throw new Error('planted accessor ran')
        }
      }

      const counted = withRoot(name, accessor, plantedOnRoot)
      const refusal = withRoot(name, accessor, () => failureOf(assertRootIsStandard))

      expect(counted).toBe(1)
      expect(refusal).toBeInstanceOf(AuthException)
      expect(calls).toBe(0)
    }
  )

  // Scenario: a symbol planted on the root. Expected: it is not counted. Why: the guard judges the string keys that a JSON
  // flaw can write and an option name can be.
  it('does not count a symbol key', () => {
    const symbol = Symbol('planted')
    Object.defineProperty(Object.prototype, symbol, { value: 1, configurable: true })
    try {
      expect(plantedOnRoot()).toBe(0)
    } finally {
      Reflect.deleteProperty(Object.prototype, symbol)
    }
  })

  // Scenario: the guard module loaded while a standard entry is already overwritten with a number, deleted, made enumerable or,
  // for `__proto__`, turned into plain data, and then the root restored. Expected: the import does not throw, the root is counted
  // while it is still unlike the runtime's, and it is counted from then on. Why: the module cannot know what the standard entry
  // was once it was replaced before load, so it refuses on use and never throws from an import.
  it.each([
    ['overwritten with a number', '__lookupGetter__', () => ({ value: 1, writable: true })],
    ['deleted', '__lookupGetter__', () => undefined],
    [
      'made enumerable',
      '__lookupGetter__',
      (held: PropertyDescriptor) => ({ ...held, enumerable: true })
    ],
    ['turned into data', '__proto__', () => ({ value: 1, writable: true })],
    ['left with only a getter', '__proto__', () => ({ get: (): number => 1 })],
    ['left with only a setter', '__proto__', () => ({ set: (): void => undefined })]
  ] as const)(
    'refuses on use, and does not throw at import, when %s at load',
    (_what, key, change) => {
      const held = Object.getOwnPropertyDescriptor(Object.prototype, key) as PropertyDescriptor
      let late: { plantedOnRoot: () => number } | undefined
      let whileChanged = 0
      try {
        Reflect.deleteProperty(Object.prototype, key)
        const changed = change(held)
        if (changed !== undefined)
          Object.defineProperty(Object.prototype, key, { ...changed, configurable: true })
        jest.isolateModules(() => {
          late = require('./object-prototype-guard') as { plantedOnRoot: () => number }
        })
        whileChanged = late?.plantedOnRoot() ?? 0
      } finally {
        Reflect.deleteProperty(Object.prototype, key)
        Object.defineProperty(Object.prototype, key, held)
      }

      expect(late).toBeDefined()
      expect(whileChanged).toBeGreaterThan(0)
      expect(late?.plantedOnRoot()).toBeGreaterThan(0)
    }
  )
})

describe('a runtime started with --disable-proto=delete', () => {
  // Scenario: the guard module loaded while `__proto__` is absent from Object.prototype, as the runtime leaves it with
  // `--disable-proto=delete`, and then a `__proto__` added afterwards. Expected: the root with no `__proto__` is standard, and
  // the one that appears is counted once. Why: a hardened runtime is not a planted one, and an entry that was not there at
  // load is one the process added.
  it('has a standard root without __proto__, and counts one that appears later', () => {
    const held = Object.getOwnPropertyDescriptor(
      Object.prototype,
      '__proto__'
    ) as PropertyDescriptor
    let late: { plantedOnRoot: () => number } | undefined
    let hardened = -1
    let later = -1
    try {
      Reflect.deleteProperty(Object.prototype, '__proto__')
      jest.isolateModules(() => {
        late = require('./object-prototype-guard') as { plantedOnRoot: () => number }
      })
      hardened = late?.plantedOnRoot() ?? -1
      Object.defineProperty(Object.prototype, '__proto__', {
        value: 1,
        writable: true,
        configurable: true
      })
      later = late?.plantedOnRoot() ?? -1
    } finally {
      Reflect.deleteProperty(Object.prototype, '__proto__')
      Object.defineProperty(Object.prototype, '__proto__', held)
    }

    expect(hardened).toBe(0)
    expect(later).toBe(1)
  })
})

describe('the failure a verification reports', () => {
  // Scenario: the library's own refusal, and any other error, given to the helper a verification's catch uses. Expected: the
  // refusal comes back as it is and the other error becomes the code the caller gives. Why: a polluted process must answer 500
  // and must not look like every token being invalid.
  it('passes the refusal through and gives any other error the code of a token that did not verify', () => {
    const refusal = withRoot('sessions', PLANTED, () => failureOf(assertRootIsStandard))

    expect(refusal).toBeInstanceOf(RootNotStandardException)
    expect(refusedOr(refusal, AUTH_ERROR_CODES.TOKEN_INVALID)).toBe(refusal)
    expect(
      refusedOr(new Error('jwt expired'), AUTH_ERROR_CODES.TOKEN_INVALID).getResponse()
    ).toMatchObject({
      error: { code: AUTH_ERROR_CODES.TOKEN_INVALID }
    })
    expect(
      refusedOr(
        new AuthException(AUTH_ERROR_CODES.INTERNAL),
        AUTH_ERROR_CODES.TOKEN_INVALID
      ).getResponse()
    ).toMatchObject({ error: { code: AUTH_ERROR_CODES.TOKEN_INVALID } })
  })
})

describe('what the library refuses to do while the root holds a planted key', () => {
  const options = Object.assign({} as ResolvedOptions, {
    jwt: { secret: SECRET, algorithm: 'HS256', previousSecrets: [] }
  })
  const service = new JwtService(jwtModuleOptions(SECRET))
  const token = service.sign({ sub: 'user' }, { expiresIn: 600 })
  const passwords = async (): Promise<PasswordService> =>
    (
      await Test.createTestingModule({
        providers: [
          PasswordService,
          {
            provide: BYMAX_AUTH_OPTIONS,
            useValue: {
              password: { minLength: 15, costFactor: 16_384, blockSize: 8, parallelization: 1 }
            }
          },
          { provide: BYMAX_AUTH_BREACH_CHECKER, useValue: { isBreached: jest.fn() } }
        ]
      }).compile()
    ).get(PasswordService)

  const code = (error: unknown): unknown =>
    (error as AuthException).getResponse() as { error: { code: string } }

  // Scenario: each place the library signs, verifies or writes a cookie, called while a key is planted. Expected: each
  // refuses with `auth.internal`. Why: those are the calls whose dependencies copy the options into a new object and read
  // names nobody set.
  it.each([
    ['a verification', () => verifyWithRotation(service, options, token)],
    ['the options of a signature', () => jwtSignOptions({ expiresIn: '10m' })],
    ['the options of a cookie', () => cookieOptions({ path: '/' })]
  ] as const)('refuses %s', (_what, call) => {
    expect(failureOf(call)).toBeUndefined()

    const refusal = withRoot('sessions', PLANTED, () => failureOf(call))

    expect(refusal).toBeInstanceOf(AuthException)
    expect(code(refusal)).toMatchObject({ error: { code: AUTH_ERROR_CODES.INTERNAL } })
  })

  // Scenario: a password hashed, compared and compared against the decoy while a key is planted. Expected: each refuses with
  // `auth.internal`. Why: a hash and a verify run scrypt with an options object a dependency copies.
  it.each(['hash', 'compare', 'compareDummy'] as const)(
    'refuses PasswordService.%s',
    async (method) => {
      const service = await passwords()
      const run = (): Promise<unknown> =>
        method === 'hash'
          ? service.hash('pw')
          : method === 'compare'
            ? service.compare('pw', 'x')
            : service.compareDummy('pw')

      const refusal = await withRoot('sessions', PLANTED, async () =>
        run().catch((error: unknown) => error)
      )

      expect(refusal).toBeInstanceOf(AuthException)
      expect(code(refusal)).toMatchObject({ error: { code: AUTH_ERROR_CODES.INTERNAL } })
    }
  )

  // Scenario: the module registered while a key is planted. Expected: it does not start and says how many entries are
  // planted, and no name. Why: a process that already carries a planted key must not come up as if its options were its own.
  it('does not start', async () => {
    @Module({
      imports: [
        BymaxAuthModule.registerAsync({
          useFactory: () =>
            ({
              jwt: { secret: 'xY9!kL2@mN5#pQ8$rS1%tU4^vW7&zA0B' },
              roles: { hierarchy: { MEMBER: [] } },
              rateLimit: { clientIpSource: 'peer' }
            }) as never,
          extraProviders: [
            { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: {} },
            { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: {} }
          ] as never
        })
      ]
    })
    class Host {}

    Object.defineProperty(Object.prototype, 'sessions', { configurable: true, ...PLANTED })
    let refusal: unknown
    try {
      refusal = await Test.createTestingModule({ imports: [Host] })
        .compile()
        .catch((error: unknown) => error)
    } finally {
      Reflect.deleteProperty(Object.prototype, 'sessions')
    }

    expect((refusal as Error).message).toContain(
      "Object.prototype holds 1 entries that are not the runtime's own; the module does not start while a key is planted there."
    )
    expect((refusal as Error).message).toContain('Object.prototype holds 1 entries')
    expect((refusal as Error).message).not.toContain('sessions')
  })
})
