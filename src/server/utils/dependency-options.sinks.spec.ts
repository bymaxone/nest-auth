/**
 * @fileoverview The option objects handed to `crypto.scrypt`, to `express` cookies and to the JWT libraries carry an own
 * key for every name the pinned dependency reads, and a dependency that gains a name reads nothing unlisted: the sources of
 * the pinned versions are read and every option name they read has to be one the library chose or shadowed.
 *
 * @layer Test
 */

import { readFileSync, readdirSync, statSync } from 'node:fs'
import { createRequire } from 'node:module'
import { join } from 'node:path'

import { Test } from '@nestjs/testing'
import express from 'express'

import { BYMAX_AUTH_BREACH_CHECKER, BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import { PasswordService } from '../services/password.service'
import {
  COOKIE_SHADOWS,
  JWT_MODULE_SHADOWS,
  JWT_SIGN_SHADOWS,
  JWT_SIGN_UNSHADOWABLE,
  JWT_VERIFY_SHADOWS,
  SCRYPT_SHADOWS
} from './dependency-options'

/** Runs `body` with `key` planted on the root object of the process and always takes it away again. */
function withPlanted<T>(key: string, value: unknown, body: () => T): T {
  const held = Object.getOwnPropertyDescriptor(Object.prototype, key)
  Object.defineProperty(Object.prototype, key, {
    value,
    configurable: true,
    enumerable: false,
    writable: true
  })
  try {
    return body()
  } finally {
    if (held === undefined) Reflect.deleteProperty(Object.prototype, key)
    else Object.defineProperty(Object.prototype, key, held)
  }
}

describe('hashing with a key planted on Object.prototype', () => {
  const options = {
    password: { minLength: 15, costFactor: 16_384, blockSize: 8, parallelization: 1 }
  }

  // Scenario: each alias of the scrypt cost options planted on Object.prototype, then a hash and its verification.
  // Expected: the hash is made and it verifies. Why: `crypto.scrypt` throws when an alias is given next to `N`, `r` or
  // `p`, so a planted alias would end every login and every password change.
  it.each([
    ['cost', 4],
    ['blockSize', 1],
    ['parallelization', 2]
  ] as const)('does not read %s', async (name, value) => {
    const module = await Test.createTestingModule({
      providers: [
        PasswordService,
        { provide: BYMAX_AUTH_OPTIONS, useValue: options },
        { provide: BYMAX_AUTH_BREACH_CHECKER, useValue: { isBreached: jest.fn() } }
      ]
    }).compile()
    const service = module.get(PasswordService)

    const stored = await withPlanted(name, value, () =>
      service.hash('correct horse battery staple')
    )
    const verified = await withPlanted(name, value, () =>
      service.compare('correct horse battery staple', stored)
    )

    expect(verified).toBe(true)
  })
})

/** A response of the real `express`, collecting the Set-Cookie header it writes. */
function response(): { res: express.Response; header: () => string } {
  const app = express()
  const headers: Record<string, string[]> = {}
  const res = Object.create(app.response) as express.Response
  Object.assign(res, {
    app,
    req: { app },
    append(name: string, value: string | string[]) {
      headers[name] = (headers[name] ?? []).concat(value)
      return res
    },
    getHeader: (name: string) => headers[name],
    setHeader: (name: string, value: string[]) => {
      headers[name] = value
    },
    get: (name: string) => headers[name],
    set: (name: string, value: string[]) => {
      headers[name] = value
    }
  })
  return {
    res,
    header: () => (headers['Set-Cookie'] ?? []).join('|').replace(/Expires=[^;]*/u, 'Expires=X')
  }
}

describe('setting a cookie with a key planted on Object.prototype', () => {
  const chosen = {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    path: '/',
    maxAge: 900_000
  } as const
  const set = (): string => {
    const { res, header } = response()
    res.cookie('access_token', 'token', { ...COOKIE_SHADOWS, ...chosen })
    return header()
  }
  const clear = (): string => {
    const { res, header } = response()
    res.clearCookie('access_token', {
      ...COOKIE_SHADOWS,
      httpOnly: true,
      secure: true,
      sameSite: 'lax'
    })
    return header()
  }

  // Scenario: each option of `res.cookie` the library does not choose, planted on Object.prototype with a value that
  // would scope the cookie to another domain, change its attributes or make the call throw. Expected: the header written
  // is the one written with nothing planted, for a cookie that is set and for one that is cleared. Why: `express` copies
  // the options into a new object and `cookie` reads each name from the copy.
  it.each([
    ['domain', '.attacker.example'],
    ['partitioned', true],
    ['priority', 'high'],
    ['signed', true],
    ['expires', '2099-01-01'],
    ['encode', 'planted']
  ] as const)('does not read %s', (name, value) => {
    const baselineSet = set()
    const baselineClear = clear()

    expect(withPlanted(name, value, set)).toBe(baselineSet)
    expect(withPlanted(name, value, clear)).toBe(baselineClear)
  })
})

/** The shipped source files of the server, without the specs. */
function serverSources(dir = join(__dirname, '..')): string[] {
  return readdirSync(dir).flatMap((entry) => {
    const path = join(dir, entry)
    if (statSync(path).isDirectory()) return entry === '__tests__' ? [] : serverSources(path)
    return /\.ts$/u.test(entry) && !/\.(spec|test)\.ts$/u.test(entry) ? [path] : []
  })
}

describe('every call that sets or clears a cookie', () => {
  // Scenario: each `res.cookie(` and `res.clearCookie(` in the shipped code. Expected: its options carry the shadows, or are
  // the base options of the delivery service, which carry them. Why: a new call site that forgets the shadows would read a
  // planted `domain` again, and no row of the existing sites would notice.
  it('names the shadows in its options', () => {
    const calls = serverSources().flatMap((file) => {
      const text = readFileSync(file, 'utf8')
      return [...text.matchAll(/res\.(?:cookie|clearCookie)\(/gu)].map((match) => ({
        file,
        call: text.slice(match.index, match.index + 420)
      }))
    })

    const missing = calls.filter(
      ({ call }) => !/COOKIE_SHADOWS|\.\.\.(?:base|cookieOpts)\b/u.test(call)
    )
    const base = readFileSync(join(__dirname, '../services/token-delivery.service.ts'), 'utf8')

    expect(calls.length).toBeGreaterThan(0)
    expect(missing).toEqual([])
    expect(base).toMatch(/baseCookieOptions[\s\S]{0,400}\.\.\.COOKIE_SHADOWS/u)
  })
})

/** The option names a source reads through the given pattern. */
function namesRead(source: string, pattern: RegExp): Set<string> {
  return new Set([...source.matchAll(pattern)].map((match) => match[1] as string))
}

/** Reads the source of a file of a dependency, resolved from the package that depends on it. */
function dependencySource(name: string, from: string, file: string): string {
  const start = createRequire(join(process.cwd(), 'package.json')).resolve(from)
  const root = createRequire(start).resolve(`${name}/package.json`)
  return readFileSync(join(root, '..', file), 'utf8')
}

describe('the option names the pinned dependencies read', () => {
  const keys = (object: object): string[] => Object.keys(object)
  const verifyKnown = new Set([
    ...keys(JWT_VERIFY_SHADOWS),
    'algorithms',
    'ignoreExpiration',
    'issuer',
    'audience'
  ])
  const signKnown = new Set([
    ...keys(JWT_SIGN_SHADOWS),
    ...JWT_SIGN_UNSHADOWABLE,
    'algorithm',
    'expiresIn'
  ])
  const cookieKnown = new Set([
    ...keys(COOKIE_SHADOWS),
    'httpOnly',
    'secure',
    'sameSite',
    'path',
    'maxAge'
  ])

  // Scenario: the option names read in `jsonwebtoken` verify and sign, in the module of `@nestjs/jwt`, in `cookie` and in the
  // cookie methods of `express`. Expected: each is one the library sets itself or shadows with an own key. Why: a version
  // that reads a name nobody listed reads it from `Object.prototype`, and only this row would notice.
  it('are all chosen or shadowed by the library', () => {
    const verify = namesRead(
      dependencySource('jsonwebtoken', '@nestjs/jwt', 'verify.js'),
      /\boptions\.([A-Za-z]+)/gu
    )
    const sign = namesRead(
      dependencySource('jsonwebtoken', '@nestjs/jwt', 'sign.js'),
      /\boptions\.([A-Za-z]+)/gu
    )
    const nest = dependencySource('@nestjs/jwt', '@nestjs/jwt', 'dist/jwt.service.js')
    const nestRead = new Set([
      ...namesRead(nest, /\bthis\.options\.([A-Za-z]+)/gu),
      ...namesRead(nest, /\bmergeJwtOptions\([^,]+, '([A-Za-z]+)'\)/gu)
    ])
    const cookie = namesRead(
      dependencySource('cookie', 'express', 'index.js'),
      /\bopt\.([A-Za-z]+)/gu
    )
    const response = dependencySource('express', 'express', 'lib/response.js')
    const methods = response.slice(response.indexOf('res.clearCookie = function'))
    const express = namesRead(methods, /\bopts\.([A-Za-z]+)/gu)

    const unknown = {
      verify: [...verify].filter((name) => !verifyKnown.has(name)),
      // `join` and `length` are read from arrays inside the sign source, not from the options.
      sign: [...sign].filter((name) => !signKnown.has(name) && !['join', 'length'].includes(name)),
      nest: [...nestRead].filter(
        (name) => ![...keys(JWT_MODULE_SHADOWS), 'secret', 'signOptions'].includes(name)
      ),
      // `decode` belongs to the parser of cookies, which the library does not call with options.
      cookie: [...cookie].filter((name) => !cookieKnown.has(name) && name !== 'decode'),
      express: [...express].filter((name) => !cookieKnown.has(name))
    }

    expect(unknown).toEqual({ verify: [], sign: [], nest: [], cookie: [], express: [] })
  })

  // Scenario: the properties `@nestjs/jwt` and the cookie methods of `express` read from `this`, not from an options object.
  // Expected: each is an own property, a method of the class, or `req.secret`, which only a signed cookie reads. Why: an
  // optional property read from an instance resolves through `Object.prototype` like an option does, and the library cannot
  // shadow what it does not construct; the one such read is closed by `signed: false` in the cookie shadows.
  it('reads from the instance only what the instance holds', () => {
    const nest = dependencySource('@nestjs/jwt', '@nestjs/jwt', 'dist/jwt.service.js')
    const response = dependencySource('express', 'express', 'lib/response.js')
    const cookieMethods = response.slice(
      response.indexOf('res.cookie = function'),
      response.indexOf('res.location = function')
    )

    const unknown = {
      nest: [...namesRead(nest, /\bthis\.([A-Za-z]+)/gu)].filter(
        (name) =>
          ![
            'options',
            'logger',
            'mergeJwtOptions',
            'getSecretKey',
            'overrideSecretFromOptions'
          ].includes(name)
      ),
      express: [...namesRead(cookieMethods, /\bthis\.([A-Za-z]+)/gu)].filter(
        (name) => !['req', 'append', 'cookie'].includes(name)
      )
    }

    expect(unknown).toEqual({ nest: [], express: [] })
    expect(cookieMethods).toMatch(/this\.req\.secret/u)
    expect(COOKIE_SHADOWS).toHaveProperty('signed', false)
  })

  // Scenario: the aliases of `crypto.scrypt` that the library shadows. Expected: they are exactly the three Node documents.
  // Why: the aliases are fixed by the runtime, not by a package, so the list is pinned here.
  it('lists the aliases of the scrypt options', () => {
    expect(keys(SCRYPT_SHADOWS).sort()).toEqual(['blockSize', 'cost', 'parallelization'])
  })
})
