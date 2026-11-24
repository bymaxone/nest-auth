/**
 * @fileoverview The dashboard and platform JWT guards check the built-ins their decisions are made with before they read the
 * route, so a public route is not admitted while a built-in is replaced.
 *
 * @layer Test
 */

import type { ExecutionContext } from '@nestjs/common'
import { Reflector } from '@nestjs/core'

import { IS_PUBLIC_KEY } from '../decorators/public.decorator'
import { JwtAuthGuard } from './jwt-auth.guard'
import { JwtPlatformGuard } from './jwt-platform.guard'

// The test's own copies: the window below replaces a built-in, so nothing inside it may call a live one.
const define = Object.defineProperty
const getOwn = Object.getOwnPropertyDescriptor

/** An execution context for a public handler. */
function publicContext(): ExecutionContext {
  class Controller {
    handler(): void {}
  }
  Reflect.defineMetadata(IS_PUBLIC_KEY, true, Controller.prototype.handler)
  return Object.assign({} as ExecutionContext, {
    getHandler: () => Controller.prototype.handler,
    getClass: () => Controller,
    switchToHttp: () => ({ getRequest: () => ({ headers: {} }) })
  })
}

const GUARDS: readonly (readonly [
  string,
  () => { canActivate(c: ExecutionContext): Promise<boolean> }
])[] = [
  [
    'JwtAuthGuard',
    () => new JwtAuthGuard(...(Array(4).fill({}) as [never, never, never, never]), {} as never)
  ],
  [
    'JwtPlatformGuard',
    () => new JwtPlatformGuard(...(Array(4).fill({}) as [never, never, never, never]), {} as never)
  ]
]

describe('the JWT guards while a built-in is replaced', () => {
  // Scenario: each guard called on a public route with nothing replaced. Expected: admitted. Why: the control for the rows below.
  it.each(GUARDS)('%s admits a public route with nothing replaced', async (_name, make) => {
    const guard = make()
    Reflect.set(guard, 'reflector', new Reflector())

    await expect(guard.canActivate(publicContext())).resolves.toBe(true)
  })

  // Scenario: `Array.prototype.every` replaced before each guard runs on a public route. Expected: the library's refusal (500).
  // Why: a public route returns before any other check, so only the check at the start refuses the replacement.
  it.each(GUARDS)(
    '%s is refused on a public route while a built-in is replaced',
    async (_name, make) => {
      const guard = make()
      Reflect.set(guard, 'reflector', new Reflector())
      const held = getOwn(Array.prototype, 'every') as PropertyDescriptor
      define(Array.prototype, 'every', { ...held, value: () => true })
      let status: number | undefined | true
      try {
        status = (await guard.canActivate(publicContext())) ? true : undefined
      } catch (error) {
        status = (error as { getStatus?: () => number }).getStatus?.()
      } finally {
        define(Array.prototype, 'every', held)
      }

      expect(status).toBe(500)
    }
  )
})
