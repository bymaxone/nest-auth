/**
 * @fileoverview Every route the metrics and spans describe is marked, with the operation and plane it
 * belongs to, and the marker is where the interceptor reads it.
 *
 * @layer Test
 */

import { AuthController } from '../controllers/auth.controller'
import { MfaController } from '../controllers/mfa.controller'
import { PasswordResetController } from '../controllers/password-reset.controller'
import { PlatformAuthController } from '../controllers/platform-auth.controller'
import { AuthObservabilityInterceptor, OBSERVE_AUTH_METADATA } from './observe-auth'
import type { ObservedOperation } from './observe-auth'
import type { AuthPlane } from '../services/auth-token-verifier.service'

/** Controller, method, the operation it is observed as, and the plane. */
const OBSERVED_ROUTES: ReadonlyArray<[string, Function, string, ObservedOperation, AuthPlane]> = [
  ['POST /login', AuthController, 'login', 'login', 'dashboard'],
  ['POST /refresh', AuthController, 'refresh', 'refresh', 'dashboard'],
  ['POST /mfa/challenge', MfaController, 'challenge', 'mfa_verify', 'dashboard'],
  [
    'POST /password/forgot-password',
    PasswordResetController,
    'forgotPassword',
    'password_reset',
    'dashboard'
  ],
  [
    'POST /password/reset-password',
    PasswordResetController,
    'resetPassword',
    'password_reset',
    'dashboard'
  ],
  ['POST /platform/auth/login', PlatformAuthController, 'login', 'login', 'platform'],
  [
    'POST /platform/auth/mfa/challenge',
    PlatformAuthController,
    'mfaChallenge',
    'mfa_verify',
    'platform'
  ],
  ['POST /platform/auth/refresh', PlatformAuthController, 'refresh', 'refresh', 'platform']
]

describe('observed routes', () => {
  // Scenario: each route the library's metrics and spans describe. Expected: its handler carries the
  // operation and the plane, and the interceptor is attached to it.
  it.each(OBSERVED_ROUTES)(
    '%s is observed as %s %s',
    (_route, controller, method, operation, plane) => {
      const handler: unknown = Reflect.get(controller.prototype as object, method)

      expect(Reflect.getMetadata(OBSERVE_AUTH_METADATA, handler as object)).toEqual({
        operation,
        plane
      })
      expect(Reflect.getMetadata('__interceptors__', handler as object)).toContain(
        AuthObservabilityInterceptor
      )
    }
  )

  // Scenario: every handler of the four controllers that carries the marker. Expected: it is one of the
  // routes above, so a route cannot be marked without a row naming it, and the counts of a plane are not
  // fed by a route on the other.
  it('marks no handler that is not in the table', () => {
    const listed = new Set(
      OBSERVED_ROUTES.map(([, controller, method]) => `${controller.name}.${method}`)
    )
    const marked: string[] = []

    for (const controller of [
      AuthController,
      MfaController,
      PasswordResetController,
      PlatformAuthController
    ]) {
      for (const name of Object.getOwnPropertyNames(controller.prototype)) {
        const handler: unknown = Reflect.get(controller.prototype as object, name)
        if (typeof handler === 'function' && Reflect.hasMetadata(OBSERVE_AUTH_METADATA, handler)) {
          marked.push(`${controller.name}.${name}`)
        }
      }
    }

    expect(marked.sort()).toEqual([...listed].sort())
  })
})
