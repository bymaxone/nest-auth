/**
 * @fileoverview `registerAsync` refuses a controller flag that is not `true` or `false`, and a hooks or
 * email provider value that cannot work, when it is called, before anything is built.
 *
 * @layer Test
 */

import { BymaxAuthModule } from './bymax-auth.module'
import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_REDIS_CLIENT,
  BYMAX_AUTH_USER_REPOSITORY
} from './bymax-auth.constants'
import type { BymaxAuthModuleOptions } from './interfaces/auth-module-options.interface'
import type { ControllerFlags } from './interfaces/controller-flags.interface'

/** A value read back as the type a test needs it to be, for a flag a typed call would refuse. */
function untyped<T>(value: unknown): T {
  return value as T
}

const OPTIONS: BymaxAuthModuleOptions = {
  jwt: { secret: 'xY9!kL2@mN5#pQ8$rS1%tU4^vW7&zA0B' },
  roles: { hierarchy: { MEMBER: [] } },
  rateLimit: { enabled: false }
}

/** Providers every registration needs, beside the ones under test. */
const REQUIRED = [
  { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: {} },
  { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: {} }
]

describe('BymaxAuthModule.registerAsync shapes', () => {
  // Scenario: hooks with a member that is not a function. Expected: refused at the call, not at the
  // first login that fires the hook.
  it('refuses hooks that hold a member that is not a function', () => {
    expect(() =>
      BymaxAuthModule.registerAsync({
        useFactory: () => OPTIONS,
        extraProviders: [
          ...REQUIRED,
          { provide: BYMAX_AUTH_HOOKS, useValue: { onLoginFailed: true } }
        ]
      })
    ).toThrow('BYMAX_AUTH_HOOKS.onLoginFailed must be a function (received a boolean)')
  })

  // Scenario: an email provider with no methods. Expected: refused at the call.
  it('refuses an email provider that lacks the required methods', () => {
    expect(() =>
      BymaxAuthModule.registerAsync({
        useFactory: () => OPTIONS,
        extraProviders: [...REQUIRED, { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: {} }]
      })
    ).toThrow(
      'BYMAX_AUTH_EMAIL_PROVIDER.sendPasswordResetToken is required and must be a function.'
    )
  })

  // Scenario: a controller flag that is a string. Expected: refused at the call (the opt-in controllers
  // were enabled only by `=== true`, so 'yes' silently left MFA off).
  it('refuses a controller flag that is not a boolean', () => {
    expect(() =>
      BymaxAuthModule.registerAsync({
        useFactory: () => OPTIONS,
        extraProviders: REQUIRED,
        controllers: untyped<ControllerFlags>({ mfa: 'yes' })
      })
    ).toThrow('controllers.mfa must be true or false (received a string)')
  })
})
