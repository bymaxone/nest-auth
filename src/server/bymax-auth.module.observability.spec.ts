/**
 * @fileoverview `registerAsync` registers what the flows count with and exports what the optional
 * `observability` subpath reads, whichever controllers are enabled.
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
import { completeEmailProvider } from './__tests__/complete-email-provider'
import { AuthHealthProbe } from './observability/auth-health-probe'
import { AuthMetricsTally } from './observability/auth-metrics-tally'
import { AuthTracing } from './observability/auth-tracing'
import { AuthObservabilityInterceptor } from './observability/observe-auth'
import type { BymaxAuthModuleOptions } from './interfaces/auth-module-options.interface'
import type { ControllerFlags } from './interfaces/controller-flags.interface'

const OPTIONS: BymaxAuthModuleOptions = {
  jwt: { secret: 'xY9!kL2@mN5#pQ8$rS1%tU4^vW7&zA0B' },
  roles: { hierarchy: { MEMBER: [] } },
  rateLimit: { enabled: false }
}

const REQUIRED = [
  { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: {} },
  { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: {} },
  { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: completeEmailProvider() },
  { provide: BYMAX_AUTH_HOOKS, useValue: {} }
]

/** The module registered with the given controller flags. */
function register(controllers?: ControllerFlags): ReturnType<typeof BymaxAuthModule.registerAsync> {
  return BymaxAuthModule.registerAsync({
    useFactory: () => OPTIONS,
    extraProviders: REQUIRED,
    ...(controllers === undefined ? {} : { controllers })
  })
}

describe('BymaxAuthModule observability providers', () => {
  // Scenario: the default registration, and one with every optional controller off. Expected: the tally, the
  // seam, the probe and the interceptor are registered, and the tally and the probe are exported, so a host
  // module that lists the contributor and the indicator can inject them.
  it.each([
    ['the default controllers', undefined],
    ['the auth controller off', { auth: false, passwordReset: false }]
  ])('registers the providers and exports what the subpath reads with %s', (_case, controllers) => {
    const module = register(controllers)

    expect(module.providers).toEqual(
      expect.arrayContaining([
        AuthMetricsTally,
        AuthTracing,
        AuthHealthProbe,
        AuthObservabilityInterceptor
      ])
    )
    expect(module.exports).toEqual(expect.arrayContaining([AuthMetricsTally, AuthHealthProbe]))
    expect(module.exports).not.toContain(AuthTracing)
    expect(module.exports).not.toContain(AuthObservabilityInterceptor)
  })
})
