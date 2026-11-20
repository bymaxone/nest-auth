/**
 * @fileoverview The providers the module registers for observability, and the ones it exports for the
 * optional `observability` subpath to read.
 *
 * @layer Config
 */

import { AuthHealthProbe } from './auth-health-probe'
import { AuthMetricsTally } from './auth-metrics-tally'
import { AuthTracing } from './auth-tracing'
import { AuthObservabilityInterceptor } from './observe-auth'

/** Registered unconditionally: they depend on nothing a host has to configure, and cost integer increments. */
export const OBSERVABILITY_PROVIDERS = [
  AuthMetricsTally,
  AuthTracing,
  AuthHealthProbe,
  AuthObservabilityInterceptor
]

/** What a host module's metrics contributor and health indicator inject. */
export const OBSERVABILITY_EXPORTS = [AuthMetricsTally, AuthHealthProbe]
