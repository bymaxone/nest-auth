/**
 * @fileoverview Publishes what the authentication flows counted to the application's metrics registry.
 *
 * An optional subpath: it names `prom-client`, which an application that publishes no metrics never
 * installs, so nothing outside `src/observability` may import it. The counts are kept by `AuthMetricsTally`
 * in the server entry, in plain numbers; this class only reads them.
 *
 * This package imports no other Bymax library. The contract of `@bymax-one/nest-core` that this class meets is
 * written out below, and the key `BymaxCoreModule` discovers a contributor by is the documented string
 * literal, so nothing here names that package; a spec compares both with the published declarations.
 *
 * @layer Observability
 */

import { Inject, Injectable, SetMetadata } from '@nestjs/common'
import { Counter } from 'prom-client'
import type { Registry } from 'prom-client'

import {
  AUTH_PLANES,
  AuthMetricsTally,
  LOGIN_OUTCOMES,
  MFA_OUTCOMES,
  REFRESH_OUTCOMES
} from '@bymax-one/nest-auth'
import type { AuthPlane } from '@bymax-one/nest-auth'

/** The registry the application's scrape endpoint serves. */
type MetricsRegistry = Registry

/** What a component that publishes metrics implements: it receives the registry at bootstrap. */
interface MetricsContributor {
  registerMetrics(registry: MetricsRegistry): void
}

/** The metadata key a metrics module discovers contributors by. */
export const METRICS_CONTRIBUTOR_METADATA = 'bymax-one:metrics-contributor'

/** A counter labelled by plane and outcome, read from the tally on every scrape after a reset. */
function countedByPlaneAndOutcome<K extends string>(
  registry: MetricsRegistry,
  spec: {
    readonly name: string
    readonly help: string
    readonly outcomes: readonly K[]
    readonly read: () => Readonly<Record<AuthPlane, Readonly<Record<K, number>>>>
  }
): void {
  const { outcomes, read } = spec
  new Counter({
    name: spec.name,
    help: spec.help,
    labelNames: ['plane', 'outcome'],
    registers: [registry],
    collect(): void {
      this.reset()
      const counts = read()
      for (const plane of AUTH_PLANES) {
        for (const outcome of outcomes) this.inc({ plane, outcome }, counts[plane][outcome])
      }
    }
  })
}

/**
 * Registers the authentication collectors on the registry the scrape endpoint serves.
 *
 * Every counter is read from the tally on each scrape, after a reset, instead of being written as events
 * arrive: the tally starts counting before this class runs, and a counter fed by events would drop that
 * window. Labels are the closed sets the tally is keyed by; no id, tenant, user, address or message ever
 * becomes one.
 *
 * @example
 * // providers: [AuthMetrics]  (BymaxCoreModule discovers it and calls registerMetrics once at bootstrap)
 */
@SetMetadata(METRICS_CONTRIBUTOR_METADATA, true)
@Injectable()
export class AuthMetrics implements MetricsContributor {
  constructor(@Inject(AuthMetricsTally) private readonly tally: AuthMetricsTally) {}

  /** Registers the collectors; called once at bootstrap by the metrics module. */
  registerMetrics(registry: MetricsRegistry): void {
    const { tally } = this
    countedByPlaneAndOutcome(registry, {
      name: 'bymax_auth_logins_total',
      help: 'Login attempts by plane and outcome.',
      outcomes: LOGIN_OUTCOMES,
      read: () => tally.snapshot().logins
    })
    countedByPlaneAndOutcome(registry, {
      name: 'bymax_auth_refresh_total',
      help: 'Refresh attempts by plane and outcome.',
      outcomes: REFRESH_OUTCOMES,
      read: () => tally.snapshot().refreshes
    })
    countedByPlaneAndOutcome(registry, {
      name: 'bymax_auth_mfa_verifications_total',
      help: 'MFA verifications by plane and outcome.',
      outcomes: MFA_OUTCOMES,
      read: () => tally.snapshot().mfa
    })
    new Counter({
      name: 'bymax_auth_bruteforce_lockouts_total',
      help: 'Identifiers locked out after too many failed attempts.',
      registers: [registry],
      collect(): void {
        this.reset()
        this.inc(tally.snapshot().lockouts)
      }
    })
  }
}
