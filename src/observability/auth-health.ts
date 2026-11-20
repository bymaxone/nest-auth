/**
 * @fileoverview Reports whether the store the authentication flows depend on answers.
 *
 * This package imports no other Bymax library. The readiness contract of `@bymax-one/nest-core` that this
 * class meets is written out below, and the key `BymaxCoreModule` discovers an indicator by is the
 * documented string literal; a spec compares both with the published declarations.
 *
 * @layer Observability
 */

import { Inject, Injectable, SetMetadata } from '@nestjs/common'

import { AuthHealthProbe } from '@bymax-one/nest-auth'

/** The outcome of one readiness check. */
interface HealthIndicatorResult {
  status: 'up' | 'down'
  details?: Record<string, unknown>
}

/** What a readiness indicator implements. */
interface HealthIndicator {
  readonly name: string
  check(signal?: AbortSignal): Promise<HealthIndicatorResult>
}

/** The metadata key a health module discovers indicators by. */
export const HEALTH_INDICATOR_METADATA = 'bymax-one:health-indicator'

/**
 * The readiness check of the authentication store.
 *
 * It asks the Redis client the module was given for a `PING`: one round trip, nothing written and nothing
 * read that a caller owns. A client that rejects, answers anything but `PONG`, or does not answer in time is
 * `down`: the probe gives up after its own timeout, under the aggregator's, and when the aggregator's signal
 * aborts, and the aggregator turns the rejection into a `down` entry, so this class does not catch. No
 * detail is reported, so nothing about the store leaves with it.
 */
@SetMetadata(HEALTH_INDICATOR_METADATA, true)
@Injectable()
export class AuthRedisHealthIndicator implements HealthIndicator {
  readonly name = 'auth-redis'

  constructor(@Inject(AuthHealthProbe) private readonly probe: AuthHealthProbe) {}

  /** Whether the store answers in time; the aggregator's signal ends the wait. */
  async check(signal?: AbortSignal): Promise<HealthIndicatorResult> {
    return { status: (await this.probe.ping(signal)) ? 'up' : 'down' }
  }
}
