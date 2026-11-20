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
 * read that a caller owns. A client that rejects, or answers anything but `PONG`, is `down`; the
 * aggregator bounds the check by its own timeout and turns a rejection into a `down` entry, so this class
 * neither times itself out nor catches. No detail is reported, so nothing about the store leaves with it.
 */
@SetMetadata(HEALTH_INDICATOR_METADATA, true)
@Injectable()
export class AuthRedisHealthIndicator implements HealthIndicator {
  readonly name = 'auth-redis'

  constructor(@Inject(AuthHealthProbe) private readonly probe: AuthHealthProbe) {}

  /** Whether the store answers. */
  async check(): Promise<HealthIndicatorResult> {
    return { status: (await this.probe.ping()) ? 'up' : 'down' }
  }
}
