/**
 * @fileoverview The one question the readiness check asks of the store the library depends on.
 *
 * @layer Service
 */

import { Inject, Injectable } from '@nestjs/common'

import { BYMAX_AUTH_REDIS_CLIENT } from '../bymax-auth.constants'

/**
 * Asks the Redis client the module was given whether it answers.
 *
 * A `PING` writes nothing and reads nothing a caller owns, so a readiness probe costs the store one round
 * trip and no data. It lives in the main entry because the client is private to the module; the optional
 * `observability` subpath wraps it as a health indicator.
 */
@Injectable()
export class AuthHealthProbe {
  constructor(
    @Inject(BYMAX_AUTH_REDIS_CLIENT) private readonly redis: { ping(): Promise<string> }
  ) {}

  /**
   * Whether the store answers a `PING`.
   *
   * @returns `true` when it answers `PONG`, `false` for any other answer.
   * @throws Whatever the client throws when the store cannot be reached; the health aggregator turns it
   *   into a `down` entry.
   */
  async ping(): Promise<boolean> {
    return (await this.redis.ping()) === 'PONG'
  }
}
