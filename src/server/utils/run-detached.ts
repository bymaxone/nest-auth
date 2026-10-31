/**
 * @fileoverview Runs a side effect without awaiting it and without letting it change an outcome.
 *
 * @layer Utility
 */

import type { Logger } from '@nestjs/common'

import { describeChannelStatus } from './describe-error'

/**
 * Starts `run` and returns at once. A rejection and a synchronous throw are both caught and logged.
 *
 * Meant for the effects that follow a login that has already succeeded — recording the last
 * login, the host's `afterLogin` hook. Neither may turn a completed sign-in into a failure, and
 * what a failing party wrote is not published: the repository's message can carry an account id
 * and a hook's can carry anything, so the line carries `failure` and the shape of the error only.
 *
 * @param logger - The logger of the calling service.
 * @param run - The side effect.
 * @param failure - The log text for a failed effect, without a trailing colon.
 */
export function runDetached(
  logger: Logger,
  run: () => Promise<unknown> | unknown,
  failure: string
): void {
  try {
    void Promise.resolve(run()).catch((err: unknown) => {
      logger.error(`${failure}: ${describeChannelStatus(err)}`)
    })
  } catch (err: unknown) {
    logger.error(`${failure}: ${describeChannelStatus(err)}`)
  }
}
