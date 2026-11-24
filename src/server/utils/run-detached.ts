/**
 * @fileoverview Runs a side effect without awaiting it and without letting it change an outcome.
 *
 * @layer Utility
 */

import type { Logger } from '@nestjs/common'

import { detached } from './settle'
import { logHook } from '../observability/log-event'
import type { HookStep } from '../observability/log-event'

/**
 * Starts `run` and returns at once. A rejection and a synchronous throw are both caught and written as an event.
 *
 * Meant for the effects that follow a login that has already succeeded — recording the last
 * login, the host's `afterLogin` hook. Neither may turn a completed sign-in into a failure, and
 * what a failing party wrote is not published: the repository's message can carry an account id
 * and a hook's can carry anything, so the event carries the step and how it failed, and nothing else.
 *
 * @param logger - The logger of the calling service.
 * @param run - The side effect.
 * @param hook - The step that ran, from the closed set above.
 */
export function runDetached(
  logger: Logger,
  run: () => Promise<unknown> | unknown,
  hook: HookStep
): void {
  detached(run, (how) => {
    logHook(logger, hook, how)
  })
}
