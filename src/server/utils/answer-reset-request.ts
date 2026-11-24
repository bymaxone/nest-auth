/**
 * @fileoverview The flow shared by `forgot-password` and `resend-otp`: claim the resend cooldown,
 * look the account up, and issue a code when it exists, with one rule for what a failure may tell
 * the caller.
 *
 * Both routes acknowledge with 200 whether or not the account exists, so a failure reaches the
 * caller only if it cannot tell the caller anything about the address:
 *
 * - a failure BEFORE the account is known (the cooldown store, the account lookup) is the same for
 *   every address, because the cooldown is the first thing every request consults, ahead of any
 *   step that depends on the account, so it answers after the floor: `auth.service_unavailable` (503) when the
 *   cooldown store cannot answer, `auth.internal` (500) otherwise;
 * - a failure AFTER the account is known (issuing or storing the code) happens only for a
 *   registered address, so it is logged and the 200 acknowledgement stands;
 * - the cooldown this call took is released when the request itself observes the failure (the lookup
 *   or the code store), so the retry a 500 invites is not refused for the rest of the window. A send
 *   that fails after the response has left is detached and never releases it: a release from there
 *   is a delete by key that can remove a later request's fresh cooldown. A cooldown hit takes the
 *   same floor as every other exit, so releasing it for some accounts opens no timing difference.
 *
 * @layer Utility
 */

import type { Logger } from '@nestjs/common'

import { isRefusal } from './object-prototype-guard'
import { checked, pinned } from './settle'
import { sleep } from './sleep'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { logStore } from '../observability/log-event'
import type { AuthRedisService } from '../redis/auth-redis.service'
import { isServiceUnavailable } from '../redis/redis-outage'

/** What {@link answerResetRequest} needs from the service that calls it. */
export interface ResetRequestDeps {
  readonly redis: Pick<AuthRedisService, 'setnx' | 'del'>
  readonly logger: Logger
}

/** One reset request, described by the caller. */
export interface ResetRequest {
  /** The key the resend cooldown lives under, shared by both entry points. */
  readonly cooldownKey: string
  readonly cooldownSeconds: number
  /** The anti-enumeration floor, in milliseconds, measured from `start`. */
  readonly floorMs: number
  /** `Date.now()` taken when the request began. */
  readonly start: number
  /** Resolves the account, or `null` when there is none the request may act on. */
  readonly findAccount: () => Promise<{ id: string; status: string } | null>
  readonly isBlocked: (status: string) => boolean
  /** Issues and stores the code for the account; the mail itself is not awaited. */
  readonly issue: (userId: string) => Promise<void>
}

/**
 * Runs one reset request and waits out the floor on every exit.
 *
 * @throws {@link AuthException} `SERVICE_UNAVAILABLE` when the cooldown store cannot answer,
 *   `INTERNAL` when it or the account lookup fails otherwise.
 */
export async function answerResetRequest(
  deps: ResetRequestDeps,
  request: ResetRequest
): Promise<void> {
  const { redis, logger } = deps
  const { cooldownKey, start } = request
  const holdFloor = (): Promise<void> => sleep(Math.max(0, request.floorMs - (Date.now() - start)))
  // A release that fails is logged and never raised: the failure that called for it is the answer.
  const releaseCooldown = async (): Promise<void> => {
    try {
      await pinned(redis.del(cooldownKey))
    } catch (err: unknown) {
      logStore(logger, 'AUTH_STORE_FAILED', 'reset_cooldown_release', err)
    }
  }

  let claimed: boolean
  try {
    claimed = await pinned(redis.setnx(cooldownKey, request.cooldownSeconds))
  } catch (err: unknown) {
    logStore(logger, 'AUTH_STORE_FAILED', 'reset_cooldown_store', err)
    await pinned(holdFloor())
    throw isServiceUnavailable(err) ? err : new AuthException(AUTH_ERROR_CODES.INTERNAL)
  }
  // Silent success on a cooldown hit, with the same floor as every other exit, so the throttle
  // does not itself answer whether the account exists.
  if (!claimed) {
    await pinned(holdFloor())
    return
  }

  let account: { id: string; status: string } | null
  try {
    account = await pinned(request.findAccount())
  } catch (err: unknown) {
    logStore(logger, 'AUTH_STORE_FAILED', 'reset_account_lookup', err)
    await pinned(releaseCooldown())
    await pinned(holdFloor())
    throw new AuthException(AUTH_ERROR_CODES.INTERNAL)
  }

  const issued = await pinned(issueQuietly(logger, request, account))
  if (issued.failed) await pinned(releaseCooldown())
  await pinned(holdFloor())
  // The refusal of the runtime is raised last, after the cooldown was released and the floor was held.
  if (issued.refusal !== undefined) throw issued.refusal
}

/**
 * Issues the reset for an account that may receive one. A failure is logged and reported, never raised: the answer must not depend
 * on it. The refusal of the runtime is reported apart, because it is raised once the floor has been paid.
 */
async function issueQuietly(
  logger: Logger,
  request: ResetRequest,
  account: { id: string; status: string } | null
): Promise<{ failed: boolean; refusal: unknown }> {
  try {
    if (account && !request.isBlocked(account.status)) await pinned(request.issue(account.id))
    return checked({ failed: false, refusal: undefined })
  } catch (err: unknown) {
    if (!isRefusal(err)) logStore(logger, 'AUTH_STORE_FAILED', 'reset_issue', err)
    return checked({ failed: true, refusal: isRefusal(err) ? err : undefined })
  }
}
