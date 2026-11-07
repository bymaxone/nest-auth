/**
 * @fileoverview The flow shared by `forgot-password` and `resend-otp`: claim the resend cooldown,
 * look the account up, and issue a code when it exists, with one rule for what a failure may tell
 * the caller.
 *
 * Both routes acknowledge with 200 whether or not the account exists, so a failure reaches the
 * caller only if it cannot tell the caller anything about the address:
 *
 * - a failure BEFORE the account is known (the cooldown store, the account lookup) is the same for
 *   every address, so it answers `auth.internal` (500) after the floor;
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

import { describeChannelStatus } from './describe-error'
import { sleep } from './sleep'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { AuthRedisService } from '../redis/auth-redis.service'

/** What {@link answerResetRequest} needs from the service that calls it. */
export interface ResetRequestDeps {
  readonly redis: Pick<AuthRedisService, 'setnx' | 'del'>
  readonly logger: Logger
}

/** One reset request, described by the caller. */
export interface ResetRequest {
  /** Names the entry point in log lines. */
  readonly label: 'initiateReset' | 'resendOtp'
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
 * @throws {@link AuthException} `INTERNAL` when the cooldown store or the account lookup fails.
 */
export async function answerResetRequest(
  deps: ResetRequestDeps,
  request: ResetRequest
): Promise<void> {
  const { redis, logger } = deps
  const { label, cooldownKey, start } = request
  const holdFloor = (): Promise<void> => sleep(Math.max(0, request.floorMs - (Date.now() - start)))
  // A release that fails is logged and never raised: the failure that called for it is the answer.
  const releaseCooldown = async (): Promise<void> => {
    try {
      await redis.del(cooldownKey)
    } catch (err: unknown) {
      logger.error(`${label}: cooldown release failed: ${describeChannelStatus(err)}`)
    }
  }

  let claimed: boolean
  try {
    claimed = await redis.setnx(cooldownKey, request.cooldownSeconds)
  } catch (err: unknown) {
    logger.error(`${label}: cooldown store failed: ${describeChannelStatus(err)}`)
    await holdFloor()
    throw new AuthException(AUTH_ERROR_CODES.INTERNAL)
  }
  // Silent success on a cooldown hit, with the same floor as every other exit, so the throttle
  // does not itself answer whether the account exists.
  if (!claimed) {
    await holdFloor()
    return
  }

  let account: { id: string; status: string } | null
  try {
    account = await request.findAccount()
  } catch (err: unknown) {
    logger.error(`${label}: account lookup failed: ${describeChannelStatus(err)}`)
    await releaseCooldown()
    await holdFloor()
    throw new AuthException(AUTH_ERROR_CODES.INTERNAL)
  }

  try {
    if (account && !request.isBlocked(account.status)) await request.issue(account.id)
  } catch (err: unknown) {
    logger.error(`${label}: unexpected error: ${describeChannelStatus(err)}`)
    await releaseCooldown()
  }
  await holdFloor()
}
