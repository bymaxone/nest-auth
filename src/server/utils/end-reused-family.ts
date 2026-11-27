/**
 * @fileoverview What a replayed refresh token costs: its lineage is revoked and the host is told.
 *
 * @layer Utility
 */

import type { Logger } from '@nestjs/common'

import { runDetached } from './run-detached'
import { createEmptyHookContext } from './sanitize-headers'
import { announceSessionsRevoked } from './session-revocation'
import { pinned } from './settle'
import type { IAuthHooks } from '../interfaces/auth-hooks.interface'
import { logEvent } from '../observability/log-event'
import type { AuthRedisService } from '../redis/auth-redis.service'

/** The family a replayed token belongs to, and who presented the token. */
export interface ReusedFamily {
  /** The identity plane the family belongs to. */
  kind: 'dashboard' | 'platform'
  /** The rotation outcome that found the replay. */
  outcome: { familyId: string }
  ip: string
  userAgent: string
}

/**
 * Emits {@link IAuthHooks.onRefreshTokenReuseDetected}, fire-and-forget.
 *
 * The owner is read from the stored session where it can be — a replay of a token whose live
 * key is already gone leaves nothing to read, and the hook is skipped rather than fired with
 * an empty identity that a consumer would have to guess about.
 *
 * **The context describes WHO PRESENTED the replayed token**, which is the whole reason a
 * consumer subscribes to this hook. `userId` says whose account the family belongs to; `ip` and
 * `userAgent` are the only description of the party holding the token that should not exist, so
 * a report carrying the first and not the second says a compromise happened and gives nothing
 * to act on.
 *
 * `sanitizedHeaders` stays empty and that is honest — the rotation path receives the address
 * and the agent, never the header map, so there is nothing to sanitize. Inventing one would be
 * worse than an empty object a consumer can see is empty.
 */
export async function endReusedFamily(
  redis: AuthRedisService,
  hooks: IAuthHooks | null,
  logger: Logger,
  { kind, outcome, ip, userAgent }: ReusedFamily
): Promise<void> {
  const { familyId } = outcome
  const { ownerId: userId, tenantId } = await pinned(
    kind === 'platform' ? redis.revokeFamily(familyId, 'platform') : redis.revokeFamily(familyId)
  )
  announceSessionsRevoked(hooks, logger, {
    userId,
    ...(tenantId === undefined ? {} : { tenantId }),
    plane: kind,
    reason: 'refresh_reuse'
  })
  // Named on both planes: on the platform one this is the highest-privilege identity.
  logEvent(logger, 'AUTH_REFRESH_FAMILY_REVOKED', { plane: kind, familyId: outcome.familyId })
  // The one moment the library can say "this is not a guess about risk": a token that was already
  // exchanged has been presented again, so one of its two holders is not the owner. Emitted after
  // the revocation, so a consumer that reacts by paging someone is reacting to a lineage that is
  // already dead rather than one still being torn down.
  if (!hooks?.onRefreshTokenReuseDetected || userId === '') return
  const onReuse = hooks.onRefreshTokenReuseDetected.bind(hooks)
  runDetached(
    logger,
    () =>
      onReuse({ userId, familyId }, { ...createEmptyHookContext(), plane: kind, ip, userAgent }),
    'onRefreshTokenReuseDetected'
  )
}
