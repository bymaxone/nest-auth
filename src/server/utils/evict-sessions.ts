/**
 * @fileoverview The removal of the dashboard sessions the session limit pushed out.
 *
 * @layer Utility
 */

import type { Logger } from '@nestjs/common'

import { describeChannelStatus } from './describe-error'
import { runDetached } from './run-detached'
import { announceSessionsRevoked } from './session-revocation'
import { pinned } from './settle'
import type { HookContext, IAuthHooks } from '../interfaces/auth-hooks.interface'
import { logEvent } from '../observability/log-event'
import type { AuthRedisService } from '../redis/auth-redis.service'

/** The account and the request an eviction pass is made for, and the account's session index. */
export interface EvictionRequest {
  userId: string
  tenantId: string
  ip: string
  userAgent: string
  index: string
}

/**
 * What `onSessionEvicted` receives beside the account and the session.
 *
 * Names the account as well as the request. An eviction context must carry tenant-qualified
 * identity: a repository id is unique only within a tenant, so a consumer disconnecting sockets on
 * a bare id reaches another tenant's user. Both values are part of the request, so there is nothing
 * to look up.
 */
function evictionContext({
  userId,
  tenantId,
  ip,
  userAgent
}: Omit<EvictionRequest, 'index'>): HookContext {
  return { plane: 'dashboard', userId, tenantId, ip, userAgent, sanitizedHeaders: {} }
}

/**
 * Removes the sessions the limit pushed out. Each one whose three writes are accepted fires
 * `onSessionEvicted`; the pass then fires `onSessionsRevoked` once, naming every session whose
 * refresh token was deleted.
 */
export async function evictSessions(
  redis: Pick<AuthRedisService, 'del' | 'srem'>,
  hooks: IAuthHooks | null,
  logger: Logger,
  { userId, tenantId, ip, userAgent, index }: EvictionRequest,
  toEvict: ReadonlyArray<{ member: string; memberHash: string }>
): Promise<void> {
  const context = evictionContext({ userId, tenantId, ip, userAgent })

  const evicted: string[] = []
  for (const entry of toEvict) {
    try {
      // Best-effort eviction: partial Redis failures leave stale keys that expire via TTL.
      // The new session is already committed at this point — a mid-eviction failure
      // MUST NOT propagate back to createSession callers.
      await pinned(redis.del(`rt:${entry.memberHash}`))
      evicted.push(entry.memberHash)
      await pinned(redis.srem(index, entry.member))
      await pinned(redis.del(`sd:${entry.memberHash}`))
    } catch (err: unknown) {
      logEvent(logger, 'AUTH_SESSION_EVICTION_FAILED', {
        detail: describeChannelStatus(err)
      })
      continue
    }

    // Fire onSessionEvicted hook — fire-and-forget; errors must not propagate.
    if (hooks?.onSessionEvicted) {
      const onSessionEvicted = hooks.onSessionEvicted.bind(hooks)
      runDetached(
        logger,
        () => onSessionEvicted(userId, entry.memberHash, context),
        'onSessionEvicted'
      )
    }
  }

  if (evicted.length > 0) {
    announceSessionsRevoked(hooks, logger, {
      userId,
      tenantId,
      plane: 'dashboard',
      reason: 'session_evicted',
      sessionIds: evicted
    })
  }
}
