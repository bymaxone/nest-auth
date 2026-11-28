/**
 * @fileoverview The removal of the dashboard sessions the session limit pushed out.
 *
 * @layer Utility
 */

import type { Logger } from '@nestjs/common'

import { describeChannelStatus } from './describe-error'
import { runDetached } from './run-detached'
import { endSignIn } from './session-access'
import { announceSessionsRevoked } from './session-revocation'
import { pinned } from './settle'
import { raiseFirst, settleWrites } from './settle-writes'
import type { HookContext, IAuthHooks } from '../interfaces/auth-hooks.interface'
import { logEvent } from '../observability/log-event'
import type { AuthRedisService } from '../redis/auth-redis.service'

/** The store operations an eviction needs. */
export type EvictionStore = Pick<
  AuthRedisService,
  'del' | 'srem' | 'set' | 'readSessionOwner' | 'revokeFamily'
>

/** The account and the request an eviction pass is made for, and the account's session index. */
export interface EvictionRequest {
  userId: string
  tenantId: string
  ip: string
  userAgent: string
  index: string
  /** The resolved JWT options; the access lifetime bounds how long an ended session's entry lives. */
  jwt: { accessExpiresIn: string }
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
}: Omit<EvictionRequest, 'index' | 'jwt'>): HookContext {
  return { plane: 'dashboard', userId, tenantId, ip, userAgent, sanitizedHeaders: {} }
}

/**
 * Removes one evicted session and ends its sign-in. `onRemoved` is given its hash once the refresh
 * token is deleted, and the hashes of the sign-in once that is ended; the writes after the delete
 * are all attempted, and the first failure is raised.
 */
async function removeEvicted(
  redis: EvictionStore,
  { index, jwt }: Pick<EvictionRequest, 'index' | 'jwt'>,
  { member, memberHash }: { member: string; memberHash: string },
  onRemoved: (sessionHashes: string[]) => void
): Promise<void> {
  const { familyId } = await pinned(redis.readSessionOwner(`rt:${memberHash}`))
  await pinned(redis.del(`rt:${memberHash}`))
  onRemoved([memberHash])
  const endAccess = (): Promise<void> =>
    endSignIn(redis, 'dashboard', familyId, jwt.accessExpiresIn, onRemoved)
  raiseFirst(
    await pinned(
      settleWrites([
        endAccess,
        (): Promise<unknown> => redis.srem(index, member),
        (): Promise<unknown> => redis.del(`sd:${memberHash}`)
      ])
    )
  )
}

/**
 * Removes the sessions the limit pushed out. Each one whose writes are all accepted fires
 * `onSessionEvicted`; the pass then fires `onSessionsRevoked` once, naming every session whose
 * refresh token was deleted, the other sessions of its sign-in included.
 */
export async function evictSessions(
  redis: EvictionStore,
  hooks: IAuthHooks | null,
  logger: Logger,
  { userId, tenantId, ip, userAgent, index, jwt }: EvictionRequest,
  toEvict: ReadonlyArray<{ member: string; memberHash: string }>
): Promise<void> {
  const context = evictionContext({ userId, tenantId, ip, userAgent })

  const evicted = new Set<string>()
  for (const entry of toEvict) {
    try {
      // Best-effort eviction: partial Redis failures leave stale keys that expire via TTL.
      // The new session is already committed at this point — a mid-eviction failure
      // MUST NOT propagate back to createSession callers.
      await pinned(
        removeEvicted(redis, { index, jwt }, entry, (sessionHashes) => {
          for (const hash of sessionHashes) evicted.add(hash)
        })
      )
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

  if (evicted.size > 0) {
    announceSessionsRevoked(hooks, logger, {
      userId,
      tenantId,
      plane: 'dashboard',
      reason: 'session_evicted',
      sessionIds: [...evicted]
    })
  }
}
