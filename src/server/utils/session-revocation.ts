/**
 * @fileoverview The announcement every session revocation makes, and the revocation of every
 * session of an account that several flows share.
 *
 * @layer Utility
 */

import type { Logger } from '@nestjs/common'

import { runDetached } from './run-detached'
import { pinned } from './settle'
import type { IAuthHooks, SessionsRevokedEvent } from '../interfaces/auth-hooks.interface'
import type { AuthRedisService } from '../redis/auth-redis.service'

/**
 * Tells the host that sessions were revoked, through `onSessionsRevoked`, without awaiting it.
 *
 * Nothing the hook does reaches the caller. A platform event never carries a tenant, and an event
 * with no account is not sent: there is nobody to name.
 *
 * @param hooks - The host's hooks, if any.
 * @param logger - The logger of the calling service.
 * @param event - The revocation, after the store has deleted the sessions.
 */
export function announceSessionsRevoked(
  hooks: IAuthHooks | null,
  logger: Logger,
  event: SessionsRevokedEvent
): void {
  if (!hooks?.onSessionsRevoked || !event.userId) return

  const { userId, tenantId, plane, reason, sessionIds } = event
  const payload: SessionsRevokedEvent = { userId, plane, reason }
  if (plane === 'dashboard' && tenantId !== undefined) payload.tenantId = tenantId
  if (sessionIds !== undefined) payload.sessionIds = sessionIds

  const notify = hooks.onSessionsRevoked.bind(hooks)
  runDetached(logger, () => notify(payload), 'onSessionsRevoked')
}

/**
 * Deletes every refresh session of an account, advances its token epoch and announces it.
 *
 * The announcement is made once the sessions are deleted, whether or not the epoch write that
 * follows succeeds; a refused deletion announces nothing. Either refusal reaches the caller.
 *
 * @param redis - The store.
 * @param hooks - The host's hooks, if any.
 * @param logger - The logger of the calling service.
 * @param revocation - The account, its plane and why its sessions are ending.
 */
export async function revokeEverySession(
  redis: Pick<AuthRedisService, 'invalidateUserSessions' | 'bumpUserTokenEpoch'>,
  hooks: IAuthHooks | null,
  logger: Logger,
  revocation: Omit<SessionsRevokedEvent, 'sessionIds'>
): Promise<void> {
  const { userId, tenantId, plane } = revocation
  await pinned(redis.invalidateUserSessions(userId, tenantId, plane))
  try {
    await pinned(redis.bumpUserTokenEpoch(userId, tenantId, plane))
  } finally {
    announceSessionsRevoked(hooks, logger, revocation)
  }
}
