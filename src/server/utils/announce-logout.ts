/**
 * @fileoverview What a completed dashboard logout tells the host.
 *
 * @layer Utility
 */

import type { Logger } from '@nestjs/common'

import { runDetached } from './run-detached'
import { createEmptyHookContext } from './sanitize-headers'
import { announceSessionsRevoked } from './session-revocation'
import type { HookContext, IAuthHooks } from '../interfaces/auth-hooks.interface'

/** The session a logout ended. */
export interface EndedSession {
  /** The account that signed out; empty when the record named no owner. */
  userId: string
  /** The tenant from the session record, absent on a record that carries none. */
  tenantId: string | undefined
  /** The hash of the session that ended. */
  sessionHash: string
}

/**
 * Announces a completed logout, through `onSessionsRevoked` and `afterLogout`, awaiting neither.
 *
 * The context names the account, because `logout` knows it — `readSessionOwner` returns both
 * fields and the session revoke is keyed on them. A consumer disconnecting live sockets must
 * match the tenant as well as the id, since a repository id is unique only within a tenant, so a
 * hook naming only the id cannot be acted on safely: acting on it would reach another tenant's
 * account.
 *
 * `ip` and `userAgent` stay empty because `logout` receives two tokens and no request, and an
 * invented value would be worse than an empty string a consumer can see is empty. `tenantId` is
 * omitted rather than set to `undefined` when the session record carries none, so its absence
 * reads as "the record did not say" rather than as a tenant literally named `undefined`.
 *
 * With no account named there is nobody to announce and nothing fires.
 */
export function announceLogout(
  hooks: IAuthHooks | null,
  logger: Logger,
  { userId, tenantId, sessionHash }: EndedSession
): void {
  announceSessionsRevoked(hooks, logger, {
    userId,
    ...(tenantId === undefined ? {} : { tenantId }),
    plane: 'dashboard',
    reason: 'logout',
    sessionIds: [sessionHash]
  })
  if (!hooks?.afterLogout || !userId) return

  const context: HookContext = { ...createEmptyHookContext(), plane: 'dashboard', userId }
  if (tenantId !== undefined) {
    context.tenantId = tenantId
  }

  // `runDetached` calls the hook inside its own `try`: `afterLogout` may be declared `void`, and a
  // synchronous throw must be logged, not escape into a `logout` whose Redis writes have completed.
  const afterLogout = hooks.afterLogout.bind(hooks)
  runDetached(logger, () => afterLogout(userId, context), 'afterLogout')
}
