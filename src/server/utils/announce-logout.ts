/**
 * @fileoverview What a dashboard logout tells the host.
 *
 * @layer Utility
 */

import type { Logger } from '@nestjs/common'

import { runDetached } from './run-detached'
import { createEmptyHookContext } from './sanitize-headers'
import { announceSessionsRevoked } from './session-revocation'
import { pinned } from './settle'
import type {
  HookContext,
  IAuthHooks,
  SessionsRevokedEvent
} from '../interfaces/auth-hooks.interface'

/** The session a logout ended. */
export interface EndedSession {
  /** The account that signed out; empty when the record named no owner. */
  userId: string
  /** The tenant from the session record, absent on a record that carries none. */
  tenantId: string | undefined
  /** The hash of the session that ended. */
  sessionHash: string
}

/** What one `logout` call tells the host. */
export interface LogoutNotice {
  /** Waits for the session delete, and tells `onSessionsRevoked` if it removed the session. */
  after(removal: Promise<boolean>): Promise<void>
  /** Tells `onSessionsRevoked` what ending the sign-in removed, the others in their own event. */
  readonly signInEnded: (sessionHashes: string[]) => void
  /**
   * For a completed logout: tells `onSessionsRevoked` unless this call already did, then
   * `afterLogout` on the dashboard plane.
   */
  completed(): void
}

/**
 * Builds the notice of one `logout` call. `onSessionsRevoked` is told as soon as the session is
 * gone, whether or not the other writes are accepted, and at most once per call; any other session
 * of the same sign-in is named in a second event. A completed logout
 * tells it even when the delete removed nothing, because a delete applied with its reply lost
 * leaves the retry nothing to remove. With no account named nothing fires.
 */
export function logoutNotice(
  hooks: IAuthHooks | null,
  logger: Logger,
  ended: EndedSession,
  plane: SessionsRevokedEvent['plane'] = 'dashboard'
): LogoutNotice {
  const { userId, tenantId, sessionHash } = ended
  let told = false
  const announce = (sessionIds: string[]): void => {
    announceSessionsRevoked(hooks, logger, {
      userId,
      ...(tenantId === undefined ? {} : { tenantId }),
      plane,
      reason: 'logout',
      sessionIds
    })
  }
  const tell = (): void => {
    if (told) return
    told = true
    announce([sessionHash])
  }
  return {
    after: async (removal: Promise<boolean>): Promise<void> => {
      if (await pinned(removal)) tell()
    },
    signInEnded: (sessionHashes: string[]): void => {
      if (sessionHashes.includes(sessionHash)) tell()
      const rest = sessionHashes.filter((hash) => hash !== sessionHash)
      if (rest.length > 0) announce(rest)
    },
    completed: (): void => {
      tell()
      if (plane === 'dashboard') announceLogout(hooks, logger, ended)
    }
  }
}

/**
 * Announces a completed logout through `afterLogout`, without awaiting it.
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
function announceLogout(
  hooks: IAuthHooks | null,
  logger: Logger,
  { userId, tenantId }: EndedSession
): void {
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
