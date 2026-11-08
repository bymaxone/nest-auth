/**
 * @fileoverview Fire-and-forget delivery of an MFA state-change notice.
 *
 * @layer Utility
 */

import type { Logger } from '@nestjs/common'

import { describeChannelStatus } from './describe-error'
import { logSafe } from './log-safe'
import { safeLogLine } from './safe-log-line'
import type { IEmailProvider } from '../interfaces/email-provider.interface'
import type { AuthPlatformUser } from '../interfaces/platform-user-repository.interface'
import type { AuthUser } from '../interfaces/user-repository.interface'

/**
 * The tenant a platform-plane MFA notice is attributed to. A platform admin is cross-tenant and
 * carries no `tenantId`, but the email port takes one for a notification backend's audit
 * attribution and routing; `'platform'` names that plane, mirroring the `pep:` epoch namespace.
 *
 * This is a **reserved** attribution, not a real tenant: because tenant ids are arbitrary strings,
 * a dashboard tenant literally named `'platform'` would otherwise be indistinguishable from the
 * admin plane at the port. A deployment that lets tenants choose their own id must keep this one
 * out of that space, the same way `pep:`/`ep:` keep the two epoch namespaces from colliding in
 * Redis. A single-tenant provider ignores the value and the question does not arise.
 */
const PLATFORM_EMAIL_TENANT = 'platform'

/**
 * The tenant an MFA email is attributed to: a dashboard user's own tenant, or the platform plane
 * for a cross-tenant admin who carries none.
 *
 * @param user - The dashboard or platform user the notice is about.
 * @returns The tenant id for the email port.
 */
function emailTenantOf(user: AuthUser | AuthPlatformUser): string {
  return 'tenantId' in user ? user.tenantId : PLATFORM_EMAIL_TENANT
}

/**
 * Sends an MFA state-change notice, fire-and-forget, with the recipient kept out of the log.
 *
 * **Not awaited, by design.** A rejected delivery that travelled out of the service would reach
 * `AuthExceptionFilter` and answer the caller with an error for an operation that has ALREADY
 * completed: by then the secret is written, the sessions are invalidated and the token epoch is
 * bumped, and telling the user it failed is how they end up locked out of an account they just
 * secured. `PasswordResetService.notifyPasswordChanged` follows the same rule for the same reason.
 *
 * **The address does not reach the log.** An SMTP rejection routinely NAMES the recipient it
 * refused (`550 user@example.com: recipient rejected`) with no quoted body required, which makes
 * it the likeliest exposure of the set. `describeChannelStatus` publishes nothing the channel
 * wrote, and nothing parsed off it either, so no part of that name comes through. `withheld`
 * covers the fields this line composes rather than the error, and `safeLogLine` checks the seam
 * the template opens between them.
 *
 * @param logger - Where a failed delivery is recorded.
 * @param emailProvider - The configured email port.
 * @param origin - The calling flow, for the log line.
 * @param userId - Whose account changed.
 * @param user - The account, read for its tenant and address.
 * @param send - Which notice to dispatch.
 */
export function notifyMfaChange(
  logger: Logger,
  emailProvider: IEmailProvider,
  origin: string,
  userId: string,
  user: AuthUser | AuthPlatformUser,
  send: (provider: IEmailProvider, tenantId: string, email: string) => Promise<void> | void
): void {
  const tenantId = emailTenantOf(user)
  const email = user.email
  const withheld = [email]

  // An async IIFE rather than `Promise.resolve(send(...))`: the second evaluates the call before
  // the promise wraps it, so a provider that throws SYNCHRONOUSLY skips this handler entirely.
  // Inside the IIFE the call is still made synchronously and the `try` still catches the throw.
  //
  // Detached rather than awaited, and the trade is worth stating because the `catch` below means
  // awaiting would not fail the operation. What awaiting WOULD buy is that the handoff to the
  // channel completed before the caller was answered — which is not the same as the notice
  // arriving, and is bought with the user's request waiting on a third party after their MFA
  // state has already changed. A relay that is slow, not down, would then stall an enable that
  // has fully succeeded. Neither shape survives a freeze mid-flight: an awaited send loses the
  // notice AND the response. A guarantee that this notice is delivered belongs to a queue, which
  // is the consumer's `IEmailProvider` to provide and this library cannot supply on its behalf.
  void (async (): Promise<void> => {
    try {
      await send(emailProvider, tenantId, email)
    } catch (err: unknown) {
      logger.error(
        safeLogLine(
          `${origin}: MFA notice delivery failed for user ${logSafe(userId)}: ` +
            describeChannelStatus(err),
          withheld
        )
      )
    }
  })()
}
