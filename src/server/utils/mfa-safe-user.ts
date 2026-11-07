/**
 * @fileoverview Projections of an account that are safe to hand to hooks and email providers:
 * credentials and MFA secret fields stripped, for either identity plane.
 *
 * @layer Utility
 */

import type {
  AuthPlatformUser,
  SafeAuthPlatformUser
} from '../interfaces/platform-user-repository.interface'
import type { AuthUser, SafeAuthUser } from '../interfaces/user-repository.interface'

/**
 * Returns a `SafeAuthUser` projection of a dashboard user, stripping credentials
 * and MFA secret fields before passing to hooks or email providers.
 *
 * @param user - The full account record.
 * @returns The record without `passwordHash`, `mfaSecret` and `mfaRecoveryCodes`.
 */
export function toSafeUser(user: AuthUser): SafeAuthUser {
  const { passwordHash: _ph, mfaSecret: _ms, mfaRecoveryCodes: _mrc, ...safe } = user
  return safe
}

/**
 * Returns a `SafeAuthPlatformUser` projection of a platform admin, stripping
 * credentials and MFA secret fields.
 *
 * @param admin - The full admin record.
 * @returns The record without `passwordHash`, `mfaSecret` and `mfaRecoveryCodes`.
 */
export function toSafePlatformUser(admin: AuthPlatformUser): SafeAuthPlatformUser {
  const { passwordHash: _ph, mfaSecret: _ms, mfaRecoveryCodes: _mrc, ...safe } = admin
  return safe
}

/**
 * Constructs a `SafeAuthUser`-compatible object from a `SafeAuthPlatformUser` so
 * that it can be passed to hooks typed for `SafeAuthUser`.
 *
 * Platform admins have no `tenantId` or `emailVerified` fields. These are filled
 * with sentinel values (`''` and `true` respectively) since platform admins are
 * provisioned directly and do not participate in the tenant/email-verification flow.
 *
 * @param admin - The full admin record.
 * @returns The admin projected into the dashboard user's shape.
 */
export function platformUserAsSafeUser(admin: AuthPlatformUser): SafeAuthUser {
  const safe = toSafePlatformUser(admin)
  return {
    ...safe,
    tenantId: '',
    emailVerified: true
  }
}

/**
 * The account a hook is handed after an MFA transition, projected from the state the transition
 * wrote.
 *
 * The record in hand was read before the transition, so its `mfaEnabled` describes the state the
 * transition replaced; the hooks run after the write and must be told what it produced. Only the
 * flag is overridden. The secret and recovery-code fields are stripped by the same projections
 * every other hook payload uses, and the repository's own record is not modified.
 *
 * @param context - The identity plane the account belongs to.
 * @param user - The record read before the transition.
 * @param mfaEnabled - Whether the transition left the second factor enabled.
 * @returns The projection for the plane, with `mfaEnabled` as written.
 */
export function committedSafeUser(
  context: 'dashboard' | 'platform',
  user: AuthUser | AuthPlatformUser,
  mfaEnabled: boolean
): SafeAuthUser {
  const committed = { ...user, mfaEnabled }
  return context === 'platform'
    ? platformUserAsSafeUser(committed as AuthPlatformUser)
    : toSafeUser(committed as AuthUser)
}
