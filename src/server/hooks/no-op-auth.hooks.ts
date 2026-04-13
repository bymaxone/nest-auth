import { Injectable } from '@nestjs/common'

import type {
  BeforeRegisterResult,
  HookContext,
  IAuthHooks,
  OAuthLoginResult
} from '../interfaces/auth-hooks.interface'
import type { OAuthProfile } from '../interfaces/oauth-provider.interface'
import type { SafeAuthUser } from '../interfaces/user-repository.interface'

/**
 * No-operation authentication hooks implementation.
 *
 * Implements {@link IAuthHooks} with safe, permissive defaults for all lifecycle
 * hooks. Register this as the default when no consumer-provided hooks are injected.
 *
 * @remarks
 * - {@link beforeRegister} returns `{ allowed: true }` unconditionally.
 * - {@link onOAuthLogin} applies the standard account-resolution strategy:
 *   link if an existing user matches the profile email, create if no existing
 *   user is found, and reject on email mismatch.
 * - All other hooks are no-ops (return `void`).
 *
 * Replace this with a custom `IAuthHooks` implementation to enforce domain
 * allowlists, audit logging, or custom session policies.
 */
@Injectable()
export class NoOpAuthHooks implements IAuthHooks {
  /**
   * Permits all registration attempts unconditionally.
   *
   * @returns `{ allowed: true }` — never blocks registration.
   */
  beforeRegister(
    _data: { email: string; name: string; tenantId: string },
    _context: HookContext
  ): BeforeRegisterResult {
    return { allowed: true }
  }

  /**
   * Resolves OAuth login by linking to an existing account, creating a new one,
   * or rejecting on email mismatch.
   *
   * @param profile - Normalized OAuth profile from the provider.
   * @param existingUser - Existing user found by the profile email, or `null`.
   * @returns An {@link OAuthLoginResult} controlling the account resolution strategy.
   */
  onOAuthLogin(
    profile: OAuthProfile,
    existingUser: SafeAuthUser | null,
    _context: HookContext
  ): OAuthLoginResult {
    if (existingUser === null) {
      return { action: 'create' }
    }

    if (existingUser.email === profile.email) {
      return { action: 'link' }
    }

    return { action: 'reject', reason: 'Email mismatch' }
  }
}
