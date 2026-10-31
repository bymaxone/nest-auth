/**
 * @fileoverview No-operation default implementation of {@link IAuthHooks}.
 *
 * All methods resolve immediately without performing any action. Used as the
 * fallback when the consuming application does not register a custom hooks provider.
 *
 * @layer Hooks
 */
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
 *   create if this provider identity is not linked yet, link if the linked user's
 *   address equals the profile's and the provider verified it, and reject otherwise.
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
   * @param _data - Registration payload containing `email`, `name`, and `tenantId`.
   * @param _context - Hook execution context carrying request metadata.
   * @returns `{ allowed: true }` — never blocks registration.
   */
  beforeRegister(
    _data: { email: string; name: string; tenantId: string },
    _context: HookContext
  ): BeforeRegisterResult {
    return { allowed: true }
  }

  /**
   * Resolves OAuth login: creates an account for an unlinked identity, keeps an existing link
   * when the address still matches and the provider vouches for it, and rejects otherwise.
   *
   * @param profile - Normalized OAuth profile from the provider.
   * @param existingUser - The user already linked to this provider identity, or `null`.
   * @param _context - Hook execution context carrying request metadata.
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

    if (existingUser.email !== profile.email) {
      return { action: 'reject', reason: 'Email mismatch' }
    }

    // A link is trusted on the address, so a provider that does not vouch for it never links.
    // Strictly `true`: a missing or loosely truthy value is not a verification.
    if (profile.emailVerified !== true) {
      return { action: 'reject', reason: 'Email not verified' }
    }

    return { action: 'link' }
  }
}
