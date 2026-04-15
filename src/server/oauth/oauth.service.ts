/**
 * @fileoverview OAuth 2.0 Authorization Code flow service for @bymax-one/nest-auth.
 *
 * Handles the two-leg OAuth flow:
 *  1. `initiateOAuth()` — generates a CSRF-protection state, stores it in Redis,
 *     and redirects the user to the provider's authorization URL.
 *  2. `handleCallback()` — validates the state, exchanges the authorization code,
 *     fetches the profile, runs the `onOAuthLogin` hook, and issues auth tokens.
 *
 * @remarks
 * **Tenant spoofing warning:** `initiateOAuth()` stores the `tenantId` provided
 * by the caller without verifying that the tenant exists. The `onOAuthLogin` hook
 * is the appropriate validation point. Without an `onOAuthLogin` implementation,
 * any caller triggers `OAUTH_FAILED` — OAuth sign-in is fully disabled by default.
 * Implement `onOAuthLogin` to enable it and enforce tenant membership.
 */

import { Inject, Injectable, Logger, Optional } from '@nestjs/common'
import type { Response } from 'express'

import { OAUTH_PLUGINS } from './oauth.constants'
import {
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import { generateSecureToken, sha256 } from '../crypto/secure-token'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { IAuthHooks } from '../interfaces/auth-hooks.interface'
import type { AuthResult } from '../interfaces/auth-result.interface'
import type { OAuthProviderPlugin } from '../interfaces/oauth-provider.interface'
import type {
  AuthUser,
  IUserRepository,
  SafeAuthUser
} from '../interfaces/user-repository.interface'
import { AuthRedisService } from '../redis/auth-redis.service'
import { SessionService } from '../services/session.service'
import { TokenManagerService } from '../services/token-manager.service'
import { sanitizeHeaders } from '../utils/sanitize-headers'

/** TTL for the OAuth CSRF state value stored in Redis (10 minutes). */
const OAUTH_STATE_TTL_SECONDS = 600

/**
 * Stored payload for an OAuth state entry in Redis.
 * Keyed under `os:{sha256(state)}` — the raw state is never stored server-side.
 */
interface StoredOAuthState {
  /** Tenant identifier passed by the caller when initiating the flow. */
  tenantId: string
}

/** Narrows an unknown value to `StoredOAuthState` after `JSON.parse`. */
function isStoredOAuthState(value: unknown): value is StoredOAuthState {
  if (typeof value !== 'object' || value === null) return false
  const v = value as Record<string, unknown>
  return typeof v['tenantId'] === 'string'
}

/** Strips credential fields from an `AuthUser` to produce a `SafeAuthUser`. */
function toSafeUser(user: AuthUser): SafeAuthUser {
  const { passwordHash: _ph, mfaSecret: _ms, mfaRecoveryCodes: _mrc, ...safe } = user
  return safe
}

/**
 * Core OAuth 2.0 service — provider-agnostic flow orchestration.
 *
 * Each OAuth provider is abstracted by an {@link OAuthProviderPlugin}. The
 * service resolves the correct plugin by name and delegates the provider-specific
 * steps (authorize URL, code exchange, profile fetch) to the plugin.
 */
@Injectable()
export class OAuthService {
  private readonly logger = new Logger(OAuthService.name)

  constructor(
    @Inject(OAUTH_PLUGINS) private readonly plugins: OAuthProviderPlugin[],
    @Inject(BYMAX_AUTH_USER_REPOSITORY) private readonly userRepo: IUserRepository,
    // @Optional() tolerates the case where no IAuthHooks implementation is registered
    // (e.g. in standalone testing). The service treats a null hooks object the same as
    // a hooks object with no onOAuthLogin method — both result in OAUTH_FAILED.
    @Inject(BYMAX_AUTH_HOOKS) @Optional() private readonly hooks: IAuthHooks | null,
    private readonly redis: AuthRedisService,
    private readonly tokenManager: TokenManagerService,
    private readonly sessionService: SessionService,
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions
  ) {}

  // ---------------------------------------------------------------------------
  // initiateOAuth()
  // ---------------------------------------------------------------------------

  /**
   * Initiates the OAuth 2.0 Authorization Code flow.
   *
   * Steps:
   * 1. Validates the `provider` format and resolves the named plugin.
   * 2. Generates a 32-byte (64 hex char) cryptographically random state nonce.
   * 3. Stores `os:{sha256(state)} → { tenantId }` in Redis with a 10-minute TTL.
   * 4. Constructs the provider's authorization URL via `plugin.authorizeUrl(state)`.
   * 5. Issues a 302 redirect via the Express `res` object.
   *
   * @param provider - Provider name matching a registered {@link OAuthProviderPlugin}.
   * @param tenantId - Tenant the user will join on successful login.
   *   **Warning:** Not validated against the database — implement `onOAuthLogin`
   *   to enforce tenant membership. Without the hook, OAuth sign-in is disabled.
   * @param res - Express response in passthrough mode (used for the 302 redirect).
   * @throws `AuthException(OAUTH_FAILED)` when no plugin is registered for `provider`.
   */
  async initiateOAuth(provider: string, tenantId: string, res: Response): Promise<void> {
    // Validate and resolve early so the Redis write is never attempted for unknown providers.
    const plugin = this.resolvePlugin(provider)

    // Generate a 64-char hex nonce for CSRF protection.
    const state = generateSecureToken(32)
    const stateKey = `os:${sha256(state)}`

    const stored: StoredOAuthState = { tenantId }
    await this.redis.set(stateKey, JSON.stringify(stored), OAUTH_STATE_TTL_SECONDS)

    const authUrl = plugin.authorizeUrl(state)
    res.redirect(authUrl)
  }

  // ---------------------------------------------------------------------------
  // handleCallback()
  // ---------------------------------------------------------------------------

  /**
   * Processes the OAuth provider callback and issues auth tokens.
   *
   * Steps:
   * 1. Validates the `provider` format before touching Redis.
   * 2. Validates the `state` nonce — atomically reads and deletes `os:{sha256(state)}`.
   *    Missing key → `OAUTH_FAILED` (expired, forged, or already consumed).
   * 3. Extracts `tenantId` from the stored state payload.
   * 4. Exchanges `code` for an access token via the plugin.
   * 5. Fetches the normalized user profile from the provider.
   * 6. Looks up any existing user linked to the OAuth identity.
   * 7. Calls `hooks.onOAuthLogin(profile, existingUser, context)` to determine
   *    the account resolution strategy (`create`, `link`, or `reject`).
   *    If no hook is configured (null hooks or missing method), throws `OAUTH_FAILED`.
   * 8. Executes the strategy:
   *    - `'create'` — creates a new user via `userRepo.createWithOAuth()`.
   *    - `'link'`   — links the OAuth identity to an existing user via `userRepo.linkOAuth()`.
   *      Re-fetches the user by primary key after linking.
   *    - `'reject'` — throws `AuthException(OAUTH_FAILED)`.
   * 9. Issues dashboard tokens with a safe (credential-stripped) user projection.
   * 10. Creates a session if session tracking is enabled.
   *
   * @param provider - Provider name matching a registered plugin.
   * @param code - Authorization code received on the callback URL.
   * @param state - CSRF nonce received on the callback URL (must match the stored value).
   * @param ip - Client IP for session audit (truncated to 64 chars).
   * @param userAgent - User-Agent string for session audit.
   * @param headers - Raw request headers passed to the `onOAuthLogin` hook context.
   * @returns Full `AuthResult` with access token, refresh token, and safe user record.
   * @throws `AuthException(OAUTH_FAILED)` when state is invalid, expired, or the hook rejects.
   */
  async handleCallback(
    provider: string,
    code: string,
    state: string,
    ip: string,
    userAgent: string,
    headers: Record<string, string | string[] | undefined>
  ): Promise<AuthResult> {
    // Validate provider format and resolve the plugin before consuming the CSRF state.
    // Moving this check before getdel() prevents the state from being silently consumed
    // for an invalid provider — a user who encounters a misconfigured provider would
    // otherwise need to restart the entire flow.
    const plugin = this.resolvePlugin(provider)

    // Atomically read and delete the CSRF state — single-use enforcement.
    const stateKey = `os:${sha256(state)}`
    const rawState = await this.redis.getdel(stateKey)

    if (!rawState) {
      throw new AuthException(AUTH_ERROR_CODES.OAUTH_FAILED)
    }

    let parsedState: unknown
    try {
      parsedState = JSON.parse(rawState)
    } catch {
      throw new AuthException(AUTH_ERROR_CODES.OAUTH_FAILED)
    }

    if (!isStoredOAuthState(parsedState)) {
      throw new AuthException(AUTH_ERROR_CODES.OAUTH_FAILED)
    }

    const { tenantId } = parsedState

    // Exchange code and fetch profile — wrap in try/catch for observability.
    let profile: Awaited<ReturnType<typeof plugin.fetchProfile>>
    try {
      const tokenResponse = await plugin.exchangeCode(code)
      profile = await plugin.fetchProfile(tokenResponse.access_token)
    } catch (err: unknown) {
      this.logger.error(
        `OAuth plugin '${provider}' failed during code exchange or profile fetch`,
        err
      )
      throw new AuthException(AUTH_ERROR_CODES.OAUTH_FAILED)
    }

    // Look up an existing user linked to this OAuth identity.
    const existingAuthUser = await this.userRepo.findByOAuthId(
      provider,
      profile.providerId,
      tenantId
    )

    // Strip credential fields before passing to the hook.
    const existingUser: SafeAuthUser | null = existingAuthUser ? toSafeUser(existingAuthUser) : null

    // Build the hook context with properly sanitized headers.
    const hookContext = {
      ip,
      userAgent,
      sanitizedHeaders: sanitizeHeaders(headers)
    }

    // Run the onOAuthLogin hook — required for account resolution strategy.
    // Null hooks or a missing onOAuthLogin method both result in OAUTH_FAILED,
    // preventing unauthenticated OAuth logins on unconfigured installations.
    const hookResult = await this.hooks?.onOAuthLogin?.(profile, existingUser, hookContext)

    if (!hookResult) {
      throw new AuthException(AUTH_ERROR_CODES.OAUTH_FAILED)
    }

    let authUser: AuthUser
    switch (hookResult.action) {
      case 'create': {
        authUser = await this.userRepo.createWithOAuth({
          email: profile.email,
          name: profile.name ?? (profile.email.split('@')[0] as string),
          tenantId,
          emailVerified: true,
          oauthProvider: provider,
          oauthProviderId: profile.providerId
        })
        break
      }

      case 'link': {
        if (!existingAuthUser) {
          // Hook returned 'link' but there is no existing user — treat as OAuth failure.
          throw new AuthException(AUTH_ERROR_CODES.OAUTH_FAILED)
        }
        await this.userRepo.linkOAuth(existingAuthUser.id, provider, profile.providerId)
        // Re-fetch by primary key (more direct than findByOAuthId — id is already known).
        const linked = await this.userRepo.findById(existingAuthUser.id)
        if (!linked) {
          throw new AuthException(AUTH_ERROR_CODES.OAUTH_FAILED)
        }
        authUser = linked
        break
      }

      case 'reject':
      default: {
        throw new AuthException(AUTH_ERROR_CODES.OAUTH_FAILED)
      }
    }

    // Strip credentials before token issuance — prevents passwordHash / mfaSecret
    // from flowing into the AuthResult.user field that is serialized in the response.
    const safeUser = toSafeUser(authUser)
    const result = await this.tokenManager.issueTokens(safeUser, ip, userAgent)

    // Create a tracked session if session management is enabled.
    if (this.options.sessions.enabled) {
      await this.sessionService.createSession(safeUser.id, result.rawRefreshToken, ip, userAgent)
    }

    return result
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  /**
   * Resolves a plugin by name or throws `OAUTH_FAILED` when not found.
   *
   * Validates the `provider` format against `/^[a-z0-9-]{1,64}$/` before the
   * registry lookup. This ensures that a malformed or oversized provider name
   * (e.g. path traversal characters, null bytes) is explicitly rejected rather
   * than silently failing the `find()` with a format-dependent miss.
   *
   * @param provider - Plugin name to look up.
   * @returns The matching plugin.
   * @throws `AuthException(OAUTH_FAILED)` when the name is invalid or no plugin matches.
   */
  private resolvePlugin(provider: string): OAuthProviderPlugin {
    // Reject provider names that do not conform to the expected URL-safe lowercase format.
    if (!/^[a-z0-9-]{1,64}$/.test(provider)) {
      throw new AuthException(AUTH_ERROR_CODES.OAUTH_FAILED)
    }

    const plugin = this.plugins.find((p) => p.name === provider)
    if (!plugin) {
      throw new AuthException(AUTH_ERROR_CODES.OAUTH_FAILED)
    }
    return plugin
  }
}
