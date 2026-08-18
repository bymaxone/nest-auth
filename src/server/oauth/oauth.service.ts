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
 *
 * @layer Service
 */

import { createHash } from 'node:crypto'

import { Inject, Injectable, Logger, Optional } from '@nestjs/common'
import type { Request, Response } from 'express'

import { OAUTH_PLUGINS } from './oauth.constants'
import {
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import {
  OAUTH_STATE_COOKIE_MAX_AGE_SECONDS,
  OAUTH_STATE_COOKIE_NAME,
  OAUTH_STATE_COOKIE_SAME_SITE
} from '../constants/oauth-state-cookie'
import { generateSecureToken, sha256, timingSafeCompare } from '../crypto/secure-token'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { HookContext, IAuthHooks } from '../interfaces/auth-hooks.interface'
import type { AuthResult, OAuthMfaChallengeResult } from '../interfaces/auth-result.interface'
import type { OAuthProviderPlugin } from '../interfaces/oauth-provider.interface'
import type {
  AuthUser,
  IUserRepository,
  SafeAuthUser
} from '../interfaces/user-repository.interface'
import { AuthRedisService } from '../redis/auth-redis.service'
import { SessionService } from '../services/session.service'
import { TokenManagerService } from '../services/token-manager.service'
import { assertNotBlocked } from '../utils/assert-not-blocked'
import { describeChannelStatus } from '../utils/describe-error'
import { logSafe } from '../utils/log-safe'
import { maskEmail } from '../utils/mask-email'
import { resolveTenantId } from '../utils/resolve-tenant-id'
import { sanitizeHeaders } from '../utils/sanitize-headers'

/** TTL for the OAuth CSRF state value stored in Redis (10 minutes). */
const OAUTH_STATE_TTL_SECONDS = 600

/**
 * Stored payload for an OAuth state entry in Redis.
 * Keyed under `os:{sha256(state)}` — the raw state is never stored server-side.
 */
interface StoredOAuthState {
  /**
   * The provider this state was minted for, compared against the provider named by the
   * callback path before the record is used.
   *
   * RFC 9700 §2.1/§4.4 makes mix-up defence REQUIRED for a client that talks to more than one
   * authorization server. Without this field the callback resolves the provider from its own
   * URL and then consumes any structurally valid state, so an attacker able to steer an honest
   * provider's callback to a hostile provider's path receives both the `code` and the PKCE
   * `code_verifier` — enough to redeem the code at the honest provider. PKCE does not help:
   * the verifier travels with the code by design.
   *
   * Only Google ships in-tree today, so this is defence-in-depth. It is stored anyway because
   * the record is a shared structure and adding a field costs less now than after a second
   * provider lands. Held byte-compatible with rust-auth.
   */
  provider: string
  /** Tenant identifier passed by the caller when initiating the flow. */
  tenantId: string
  /**
   * PKCE `code_verifier` (RFC 7636), held server-side for the lifetime of the
   * authorization flow and forwarded to the provider's token endpoint on
   * callback.
   *
   * Required, deliberately. `getAuthorizationUrl` writes one on every flow regardless of
   * provider, so a record without it is corrupt or forged — and treating it as "this flow
   * had no PKCE" would hand an attacker a downgrade: present a state record with the field
   * stripped and the exchange proceeds with no proof the caller started the flow.
   * `rust-auth` types the field as a plain `String`, so a record missing it fails to
   * deserialize there; refusing it here keeps the shared record readable by exactly one rule.
   */
  codeVerifier: string
}

/** Narrows an unknown value to `StoredOAuthState` after `JSON.parse`. */
function isStoredOAuthState(value: unknown): value is StoredOAuthState {
  // Stryker disable next-line ConditionalExpression: non-object JSON values also fail the `typeof parsed['tenantId'] !== 'string'` check below, so dropping the type guard yields the same false
  if (typeof value !== 'object' || value === null) return false
  const v = value as Record<string, unknown>
  // Required, like `codeVerifier` and for the same reason: a record without it is corrupt or
  // forged, and accepting one would restore exactly the unbound state the field exists to
  // prevent. rust-auth types it as a plain `String`, so a record missing it fails to
  // deserialize there too.
  if (typeof v['provider'] !== 'string') return false
  if (typeof v['tenantId'] !== 'string') return false
  if (typeof v['codeVerifier'] !== 'string') return false
  return true
}

/**
 * URL-safe base64 (RFC 4648 §5) — no padding, `+` → `-`, `/` → `_`.
 *
 * Used for the PKCE `code_challenge` derivation. Node's `Buffer.toString('base64url')`
 * handles all three substitutions natively.
 */
function base64url(input: Buffer): string {
  return input.toString('base64url')
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
 * operations (authorize URL, code exchange, profile fetch) to the plugin.
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
    @Inject(AuthRedisService) private readonly redis: AuthRedisService,
    @Inject(TokenManagerService) private readonly tokenManager: TokenManagerService,
    @Inject(SessionService) private readonly sessionService: SessionService,
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions
  ) {}

  // ---------------------------------------------------------------------------
  // initiateOAuth()
  // ---------------------------------------------------------------------------

  /**
   * Initiates the OAuth 2.0 Authorization Code flow.
   *
   * Sequence:
   * 1. Validates the `provider` format and resolves the named plugin.
   * 2. Generates a 32-byte (64 hex char) cryptographically random state nonce.
   * 3. Stores `os:{sha256(state)} → { provider, tenantId, codeVerifier }` in Redis with a
   *    10-minute TTL. `provider` is what the callback checks itself against (RFC 9700
   *    mix-up defence).
   * 4. Constructs the provider's authorization URL via `plugin.authorizeUrl(state)`.
   * 5. Issues a 302 redirect via the Express `res` object.
   *
   * @param provider - Provider name matching a registered {@link OAuthProviderPlugin}.
   * @param tenantId - Tenant the user will join on successful login, as named by the caller in
   *   the query string. **Refused** with `auth.validation` when a `tenantIdResolver` is
   *   configured, since the deployment decides the tenant and a value it discards would only
   *   mislead the caller. Never validated against the database — implement `onOAuthLogin` to
   *   enforce tenant membership. Without the hook, OAuth sign-in is disabled.
   * @param req - Incoming Express request, read by the configured `tenantIdResolver`.
   * @param res - Express response in passthrough mode (used for the 302 redirect).
   * @throws `AuthException(OAUTH_FAILED)` when no plugin is registered for `provider`.
   */
  async initiateOAuth(
    provider: string,
    tenantId: string | undefined,
    req: Request,
    res: Response
  ): Promise<void> {
    // Validate and resolve early so the Redis write is never attempted for unknown providers.
    const plugin = this.resolvePlugin(provider)

    // The configured resolver is authoritative, exactly as it is for login, register and the
    // reset flows: a deployment that derives the tenant from the request has stated that the
    // caller's value is not to be trusted. This was the one door that still took it verbatim —
    // and it is the door that decides which tenant an account gets provisioned into, which is
    // strictly more than the others were protecting. The resolved value is what goes into the
    // state record, so the callback cannot be talked into a different one either.
    tenantId = await resolveTenantId(tenantId, req, this.options.tenantIdResolver)

    // Generate a 64-char hex nonce for CSRF protection.
    const state = generateSecureToken(32)
    const stateKey = `os:${sha256(state)}`

    // PKCE code_verifier: RFC 7636 requires 43–128 URL-safe chars. A 32-byte
    // random value base64url-encoded gives 43 chars. The verifier is stored
    // server-side; only the challenge (its sha256 hash) is sent to the provider.
    const codeVerifier = generateSecureToken(32)
    const codeChallenge = base64url(createHash('sha256').update(codeVerifier, 'utf8').digest())

    const stored: StoredOAuthState = { provider, tenantId, codeVerifier }
    await this.redis.set(stateKey, JSON.stringify(stored), OAUTH_STATE_TTL_SECONDS)

    // Bind the flow to THIS browser. The `state` parameter alone proves only that somebody
    // started a flow: an attacker can begin their own authorization, complete consent at the
    // provider, capture the resulting callback URL without visiting it, and lure the victim
    // there — the victim's browser then receives the attacker's session, and everything they
    // do next lands in the attacker's account. PKCE does not help, because the verifier lives
    // server-side and is replayed for whoever presents the state. RFC 6749 §10.12 requires
    // this binding. `SameSite` is forced to `lax`: the callback is a cross-site top-level GET
    // and `strict` would withhold the cookie on exactly that hop.
    res.cookie(OAUTH_STATE_COOKIE_NAME, state, {
      httpOnly: true,
      secure: this.options.secureCookies,
      sameSite: OAUTH_STATE_COOKIE_SAME_SITE,
      path: '/',
      maxAge: OAUTH_STATE_COOKIE_MAX_AGE_SECONDS * 1_000
    })

    const authUrl = plugin.authorizeUrl(state, codeChallenge)
    res.redirect(authUrl)
  }

  // ---------------------------------------------------------------------------
  // handleCallback()
  // ---------------------------------------------------------------------------

  /**
   * Processes the OAuth provider callback and issues auth tokens.
   *
   * Sequence:
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
   * @param stateCookie - Value of the `oauth_state` cookie planted by `initiateOAuth()`, or
   *   `undefined` when the browser sent none. Must equal `state`; see the binding check below.
   * @param ip - Client IP for session audit (truncated to 64 chars).
   * @param userAgent - User-Agent string for session audit.
   * @param headers - Raw request headers passed to the `onOAuthLogin` hook context.
   * @returns Full `AuthResult` with access token, refresh token, and safe user record,
   *   OR an `OAuthMfaChallengeResult` with `mfaRequired: true` and a short-lived MFA
   *   temp token when the resolved user has MFA enabled. The caller routes the two
   *   shapes to different responses (session cookies vs MFA-challenge cookie/redirect).
   * @throws `AuthException(OAUTH_FAILED)` when state is invalid, expired, or the hook rejects.
   */
  async handleCallback(
    provider: string,
    code: string,
    state: string,
    stateCookie: string | undefined,
    ip: string,
    userAgent: string,
    headers: Record<string, string | string[] | undefined>
  ): Promise<AuthResult | OAuthMfaChallengeResult> {
    // Validate provider format and resolve the plugin before consuming the CSRF state.
    // Moving this check before getdel() prevents the state from being silently consumed
    // for an invalid provider — a user who encounters a misconfigured provider would
    // otherwise need to restart the entire flow.
    const plugin = this.resolvePlugin(provider)

    // Bind the callback to the browser that started the flow (RFC 6749 §10.12). A `state`
    // that merely exists in Redis proves only that *somebody* started a flow: an attacker can
    // run their own authorization to the point of holding a valid `?code=…&state=…` URL, never
    // visit it, and lure the victim there instead — the victim's browser would then be logged
    // into the attacker's account, and anything they added afterwards would be the attacker's
    // to read. Only the cookie distinguishes the two, so a missing one is as fatal as a wrong
    // one. Checked before `getdel` so a callback that fails the binding cannot burn a state
    // the legitimate browser is still entitled to complete. Hashes are compared rather than
    // the raw values so the constant-time path is not skipped by a length mismatch.
    if (stateCookie === undefined || !timingSafeCompare(sha256(state), sha256(stateCookie))) {
      this.logger.warn(`handleCallback: OAuth state not bound to this browser provider=${provider}`)
      throw new AuthException(AUTH_ERROR_CODES.OAUTH_FAILED)
    }

    // Atomically read and delete the CSRF state — single-use enforcement.
    const stateKey = `os:${sha256(state)}`
    const rawState = await this.redis.getdel(stateKey)

    if (!rawState) {
      this.logger.warn(`handleCallback: invalid or expired OAuth state provider=${provider}`)
      throw new AuthException(AUTH_ERROR_CODES.OAUTH_FAILED)
    }

    let parsedState: unknown
    try {
      parsedState = JSON.parse(rawState)
    } catch {
      // A state key that exists but does not parse is corrupted storage, not a stale or
      // forged callback — the two are indistinguishable to the caller (both answer
      // OAUTH_FAILED) and only this line tells them apart in an operator's logs.
      this.logger.warn(`handleCallback: unparseable OAuth state provider=${provider}`)
      throw new AuthException(AUTH_ERROR_CODES.OAUTH_FAILED)
    }

    if (!isStoredOAuthState(parsedState)) {
      throw new AuthException(AUTH_ERROR_CODES.OAUTH_FAILED)
    }

    // Mix-up defence (RFC 9700 §2.1/§4.4). `provider` here comes from the callback's own URL
    // path; the record says which provider the flow was actually started with. A mismatch means
    // this state was minted for somebody else, and consuming it would forward the `code` and
    // the PKCE `code_verifier` to a provider the user never authorized — which is exactly what
    // lets a hostile provider redeem an honest one's code.
    //
    // A plain comparison, deliberately, unlike the state-cookie binding above: this is not a
    // secret. Both sides are provider names drawn from the registered plugins, and the
    // callback's own value is a URL path segment the caller supplied. There is nothing here for
    // a timing side channel to reveal, and a constant-time compare would only imply otherwise.
    if (parsedState.provider !== provider) {
      this.logger.warn(`handleCallback: OAuth state provider mismatch provider=${provider}`)
      throw new AuthException(AUTH_ERROR_CODES.OAUTH_FAILED)
    }

    const { tenantId, codeVerifier } = parsedState

    // Exchange code and fetch profile — wrap in try/catch for observability.
    //
    // The access token stays INSIDE the `try`. It was hoisted out for one reason — so the catch
    // could name it in a redaction list — and that list is gone, because nothing the plugin wrote
    // is published any more. Left hoisted, its `''` initialiser would be a value no test can
    // observe, which is a mutation survivor and, more plainly, a variable whose scope no longer
    // matches its use.
    let profile: Awaited<ReturnType<typeof plugin.fetchProfile>>
    try {
      const tokenResponse = await plugin.exchangeCode(code, codeVerifier)
      profile = await plugin.fetchProfile(tokenResponse.access_token)
    } catch (err: unknown) {
      // Nothing the plugin wrote is published. This path holds a LIVE ACCESS TOKEN: the plugin
      // received `code`, `codeVerifier` and `accessToken`, and an HTTP client attaching its
      // request config to the error is the ordinary case rather than an exotic one — axios does
      // it by default.
      //
      // Naming the three values was the previous shape, and the comment justifying it conceded
      // the defect in its own second sentence: redaction is a substring match, so it holds for a
      // value the plugin echoed as given and not for one it re-encoded. A token in a base64 or
      // URL-encoded request body is not present as written, so no list finds it — the same
      // measurement that took the mail channel's text out of these lines. There is nothing to
      // name because nothing the plugin authored comes through.
      //
      // A plugin that wants its own diagnostics logged in full can log them itself, where the
      // operator knows the audience.
      this.logger.error(
        `OAuth plugin '${provider}' failed during code exchange or profile fetch: ` +
          describeChannelStatus(err)
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
    //
    // The tenant and the address travel with it. `onOAuthLogin` is the documented — and only —
    // place a deployment can enforce tenant membership, and it was being asked to decide that
    // without being told which tenant, or which address, the flow had resolved to. The values
    // come from the server-side state record and the verified profile, never from the callback
    // request.
    const hookContext: HookContext = {
      tenantId,
      email: profile.email,
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
        // `String.prototype.split` always returns at least one element on a
        // non-empty input (which `@IsEmail` has already validated), so the
        // `?? profile.email` defence-in-depth branch is not expected at runtime.
        /* istanbul ignore next -- defensive fallback: split('@')[0] is always defined for a validated email */
        const derivedName = profile.name ?? profile.email.split('@')[0] ?? profile.email

        // An account may already own this address without being linked to this OAuth identity
        // — a local registration, or a link to a different provider. `findByOAuthId` above does
        // not see it, so creating would violate the repository's uniqueness constraint and
        // surface as an opaque 500. It is a conflict, and the caller can act on it (sign in and
        // link instead), so it is reported as one. rust-auth answers the same 409
        // `auth.oauth_email_mismatch` for the same collision.
        //
        // A concurrent create between this check and the insert still reaches the repository.
        // Nothing portable can be done about that here — `IUserRepository` is host-implemented
        // and its errors are untyped — so the check closes the deterministic case and leaves
        // the race to the constraint.
        if (await this.userRepo.findByEmail(profile.email, tenantId)) {
          this.logger.warn(
            `oauth: create refused — ${maskEmail(profile.email)} already exists in tenant ${logSafe(tenantId)}`
          )
          throw new AuthException(AUTH_ERROR_CODES.OAUTH_EMAIL_MISMATCH)
        }

        authUser = await this.userRepo.createWithOAuth({
          email: profile.email,
          name: derivedName,
          tenantId,
          // What the provider actually asserted, not a convenient constant. An account created
          // from an unverified address belongs to whoever controls the OAuth account, not to
          // whoever controls the mailbox; marking it verified would make the consumer's
          // "this email is proven" invariant false from the first login.
          emailVerified: profile.emailVerified,
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
        await this.userRepo.linkOAuth(
          existingAuthUser.id,
          existingAuthUser.tenantId,
          provider,
          profile.providerId
        )
        // Re-fetch by primary key (more direct than findByOAuthId — id is already known).
        const linked = await this.userRepo.findById(existingAuthUser.id, existingAuthUser.tenantId)
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

    // Status gate. Every credential flow in this library runs it — password login, the MFA
    // challenge, both password-reset steps, the platform login — and OAuth was the one that
    // did not, so a BANNED or SUSPENDED account holding a linked provider identity walked
    // straight back in. Ban is the primary account kill switch; a flow that ignores it makes
    // it advisory. Run before the MFA branch so a blocked account cannot even obtain a temp
    // token. `rust-auth` gates the same point.
    assertNotBlocked(authUser.status, this.options.blockedStatuses)

    // Email-verification gate, on the same footing as password login: when a deployment
    // requires a verified address, an OAuth identity does not substitute for one. The `create`
    // branch above records what the provider actually asserted, so an unverified provider
    // profile stays unverified here rather than being promoted by the act of signing in.
    if (this.options.emailVerification.required && !authUser.emailVerified) {
      throw new AuthException(AUTH_ERROR_CODES.EMAIL_NOT_VERIFIED)
    }

    // MFA branch: when the resolved user has MFA enabled, the OAuth flow has only
    // proven control of the OAuth provider account — not the second factor. Issuing
    // a session with `mfaVerified: false` would be rejected on every request by the
    // global `MfaRequiredGuard`, leaving the user locked out. Instead, we issue a
    // short-lived MFA temp token via TokenManagerService (the same path the
    // password-login flow uses) and let the controller plant it in a cookie or
    // surface it in the response body. The user completes `/auth/mfa/challenge`
    // to obtain real session tokens. No `MfaService` dependency is required —
    // `issueMfaTempToken` lives on `TokenManagerService`, which is always
    // registered.
    if (authUser.mfaEnabled) {
      // OAuth is dashboard-only; bind the tenant so the challenge resolves this account
      // tenant-scoped rather than by `sub` alone.
      const mfaTempToken = await this.tokenManager.issueMfaTempToken(
        authUser.id,
        'dashboard',
        authUser.tenantId
      )
      this.logger.log(
        `handleCallback: OAuth MFA challenge issued provider=${provider} userId=${logSafe(authUser.id)} tenantId=${logSafe(tenantId)} action=${hookResult.action}`
      )
      return { mfaRequired: true, mfaTempToken }
    }

    // Strip credentials before token issuance — prevents passwordHash / mfaSecret
    // from flowing into the AuthResult.user field that is serialized in the response.
    const safeUser = toSafeUser(authUser)
    const result = await this.tokenManager.issueTokens(safeUser, ip, userAgent)

    // Create a tracked session if session management is enabled.
    if (this.options.sessions.enabled) {
      await this.sessionService.createSession({
        userId: safeUser.id,
        tenantId: safeUser.tenantId,
        rawRefreshToken: result.rawRefreshToken,
        ip,
        userAgent
      })
    }

    this.logger.log(
      `handleCallback: OAuth login success provider=${provider} userId=${logSafe(safeUser.id)} tenantId=${logSafe(tenantId)} action=${hookResult.action}`
    )
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
