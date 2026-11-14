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

import { isStoredOAuthState, type StoredOAuthState } from './oauth-state'
import { OAUTH_PLUGINS } from './oauth.constants'
import { pluginDeadlineMs, withDeadline } from './plugin-deadline'
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
import type { HookContext, IAuthHooks, OAuthLoginResult } from '../interfaces/auth-hooks.interface'
import type { AuthResult, OAuthMfaChallengeResult } from '../interfaces/auth-result.interface'
import type { OAuthProfile, OAuthProviderPlugin } from '../interfaces/oauth-provider.interface'
import type {
  AuthUser,
  IUserRepository,
  SafeAuthUser
} from '../interfaces/user-repository.interface'
import { AuthRedisService } from '../redis/auth-redis.service'
import { SessionService } from '../services/session.service'
import { CREDENTIAL_PROVED, TokenManagerService } from '../services/token-manager.service'
import {
  WorkspaceInvitationAcceptService,
  type LoadedInvitation
} from '../services/workspace-invitation-accept.service'
import { assertNotBlocked } from '../utils/assert-not-blocked'
import { describeChannelStatus } from '../utils/describe-error'
import { logSafe } from '../utils/log-safe'
import { maskEmail } from '../utils/mask-email'
import { resolveTenantId } from '../utils/resolve-tenant-id'
import { runDetached } from '../utils/run-detached'
import { sanitizeHeaders } from '../utils/sanitize-headers'

/** TTL for the OAuth CSRF state value stored in Redis (10 minutes). */
const OAUTH_STATE_TTL_SECONDS = 600

/** A vetted invitation, waiting for the account its flow signs in. */
interface PendingInvitation {
  /** Writes the membership for `user` and spends the token; `created` is whether the flow made the account. */
  complete(user: AuthUser, created: boolean, context: HookContext): Promise<void>
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
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions,
    // Present only when `workspaces.enabled`; without it a flow cannot carry an invitation.
    @Inject(WorkspaceInvitationAcceptService)
    @Optional()
    private readonly invitations: WorkspaceInvitationAcceptService | null = null
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
   * @param workspaceInvitation - The raw workspace invitation token the flow accepts, when it
   *   does. Only its sha256 is stored, and the response carries `Referrer-Policy: no-referrer`
   *   because the request URL held the token.
   * @throws `AuthException(OAUTH_FAILED)` when no plugin is registered for `provider`, and
   *   `AuthException(INVALID_INVITATION_TOKEN)` for a token when workspaces are not enabled.
   */
  async initiateOAuth(
    provider: string,
    tenantId: string | undefined,
    req: Request,
    res: Response,
    workspaceInvitation?: string
  ): Promise<void> {
    // Validate and resolve early so the Redis write is never attempted for unknown providers.
    const plugin = this.resolvePlugin(provider)

    // The configured resolver is authoritative, exactly as it is for login, register and the
    // reset flows: a deployment that derives the tenant from the request has stated that the
    // caller's value is not to be trusted. The resolved value is what goes into the state record,
    // so the callback cannot be talked into a different tenant either.
    tenantId = await resolveTenantId(tenantId, req, this.options.tenantIdResolver)
    const invitation = this.hashInvitation(workspaceInvitation)

    // Generate a 64-char hex nonce for CSRF protection.
    const state = generateSecureToken(32)
    const stateKey = `os:${sha256(state)}`

    // PKCE code_verifier: RFC 7636 requires 43–128 URL-safe chars. A 32-byte
    // random value base64url-encoded gives 43 chars. The verifier is stored
    // server-side; only the challenge (its sha256 hash) is sent to the provider.
    const codeVerifier = generateSecureToken(32)
    const codeChallenge = base64url(createHash('sha256').update(codeVerifier, 'utf8').digest())

    const stored: StoredOAuthState = {
      provider,
      tenantId,
      codeVerifier,
      ...(invitation === undefined ? {} : { workspaceInvitation: invitation })
    }
    await this.redis.set(stateKey, JSON.stringify(stored), OAUTH_STATE_TTL_SECONDS)

    this.bindToBrowser(res, state)
    if (invitation !== undefined) res.setHeader('Referrer-Policy', 'no-referrer')
    res.redirect(plugin.authorizeUrl(state, codeChallenge))
  }

  /**
   * Hashes the invitation token a flow carries, so Redis never holds the raw token.
   *
   * @param carried - The raw invitation value from the query string, if any.
   * @returns Its sha256, or `undefined` when the flow carries none.
   * @throws `AuthException(INVALID_INVITATION_TOKEN)` when workspaces are not enabled.
   */
  private hashInvitation(carried: string | undefined): string | undefined {
    if (carried === undefined) return undefined
    if (this.invitations === null)
      throw new AuthException(AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN)
    return sha256(carried)
  }

  /**
   * Plants the cookie that binds a flow to the browser that started it.
   *
   * The `state` parameter alone proves only that somebody started a flow: an attacker can begin
   * their own authorization, complete consent at the provider, capture the resulting callback URL
   * without visiting it, and lure the victim there — the victim's browser then receives the
   * attacker's session. PKCE does not help, because the verifier lives server-side and is replayed
   * for whoever presents the state. RFC 6749 §10.12 requires this binding, and it is what keeps a
   * flow started with someone else's invitation from being finished in another browser.
   * `SameSite` is forced to `lax`: the callback is a cross-site top-level GET and `strict` would
   * withhold the cookie on exactly that hop.
   *
   * @param res - The response to set the cookie on.
   * @param state - The raw state nonce.
   */
  private bindToBrowser(res: Response, state: string): void {
    res.cookie(OAUTH_STATE_COOKIE_NAME, state, {
      httpOnly: true,
      secure: this.options.secureCookies,
      sameSite: OAUTH_STATE_COOKIE_SAME_SITE,
      path: '/',
      maxAge: OAUTH_STATE_COOKIE_MAX_AGE_SECONDS * 1_000
    })
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
    // Resolve the plugin before the state is consumed, so a misconfigured provider cannot burn a
    // state the user would otherwise have to restart the whole flow to replace.
    const plugin = this.resolvePlugin(provider)

    const record = await this.consumeState(provider, state, stateCookie)
    const { tenantId, codeVerifier } = record

    const profile = await this.fetchProfile(plugin, provider, code, codeVerifier)
    const invitation = await this.vetInvitation(record, profile)

    // Look up an existing user linked to this OAuth identity.
    const existingAuthUser = await this.userRepo.findByOAuthId({
      provider,
      providerId: profile.providerId,
      tenantId
    })

    // Strip credential fields before passing to the hook.
    const existingUser: SafeAuthUser | null = existingAuthUser ? toSafeUser(existingAuthUser) : null

    // The hook is told which tenant and which address the flow resolved to: it is the only place
    // a deployment can enforce tenant membership. Both come from the server-side state record and
    // the verified profile, never from the callback request.
    const hookContext: HookContext = {
      plane: 'dashboard',
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

    const authUser = await this.resolveAccount(
      { provider, tenantId, profile, hookResult, existingAuthUser },
      invitation
    )

    this.assertMaySignIn(authUser)

    if (authUser.mfaEnabled) {
      return this.issueMfaChallenge(authUser, provider, hookResult)
    }

    const created = hookResult.action === 'create'
    await invitation?.complete(authUser, created, { ...hookContext, userId: authUser.id })
    return this.openSession(authUser, provider, hookResult, hookContext, ip, userAgent)
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  /**
   * Refuses an account that may not sign in: a blocked status, or an unverified address where the
   * deployment requires one.
   *
   * @param authUser - The account the flow resolved to.
   * @throws `AuthException` for a blocked status or an unverified address.
   */
  private assertMaySignIn(authUser: AuthUser): void {
    // Status gate. Every credential flow in this library runs it — password login, the MFA
    // challenge, both password-reset steps, the platform login — so a BANNED or SUSPENDED account
    // holding a linked provider identity cannot sign back in. Ban is the primary account kill
    // switch; a flow that ignores it makes it advisory. Run before the MFA branch so a blocked
    // account cannot even obtain a temp token. `rust-auth` gates the same point.
    assertNotBlocked(authUser.status, this.options.blockedStatuses)

    // Email-verification gate, on the same footing as password login: when a deployment
    // requires a verified address, an OAuth identity does not substitute for one. The `create`
    // branch records what the provider actually asserted, so an unverified provider profile
    // stays unverified here rather than being promoted by the act of signing in.
    if (this.options.emailVerification.required && !authUser.emailVerified) {
      throw new AuthException(AUTH_ERROR_CODES.EMAIL_NOT_VERIFIED)
    }
  }

  /**
   * Issues the MFA temp token for an account that has a second factor.
   *
   * @param authUser - The account the flow resolved to.
   * @param provider - The provider name, for the log line.
   * @param hookResult - The hook's decision, whose action goes in the log line.
   * @returns The challenge the controller plants in a cookie or surfaces in the body.
   */
  private async issueMfaChallenge(
    authUser: AuthUser,
    provider: string,
    hookResult: OAuthLoginResult
  ): Promise<OAuthMfaChallengeResult> {
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
    // OAuth is dashboard-only; bind the tenant so the challenge resolves this account
    // tenant-scoped rather than by `sub` alone.
    const mfaTempToken = await this.tokenManager.issueMfaTempToken(
      authUser.id,
      'dashboard',
      authUser.tenantId
    )
    this.logger.log(
      `handleCallback: OAuth MFA challenge issued provider=${provider} userId=${logSafe(authUser.id)} tenantId=${logSafe(authUser.tenantId)} action=${hookResult.action}`
    )
    return { mfaRequired: true, mfaTempToken }
  }

  /**
   * Issues the tokens and the tracked session of a completed sign-in, then runs the non-blocking
   * side effects of a login.
   *
   * @param authUser - The account the flow resolved to.
   * @param provider - The provider name, for the log line.
   * @param hookResult - The hook's decision, whose action goes in the log line.
   * @param hookContext - The context the hooks were given.
   * @param ip - The client address.
   * @param userAgent - The `User-Agent` header.
   * @returns The auth result.
   */
  private async openSession(
    authUser: AuthUser,
    provider: string,
    hookResult: OAuthLoginResult,
    hookContext: HookContext,
    ip: string,
    userAgent: string
  ): Promise<AuthResult> {
    // Strip credentials before token issuance — prevents passwordHash / mfaSecret
    // from flowing into the AuthResult.user field that is serialized in the response.
    const safeUser = toSafeUser(authUser)
    const result = await this.tokenManager.issueTokens(safeUser, ip, userAgent, CREDENTIAL_PROVED)

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
      `handleCallback: OAuth login success provider=${provider} userId=${logSafe(safeUser.id)} tenantId=${logSafe(authUser.tenantId)} action=${hookResult.action}`
    )

    // The same non-blocking side effects a password login runs once it has succeeded. An MFA
    // account reaches them from the challenge completion instead, so this is only the path that
    // issued a session.
    runDetached(
      this.logger,
      () => this.userRepo.updateLastLogin({ id: safeUser.id, tenantId: safeUser.tenantId }),
      'oauth: updateLastLogin failed'
    )
    if (this.hooks?.afterLogin) {
      const afterLogin = this.hooks.afterLogin.bind(this.hooks)
      runDetached(
        this.logger,
        () => afterLogin(safeUser, { ...hookContext, userId: safeUser.id }),
        'oauth: afterLogin hook threw'
      )
    }
    return result
  }

  /**
   * Validates and spends the `state` of a callback.
   *
   * The state must be bound to this browser by the `oauth_state` cookie, must exist (and is
   * deleted as it is read), must parse, and must name the provider the callback names.
   *
   * @param provider - The provider named by the callback path.
   * @param state - The `state` query value.
   * @param stateCookie - The `oauth_state` cookie value, or `undefined` when none was sent.
   * @returns The stored record of the flow.
   * @throws `AuthException(OAUTH_FAILED)` for a state that is unbound, missing, unparseable,
   *   malformed or minted for another provider.
   */
  private async consumeState(
    provider: string,
    state: string,
    stateCookie: string | undefined
  ): Promise<StoredOAuthState> {
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

    const stored = await this.readState(provider, state)

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
    if (stored.provider !== provider) {
      this.logger.warn(`handleCallback: OAuth state provider mismatch provider=${provider}`)
      throw new AuthException(AUTH_ERROR_CODES.OAUTH_FAILED)
    }

    return stored
  }

  /**
   * Reads and deletes the state record of a flow, in one step so it can be used once.
   *
   * @param provider - The provider named by the callback path, for the log lines.
   * @param state - The `state` query value.
   * @returns The stored record.
   * @throws `AuthException(OAUTH_FAILED)` for a state that is missing, unparseable or malformed.
   */
  private async readState(provider: string, state: string): Promise<StoredOAuthState> {
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
      // Stryker disable next-line CallExpression: equivalent — the warn above is already emitted, and with this throw gone the unparsed state fails `isStoredOAuthState` on the next line and raises the identical OAUTH_FAILED.
      throw new AuthException(AUTH_ERROR_CODES.OAUTH_FAILED)
    }

    if (!isStoredOAuthState(parsedState)) {
      throw new AuthException(AUTH_ERROR_CODES.OAUTH_FAILED)
    }

    return parsedState
  }

  /**
   * Exchanges the authorization code and fetches the provider's profile.
   *
   * @param plugin - The provider plugin.
   * @param provider - Its name, for the log line.
   * @param code - The authorization code.
   * @param codeVerifier - The PKCE verifier stored with the state.
   * @returns The normalized profile.
   * @throws `AuthException(OAUTH_FAILED)` when the exchange or the fetch fails, or the plugin's
   *   deadline passes first.
   */
  private async fetchProfile(
    plugin: OAuthProviderPlugin,
    provider: string,
    code: string,
    codeVerifier: string
  ): Promise<OAuthProfile> {
    try {
      return await withDeadline(async () => {
        const tokenResponse = await plugin.exchangeCode(code, codeVerifier)
        return await plugin.fetchProfile(tokenResponse.access_token)
      }, pluginDeadlineMs(plugin))
    } catch (err: unknown) {
      // Nothing the plugin wrote is published. This path holds a LIVE ACCESS TOKEN: the plugin
      // received `code`, `codeVerifier` and `accessToken`, and an HTTP client attaching its
      // request config to the error is the ordinary case rather than an exotic one — axios does
      // it by default. Redaction is a substring match, so it cannot find a token the plugin
      // re-encoded (in a base64 or URL-encoded request body); there is nothing to name because
      // nothing the plugin authored comes through.
      //
      // A plugin that wants its own diagnostics logged in full can log them itself, where the
      // operator knows the audience.
      this.logger.error(
        `OAuth plugin '${provider}' failed during code exchange or profile fetch: ` +
          describeChannelStatus(err)
      )
      throw new AuthException(AUTH_ERROR_CODES.OAUTH_FAILED)
    }
  }

  /**
   * Provisions a new account from a verified OAuth profile.
   *
   * @param provider - The provider name.
   * @param tenantId - The tenant the flow resolved to.
   * @param profile - The provider's profile.
   * @returns The created account.
   * @throws `AuthException(OAUTH_EMAIL_MISMATCH)` when the address already belongs to an account.
   */
  private async createAccount(
    provider: string,
    tenantId: string,
    profile: OAuthProfile
  ): Promise<AuthUser> {
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
    if (await this.userRepo.findByEmail({ email: profile.email, tenantId })) {
      this.logger.warn(
        `oauth: create refused — ${maskEmail(profile.email)} already exists in tenant ${logSafe(tenantId)}`
      )
      throw new AuthException(AUTH_ERROR_CODES.OAUTH_EMAIL_MISMATCH)
    }

    return this.userRepo.createWithOAuth({
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
  }

  /**
   * Links the OAuth identity to the account the flow already found.
   *
   * @param provider - The provider name.
   * @param profile - The provider's profile.
   * @param existingAuthUser - The account to link, or `null` when there is none.
   * @returns The account re-read after linking.
   * @throws `AuthException(OAUTH_FAILED)` when there is no account to link or it cannot be re-read.
   */
  private async linkAccount(
    provider: string,
    profile: OAuthProfile,
    existingAuthUser: AuthUser | null
  ): Promise<AuthUser> {
    if (!existingAuthUser) {
      // Hook returned 'link' but there is no existing user — treat as OAuth failure.
      throw new AuthException(AUTH_ERROR_CODES.OAUTH_FAILED)
    }
    await this.userRepo.linkOAuth({
      id: existingAuthUser.id,
      tenantId: existingAuthUser.tenantId,
      provider,
      providerId: profile.providerId
    })
    // Re-fetch by primary key (more direct than findByOAuthId — id is already known).
    const linked = await this.userRepo.findById({
      id: existingAuthUser.id,
      tenantId: existingAuthUser.tenantId
    })
    if (!linked) {
      throw new AuthException(AUTH_ERROR_CODES.OAUTH_FAILED)
    }
    return linked
  }

  /**
   * Carries out the account strategy the `onOAuthLogin` hook chose.
   *
   * Under `registration: 'invitation-only'` a `create` is allowed only for a flow that carries a
   * vetted invitation; linking and signing in an existing account are not sign-ups.
   *
   * @param flow - What the callback resolved: the provider, the tenant, the verified profile, the
   *   hook's decision and the account already linked to this identity, or `null`.
   * @param invitation - The invitation the flow carries, or `null`.
   * @returns The account the flow signs in.
   * @throws `AuthException` for a rejected flow, a closed registration, a `link` with no account
   *   to link, or a create that collides with an existing address.
   */
  private async resolveAccount(
    flow: {
      provider: string
      tenantId: string
      profile: OAuthProfile
      hookResult: OAuthLoginResult
      existingAuthUser: AuthUser | null
    },
    invitation: PendingInvitation | null
  ): Promise<AuthUser> {
    const { provider, tenantId, profile, hookResult, existingAuthUser } = flow
    switch (hookResult.action) {
      case 'create':
        if (invitation === null && this.options.registration === 'invitation-only') {
          throw new AuthException(AUTH_ERROR_CODES.REGISTRATION_CLOSED)
        }
        return this.createAccount(provider, tenantId, profile)
      case 'link':
        return this.linkAccount(provider, profile, existingAuthUser)
      case 'reject':
      default:
        throw new AuthException(AUTH_ERROR_CODES.OAUTH_FAILED)
    }
  }

  /**
   * Vets the invitation a flow was started with against the provider's profile.
   *
   * @param record - The consumed state record.
   * @param profile - The provider's profile.
   * @returns What completes the invitation once the account is known, or `null` for a flow that
   *   carries none.
   * @throws `AuthException(INVALID_INVITATION_TOKEN)` when workspaces are not enabled, and the
   *   refusals of `WorkspaceInvitationAcceptService.prepareOAuth` otherwise.
   */
  private async vetInvitation(
    record: StoredOAuthState,
    profile: OAuthProfile
  ): Promise<PendingInvitation | null> {
    if (record.workspaceInvitation === undefined) return null
    if (this.invitations === null)
      throw new AuthException(AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN)
    const accepts = this.invitations
    const loaded: LoadedInvitation = await accepts.prepareOAuth(
      record.workspaceInvitation,
      record.tenantId,
      { email: profile.email, emailVerified: profile.emailVerified }
    )
    return {
      complete: async (user, created, context): Promise<void> => {
        await accepts.completeOAuth(loaded, user, created, context)
      }
    }
  }

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
