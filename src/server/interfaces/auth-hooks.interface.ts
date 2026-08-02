/**
 * Authentication lifecycle hooks contract for @bymax-one/nest-auth.
 *
 * Hooks allow consumers to inject custom logic at key points in the auth flow
 * without modifying library internals. All hooks are optional — unimplemented
 * hooks are silently skipped.
 *
 * @remarks
 * - Hooks are called synchronously in the auth flow. Long-running operations
 *   (e.g. analytics, audit logging) should be fire-and-forget or offloaded to
 *   a queue inside the implementation.
 * - `beforeRegister` is the only hook that can block or modify the flow.
 *   All `after*` and `on*` hooks are informational.
 * - Never access raw HTTP headers inside hooks — use `context.sanitizedHeaders`
 *   which has been pre-processed by the `sanitizeHeaders` utility to remove
 *   authorization tokens, cookies, and other sensitive values.
 *
 * @layer Interface
 */

import type { SessionInfo } from './email-provider.interface'
import type { OAuthProfile } from './oauth-provider.interface'
import type { SafeAuthUser } from './user-repository.interface'

/**
 * Request context passed to every hook invocation.
 *
 * Contains the minimal set of HTTP request metadata needed for audit logging,
 * rate limiting, and geolocation — without exposing sensitive header values.
 */
export interface HookContext {
  /** Internal user ID, available after the user has been identified. */
  userId?: string
  /** User email address, available after identification. */
  email?: string
  /** Tenant identifier, available in multi-tenant flows. */
  tenantId?: string
  /**
   * IP address of the originating request.
   *
   * @remarks
   * Must be extracted using a trusted proxy configuration (e.g. Express
   * `app.set('trust proxy', 1)`). Never read directly from `X-Forwarded-For`
   * without proxy trust configured — false IPs undermine brute-force protection
   * and geolocation-based alerting.
   */
  ip: string
  /** Raw `User-Agent` header value from the request. */
  userAgent: string
  /**
   * Headers pre-sanitized by the `sanitizeHeaders` utility — never raw request headers.
   * Sensitive values (authorization, cookies, tokens, secrets, keys) have been removed
   * and all keys are normalized to lowercase.
   */
  sanitizedHeaders: Record<string, string | string[] | undefined>
}

/**
 * Return value of the {@link IAuthHooks.beforeRegister} hook.
 *
 * Controls whether the registration should proceed and optionally overrides
 * default field values assigned to the new user.
 */
export interface BeforeRegisterResult {
  /** When `false`, registration is rejected and `reason` is returned to the caller. */
  allowed: boolean
  /**
   * Human-readable explanation surfaced when `allowed` is `false`.
   * Avoid including sensitive information — this value may be returned to the client.
   */
  reason?: string
  /**
   * Optional field overrides applied to the new user record before persistence.
   * Only fields explicitly set here are modified; omitted fields use defaults.
   */
  modifiedData?: {
    /** Override the default role assigned at registration (e.g. `'viewer'`). */
    role?: string
    /** Override the initial account status (e.g. `'pending'`, `'active'`). */
    status?: string
    /** Override the default email-verification state at registration. */
    emailVerified?: boolean
  }
}

/**
 * Return value of the {@link IAuthHooks.onOAuthLogin} hook.
 *
 * Determines how an OAuth login should be handled when the provider profile
 * arrives (create new user, link to existing, or reject).
 */
export interface OAuthLoginResult {
  /**
   * Desired action for this OAuth login attempt:
   * - `'create'` — provision a new user account from the OAuth profile.
   * - `'link'`   — link the OAuth identity to an existing user account.
   * - `'reject'` — deny the login attempt (e.g. domain allowlist enforcement).
   */
  action: 'link' | 'create' | 'reject'
  /**
   * Human-readable explanation for a `'reject'` action.
   * Avoid including sensitive information — this value may be returned to the client.
   */
  reason?: string
}

/**
 * Optional lifecycle hooks that consumers can implement to extend the default
 * authentication behaviour of @bymax-one/nest-auth.
 *
 * @remarks
 * Register the implementation via the `hooks` option in `AuthModule.forRoot()`.
 * The library calls each hook via the injection token — no manual wiring needed.
 *
 * Hook parameters use {@link SafeAuthUser} instead of the full `AuthUser` to
 * ensure that `passwordHash`, `mfaSecret`, and `mfaRecoveryCodes` are never
 * forwarded to consumer code (analytics, audit loggers, etc.).
 *
 * @example
 * ```typescript
 * class MyAuthHooks implements IAuthHooks {
 *   async afterLogin(user: SafeAuthUser, context: HookContext): Promise<void> {
 *     await this.auditService.log('login', user.id, context.ip)
 *   }
 * }
 * ```
 */
export interface IAuthHooks {
  /**
   * Called before a new user account is persisted during registration.
   *
   * Use this hook to enforce domain allowlists, custom business rules, or to
   * override default field values (role, status, emailVerified) for the new user.
   * Return `{ allowed: false, reason }` to reject the registration.
   *
   * @param data - The registration payload as submitted by the user.
   * @param context - Request metadata (IP, user agent, sanitized headers).
   * @returns A {@link BeforeRegisterResult} controlling whether to proceed.
   */
  beforeRegister?(
    data: { email: string; name: string; tenantId: string },
    context: HookContext
  ): Promise<BeforeRegisterResult> | BeforeRegisterResult

  /**
   * Called immediately after a new user account has been successfully created.
   *
   * Use this hook for post-registration side effects: welcome emails, analytics
   * events, audit log entries, or CRM sync.
   *
   * @param user - The newly created user (credential fields omitted).
   * @param context - Request metadata (IP, user agent, sanitized headers).
   */
  afterRegister?(user: SafeAuthUser, context: HookContext): Promise<void> | void

  /**
   * Called before credentials are validated during a login attempt.
   *
   * Use this hook to enforce pre-authentication rules such as tenant-level IP
   * allowlists, login-time restrictions, or maintenance-mode blocks.
   *
   * **To abort the login:** throw an exception (e.g. `throw new UnauthorizedException()`).
   * Returning normally (void) allows the login to proceed to credential validation.
   * Unlike `beforeRegister`, there is no return-value-based rejection — throwing is
   * the only way to block. Choose a meaningful exception class so guards can
   * translate it into the correct HTTP response.
   *
   * @param email - The email address submitted in the login request.
   * @param tenantId - The tenant context for this login attempt.
   * @param context - Request metadata (IP, user agent, sanitized headers).
   */
  beforeLogin?(email: string, tenantId: string, context: HookContext): Promise<void> | void

  /**
   * Called immediately after a successful login and token issuance.
   *
   * Use this hook for post-login side effects: last-login timestamp updates,
   * audit log entries, or analytics events.
   *
   * @param user - The authenticated user (credential fields omitted).
   * @param context - Request metadata (IP, user agent, sanitized headers).
   */
  afterLogin?(user: SafeAuthUser, context: HookContext): Promise<void> | void

  /**
   * Called after the user's session has been successfully invalidated (logout).
   *
   * Use this hook to clean up session-related state, emit audit events, or
   * notify downstream services.
   *
   * @param userId - The internal ID of the user who logged out.
   * @param context - Request metadata (IP, user agent, sanitized headers).
   */
  afterLogout?(userId: string, context: HookContext): Promise<void> | void

  /**
   * Called when a login attempt is refused.
   *
   * Every other hook on this interface fires on a success path, which leaves the failure side
   * of authentication with no structured seam at all: the events that matter most to detection
   * — a burst of wrong passwords, an account tripping its lockout, a stolen refresh token being
   * replayed — existed only as English log lines whose wording is not a contract and whose
   * change is not semver-visible. ASVS v5 §16.3.1 expects authentication operations to be
   * logged with their outcome, and §6.1.1 expects an *adaptive* response, which needs a signal
   * to adapt to.
   *
   * The email is passed rather than a user id because the common case has no user: a failure
   * against an address that does not exist is exactly the credential-stuffing signal a consumer
   * wants. `userId` is present only when the account resolved and the credential did not match.
   *
   * Fire-and-forget, like every hook here: a throw is logged and swallowed, never turned into a
   * different answer for the caller.
   *
   * @param details - What failed, and for whom, as far as it is known.
   * @param context - Request metadata (IP, user agent, sanitized headers).
   */
  onLoginFailed?(
    details: {
      /** The address the attempt was made against, as submitted. */
      email: string
      /** The tenant the attempt was scoped to. */
      tenantId: string
      /** Present only when the account exists and the password did not match. */
      userId?: string
      /**
       * Why it was refused. `invalid_credentials` covers both an unknown address and a wrong
       * password — the two are deliberately indistinguishable to the *caller*, but not to the
       * hook, which the `userId` above tells apart.
       */
      reason: 'invalid_credentials' | 'account_blocked' | 'email_not_verified' | 'locked_out'
    },
    context: HookContext
  ): Promise<void> | void

  /**
   * Called when an identifier crosses the brute-force threshold and is locked out.
   *
   * The single highest-value moment for alerting: one account under sustained attack, or —
   * seen across many identifiers at once — a credential-stuffing run in progress. It is also
   * the moment a support queue is about to receive a call, since the lockout is indiscriminate
   * about who is doing the guessing.
   *
   * @param details - The locked identifier and the window it is locked for.
   * @param context - Request metadata (IP, user agent, sanitized headers).
   */
  onLockout?(
    details: {
      /** The address that was locked, as submitted. */
      email: string
      /** The tenant the lockout is scoped to. */
      tenantId: string
      /** Seconds until the window expires and attempts are accepted again. */
      retryAfterSeconds: number
    },
    context: HookContext
  ): Promise<void> | void

  /**
   * Called when a consumed refresh token is replayed after its grace window — the signature of
   * a stolen token — and its family is revoked.
   *
   * This is the strongest evidence of compromise the library produces. It is not a guess about
   * risk: a token that was already exchanged has been presented again by *someone*, and one of
   * the two holders is not the owner. A consumer wanting to force a password reset, page an
   * on-call, or raise the account's risk score has nothing else to key on.
   *
   * @param details - Whose lineage was revoked.
   * @param context - Request metadata (IP, user agent, sanitized headers).
   */
  onRefreshTokenReuseDetected?(
    details: {
      /** The account whose token family was revoked. */
      userId: string
      /** The revoked lineage, for correlating with a session listing. */
      familyId: string
    },
    context: HookContext
  ): Promise<void> | void

  /**
   * Called after MFA has been successfully enabled on a user account.
   *
   * Use this hook to send security notifications (via `IEmailProvider`),
   * update audit logs, or propagate the change to downstream systems.
   *
   * @param user - The user who enabled MFA (credential fields omitted).
   * @param context - Request metadata (IP, user agent, sanitized headers).
   */
  afterMfaEnabled?(user: SafeAuthUser, context: HookContext): Promise<void> | void

  /**
   * Called after MFA has been successfully disabled on a user account.
   *
   * Use this hook to send security alerts, update audit logs, or enforce
   * organizational policies that require MFA.
   *
   * @param user - The user who disabled MFA (credential fields omitted).
   * @param context - Request metadata (IP, user agent, sanitized headers).
   */
  afterMfaDisabled?(user: SafeAuthUser, context: HookContext): Promise<void> | void

  /**
   * Called after MFA recovery codes have been successfully regenerated.
   *
   * Use this hook to send a security alert reminding the user to store the new
   * codes safely, append an audit-log entry, or propagate the rotation to
   * downstream systems. The plain-text codes themselves are NOT passed to the
   * hook — they are only delivered to the requesting client.
   *
   * @param user - The user whose recovery codes were regenerated
   *   (credential fields omitted).
   * @param context - Request metadata (IP, user agent, sanitized headers).
   */
  afterMfaRecoveryCodesRegenerated?(user: SafeAuthUser, context: HookContext): Promise<void> | void

  /**
   * Called when a successful login originates from a new device or location.
   *
   * Use this hook to trigger new-session security alerts (via
   * `IEmailProvider.sendNewSessionAlert`) or to update device tracking records.
   *
   * @param user - The authenticated user (credential fields omitted).
   * @param sessionInfo - Device, IP, and session hash for the new session.
   * @param context - Request metadata (IP, user agent, sanitized headers).
   */
  onNewSession?(
    user: SafeAuthUser,
    sessionInfo: SessionInfo,
    context: HookContext
  ): Promise<void> | void

  /**
   * Called after the user's email address has been successfully verified.
   *
   * Use this hook to unlock features gated on email verification, send welcome
   * emails, or emit analytics events.
   *
   * @param user - The user whose email was verified (credential fields omitted).
   * @param context - Request metadata (IP, user agent, sanitized headers).
   */
  afterEmailVerified?(user: SafeAuthUser, context: HookContext): Promise<void> | void

  /**
   * Called after the user has successfully completed a password reset.
   *
   * Use this hook to invalidate all other active sessions, send confirmation
   * emails, or update audit logs.
   *
   * @param user - The user who reset their password (credential fields omitted).
   * @param context - Request metadata (IP, user agent, sanitized headers).
   */
  afterPasswordReset?(user: SafeAuthUser, context: HookContext): Promise<void> | void

  /**
   * Called when a user attempts to log in via OAuth and a profile has been
   * retrieved from the provider.
   *
   * Use this hook to decide whether to create a new account, link the OAuth
   * identity to an existing account, or reject the login (e.g. domain allowlists).
   *
   * @param profile - Normalized OAuth profile from the provider.
   * @param existingUser - Existing user (credential fields omitted) if one is found
   *   by email, otherwise `null`.
   * @param context - Request metadata (IP, user agent, sanitized headers).
   * @returns An {@link OAuthLoginResult} controlling the account resolution strategy.
   */
  onOAuthLogin?(
    profile: OAuthProfile,
    existingUser: SafeAuthUser | null,
    context: HookContext
  ): Promise<OAuthLoginResult> | OAuthLoginResult

  /**
   * Called after an invited user has successfully accepted their invitation and
   * completed account setup.
   *
   * Use this hook to update tenant membership records, notify the inviter, or
   * emit onboarding analytics events.
   *
   * @param user - The user who accepted the invitation (credential fields omitted).
   * @param context - Request metadata (IP, user agent, sanitized headers).
   */
  afterInvitationAccepted?(user: SafeAuthUser, context: HookContext): Promise<void> | void

  /**
   * Called when the session manager evicts an existing session to make room for
   * a new one (triggered by the `'fifo'` eviction strategy when the session limit
   * is reached).
   *
   * Use this hook to alert the affected user, emit a security audit event, or
   * track potential unauthorized access (an attacker establishing a new session
   * will silently evict a legitimate one under FIFO).
   *
   * @param userId - The internal ID of the user whose session was evicted.
   * @param evictedSessionHash - The SHA-256 hash of the evicted refresh token.
   *   This is the same value stored in Redis — never the raw token.
   * @param context - Request metadata (IP, user agent, sanitized headers).
   */
  onSessionEvicted?(
    userId: string,
    evictedSessionHash: string,
    context: HookContext
  ): Promise<void> | void
}
