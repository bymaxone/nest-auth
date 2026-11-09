/**
 * @fileoverview The `oauth` group of the module options: provider configuration and the redirects
 * that follow a callback.
 *
 * @layer Interface
 */

/** Options for OAuth sign-in. See {@link BymaxAuthModuleOptions.oauth}. */
export interface OAuthOptions {
  /**
   * URL the browser is redirected to after a successful OAuth callback.
   *
   * When set, the OAuth callback endpoint issues a `302` to this URL after
   * delivering tokens (cookies are still set via the same response). When
   * omitted, the callback returns a JSON body — appropriate for API/SPA
   * consumers that XHR/fetch the callback URL, but it leaves browser users
   * staring at a JSON page. Set this for any consumer where the OAuth flow
   * is initiated by a full-page browser navigation.
   *
   * Requires `tokenDelivery: 'cookie'` or `'both'` — bearer-only delivery is
   * incompatible with a redirect because the access token would be discarded
   * in the redirect response body. The module throws at startup if the
   * combination is misconfigured.
   *
   * In production (`NODE_ENV === 'production'`), the URL must use HTTPS or
   * be a relative path (starts with `/`) — same posture as `callbackUrl`.
   *
   * @throws {Error} When the value fails validation at module initialisation.
   *
   * @example
   * ```typescript
   * successRedirectUrl: 'https://app.example.com/dashboard'
   * // or, for same-origin deployments:
   * successRedirectUrl: '/dashboard'
   * ```
   */
  successRedirectUrl?: string

  /**
   * URL the browser is redirected to when an OAuth callback completes for
   * an MFA-enabled user — BEFORE any session tokens are issued.
   *
   * Resolves a critical UX gap for the OAuth + MFA combination: today, an
   * MFA-enabled user who signs in via OAuth would receive session cookies
   * with `mfaVerified: false`, which the global `MfaRequiredGuard` rejects
   * on every subsequent request — leaving the user locked out with no
   * surfaced path forward. With this option set, the lib instead plants a
   * short-lived `mfa_temp_token` HttpOnly cookie (Path scoped to the MFA
   * challenge endpoint, 5-minute TTL matching the underlying JWT) and
   * redirects the browser to the
   * configured URL where the consumer collects the TOTP/recovery code and
   * POSTs to `/auth/mfa/challenge` to complete the flow.
   *
   * When omitted, the callback returns a JSON body
   * `{ mfaRequired: true, mfaTempToken }` instead — appropriate for SPA
   * consumers that drive the redirect client-side.
   *
   * Same security posture as `successRedirectUrl`: must be a non-empty
   * string, and in production it must use HTTPS or be a same-origin path
   * (`/...`). Independent of `tokenDelivery` because the MFA temp token
   * always travels via the dedicated cookie/JSON channel — bearer mode is
   * accepted here.
   *
   * @example
   * ```typescript
   * mfaRedirectUrl: 'https://app.example.com/auth/mfa-challenge'
   * // or, for same-origin deployments:
   * mfaRedirectUrl: '/auth/mfa-challenge'
   * ```
   */
  mfaRedirectUrl?: string

  /**
   * URL the browser is redirected to when an OAuth callback fails with an
   * `AuthException` (e.g. invalid state, plugin error, hook rejected).
   *
   * Symmetric polish for `successRedirectUrl`: today, an OAuth failure
   * propagates as a raw JSON 401/500 response, which leaves browser users
   * looking at machine-readable output instead of a friendly error page.
   * When set, the controller redirects to the configured URL and appends
   * `?error=<code>` (e.g. `?error=oauth_failed`) so the destination page
   * can branch on the failure reason. Existing query parameters on the URL
   * are preserved (uses the `URL` constructor).
   *
   * Only `AuthException` errors trigger the redirect — unexpected
   * exceptions (programmer errors, infrastructure failures) propagate so
   * they are surfaced to monitoring instead of silently swallowed.
   *
   * Same security posture as `successRedirectUrl`: must be a non-empty
   * string, and in production it must use HTTPS or be a same-origin path.
   *
   * @example
   * ```typescript
   * errorRedirectUrl: 'https://app.example.com/auth/error'
   * // or, for same-origin deployments:
   * errorRedirectUrl: '/auth/error'
   * ```
   */
  errorRedirectUrl?: string

  /**
   * Google OAuth 2.0 configuration.
   * All three fields are required to enable Google login.
   */
  google?: {
    /** Google OAuth client ID from Google Cloud Console. */
    clientId: string
    /**
     * Google OAuth client secret from Google Cloud Console.
     * @remarks Never log this value. Treat with the same care as `jwt.secret`.
     * The consuming `resolveOptions()` implementation must redact this field
     * before any diagnostic logging.
     */
    clientSecret: string
    /** Absolute URL for the OAuth callback (must match Google Console configuration). */
    callbackUrl: string
    /**
     * OAuth scopes to request from Google.
     * Defaults to `['openid', 'email', 'profile']` when not specified.
     *
     * @example
     * ```typescript
     * scope: ['openid', 'email', 'profile', 'https://www.googleapis.com/auth/calendar.readonly']
     * ```
     */
    scope?: string[]
  }
}
