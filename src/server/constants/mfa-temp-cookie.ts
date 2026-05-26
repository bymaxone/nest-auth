/**
 * @fileoverview Shared constants for the short-lived `mfa_temp_token` cookie
 * planted by {@link OAuthController} after an MFA-gated OAuth callback and
 * consumed by {@link MfaController.challenge} as an alternate source of the
 * temp JWT.
 *
 * @layer constants
 */

/**
 * Cookie name used to plant the short-lived MFA temp token on an OAuth
 * callback that requires an MFA challenge to complete. The cookie is
 * HttpOnly, path-scoped to the MFA challenge route, and cleared on
 * successful exchange.
 *
 * @remarks
 * The literal string is asserted with `as const` so consumers that
 * destructure cookies by this name (see `readMfaTempCookie` in
 * `mfa.controller.ts`) can rely on the exact value without indirection.
 */
export const MFA_TEMP_COOKIE_NAME = 'mfa_temp_token' as const

/**
 * Lifetime in seconds of the `mfa_temp_token` cookie.
 *
 * Pinned to 300 (5 minutes) to exactly match the lifetime of the underlying
 * MFA temp JWT issued by `TokenManagerService.issueMfaTempToken`
 * (`MFA_TEMP_TOKEN_TTL_SECONDS`). Keeping the two TTLs identical prevents
 * the cookie from outliving the JWT — a state that would surface as a
 * misleading "Invalid MFA temp token" error on what looks to the user
 * like a still-valid session.
 */
export const MFA_TEMP_COOKIE_MAX_AGE_SECONDS = 300
