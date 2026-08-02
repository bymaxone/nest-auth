/**
 * @fileoverview Shared constants for the short-lived `oauth_state` cookie planted by
 * {@link OAuthController} when an OAuth flow is initiated and required back on the callback.
 *
 * @layer constants
 */

/**
 * Cookie name binding an in-flight OAuth `state` to the browser that started the flow.
 *
 * The `state` parameter alone proves only that *somebody* started a flow, not that **this**
 * browser did. Without the binding, an attacker can begin their own authorization, complete
 * consent at the provider, capture the resulting `?code=…&state=…` callback URL without
 * visiting it, and lure the victim there: the victim's browser then receives the *attacker's*
 * session, and everything the victim does next — adding a payment method, uploading a
 * document — lands in the attacker's account. PKCE does not help, because the verifier lives
 * server-side and is replayed for whoever presents the state.
 *
 * RFC 6749 §10.12 and the OAuth 2.0 Security BCP both require the state to be bound to the
 * user agent's session; this cookie is that binding.
 */
export const OAUTH_STATE_COOKIE_NAME = 'oauth_state' as const

/**
 * `SameSite` for the state cookie — always `lax`, never the configured value.
 *
 * The provider redirects the browser back with a top-level GET, which is a **cross-site**
 * navigation. `SameSite=Strict` withholds the cookie on exactly that hop, so a deployment
 * configured `strict` (a reasonable hardening choice everywhere else) would find every OAuth
 * login broken with no way to complete it. `lax` is the tightest value that still survives
 * the callback, and it is enough: the cookie is only ever read on that one navigation and is
 * useless for anything a cross-site *request* could do.
 */
export const OAUTH_STATE_COOKIE_SAME_SITE = 'lax' as const

/**
 * Lifetime of the state cookie, in seconds.
 *
 * Matches `OAUTH_STATE_TTL_SECONDS`, the TTL of the server-side `os:` record it is paired
 * with. Keeping the two identical avoids the failure mode where one outlives the other and a
 * user who took their time at the consent screen sees an opaque failure whose cause depends on
 * which half expired first.
 */
export const OAUTH_STATE_COOKIE_MAX_AGE_SECONDS = 600
