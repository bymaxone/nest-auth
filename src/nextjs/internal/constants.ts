/**
 * Internal shared constants for the `createAuthProxy` pipeline.
 *
 * These names appear in multiple internal modules
 * (`configValidation`, `proxyUtils`, `proxyHandlers`, …) so they
 * live here to keep the string literals in one place and make a
 * global search for any of them quick.
 */

/** Default upper bound on the silent-refresh retry counter. */
export const DEFAULT_MAX_REFRESH_ATTEMPTS = 2

/**
 * Query parameter the proxy uses as a counter for consecutive
 * silent-refresh redirect attempts. The leading underscore avoids
 * collisions with typical application query params and signals
 * "internal".
 */
export const REFRESH_ATTEMPT_PARAM = '_r'

/**
 * Query parameter the silent-refresh handler sets on its final
 * fallback redirect to `loginPath`. Presence of `reason=expired`
 * is the primary signal that breaks the redirect loop on a public
 * route.
 */
export const REASON_PARAM = 'reason'

/** Canonical `reason` value signalling an irrecoverable session. */
export const REASON_EXPIRED = 'expired'

/**
 * Hardcoded identity-header baseline always stripped from the
 * inbound request by {@link buildSanitizedRequestHeaders}. The
 * proxy is the only authority that may populate these slots on the
 * forwarded headers; a client-sent value MUST NEVER reach a
 * downstream server component.
 *
 * The list is separate from the consumer-configured
 * `AuthProxyConfig.userHeaders` so that a consumer using custom
 * header names cannot leave the default names spoofable through
 * the door.
 */
export const IDENTITY_HEADERS_BASELINE = [
  'x-user-id',
  'x-user-role',
  'x-tenant-id',
  'x-tenant-domain'
]
