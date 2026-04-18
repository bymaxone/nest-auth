/**
 * Access-token reading for the proxy.
 *
 * `readTokenState` is the single source of truth for every
 * downstream handler (public, protected, background) — centralising
 * the decode-vs-verify branching keeps the call sites free of
 * conditional crypto decisions.
 */

import type { NextRequest } from 'next/server'

import type { ResolvedAuthProxyConfig } from '../createAuthProxy'
import { decodeJwtToken, verifyJwtToken, type DecodedToken } from '../helpers/jwt'

/**
 * Summary of the access-token state for a single request.
 *
 * - `token`: the decoded representation, or `undefined` ONLY when no
 *   access cookie is present on the request. When the cookie is
 *   present but malformed, `token` is still a `DecodedToken` (with
 *   `isValid: false`) — use {@link hasCookie} to distinguish the two.
 * - `hasCookie`: `true` when the access cookie is present on the
 *   request, regardless of whether it decoded successfully. Needed
 *   to choose between "redirect to login" (no cookie at all) and
 *   "attempt silent refresh" (cookie present but invalid).
 * - `authenticated`: `true` when the token decodes AND has not yet
 *   expired. In verify mode (`jwtSecret` provided) this additionally
 *   implies a valid HS256 signature. In decode-only mode it reflects
 *   ONLY expiry — the caller must have arranged for upstream
 *   signature verification.
 * - `signatureVerified`: `true` only when the token was validated
 *   against the configured `jwtSecret` via HMAC. `false` in
 *   decode-only mode even when `authenticated` is `true`.
 */
export interface TokenState {
  readonly token: DecodedToken | undefined
  readonly hasCookie: boolean
  readonly authenticated: boolean
  readonly signatureVerified: boolean
}

/**
 * Decode the access-token cookie attached to the given request,
 * performing HS256 verification via Web Crypto when a `jwtSecret`
 * is configured and decode-only parsing otherwise.
 */
export async function readTokenState(
  request: NextRequest,
  config: ResolvedAuthProxyConfig
): Promise<TokenState> {
  const raw = request.cookies.get(config.cookieNames.access)?.value
  if (raw === undefined || raw.length === 0) {
    return {
      token: undefined,
      hasCookie: false,
      authenticated: false,
      signatureVerified: false
    }
  }

  const hasSecret = config.jwtSecret !== undefined && config.jwtSecret.length > 0
  const decoded = hasSecret ? await verifyJwtToken(raw, config.jwtSecret) : decodeJwtToken(raw)

  return {
    token: decoded,
    hasCookie: true,
    authenticated: decoded.isValid,
    signatureVerified: hasSecret && decoded.isValid
  }
}
