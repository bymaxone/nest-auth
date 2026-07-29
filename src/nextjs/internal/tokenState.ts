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
 * The access-token `type` discriminants the proxy admits — the dashboard and platform access
 * tokens. Any other type, notably the short-lived MFA-temp `mfa_challenge`, must never gate a
 * protected route, so it is treated as unauthenticated. Mirrors `ACCESS_TOKEN_TYPES` in
 * `rust-auth`'s proxy.
 */
const ACCESS_TOKEN_TYPES: readonly string[] = ['dashboard', 'platform']

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
  const isSession = decoded.isValid && isAccessToken(decoded)

  return {
    token: decoded,
    hasCookie: true,
    authenticated: isSession,
    signatureVerified: hasSecret && isSession
  }
}

/**
 * Whether a verified token is an **access token**, as opposed to some other credential the
 * same secret signs.
 *
 * A valid signature is not the question the proxy is actually asking. The server signs
 * several kinds of token with one key, and `mfa_challenge` is issued to a user who has proven
 * their password and **not** their second factor. Without this check, moving that temp token
 * into the access cookie walks past every proxy-protected page — precisely the state the
 * second factor exists to stop. The upstream API rejects it, because its guards check `type`;
 * the gap is the edge, where the page renders.
 *
 * Both access discriminants are admitted, matching `rust-auth`'s proxy: an operator console
 * proxied by the same middleware presents a platform token, and separating the two planes is
 * the server's job, not the edge's. A token with no `type` claim at all is refused — the claim
 * has been present since the first release, so its absence means the token was not minted by
 * this library.
 */
function isAccessToken(decoded: DecodedToken): boolean {
  return ACCESS_TOKEN_TYPES.includes(decoded.payload['type'] as string)
}
