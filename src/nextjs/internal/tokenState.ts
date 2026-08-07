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
import { verifyJwtToken, type DecodedToken } from '../helpers/jwt'

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
 * - `authenticated`: `true` when the token carried a valid HS256
 *   signature, has not yet expired, and is an access token. There is
 *   no mode in which this is `true` without a verified signature.
 * - `signatureVerified`: `true` only when the token was validated
 *   against the configured `jwtSecret` via HMAC. It carries
 *   the signature fact and NOTHING else — it stays `true` for a
 *   genuinely signed token that has expired, or that is the wrong
 *   `type`, because the signature was checked before either was
 *   read. Anything gating on identity reads `authenticated`, which
 *   is the conjunction; this field alone answers only "was a
 *   signature checked", which is never the whole question.
 */
export interface TokenState {
  readonly token: DecodedToken | undefined
  readonly hasCookie: boolean
  readonly authenticated: boolean
  readonly signatureVerified: boolean
}

/**
 * Read the access-token cookie attached to the given request and
 * verify it: HS256 via Web Crypto, against the configured
 * `jwtSecret`. An absent or empty secret authenticates nobody.
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

  // Fail closed: a request is authenticated only by an HS256 verification. There is deliberately
  // no decode-only fallback — `decodeJwtToken` answers `isValid` for any structurally sound,
  // unexpired token, including one an attacker wrote, and that value would go on to drive route
  // gating, role checks, status blocking and the identity headers injected into every server
  // component. A missing secret must therefore authenticate nobody rather than everybody.
  //
  // Verification is called unconditionally because `verifyJwtToken` already refuses an absent or
  // empty secret. Guarding the call would put the same decision in two places and let them
  // drift; `assertJwtSecretConfigured` refuses to build the proxy at all, and this is the lock
  // that survives a refactor of that one.
  const decoded: DecodedToken = await verifyJwtToken(raw, config.jwtSecret)
  const isSession = decoded.isValid && isAccessToken(decoded)

  return {
    token: decoded,
    hasCookie: true,
    authenticated: isSession,
    // Passed through, not conjoined with `isSession`. The name says "a signature was checked",
    // and folding expiry and token-type into it made the same identifier mean one thing on
    // `DecodedToken` and a stricter thing here — the kind of collision that is only ever
    // discovered by someone trusting the looser reading. `authenticated` above is where the
    // conjunction belongs, and it is the field every decision in this proxy actually reads.
    signatureVerified: decoded.signatureVerified
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
