/**
 * Utilities shared between the Next.js route handler factories
 * (`createSilentRefreshHandler`, `createClientRefreshHandler`,
 * `createLogoutHandler`).
 *
 * Keeping these in one module prevents the handlers from drifting on
 * cookie-clearing attributes, path validation rules, and other tiny
 * details that affect cross-browser compatibility.
 */

/**
 * `Sec-Fetch-Site` values that prove a request did not come from another site.
 *
 * `same-origin` is the app calling itself; `none` is a user-initiated navigation (a typed URL,
 * a bookmark), which no attacker page can cause.
 */
const SAFE_FETCH_SITES = new Set(['same-origin', 'none'])

/**
 * Whether a request to one of the route handlers came from somewhere other than this app.
 *
 * These handlers sit in front of the auth backend and every one of them ends by writing
 * `Set-Cookie`, so a cross-site caller does not need to read the response to get something out
 * of them. `POST /api/auth/logout` from an attacker's page sends no session cookie under `Lax`,
 * so the upstream revocation is a no-op — but the handler answers with three `Max-Age=0`
 * cookies anyway, and a form POST is a top-level navigation, so the browser applies them
 * first-party. Any page on the internet could sign a visitor out of the app, repeatably. The
 * silent-refresh GET is the same shape reachable from an `<img>`.
 *
 * The check is `Sec-Fetch-Site` alone. `Origin` cannot decide it: a same-origin POST sends one
 * too, and a route handler has no configured notion of its own origin to compare against —
 * `request.nextUrl.origin` is derived from `Host`, which is client-controlled. `Sec-Fetch-Site`
 * is not forgeable by a page and is sent by Chrome 76, Firefox 90 and Safari 16.4 onward; a
 * request without it is either an older browser or a non-browser client, and is admitted for
 * the same reason the server-side guard admits that shape.
 *
 * @param request - The incoming request.
 * @returns `true` when the browser has stated the request came from another site.
 */
export function isCrossSiteRequest(request: {
  headers: { get(name: string): string | null }
}): boolean {
  const fetchSite = request.headers.get('sec-fetch-site')
  return fetchSite !== null && !SAFE_FETCH_SITES.has(fetchSite)
}

/**
 * Build a `Set-Cookie` string that clears a cookie with the given
 * name on the given path.
 *
 * `HttpOnly`, `Secure`, and `SameSite=Strict` are re-applied to match
 * the attributes the NestJS server uses when the cookie was originally
 * set. RFC 6265bis requires the overwrite to carry the same (or
 * stricter) `SameSite` value, otherwise strict-mode browsers may
 * silently ignore the clear and leave the cookie alive after logout.
 *
 * PRE-CONDITION: `name` and `path` must have been validated against
 * CR/LF/NUL and other header-smuggling characters via
 * {@link assertSafeCookieName} / {@link assertSafeCookiePath} at
 * factory construction time. This helper performs no sanitisation
 * of its own.
 *
 * @param name - Cookie name (pre-validated by {@link assertSafeCookieName}).
 * @param path - Cookie path scope.
 * @returns A `Set-Cookie` header value that clears the named cookie.
 */
export function serializeClearCookie(name: string, path: string): string {
  return `${name}=; Path=${path}; Max-Age=0; HttpOnly; Secure; SameSite=Strict`
}

/**
 * Whether a candidate string is a safe same-origin pathname suitable
 * for use as a redirect destination:
 *
 *   - non-empty,
 *   - starts with `/`,
 *   - does NOT start with `//` (protocol-relative URL),
 *   - does NOT contain a backslash (Windows-path normalisation trap),
 *   - does NOT contain any C0 control character or DEL.
 *
 * The control-character rule is stated as a range rather than the CR / LF / NUL
 * trio it started as. Those three are the ones that smuggle a header, but the
 * others have no business in a path either, and enumerating the dangerous
 * characters is the kind of allowlist-by-omission that only looks complete until
 * someone finds the character nobody thought of.
 *
 * @param candidate - The path string to validate.
 * @returns `true` when `candidate` is a safe, same-origin relative path.
 */
export function isSafeSameOriginPath(candidate: string): boolean {
  return (
    typeof candidate === 'string' &&
    // Stryker disable next-line EqualityOperator,ConditionalExpression: redundant non-empty check: `candidate.startsWith('/')` below already implies length > 0, so `> 0`/`>= 0`/`true` are indistinguishable
    candidate.length > 0 &&
    candidate.startsWith('/') &&
    !candidate.startsWith('//') &&
    // eslint-disable-next-line no-control-regex -- rejecting control characters is the point
    !/[\\\u0000-\u001f\u007f]/.test(candidate)
  )
}

/**
 * Whether a candidate string is a safe upstream pathname — used to
 * validate `logoutPath`, `refreshPath`, etc. These paths are
 * concatenated onto the validated `apiBase` to build the outbound
 * request URL; they must not contain characters that could alter
 * the URL's meaning (`?`, `#`, backslash, CR/LF/NUL) or dot-segment
 * sequences that could redirect the request to a different upstream
 * route.
 *
 * @param candidate - The upstream path string to validate.
 * @returns `true` when `candidate` is a safe upstream-relative path.
 */
export function isSafeUpstreamPath(candidate: string): boolean {
  if (typeof candidate !== 'string') return false
  if (!candidate.startsWith('/')) return false
  if (candidate.includes('..')) return false
  return !/[?#\\\r\n\0]/.test(candidate)
}

/**
 * Throw when `value` is not a safe cookie name (RFC 6265 token:
 * printable ASCII excluding space, `=`, and separators).
 *
 * @param value - The cookie name string to validate.
 * @param factoryName - Name of the factory function, used in error messages.
 * @param label - Human-readable label for the field, used in error messages.
 * @throws {Error} When `value` contains characters that would make the Set-Cookie header unsafe.
 */
export function assertSafeCookieName(value: string, factoryName: string, label: string): void {
  if (!/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(value)) {
    throw new Error(`${factoryName}: invalid cookie name "${value}" for ${label}.`)
  }
}

/**
 * Throw when `value` is not a safe cookie path: starts with `/`, no
 * CR/LF/NUL/backslash, no `;` (which would terminate the `Path`
 * attribute and allow attribute smuggling).
 *
 * @param value - The cookie path string to validate.
 * @param factoryName - Name of the factory function, used in error messages.
 * @param label - Human-readable label for the field, used in error messages.
 * @throws {Error} When `value` contains characters that would make the Set-Cookie header unsafe.
 */
export function assertSafeCookiePath(value: string, factoryName: string, label: string): void {
  if (!/^\/[\x20-\x3A\x3C-\x7E]*$/.test(value)) {
    throw new Error(`${factoryName}: invalid cookie path "${value}" for ${label}.`)
  }
}

/**
 * Remove a single trailing `/` from `value`, if present.
 *
 * @param value - The string from which to remove a trailing slash.
 * @returns The input string with a single trailing `'/'` removed, if present.
 */
export function trimTrailingSlash(value: string): string {
  return value.endsWith('/') ? value.slice(0, -1) : value
}
