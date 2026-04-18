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
 *   - does NOT contain CR / LF / NUL / backslash (header-smuggling
 *     and Windows-path normalisation traps).
 */
export function isSafeSameOriginPath(candidate: string): boolean {
  return (
    typeof candidate === 'string' &&
    candidate.length > 0 &&
    candidate.startsWith('/') &&
    !candidate.startsWith('//') &&
    !/[\\\r\n\0]/.test(candidate)
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
 */
export function assertSafeCookiePath(value: string, factoryName: string, label: string): void {
  if (!/^\/[\x20-\x3A\x3C-\x7E]*$/.test(value)) {
    throw new Error(`${factoryName}: invalid cookie path "${value}" for ${label}.`)
  }
}

/** Remove a single trailing `/` from `value`, if present. */
export function trimTrailingSlash(value: string): string {
  return value.endsWith('/') ? value.slice(0, -1) : value
}
