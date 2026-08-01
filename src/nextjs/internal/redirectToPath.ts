/**
 * Same-origin redirects that do not depend on the `Host` header.
 *
 * @layer nextjs-internal
 */

import { NextResponse } from 'next/server'

/**
 * Characters that must never reach a header value. A raw CR or LF splits the response and lets
 * the rest of the string be read as further headers or a body; the other C0 codes and DEL have
 * no meaning in a path and are refused with them rather than sanitised piecemeal.
 */
// eslint-disable-next-line no-control-regex -- matching control characters is the point
const FORBIDDEN_IN_PATH = /[\u0000-\u001f\u007f]/

/**
 * Reduces `path` to something that can only ever name a location on this origin.
 *
 * The module exists so that no redirect it issues can be pointed off-site, and every current
 * caller passes a path already validated as same-origin. Enforcing it here too is what keeps
 * that true of callers not yet written: the invariant belongs to the helper that writes the
 * header, not to the discipline of everyone who reaches it. Three shapes are refused —
 *
 * - anything not beginning with `/`, which is a relative reference the browser resolves
 *   against the *directory* of the current page, or an absolute URL naming its own origin;
 * - `//host` and `/\host`, which are protocol-relative: the browser reads what follows as an
 *   authority, so `//attacker.example` is a redirect off-site written to look like a path.
 *   Browsers normalise the backslash form to the slash form, so both must go;
 * - any control character, which would let a caller inject a second header.
 *
 * A refused path falls back to `/` rather than throwing. This runs in middleware, where a throw
 * is a 500 on a request that was otherwise fine, and the app root is the one destination
 * guaranteed to be both same-origin and harmless.
 *
 * @param path - The intended same-origin path.
 * @returns `path` when it can only name this origin, `/` otherwise.
 */
function toSameOriginPath(path: string): string {
  if (!path.startsWith('/')) return '/'
  if (path.startsWith('//') || path.startsWith('/\\')) return '/'
  if (FORBIDDEN_IN_PATH.test(path)) return '/'
  return path
}

/**
 * Builds a redirect to a same-origin `path`, without naming an origin at all.
 *
 * Every redirect this proxy issues targets a path on its own app, and the path is already
 * validated as same-origin before it gets here. The origin was being supplied by
 * `request.nextUrl.origin`, which Next derives from the `Host` header — so a self-hosted
 * deployment that answers on any host handed an attacker who controls that header a
 * `Location: https://attacker.example/login`. The path validation could not see it: the path
 * was fine, and the origin was never checked at all.
 *
 * A relative `Location` removes the question. RFC 7231 §7.1.2 has allowed one since 2014 and
 * every current browser resolves it against the URL it actually requested — which is the real
 * origin as the browser knows it, not as a header claims it. There is nothing left for a
 * forged `Host` to change.
 *
 * The status is 307, matching `NextResponse.redirect`'s default, so the method and body of the
 * original request are preserved.
 *
 * A relative `Location` is only same-origin while it stays a path, so the value is run through
 * {@link toSameOriginPath} before it is written. Naming the origin was never the only way to
 * leave it: `//attacker.example` is a path to `startsWith('/')` and an authority to a browser.
 *
 * @param path - A same-origin path beginning with `/`, optionally carrying a query string.
 * @returns A 307 response whose `Location` is `path`, or `/` when `path` could name elsewhere.
 */
export function redirectToPath(path: string): NextResponse {
  return new NextResponse(null, { status: 307, headers: { location: toSameOriginPath(path) } })
}

/**
 * Appends a query parameter to a same-origin path, preserving any parameters already on it.
 *
 * Exists because the redirect targets are now plain strings rather than `URL` objects, and a
 * `URL` was what used to own the `searchParams` handling. Parsing against a fixed placeholder
 * origin keeps that behaviour — the placeholder is discarded, never emitted.
 *
 * The input is reduced by {@link toSameOriginPath} first. Resolving `//attacker.example/x`
 * against the placeholder yields a URL on *that* authority, and taking its `pathname` would
 * quietly hand back `/x` — the caller's intended destination replaced by an attacker's, with
 * no failure anywhere to notice. Refusing first makes the fallback the honest `/`.
 *
 * @param path - A same-origin path beginning with `/`.
 * @param key - Parameter name.
 * @param value - Parameter value.
 * @returns The path with the parameter set, still relative.
 */
export function withQueryParam(path: string, key: string, value: string): string {
  const parsed = new URL(toSameOriginPath(path), 'https://placeholder.invalid')
  parsed.searchParams.set(key, value)
  // The fragment rides along. It never reaches the server, so nothing here can act on it — but
  // a configured path that carries an anchor means the anchor to the browser, and dropping it
  // silently changes where the page lands after the redirect.
  return `${parsed.pathname}${parsed.search}${parsed.hash}`
}
