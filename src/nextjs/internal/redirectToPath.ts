/**
 * Same-origin redirects that do not depend on the `Host` header.
 *
 * @layer nextjs-internal
 */

import { NextResponse } from 'next/server'

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
 * @param path - A same-origin path beginning with `/`, optionally carrying a query string.
 * @returns A 307 response whose `Location` is exactly `path`.
 */
export function redirectToPath(path: string): NextResponse {
  return new NextResponse(null, { status: 307, headers: { location: path } })
}

/**
 * Appends a query parameter to a same-origin path, preserving any parameters already on it.
 *
 * Exists because the redirect targets are now plain strings rather than `URL` objects, and a
 * `URL` was what used to own the `searchParams` handling. Parsing against a fixed placeholder
 * origin keeps that behaviour — the placeholder is discarded, never emitted.
 *
 * @param path - A same-origin path beginning with `/`.
 * @param key - Parameter name.
 * @param value - Parameter value.
 * @returns The path with the parameter set, still relative.
 */
export function withQueryParam(path: string, key: string, value: string): string {
  const parsed = new URL(path, 'https://placeholder.invalid')
  parsed.searchParams.set(key, value)
  return `${parsed.pathname}${parsed.search}`
}
