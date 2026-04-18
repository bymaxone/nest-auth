/**
 * Unit tests for `src/nextjs/helpers/buildSilentRefreshUrl.ts`.
 *
 * Exercises every branch of `buildSilentRefreshUrl` and its internal
 * `resolveDestination`:
 *
 *   - explicit `redirectTo` passed through to the `redirect` param,
 *   - fallback to `nextUrl.pathname + search`,
 *   - fallback to the parsed `request.url` pathname + search when
 *     `nextUrl` is absent (structural-interface consumers),
 *   - the `own-property` guard on `nextUrl.search`,
 *   - the non-HTTP protocol throw (factory-time defence).
 */

import { buildSilentRefreshUrl } from '../helpers/buildSilentRefreshUrl'

describe('buildSilentRefreshUrl', () => {
  const origin = 'https://app.example.com'

  // Happy path with explicit redirectTo: the value is URL-encoded
  // via URLSearchParams.set and attached as the `redirect` param.
  it('appends the explicit redirectTo as an encoded redirect param', () => {
    const result = buildSilentRefreshUrl({ url: `${origin}/current` }, '/dashboard?x=1')
    const url = new URL(result)
    expect(url.pathname).toBe('/api/auth/silent-refresh')
    expect(url.searchParams.get('redirect')).toBe('/dashboard?x=1')
  })

  // Empty string redirectTo → falls back to the request's pathname.
  // Mirrors the "treat empty as missing" pattern.
  it('falls back to the request pathname when redirectTo is an empty string', () => {
    const result = buildSilentRefreshUrl({ url: `${origin}/deep/page` }, '')
    const url = new URL(result)
    expect(url.searchParams.get('redirect')).toBe('/deep/page')
  })

  // No redirectTo and no `nextUrl`: uses the parsed pathname + search
  // from `request.url`. Exercises the fallback branch for structural
  // consumers that don't supply NextRequest.
  it('uses parsed url pathname+search when nextUrl is absent', () => {
    const result = buildSilentRefreshUrl({ url: `${origin}/page?q=1` })
    const url = new URL(result)
    expect(url.searchParams.get('redirect')).toBe('/page?q=1')
  })

  // With `nextUrl`: prefers nextUrl.pathname (reflects Next.js
  // rewrites/basePath) over the raw url pathname.
  it('prefers nextUrl.pathname over request.url when nextUrl is provided', () => {
    const result = buildSilentRefreshUrl({
      url: `${origin}/raw`,
      nextUrl: { pathname: '/rewritten', search: '?a=1' }
    })
    const url = new URL(result)
    expect(url.searchParams.get('redirect')).toBe('/rewritten?a=1')
  })

  // nextUrl.search absent: the fallback in `hasOwnSearch` returns ''
  // so the resulting destination is just the pathname. Exercises
  // the branch where search is not an own property.
  it('handles nextUrl without a search property', () => {
    const result = buildSilentRefreshUrl({
      url: `${origin}/raw`,
      nextUrl: { pathname: '/rewritten' }
    })
    const url = new URL(result)
    expect(url.searchParams.get('redirect')).toBe('/rewritten')
  })

  // Protocol guard: a file:/ata:/javascript: URL on the request
  // triggers the non-HTTP throw. Defensive only — real NextRequest
  // is always http/https.
  it('throws when request.url uses a non-HTTP scheme', () => {
    expect(() => buildSilentRefreshUrl({ url: 'file:///etc/passwd' })).toThrow(
      /unsupported URL protocol/
    )
  })

  // An HTTP (plain) base is accepted — not only HTTPS.
  it('accepts an http:// request URL', () => {
    const result = buildSilentRefreshUrl({ url: 'http://localhost:3000/dev' })
    expect(new URL(result).origin).toBe('http://localhost:3000')
  })
})
