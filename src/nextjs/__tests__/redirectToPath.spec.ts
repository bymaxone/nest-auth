/**
 * Same-origin enforcement in `internal/redirectToPath.ts`.
 *
 * The module's whole purpose is that a redirect it issues cannot be pointed off-site, and it
 * achieves that by never naming an origin. Not naming one is necessary and not sufficient:
 * `//attacker.example` names no scheme, satisfies `startsWith('/')`, and is read by every
 * browser as an authority. These tests pin the reduction that closes the remaining ways a
 * caller could hand this helper a destination on someone else's origin.
 */

import { redirectToPath, withQueryParam } from '../internal/redirectToPath'

describe('redirectToPath', () => {
  it('emits a path unchanged as a relative Location', () => {
    const response = redirectToPath('/login?next=%2Fdashboard')

    expect(response.status).toBe(307)
    expect(response.headers.get('location')).toBe('/login?next=%2Fdashboard')
  })

  // A protocol-relative reference is the one off-site redirect that survives "never name an
  // origin": there is no scheme and no `://` to notice, and the browser resolves it against
  // the current scheme and the authority the caller supplied.
  it.each([
    ['a protocol-relative reference', '//attacker.example/login'],
    ['its backslash spelling, which browsers normalise to the same thing', '/\\attacker.example'],
    ['an absolute URL', 'https://attacker.example/login'],
    ['a scheme-only relative reference', 'attacker.example/login']
  ])('refuses %s and falls back to the app root', (_case, path) => {
    expect(redirectToPath(path).headers.get('location')).toBe('/')
  })

  // A bare CR or LF in a header value ends the header and lets everything after it be read as
  // further headers or as the body.
  it.each([
    ['a carriage return', '/login\r\nSet-Cookie: session=stolen'],
    ['a line feed', '/login\nX-Injected: 1'],
    ['a NUL', '/login\u0000'],
    ['a DEL', '/login\u007f']
  ])('refuses a path containing %s', (_case, path) => {
    expect(redirectToPath(path).headers.get('location')).toBe('/')
  })
})

describe('withQueryParam', () => {
  it('sets a parameter while preserving the ones already present', () => {
    expect(withQueryParam('/login?a=1', 'next', '/dashboard')).toBe('/login?a=1&next=%2Fdashboard')
  })

  it('replaces a parameter that is already set', () => {
    expect(withQueryParam('/login?next=%2Fa', 'next', '/b')).toBe('/login?next=%2Fb')
  })

  // Resolving against the placeholder origin would otherwise silently discard the authority and
  // return `/login` — the attacker's destination dropped, but the caller's own destination lost
  // with it, and no failure anywhere to reveal that the input was rejected at all.
  it('reduces a protocol-relative reference to the app root rather than salvaging its path', () => {
    expect(withQueryParam('//attacker.example/login', 'next', '/x')).toBe('/?next=%2Fx')
  })

  // The fragment never reaches the server, so nothing here acts on it — but it is where the
  // browser lands, and dropping it silently changes the destination of a configured path.
  it('preserves a fragment on the path it was given', () => {
    expect(withQueryParam('/docs#install', 'next', '/x')).toBe('/docs?next=%2Fx#install')
  })

  // Two `Stryker disable next-line StringLiteral` directives in `proxyHandlers` rest on this:
  // the mutant turns a `'/'` fallback into `''`, and the claim is that both reach the same
  // emitted `Location`. That is only true because `toSameOriginPath` maps anything not
  // beginning with `/` to `/`. Asserting it here means the day the reduction changes, the
  // equivalence the disables assert fails visibly instead of silently becoming a lie.
  it('treats an empty path and the app root identically, as the mutant suppressions assume', () => {
    expect(redirectToPath('').headers.get('location')).toBe(
      redirectToPath('/').headers.get('location')
    )
    expect(withQueryParam('', 'error', 'forbidden')).toBe(withQueryParam('/', 'error', 'forbidden'))
  })
})
