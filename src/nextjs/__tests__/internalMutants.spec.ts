/**
 * Targeted mutation-killing tests for the `createAuthProxy` internal
 * modules.
 *
 * These exercise the internal functions DIRECTLY (rather than only
 * through the assembled proxy) so each branch, boundary, and string
 * literal can be pinned precisely:
 *
 *   - `routeClassifier`: `classifyRoute`, `matchesPublicRoute`,
 *     `matchesRoutePattern`, `normalizePath` — prefix-vs-suffix
 *     matching, trailing-slash semantics, `:segment` placeholders,
 *     trailing globs, exact-length checks, and the parse-failure
 *     fallback.
 *   - `tokenState`: `readTokenState` — the full returned shape on the
 *     no-cookie / verify / decode-only / empty-secret paths so the
 *     `hasCookie`, `signatureVerified`, and `hasSecret` derivations
 *     are observable.
 *   - `proxyUtils`: `buildSanitizedRequestHeaders`,
 *     `setOrDeleteHeader`, `sanitizeHeaderValue` — header stripping,
 *     empty-value deletion, and CR/LF/NUL removal.
 *   - `configValidation`: the decode-only warning / production-throw
 *     message content and the `console`-absence guard.
 */

import {
  classifyRoute,
  matchesPublicRoute,
  matchesRoutePattern,
  normalizePath
} from '../internal/routeClassifier'
import { readTokenState } from '../internal/tokenState'
import {
  buildSanitizedRequestHeaders,
  sanitizeHeaderValue,
  setOrDeleteHeader
} from '../internal/proxyUtils'
import { createAuthProxy } from '../createAuthProxy'
import type { ResolvedAuthProxyConfig } from '../createAuthProxy'
import { DEFAULT_PROXY_CONFIG, makeMockRequest, signHs256Token } from './_testHelpers'

const TEST_SECRET = DEFAULT_PROXY_CONFIG.jwtSecret ?? 'test-secret-must-be-long-enough'

/**
 * `DEFAULT_PROXY_CONFIG` already carries a concrete
 * `maxRefreshAttempts`, so it satisfies the resolved shape the
 * internal functions expect.
 */
const RESOLVED: ResolvedAuthProxyConfig = DEFAULT_PROXY_CONFIG as ResolvedAuthProxyConfig

describe('routeClassifier — classifyRoute', () => {
  // /api/auth/* prefix → `api`. Pins the `startsWith('/api/auth/')`
  // gate: a path that starts (but does not end) with the prefix must
  // classify as api, killing the `endsWith` swap, the `if (false)`
  // short-circuit, and the emptied block.
  it('classifies a /api/auth/ prefixed path (not suffixed) as api', () => {
    expect(classifyRoute('/api/auth/silent-refresh', RESOLVED)).toEqual({
      kind: 'api',
      matched: undefined
    })
  })

  // A path that merely ENDS with /api/auth/ but does not start with it
  // must NOT be treated as api — proves the gate is a prefix check.
  it('does not classify a path that only ends with /api/auth/ as api', () => {
    expect(classifyRoute('/x/api/auth/', RESOLVED).kind).not.toBe('api')
  })

  // A configured public route classifies as `public`. Pins the
  // public-routes loop body and its `if (matchesPublicRoute)` guard
  // against the emptied-block and `if (false)` mutants.
  it('classifies a configured public route as public', () => {
    expect(classifyRoute('/about', RESOLVED)).toEqual({ kind: 'public', matched: undefined })
  })

  // A path matching NO public route (and no protected pattern)
  // classifies as `unmatched`. Pins the `if (true)` mutant on the
  // public guard, which would otherwise classify everything as public.
  it('classifies a path matching no public route as unmatched', () => {
    const config: ResolvedAuthProxyConfig = {
      ...RESOLVED,
      publicRoutes: ['/about', '/auth/login'],
      protectedRoutes: []
    }
    expect(classifyRoute('/totally-unknown', config)).toEqual({
      kind: 'unmatched',
      matched: undefined
    })
  })

  // A protected pattern wins over the public fallthrough and carries
  // the matched pattern object.
  it('classifies a matching protected pattern as protected with the matched route', () => {
    const result = classifyRoute('/dashboard/x', RESOLVED)
    expect(result.kind).toBe('protected')
    expect(result.matched).toEqual(RESOLVED.protectedRoutes[0])
  })
})

describe('routeClassifier — matchesPublicRoute', () => {
  // Exact equality matches. (Pins the `pathname === route` fast path.)
  it('matches an exact route string', () => {
    expect(matchesPublicRoute('/login', '/login')).toBe(true)
  })

  // A different path does not match by bare prefix — `/loginExtra`
  // must NOT match `/login`. Kills the `if (true)` and
  // `route.startsWith('/')` and `route.endsWith('')` mutants, all of
  // which would wrongly take the prefix branch for a non-slash route.
  it('does not match a longer path that only shares a prefix without a separator', () => {
    expect(matchesPublicRoute('/loginExtra', '/login')).toBe(false)
  })

  // A non-trailing-slash route matches a deeper path only via the
  // `<route>/` boundary. Kills the `pathname.endsWith` swap on the
  // `${route}/` branch (endsWith would reject this true match).
  it('matches a deeper path under a non-slash route via the segment boundary', () => {
    expect(matchesPublicRoute('/login/sub', '/login')).toBe(true)
  })

  // A trailing-slash route matches by prefix. Kills the `if (false)`
  // mutant on the `route.endsWith('/')` branch and the
  // `pathname.endsWith` swap inside it — both would reject this match.
  it('matches a nested path under a trailing-slash route by prefix', () => {
    expect(matchesPublicRoute('/public/nested/page', '/public/')).toBe(true)
  })

  // A path unrelated to the route does not match.
  it('does not match an unrelated path', () => {
    expect(matchesPublicRoute('/other', '/login')).toBe(false)
  })
})

describe('routeClassifier — matchesRoutePattern', () => {
  // Exact string equality matches. Kills the `return false` boolean
  // mutant on the `pattern === pathname` fast path.
  it('matches an exact pattern by string equality', () => {
    expect(matchesRoutePattern('/dashboard', '/dashboard')).toBe(true)
  })

  // A single-segment `:placeholder` matches exactly one segment. Kills
  // the `startsWith(':')` block/condition mutants, the `<` loop-bound
  // `<=` off-by-one (which would over-run and reject the match), and
  // the final `=== `→`!==`/`false` exact-length mutants.
  it('matches a :placeholder against exactly one path segment', () => {
    expect(matchesRoutePattern('/u/abc', '/u/:id')).toBe(true)
  })

  // The :placeholder pattern must NOT match a path with an extra
  // trailing segment. Kills the final `=== `→`true` exact-length
  // mutant (which would accept any longer path).
  it('rejects a path longer than a :placeholder pattern', () => {
    expect(matchesRoutePattern('/u/abc/extra', '/u/:id')).toBe(false)
  })

  // A trailing glob absorbs zero-or-more remaining segments.
  it('matches a trailing glob against multiple remaining segments', () => {
    expect(matchesRoutePattern('/dashboard/a/b', '/dashboard/:path*')).toBe(true)
  })

  // A trailing glob also matches the bare base path (zero remaining
  // segments).
  it('matches a trailing glob against the bare base path', () => {
    expect(matchesRoutePattern('/dashboard', '/dashboard/:path*')).toBe(true)
  })

  // A literal LAST segment that differs from the path must reject the
  // match. Kills the trailing-glob mutants on line 100: the `&&`→`||`
  // logical swap, the `i===len-1`→`true` short-circuit's sibling
  // `&& (true)`, the `!== '*'` equality flip, and the `endsWith("")`
  // string mutant — every one of these wrongly marks the last literal
  // segment as a glob and returns true.
  it('rejects a path whose last literal segment differs from the pattern', () => {
    expect(matchesRoutePattern('/a/x', '/a/b')).toBe(false)
  })

  // A mid-pattern glob-shaped segment is NOT a trailing glob, so a
  // literal mismatch there rejects. Kills the `true && (...)` mutant
  // that treats every glob-shaped segment (not just the last) as a
  // trailing glob.
  it('does not treat a non-last glob-shaped segment as a trailing glob', () => {
    expect(matchesRoutePattern('/x/y', '/foo*/bar')).toBe(false)
  })

  // A path shorter than the pattern (no glob to absorb the gap) does
  // not match.
  it('rejects a path shorter than the pattern', () => {
    expect(matchesRoutePattern('/a/b', '/a/b/c')).toBe(false)
  })
})

describe('routeClassifier — normalizePath', () => {
  // Collapses `/./` and `/../` dot segments via the URL parser so they
  // cannot bypass the prefix check.
  it('normalises dot and dot-dot path segments', () => {
    expect(normalizePath('/a/./b/../c')).toBe('/a/c')
  })

  // On a URL-constructor throw the safest classification — `/` — is
  // returned. Kills the `return ''` string mutant on the catch branch.
  it('falls back to "/" (not "") when URL construction throws', () => {
    const realURL = globalThis.URL
    ;(globalThis as unknown as { URL: typeof URL }).URL = function () {
      throw new TypeError('forced')
    } as unknown as typeof URL

    try {
      expect(normalizePath('/whatever')).toBe('/')
    } finally {
      ;(globalThis as unknown as { URL: typeof URL }).URL = realURL
    }
  })
})

describe('tokenState — readTokenState', () => {
  // No access cookie → the full "absent" shape. Pins `hasCookie: false`
  // and `signatureVerified: false` on the early-return object.
  it('returns the absent shape when no access cookie is present', async () => {
    const request = makeMockRequest({ url: 'https://app.example.com/dashboard' })
    const state = await readTokenState(request as never, RESOLVED)
    expect(state).toEqual({
      token: undefined,
      hasCookie: false,
      authenticated: false,
      signatureVerified: false
    })
  })

  // An EMPTY access cookie is treated as absent. Kills the
  // `raw.length === 0`→`false` mutant, which would proceed to decode
  // an empty string and report `hasCookie: true`.
  it('treats an empty access cookie as no cookie', async () => {
    const request = makeMockRequest({
      url: 'https://app.example.com/dashboard',
      cookies: { access_token: '' }
    })
    const state = await readTokenState(request as never, RESOLVED)
    expect(state.hasCookie).toBe(false)
  })

  // Verify mode + a validly-signed, unexpired token → authenticated,
  // cookie present, and signature verified. Pins `hasCookie: true`,
  // and the `signatureVerified: hasSecret && decoded.isValid` truth
  // value (kills the `false`/`||`/`hasSecret = false` mutants).
  it('reports a signed valid token as authenticated and signature-verified', async () => {
    const token = await signHs256Token(
      { type: 'dashboard', sub: 'u', role: 'admin', exp: Math.floor(Date.now() / 1000) + 600 },
      TEST_SECRET
    )
    const request = makeMockRequest({
      url: 'https://app.example.com/dashboard',
      cookies: { access_token: token }
    })
    const state = await readTokenState(request as never, RESOLVED)
    expect(state.hasCookie).toBe(true)
    expect(state.authenticated).toBe(true)
    expect(state.signatureVerified).toBe(true)
  })

  // A perfectly-signed, unexpired token that is NOT an access token. The server signs several
  // kinds of token with one key, and `mfa_challenge` is issued to a user who has proven their
  // password and NOT their second factor — so accepting any valid signature lets that user
  // walk past every proxy-protected page by moving one cookie value into another, which is
  // exactly the state the second factor exists to stop.
  it.each([['mfa_challenge'], ['ws_ticket'], ['refresh']])(
    'refuses a validly-signed %s token as a session',
    async (type) => {
      const token = await signHs256Token(
        { type, sub: 'u', role: 'admin', exp: Math.floor(Date.now() / 1000) + 600 },
        TEST_SECRET
      )
      const request = makeMockRequest({
        url: 'https://app.example.com/dashboard',
        cookies: { access_token: token }
      })
      const state = await readTokenState(request as never, RESOLVED)
      expect(state.hasCookie).toBe(true)
      expect(state.authenticated).toBe(false)
      // The signature genuinely verified — that is the whole point of the case. Asserting it
      // is what proves the refusal is on the token's TYPE and not on a signature that happened
      // not to check out, which would make the test pass for the wrong reason.
      expect(state.signatureVerified).toBe(true)
    }
  )

  // The platform access token IS admitted, matching `rust-auth`'s proxy: an operator console
  // proxied by the same middleware presents one, and separating the two planes is the server's
  // job — its guards check the discriminant — not the edge's.
  it('admits a validly-signed platform access token', async () => {
    const token = await signHs256Token(
      { type: 'platform', sub: 'a', role: 'SUPER_ADMIN', exp: Math.floor(Date.now() / 1000) + 600 },
      TEST_SECRET
    )
    const request = makeMockRequest({
      url: 'https://app.example.com/dashboard',
      cookies: { access_token: token }
    })
    const state = await readTokenState(request as never, RESOLVED)
    expect(state.authenticated).toBe(true)
  })

  // A token with no `type` claim at all. The claim has been present since the first release,
  // so its absence means the token was not minted by this library — refuse rather than guess.
  it('refuses a validly-signed token with no type claim', async () => {
    const token = await signHs256Token(
      { sub: 'u', role: 'admin', exp: Math.floor(Date.now() / 1000) + 600 },
      TEST_SECRET
    )
    const request = makeMockRequest({
      url: 'https://app.example.com/dashboard',
      cookies: { access_token: token }
    })
    const state = await readTokenState(request as never, RESOLVED)
    expect(state.authenticated).toBe(false)
  })

  // Verify mode + a present-but-invalid token → cookie present but
  // NOT authenticated and NOT signature-verified. Kills the
  // `signatureVerified: true` mutant.
  it('reports an invalid token as not signature-verified', async () => {
    const request = makeMockRequest({
      url: 'https://app.example.com/dashboard',
      cookies: { access_token: 'not-a-jwt' }
    })
    const state = await readTokenState(request as never, RESOLVED)
    expect(state.hasCookie).toBe(true)
    expect(state.authenticated).toBe(false)
    expect(state.signatureVerified).toBe(false)
  })

  // Scenario: no secret configured, and a token an attacker minted with a secret of their own.
  // Expected: nobody is authenticated. Why: this is the whole of the decode-only hole. Parsing
  // without verifying accepted any structurally sound, unexpired token, and the result drove
  // route gating, role checks, status blocking and the x-user-* identity headers injected into
  // every server component — so `role: 'admin'` was true because the attacker wrote it.
  it.each([
    ['no secret at all', undefined],
    // An empty string is "no usable secret" and must not read as one. Verification against an
    // empty key is not a weaker check, it is no check.
    ['an empty-string secret', '']
  ])('refuses a forged token under %s', async (_label, secret) => {
    const { jwtSecret: _drop, ...rest } = DEFAULT_PROXY_CONFIG
    void _drop
    const config = {
      ...rest,
      ...(secret === undefined ? {} : { jwtSecret: secret }),
      maxRefreshAttempts: 2
    } as ResolvedAuthProxyConfig
    const forged = await signHs256Token(
      { type: 'dashboard', sub: 'u', role: 'admin', exp: Math.floor(Date.now() / 1000) + 600 },
      'an-attackers-own-secret'
    )
    const request = makeMockRequest({
      url: 'https://app.example.com/dashboard',
      cookies: { access_token: forged }
    })

    const state = await readTokenState(request as never, config)

    expect(state.authenticated).toBe(false)
    expect(state.signatureVerified).toBe(false)
    // The cookie was there; it just proved nothing. The distinction still drives the choice
    // between redirect-to-login and attempt-silent-refresh.
    expect(state.hasCookie).toBe(true)
  })

  // The counterpart: with a secret configured, a token signed with THAT secret authenticates.
  // Without this, "refuse everything" would satisfy the two cases above.
  it('authenticates a genuinely signed token when the secret is configured', async () => {
    const config = { ...DEFAULT_PROXY_CONFIG, maxRefreshAttempts: 2 } as ResolvedAuthProxyConfig
    const token = await signHs256Token(
      { type: 'dashboard', sub: 'u', role: 'admin', exp: Math.floor(Date.now() / 1000) + 600 },
      TEST_SECRET
    )
    const request = makeMockRequest({
      url: 'https://app.example.com/dashboard',
      cookies: { access_token: token }
    })

    const state = await readTokenState(request as never, config)

    expect(state.authenticated).toBe(true)
    expect(state.signatureVerified).toBe(true)
  })
})

describe('proxyUtils — buildSanitizedRequestHeaders', () => {
  // A client-spoofed BASELINE identity header (`x-user-id`) is stripped
  // even when the consumer configured DIFFERENT header names. Kills the
  // emptied baseline-deletion loop: with custom userHeaders, only the
  // baseline loop removes `x-user-id`, so emptying it would let the
  // spoofed value survive.
  it('strips a baseline identity header even with custom userHeaders names', () => {
    const config: ResolvedAuthProxyConfig = {
      ...RESOLVED,
      userHeaders: {
        userId: 'x-custom-uid',
        role: 'x-custom-role',
        tenantId: 'x-custom-tid',
        tenantDomain: 'x-custom-td'
      }
    }
    const request = makeMockRequest({
      url: 'https://app.example.com/dashboard',
      headers: { 'x-user-id': 'spoofed-admin', 'x-keep-me': 'yes' }
    })
    const sanitized = buildSanitizedRequestHeaders(request as never, config)
    expect(sanitized.has('x-user-id')).toBe(false)
    // Non-identity headers are preserved.
    expect(sanitized.get('x-keep-me')).toBe('yes')
  })

  // The consumer-configured identity header names are also stripped.
  it('strips the configured userHeaders names', () => {
    const request = makeMockRequest({
      url: 'https://app.example.com/dashboard',
      headers: { 'x-user-role': 'spoofed' }
    })
    const sanitized = buildSanitizedRequestHeaders(request as never, RESOLVED)
    expect(sanitized.has('x-user-role')).toBe(false)
  })
})

describe('proxyUtils — setOrDeleteHeader', () => {
  // An empty-string value DELETES the header rather than setting it.
  // Kills the `value.length === 0`→`false` mutant, which would set the
  // header to an empty string instead of removing it.
  it('deletes the header when the value is an empty string', () => {
    const headers = new Headers({ 'x-test': 'old' })
    setOrDeleteHeader(headers, 'x-test', '')
    expect(headers.has('x-test')).toBe(false)
  })

  // An undefined value also deletes.
  it('deletes the header when the value is undefined', () => {
    const headers = new Headers({ 'x-test': 'old' })
    setOrDeleteHeader(headers, 'x-test', undefined)
    expect(headers.has('x-test')).toBe(false)
  })

  // A non-empty value is set (after sanitisation).
  it('sets the header to the sanitised value when non-empty', () => {
    const headers = new Headers()
    setOrDeleteHeader(headers, 'x-test', 'value')
    expect(headers.get('x-test')).toBe('value')
  })
})

describe('proxyUtils — sanitizeHeaderValue', () => {
  // CR / LF / NUL bytes are removed (replaced with the EMPTY string).
  // Kills the `''`→`'Stryker was here!'` replacement mutant: the
  // injected control bytes must vanish, not be substituted with a
  // marker.
  it('strips CR, LF, and NUL bytes by removing them', () => {
    expect(sanitizeHeaderValue('a\rb\nc\0d')).toBe('abcd')
  })

  // A clean value is returned unchanged.
  it('returns a value with no control bytes unchanged', () => {
    expect(sanitizeHeaderValue('clean-value')).toBe('clean-value')
  })
})

describe('configValidation — the jwtSecret requirement', () => {
  // Scenario: a proxy is built with no usable secret. Expected: it refuses to construct, in
  // every environment. Why: without a secret nothing can distinguish a token this system issued
  // from one an attacker wrote, and the proxy's whole job is deciding who may pass. This used to
  // throw only under NODE_ENV==='production' and warn otherwise, which left preview and staging
  // accepting forged identities — and staked that distinction on one unvalidated string.
  it.each([
    ['jwtSecret is absent', undefined],
    // Empty string is "no usable secret", not a short one — it must be refused identically.
    ['jwtSecret is an empty string', '']
  ])('refuses to construct when %s', (_label, secret) => {
    const { jwtSecret: _drop, ...rest } = DEFAULT_PROXY_CONFIG
    void _drop
    const config = { ...rest, ...(secret === undefined ? {} : { jwtSecret: secret }) }

    expect(() => createAuthProxy(config)).toThrow(/jwtSecret is required/)
  })

  // The environment must not enter into it. Each of these took the old warning branch and
  // shipped a proxy that trusted forged tokens: NODE_ENV unset, a near-miss spelling, and the
  // exact string with a trailing space.
  it.each([[undefined], ['development'], ['staging'], ['prod'], ['production ']])(
    'refuses to construct with NODE_ENV=%p, exactly as in production',
    (nodeEnv) => {
      const originalNodeEnv = process.env['NODE_ENV']
      const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {})
      try {
        if (nodeEnv === undefined) delete process.env['NODE_ENV']
        else process.env['NODE_ENV'] = nodeEnv
        const { jwtSecret: _drop, ...rest } = DEFAULT_PROXY_CONFIG
        void _drop

        expect(() => createAuthProxy(rest)).toThrow(/jwtSecret is required/)
        // Not downgraded to telemetry anywhere: a warning is something a deploy can scroll past.
        expect(warnSpy).not.toHaveBeenCalled()
      } finally {
        if (originalNodeEnv === undefined) delete process.env['NODE_ENV']
        else process.env['NODE_ENV'] = originalNodeEnv
        warnSpy.mockRestore()
      }
    }
  )

  // The message must carry the whole rationale: it is the only thing the person who hit this
  // will read. A distinctive substring per concatenated line kills the per-line
  // `StringLiteral`→`""` mutants that would blank out individual sentences.
  it('throws with an Error message that includes every rationale line', () => {
    const { jwtSecret: _drop, ...rest } = DEFAULT_PROXY_CONFIG
    void _drop

    expect(() => createAuthProxy(rest)).toThrow(/jwtSecret is required/)
    expect(() => createAuthProxy(rest)).toThrow(/no JWT signature can be verified/)
    expect(() => createAuthProxy(rest)).toThrow(
      /route gating, role checks, status blocking and the identity headers injected into/
    )
    expect(() => createAuthProxy(rest)).toThrow(
      /server components would all trust unverified token contents/
    )
    expect(() => createAuthProxy(rest)).toThrow(/crafted token with a future `exp` can impersonate/)
    expect(() => createAuthProxy(rest)).toThrow(
      /supply it even when an upstream gateway also verifies signatures/
    )
  })

  // The counterpart: a configured secret constructs cleanly. Without this, "always throw" would
  // satisfy every case above.
  it('constructs when a jwtSecret is configured', () => {
    expect(() => createAuthProxy(DEFAULT_PROXY_CONFIG)).not.toThrow()
  })
})
