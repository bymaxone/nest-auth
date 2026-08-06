/**
 * Miscellaneous coverage tests for `createAuthProxy`.
 *
 * Targets the branches that the loop and RBAC suites do not
 * naturally exercise:
 *
 *   - `validateConfig` throw paths (bad loginPath, mid-pattern
 *     wildcard, catch-all at segment 0, bad redirectPath).
 *   - `classifyRoute` branches: `/api/auth/*` passthrough,
 *     unmatched route, trailing-slash public route, `:segment`
 *     placeholder, exact match, path shorter than pattern.
 *   - `normalizePath` fallback to `/` on URL parse error.
 *   - Protected-route authorised response WITH `_r` param →
 *     `NextResponse.rewrite` cleanup branch.
 *   - Protected-route fallback: cookie present but invalid AND
 *     `has_session` missing → straight to login.
 */

import { createAuthProxy } from '../createAuthProxy'
import { DEFAULT_PROXY_CONFIG, makeMockRequest, signHs256Token } from './_testHelpers'

// The proxy's `Location` is absolute — Next re-parses the header a middleware sets and a
// relative one throws there; see `redirectToPathOnOrigin`. A base is passed anyway, and
// ignored, so these assertions read the same whichever form the value takes.
const RELATIVE_BASE = 'https://placeholder.invalid'

const TEST_SECRET = DEFAULT_PROXY_CONFIG.jwtSecret ?? 'test-secret-must-be-long-enough'

describe('createAuthProxy — validateConfig throw paths', () => {
  // Bad loginPath (//-prefixed) is rejected at factory time.
  it('throws when loginPath starts with //', () => {
    expect(() => createAuthProxy({ ...DEFAULT_PROXY_CONFIG, loginPath: '//evil.com' })).toThrow(
      /loginPath/
    )
  })

  // Empty loginPath rejected.
  it('throws when loginPath is empty', () => {
    expect(() => createAuthProxy({ ...DEFAULT_PROXY_CONFIG, loginPath: '' })).toThrow(/loginPath/)
  })

  // Non-relative loginPath rejected (no leading slash).
  it('throws when loginPath does not start with /', () => {
    expect(() => createAuthProxy({ ...DEFAULT_PROXY_CONFIG, loginPath: 'auth/login' })).toThrow(
      /loginPath/
    )
  })

  // Mid-pattern wildcard rejected — `*` must be at the tail only.
  it('throws on a mid-pattern wildcard', () => {
    expect(() =>
      createAuthProxy({
        ...DEFAULT_PROXY_CONFIG,
        protectedRoutes: [{ pattern: '/a/*/b', allowedRoles: ['admin'] }]
      })
    ).toThrow(/non-trailing position/)
  })

  // Catch-all at segment 0 rejected — would promote every route.
  it('throws on a catch-all first segment', () => {
    expect(() =>
      createAuthProxy({
        ...DEFAULT_PROXY_CONFIG,
        protectedRoutes: [{ pattern: '/:any*', allowedRoles: ['admin'] }]
      })
    ).toThrow(/catch-all wildcard/)
  })

  // redirectPath that is //evil is rejected.
  it('throws on a redirectPath that starts with //', () => {
    expect(() =>
      createAuthProxy({
        ...DEFAULT_PROXY_CONFIG,
        protectedRoutes: [
          {
            pattern: '/admin/:path*',
            allowedRoles: ['admin'],
            redirectPath: '//evil.com'
          }
        ]
      })
    ).toThrow(/redirectPath/)
  })

  // `loginPath` containing CR/LF/NUL/backslash is rejected — the
  // shared `isSafeSameOriginPath` validator is stricter than the
  // earlier `isSafeRelativePath` and blocks header-smuggling
  // characters in the configured path.
  it.each([['/auth/login\rbad'], ['/auth/login\nbad'], ['/auth/login\0bad'], ['/auth/login\\bad']])(
    'throws when loginPath contains control characters (%s)',
    (bad) => {
      expect(() => createAuthProxy({ ...DEFAULT_PROXY_CONFIG, loginPath: bad })).toThrow(
        /loginPath/
      )
    }
  )

  // Same strictness applies to `redirectPath` on protected routes.
  it('throws when redirectPath contains a CR/LF character', () => {
    expect(() =>
      createAuthProxy({
        ...DEFAULT_PROXY_CONFIG,
        protectedRoutes: [
          { pattern: '/admin/:p*', allowedRoles: ['admin'], redirectPath: '/ok\r/injected' }
        ]
      })
    ).toThrow(/redirectPath/)
  })
})

describe('createAuthProxy — the jwtSecret requirement', () => {
  // A missing secret is a hard refusal, not a logged warning. A warning is something a deploy
  // scrolls past; the proxy would then be the authorisation boundary while verifying nothing.
  it('refuses to construct when jwtSecret is absent, and does not merely warn', () => {
    const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      const { jwtSecret: _secret, ...rest } = DEFAULT_PROXY_CONFIG
      void _secret

      expect(() => createAuthProxy(rest)).toThrow(/jwtSecret is required/)
      expect(warnSpy).not.toHaveBeenCalled()
    } finally {
      warnSpy.mockRestore()
    }
  })

  // A configured secret constructs silently.
  it('constructs without complaint when jwtSecret is configured', () => {
    const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      expect(() => createAuthProxy(DEFAULT_PROXY_CONFIG)).not.toThrow()
      expect(warnSpy).not.toHaveBeenCalled()
    } finally {
      warnSpy.mockRestore()
    }
  })

  // Production with a valid jwtSecret remains accepted — the guard must not trigger
  // false positives on well-configured deployments.
  it('accepts a configured jwtSecret in production', () => {
    const originalNodeEnv = process.env['NODE_ENV']
    try {
      process.env['NODE_ENV'] = 'production'
      expect(() => createAuthProxy(DEFAULT_PROXY_CONFIG)).not.toThrow()
    } finally {
      if (originalNodeEnv === undefined) {
        delete process.env['NODE_ENV']
      } else {
        process.env['NODE_ENV'] = originalNodeEnv
      }
    }
  })
})

describe('createAuthProxy — classifier branches', () => {
  // /api/auth/* passthrough: the proxy must not touch these routes.
  it('passes /api/auth/* routes straight through without touching cookies', async () => {
    const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/silent-refresh'
    })

    const response = await proxy(request as never)
    expect(response.headers.get('location')).toBeNull()
    expect(response.status).not.toBe(401)
  })

  // /api/auth/* passthrough must short-circuit BEFORE the public/
  // silent-refresh logic runs. With a surviving `has_session` cookie
  // and no access token, the public handler would issue a
  // silent-refresh redirect — so if the `kind === 'api'` short-circuit
  // is removed (or its body emptied), this request would gain a
  // `location` header. The api branch guarantees it does NOT, even with
  // the session cookie present.
  it('short-circuits /api/auth/* without redirecting even when a has_session cookie is set', async () => {
    const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/silent-refresh',
      cookies: { has_session: '1' }
    })

    const response = await proxy(request as never)
    // No silent-refresh redirect was issued — the api short-circuit ran.
    expect(response.headers.get('location')).toBeNull()
    expect(response.status).not.toBe(307)
    expect(response.status).not.toBe(401)
  })

  // Unmatched route: treated as public (defer to app routing).
  // We use a config whose publicRoutes list contains NO entries that
  // prefix-match `/some-random-page` so the classifier returns the
  // true `unmatched` kind — otherwise the default `/` public route
  // would prefix-match and we'd hit `public` instead.
  it('treats a truly unmatched path as public (no redirect)', async () => {
    const { proxy } = createAuthProxy({
      ...DEFAULT_PROXY_CONFIG,
      publicRoutes: ['/about', '/auth/login'],
      publicRoutesRedirectIfAuthenticated: ['/auth/login']
    })
    const request = makeMockRequest({ url: 'https://app.example.com/some-random-page' })

    const response = await proxy(request as never)
    expect(response.headers.get('location')).toBeNull()
  })

  // Public route defined with a trailing slash matches by prefix.
  it('matches a public route defined with a trailing slash by prefix', async () => {
    const { proxy } = createAuthProxy({
      ...DEFAULT_PROXY_CONFIG,
      publicRoutes: ['/public/']
    })
    const request = makeMockRequest({ url: 'https://app.example.com/public/nested/page' })

    const response = await proxy(request as never)
    expect(response.headers.get('location')).toBeNull()
  })

  // `:segment` single-segment placeholder matches any ONE segment.
  it('matches a :segment placeholder for exactly one segment', async () => {
    const token = await signHs256Token(
      { type: 'dashboard', sub: 'u', role: 'admin', exp: Math.floor(Date.now() / 1000) + 600 },
      TEST_SECRET
    )
    const { proxy } = createAuthProxy({
      ...DEFAULT_PROXY_CONFIG,
      protectedRoutes: [{ pattern: '/tenants/:id/users', allowedRoles: ['admin'] }]
    })

    // Exact segment match passes through as authenticated.
    const okRequest = makeMockRequest({
      url: 'https://app.example.com/tenants/abc/users',
      cookies: { access_token: token }
    })
    const okResponse = await proxy(okRequest as never)
    expect(okResponse.headers.get('location')).toBeNull()

    // Extra trailing segment does NOT match the :segment (single-segment) pattern.
    const mismatchRequest = makeMockRequest({
      url: 'https://app.example.com/tenants/abc/users/extra',
      cookies: { access_token: token }
    })
    const mismatchResponse = await proxy(mismatchRequest as never)
    // Falls through to public — no protected redirect.
    expect(mismatchResponse.headers.get('location')).toBeNull()
  })

  // Pattern longer than the path (no trailing glob to absorb) does
  // NOT match — exercises the "path too short" branch.
  it('does not match when the path is shorter than the pattern', async () => {
    const token = await signHs256Token(
      { type: 'dashboard', sub: 'u', role: 'admin', exp: Math.floor(Date.now() / 1000) + 600 },
      TEST_SECRET
    )
    const { proxy } = createAuthProxy({
      ...DEFAULT_PROXY_CONFIG,
      protectedRoutes: [{ pattern: '/a/b/c', allowedRoles: ['admin'] }]
    })
    const request = makeMockRequest({
      url: 'https://app.example.com/a/b',
      cookies: { access_token: token }
    })

    const response = await proxy(request as never)
    // Does not match `/a/b/c` — falls to unmatched/public branch.
    expect(response.headers.get('location')).toBeNull()
  })

  // Literal non-matching segment rejects the pattern entirely.
  it('rejects a pattern whose middle segment differs from the path', async () => {
    const { proxy } = createAuthProxy({
      ...DEFAULT_PROXY_CONFIG,
      protectedRoutes: [{ pattern: '/a/x/c', allowedRoles: ['admin'] }]
    })
    const request = makeMockRequest({ url: 'https://app.example.com/a/y/c' })
    const response = await proxy(request as never)
    expect(response.headers.get('location')).toBeNull()
  })
})

describe('createAuthProxy — protected-route authorised response', () => {
  // _r in the URL on a successful request must be stripped via
  // NextResponse.rewrite so server components see a clean URL.
  it('strips the _r param via NextResponse.rewrite on a successful authorised request', async () => {
    const token = await signHs256Token(
      { type: 'dashboard', sub: 'u', role: 'admin', exp: Math.floor(Date.now() / 1000) + 600 },
      TEST_SECRET
    )
    const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
    const request = makeMockRequest({
      url: 'https://app.example.com/dashboard?_r=1&other=keep',
      cookies: { access_token: token }
    })

    const response = await proxy(request as never)
    // `NextResponse.rewrite` sets the internal `x-middleware-rewrite`
    // header to the cleaned URL — we assert the _r param has been
    // stripped from that rewrite target.
    const rewriteTarget = response.headers.get('x-middleware-rewrite') ?? ''
    expect(rewriteTarget).toContain('/dashboard')
    expect(rewriteTarget).not.toMatch(/_r=/)
    expect(rewriteTarget).toContain('other=keep')
  })
})

describe('createAuthProxy — protected fallback', () => {
  // Access cookie present but invalid AND no has_session → redirect
  // to login without an expired reason (never logged in case).
  it('redirects to login when the cookie is invalid and has_session is absent', async () => {
    const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
    const request = makeMockRequest({
      url: 'https://app.example.com/dashboard',
      cookies: { access_token: 'not-a-jwt' }
    })

    const response = await proxy(request as never)
    const url = new URL(response.headers.get('location') ?? '', RELATIVE_BASE)
    expect(url.pathname).toBe('/auth/login')
    expect(url.searchParams.get('reason')).toBeNull()
  })
})

describe('createAuthProxy — normalizePath fallback', () => {
  // `normalizePath` catches any URL-constructor throw and returns `/`.
  // Triggering this requires the URL constructor to fail; we force
  // that by monkey-patching `URL` to throw when called with the
  // placeholder base.
  it('falls back to / when URL construction throws', async () => {
    const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
    const realURL = globalThis.URL
    ;(globalThis as unknown as { URL: typeof URL }).URL = function (input: string, base?: string) {
      if (base === 'http://placeholder.invalid') {
        throw new TypeError('forced')
      }
      return base === undefined ? new realURL(input) : new realURL(input, base)
    } as unknown as typeof URL

    try {
      const request = makeMockRequest({ url: 'https://app.example.com/dashboard' })
      const response = await proxy(request as never)
      // The normaliser returned `/`, which does not match protected
      // routes and falls into the public handler — no redirect.
      expect(response.headers.get('location')).toBeNull()
    } finally {
      ;(globalThis as unknown as { URL: typeof URL }).URL = realURL
    }
  })
})

describe('createAuthProxy — branch coverage edge cases', () => {
  // Exact string match on a protected pattern (pattern === pathname
  // fast-path in matchesRoutePattern).
  it('matches a protected route by exact string equality', async () => {
    const token = await signHs256Token(
      { type: 'dashboard', sub: 'u', role: 'admin', exp: Math.floor(Date.now() / 1000) + 600 },
      TEST_SECRET
    )
    const { proxy } = createAuthProxy({
      ...DEFAULT_PROXY_CONFIG,
      protectedRoutes: [{ pattern: '/dashboard', allowedRoles: ['admin'] }]
    })
    const request = makeMockRequest({
      url: 'https://app.example.com/dashboard',
      cookies: { access_token: token }
    })

    const response = await proxy(request as never)
    // Pass-through — pattern matched exactly, role allowed.
    expect(response.headers.get('location')).toBeNull()
  })

  // `maxRefreshAttempts` omitted → default of 2 is applied.
  it('defaults maxRefreshAttempts to 2 when omitted', async () => {
    const { maxRefreshAttempts: _maxRefresh, ...partial } = DEFAULT_PROXY_CONFIG
    void _maxRefresh
    const { config } = createAuthProxy(partial)
    expect(config.maxRefreshAttempts).toBe(2)
  })

  // _r value is negative → clamped to 0. Exercises the
  // `parsed < 0 → 0` branch of readRefreshAttemptCounter.
  it('clamps a negative _r value to 0', async () => {
    const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
    const request = makeMockRequest({
      url: 'https://app.example.com/auth/login?_r=-5',
      cookies: { has_session: '1' }
    })

    const response = await proxy(request as never)
    // Negative clamped to 0; guards not fired; redirect happens with _r=1.
    const location = response.headers.get('location')
    expect(location).not.toBeNull()
    const destination = new URL(location ?? '', RELATIVE_BASE).searchParams.get('redirect') ?? ''
    expect(destination).toMatch(/_r=1/)
  })

  // _r value is non-numeric → treated as 0 (parseInt → NaN).
  it('treats a non-numeric _r as 0', async () => {
    const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
    const request = makeMockRequest({
      url: 'https://app.example.com/auth/login?_r=abc',
      cookies: { has_session: '1' }
    })

    const response = await proxy(request as never)
    const destination =
      new URL(response.headers.get('location') ?? '', RELATIVE_BASE).searchParams.get('redirect') ??
      ''
    expect(destination).toMatch(/_r=1/)
  })

  // getDefaultDashboard returning `//evil.com` → safeRelativePath
  // falls back to `/`.
  it('falls back to / when getDefaultDashboard returns a protocol-relative URL', async () => {
    const token = await signHs256Token(
      { type: 'dashboard', sub: 'u', role: 'admin', exp: Math.floor(Date.now() / 1000) + 600 },
      TEST_SECRET
    )
    const { proxy } = createAuthProxy({
      ...DEFAULT_PROXY_CONFIG,
      getDefaultDashboard: () => '//evil.com',
      publicRoutesRedirectIfAuthenticated: ['/auth/login']
    })
    const request = makeMockRequest({
      url: 'https://app.example.com/auth/login',
      cookies: { access_token: token }
    })

    const response = await proxy(request as never)
    // Redirect target should be `/` (the fallback), not evil.com. The origin it names is the
    // one that asked, which is the only one a middleware `Location` may carry — and evil.com
    // reaching it is exactly what Next would NOT normalise away.
    const raw = response.headers.get('location') ?? ''
    expect(new URL(raw).origin).toBe('https://app.example.com')
    expect(new URL(raw).pathname).toBe('/')
  })

  // getDefaultDashboard returning an empty string → falls back to `/`.
  it('falls back to / when getDefaultDashboard returns an empty string', async () => {
    const token = await signHs256Token(
      { type: 'dashboard', sub: 'u', role: 'admin', exp: Math.floor(Date.now() / 1000) + 600 },
      TEST_SECRET
    )
    const { proxy } = createAuthProxy({
      ...DEFAULT_PROXY_CONFIG,
      getDefaultDashboard: () => '',
      publicRoutesRedirectIfAuthenticated: ['/auth/login']
    })
    const request = makeMockRequest({
      url: 'https://app.example.com/auth/login',
      cookies: { access_token: token }
    })

    const response = await proxy(request as never)
    const location = new URL(response.headers.get('location') ?? '', RELATIVE_BASE)
    expect(location.pathname).toBe('/')
  })

  // getDefaultDashboard returning a non-slash-prefixed path → falls
  // back to `/`.
  it('falls back to / when getDefaultDashboard returns a path without a leading slash', async () => {
    const token = await signHs256Token(
      { type: 'dashboard', sub: 'u', role: 'admin', exp: Math.floor(Date.now() / 1000) + 600 },
      TEST_SECRET
    )
    const { proxy } = createAuthProxy({
      ...DEFAULT_PROXY_CONFIG,
      getDefaultDashboard: () => 'no-leading-slash',
      publicRoutesRedirectIfAuthenticated: ['/auth/login']
    })
    const request = makeMockRequest({
      url: 'https://app.example.com/auth/login',
      cookies: { access_token: token }
    })

    const response = await proxy(request as never)
    const location = new URL(response.headers.get('location') ?? '', RELATIVE_BASE)
    expect(location.pathname).toBe('/')
  })

  // Token without a `role` claim → role defaults to '' which fails
  // the RBAC check (empty string never in allowedRoles).
  it('rejects a valid token that has no role claim', async () => {
    const token = await signHs256Token(
      { type: 'dashboard', sub: 'u', exp: Math.floor(Date.now() / 1000) + 600 },
      TEST_SECRET
    )
    const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
    const request = makeMockRequest({
      url: 'https://app.example.com/dashboard',
      cookies: { access_token: token }
    })

    const response = await proxy(request as never)
    // No role → RBAC denies → redirect to default dashboard for
    // empty role = '/dashboard' (the else branch of getDefaultDashboard).
    const url = new URL(response.headers.get('location') ?? '', RELATIVE_BASE)
    expect(url.searchParams.get('error')).toBe('forbidden')
  })
})

describe('createAuthProxy — a forged token end to end', () => {
  // Scenario: an attacker mints their own admin token and presents it to a correctly configured
  // proxy. Expected: it does not reach /dashboard. Why: this is the whole point of verifying,
  // asserted through the proxy rather than through `readTokenState`. The claims are perfectly
  // well-formed and unexpired — only the signature is wrong, so nothing but the HMAC check can
  // tell the difference, and everything downstream (role gating, status blocking, the x-user-*
  // headers handed to server components) would otherwise treat `role: 'admin'` as fact.
  it('does not admit a token signed with an attacker-chosen secret', async () => {
    const forged = await signHs256Token(
      { type: 'dashboard', sub: 'u', role: 'admin', exp: Math.floor(Date.now() / 1000) + 600 },
      'an-attackers-own-secret'
    )
    const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
    const request = makeMockRequest({
      url: 'https://app.example.com/dashboard',
      cookies: { access_token: forged }
    })

    const response = await proxy(request as never)

    expect(response.headers.get('location')).not.toBeNull()
  })

  // The counterpart, so "redirect everything" cannot pass: the same claims, signed with the
  // secret the proxy was configured with, are admitted.
  it('admits the same claims when they are genuinely signed', async () => {
    const token = await signHs256Token(
      { type: 'dashboard', sub: 'u', role: 'admin', exp: Math.floor(Date.now() / 1000) + 600 },
      TEST_SECRET
    )
    const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
    const request = makeMockRequest({
      url: 'https://app.example.com/dashboard',
      cookies: { access_token: token }
    })

    const response = await proxy(request as never)

    expect(response.headers.get('location')).toBeNull()
  })
})
