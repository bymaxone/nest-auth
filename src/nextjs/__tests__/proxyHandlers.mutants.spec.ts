/**
 * Targeted mutation-killing tests for `internal/proxyHandlers.ts`
 * driven through the assembled `createAuthProxy` (the natural call
 * site for these handlers).
 *
 * Each test pins a branch or value the broader suites leave
 * ambiguous:
 *
 *   - Forwarding of the sanitised request headers on every
 *     `NextResponse.next(...)` exit (the `ObjectLiteral` mutants that
 *     would drop `{ request: { headers } }`).
 *   - `publicRoutesRedirectIfAuthenticated.some(...)` vs `.every(...)`.
 *   - The empty-role default fed to `getDefaultDashboard`.
 *   - The `has_session` cookie non-empty check on public AND protected
 *     routes.
 *   - The `!hasCookie && !hasSession` straight-to-login guard.
 *   - The empty-`status` skip guard.
 *   - The `_r`-strip fast path on the authorised response.
 *
 * A forwarded request header surfaces through Next's middleware
 * contract as `x-middleware-request-<name>` and is listed in
 * `x-middleware-override-headers`; we assert on those to prove the
 * sanitised header set rode along.
 */

import { createAuthProxy } from '../createAuthProxy'
import { DEFAULT_PROXY_CONFIG, makeMockRequest, signHs256Token } from './_testHelpers'

// The proxy emits a RELATIVE `Location` so a forged `Host` cannot redirect anywhere: see
// `redirectToPath`. Parsing needs a base for that reason, and the base is a placeholder that
// never appears in the response.
const RELATIVE_BASE = 'https://placeholder.invalid'

const TEST_SECRET = DEFAULT_PROXY_CONFIG.jwtSecret ?? 'test-secret-must-be-long-enough'

/** Future-dated `exp` (seconds) for tokens that must be valid. */
function futureExp(): number {
  return Math.floor(Date.now() / 1000) + 600
}

describe('createAuthProxy — sanitised-header forwarding on next() exits', () => {
  // Public/unmatched, unauthenticated, no has_session → renders the
  // page forwarding the sanitised headers. Kills the `ObjectLiteral`
  // mutants on the "no session cookie" return (line 86): a benign
  // inbound header must survive on the forwarded request.
  it('forwards sanitised request headers when rendering an unauthenticated public page', async () => {
    const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
    const request = makeMockRequest({
      url: 'https://app.example.com/about',
      headers: { 'x-keep-me': 'yes' }
    })

    const response = await proxy(request as never)
    expect(response.headers.get('location')).toBeNull()
    expect(response.headers.get('x-middleware-request-x-keep-me')).toBe('yes')
    expect(response.headers.get('x-middleware-override-headers')).toContain('x-keep-me')
  })

  // Public, unauthenticated, has_session present but the refresh
  // counter is already maxed → renders the page (loop-break) forwarding
  // sanitised headers. Kills the `ObjectLiteral` mutants on the
  // counter/reason break return (line 68).
  it('forwards sanitised request headers on the counter-break public render', async () => {
    const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
    const request = makeMockRequest({
      url: 'https://app.example.com/auth/login?_r=2',
      cookies: { has_session: '1' },
      headers: { 'x-keep-me': 'yes' }
    })

    const response = await proxy(request as never)
    expect(response.headers.get('location')).toBeNull()
    expect(response.headers.get('x-middleware-request-x-keep-me')).toBe('yes')
  })

  // Authenticated user on a public route that is NOT in
  // publicRoutesRedirectIfAuthenticated → passes through forwarding
  // sanitised headers (no dashboard redirect). Kills the
  // `ObjectLiteral` mutants on the authenticated-on-public return
  // (line 117) and confirms `.some(...)` returns false for `/about`.
  it('forwards sanitised request headers for an authenticated user on a non-redirect public route', async () => {
    const token = await signHs256Token(
      { type: 'dashboard', sub: 'u', role: 'admin', exp: futureExp() },
      TEST_SECRET
    )
    const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
    const request = makeMockRequest({
      url: 'https://app.example.com/about',
      cookies: { access_token: token },
      headers: { 'x-keep-me': 'yes' }
    })

    const response = await proxy(request as never)
    expect(response.headers.get('location')).toBeNull()
    expect(response.headers.get('x-middleware-request-x-keep-me')).toBe('yes')
  })
})

describe('createAuthProxy — publicRoutesRedirectIfAuthenticated matching', () => {
  // With MULTIPLE redirect-if-authenticated routes where the current
  // path matches ONE but not ALL, an authenticated user must still be
  // redirected to their dashboard. Kills the `.some(...)`→`.every(...)`
  // mutant, which would require the path to match every entry.
  it('redirects via .some when only one configured route matches', async () => {
    const token = await signHs256Token(
      { type: 'dashboard', sub: 'u', role: 'admin', exp: futureExp() },
      TEST_SECRET
    )
    const { proxy } = createAuthProxy({
      ...DEFAULT_PROXY_CONFIG,
      publicRoutes: ['/', '/auth/login', '/about'],
      publicRoutesRedirectIfAuthenticated: ['/auth/login', '/zzz-never-matches']
    })
    const request = makeMockRequest({
      url: 'https://app.example.com/auth/login',
      cookies: { access_token: token }
    })

    const response = await proxy(request as never)
    const url = new URL(response.headers.get('location') ?? '', RELATIVE_BASE)
    expect(url.pathname).toBe('/dashboard/admin')
  })
})

describe('createAuthProxy — empty-role default', () => {
  // A valid token with NO role claim resolves role to '' (the empty
  // string), which is fed to getDefaultDashboard. Kills the
  // `?? ''`→`?? 'Stryker was here!'` mutant: the dashboard function
  // must receive the empty string, routing to the empty-role branch.
  it('feeds an empty-string role to getDefaultDashboard on the RBAC-denied fallback', async () => {
    const token = await signHs256Token(
      { type: 'dashboard', sub: 'u', exp: futureExp() },
      TEST_SECRET
    )
    const { proxy } = createAuthProxy({
      ...DEFAULT_PROXY_CONFIG,
      protectedRoutes: [{ pattern: '/dashboard/:path*', allowedRoles: ['admin'] }],
      getDefaultDashboard: (role) => (role.length === 0 ? '/empty-role' : '/has-role')
    })
    const request = makeMockRequest({
      url: 'https://app.example.com/dashboard',
      cookies: { access_token: token }
    })

    const response = await proxy(request as never)
    const url = new URL(response.headers.get('location') ?? '', RELATIVE_BASE)
    expect(url.pathname).toBe('/empty-role')
    expect(url.searchParams.get('error')).toBe('forbidden')
  })
})

describe('createAuthProxy — has_session non-empty check', () => {
  // PUBLIC route, unauthenticated, has_session present but EMPTY → no
  // silent-refresh redirect; the page renders. Kills the `&& true` and
  // `>= 0` mutants on the public-route `hasSession` check (line 62),
  // which would treat an empty cookie as a live session and redirect.
  it('does not silent-refresh on a public route when has_session is empty', async () => {
    const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
    const request = makeMockRequest({
      url: 'https://app.example.com/auth/login',
      cookies: { has_session: '' }
    })

    const response = await proxy(request as never)
    expect(response.headers.get('location')).toBeNull()
  })

  // PROTECTED route, invalid token, has_session present but EMPTY →
  // straight to login (no silent-refresh). Kills the `&& true` and
  // `>= 0` mutants on the protected-route `hasSession` check (line
  // 195), which would route to /api/auth/silent-refresh instead.
  it('redirects to login (not silent-refresh) on a protected route when has_session is empty', async () => {
    const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
    const request = makeMockRequest({
      url: 'https://app.example.com/dashboard',
      cookies: { access_token: 'not-a-jwt', has_session: '' }
    })

    const response = await proxy(request as never)
    const url = new URL(response.headers.get('location') ?? '', RELATIVE_BASE)
    expect(url.pathname).toBe('/auth/login')
  })
})

describe('createAuthProxy — straight-to-login guard', () => {
  // No access cookie AND no has_session, with the refresh counter
  // already maxed. The `!hasCookie && !hasSession` guard fires FIRST,
  // so the redirect carries NO reason (this is a "never logged in"
  // case, not an expiry). Kills the `if (false)`, the `hasCookie`
  // boolean flip, and the emptied-block mutants on that guard — each
  // would instead fall through to the counter break and attach
  // reason=expired.
  it('redirects to login WITHOUT reason when neither cookie is present even at the counter cap', async () => {
    const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
    const request = makeMockRequest({
      url: 'https://app.example.com/dashboard?_r=2'
    })

    const response = await proxy(request as never)
    const url = new URL(response.headers.get('location') ?? '', RELATIVE_BASE)
    expect(url.pathname).toBe('/auth/login')
    expect(url.searchParams.get('reason')).toBeNull()
  })
})

describe('createAuthProxy — empty-status skip guard', () => {
  // An empty-string `status` claim must NOT enter the status-blocking
  // branch, even when an (unusual) empty entry is configured in
  // blockedUserStatuses. Kills the `&& true` / `>= 0` mutants on
  // `status.length > 0`: entering the block would match the empty
  // configured status and wrongly redirect an otherwise-authorised
  // admin to the login page.
  it('does not block an authorised user whose status claim is the empty string', async () => {
    const token = await signHs256Token(
      { type: 'dashboard', sub: 'u', role: 'admin', status: '', exp: futureExp() },
      TEST_SECRET
    )
    const { proxy } = createAuthProxy({ ...DEFAULT_PROXY_CONFIG, blockedUserStatuses: [''] })
    const request = makeMockRequest({
      url: 'https://app.example.com/dashboard',
      cookies: { access_token: token }
    })

    const response = await proxy(request as never)
    expect(response.headers.get('location')).toBeNull()
  })
})

describe('createAuthProxy — authorised response _r fast path', () => {
  // An authorised request WITHOUT `_r` takes the fast path and returns
  // `NextResponse.next` — NOT a rewrite. Kills the `if (false)` and
  // emptied-block mutants on the `!searchParams.has('_r')` guard, which
  // would force the rewrite path and emit an `x-middleware-rewrite`
  // header even when there is nothing to strip.
  it('does not rewrite when there is no _r param to strip', async () => {
    const token = await signHs256Token(
      { type: 'dashboard', sub: 'u', role: 'admin', exp: futureExp() },
      TEST_SECRET
    )
    const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
    const request = makeMockRequest({
      url: 'https://app.example.com/dashboard',
      cookies: { access_token: token }
    })

    const response = await proxy(request as never)
    expect(response.headers.get('location')).toBeNull()
    expect(response.headers.get('x-middleware-rewrite')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Relative Location — the Host header cannot pick the redirect target
// ---------------------------------------------------------------------------

describe('createAuthProxy — redirects name no origin', () => {
  // Every redirect this proxy issues targets a path on its own app, and the path is validated
  // as same-origin before it is used. The ORIGIN was supplied by `request.nextUrl.origin`,
  // which Next derives from the `Host` header — so a self-hosted deployment answering on any
  // host handed an attacker who controls that header a `Location: https://attacker/login`.
  // The path validation could not see it: the path was fine, the origin was never checked.
  // A relative `Location` (RFC 7231 §7.1.2) removes the question — the browser resolves it
  // against the URL it actually requested, not against a header.
  it('emits a relative Location when redirecting an unauthenticated protected route', async () => {
    const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
    const request = makeMockRequest({ url: 'https://attacker.example/dashboard' })

    const response = await proxy(request as never)
    const location = response.headers.get('location') ?? ''

    // Relative, and NOT protocol-relative: `//attacker.example/x` is an absolute URL to a
    // browser, so a leading `//` would reintroduce exactly what this removes.
    expect(location.startsWith('/')).toBe(true)
    expect(location.startsWith('//')).toBe(false)
    expect(location).not.toContain('attacker.example')
  })
})
