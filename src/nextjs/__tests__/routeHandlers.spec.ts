/**
 * Route-handler tests for the Next.js subpath.
 *
 * Covers:
 *
 *   - `createSilentRefreshHandler`: success, upstream failure,
 *     empty-cookies response, open-redirect defence, cookie
 *     deduplication, cookie clearing on failure.
 *   - `createClientRefreshHandler`: success, upstream failure,
 *     method guard, Cache-Control on all responses.
 *   - `createLogoutHandler`: cookies cleared regardless of upstream
 *     response, redirect vs status mode, method guard.
 *   - `resolveSafeDestination`: every vector from the open-redirect
 *     defence rule set.
 *
 * The upstream `fetch` is mocked so these tests exercise the handler
 * logic without a real network. Cookies are asserted via the
 * `set-cookie` header appended to the handler's response.
 */

import {
  CLIENT_REFRESH_ROUTE,
  LOGOUT_ROUTE,
  SILENT_REFRESH_ROUTE,
  createClientRefreshHandler,
  createLogoutHandler,
  createSilentRefreshHandler,
  resolveSafeDestination
} from '..'
import { makeMockRequest } from './_testHelpers'

// A route handler's response is sent as written, so its `Location` stays RELATIVE and a
// forged `Host` has nothing to name: see `redirectToPath`. Parsing needs a base for that
// reason, and the base is a placeholder that never appears in the response.
const RELATIVE_BASE = 'https://placeholder.invalid'

/**
 * Build a stub upstream `Response` whose `headers.getSetCookie()`
 * returns exactly the array we configure. `new Response(null, { headers })`
 * does NOT reliably preserve multiple `set-cookie` values through the
 * Web `Headers` → `Response` boundary in every JS runtime, so we mock
 * the shape directly to keep the test deterministic.
 */
function stubUpstreamResponse(init: {
  status: number
  setCookies?: readonly string[]
  opaqueRedirect?: boolean
}): Response {
  return {
    ok: init.status >= 200 && init.status < 300,
    status: init.status,
    type: init.opaqueRedirect === true ? 'opaqueredirect' : 'default',
    headers: {
      get: () => null,
      getSetCookie: () => [...(init.setCookies ?? [])]
    }
  } as unknown as Response
}

const BASE_CONFIG = {
  apiBase: 'https://api.example.com',
  cookieNames: {
    access: 'access_token',
    refresh: 'refresh_token',
    hasSession: 'has_session'
  }
} as const

/** Extract all Set-Cookie header values from a Response. */
function getSetCookies(response: Response): string[] {
  const all: string[] = []
  response.headers.forEach((value, name) => {
    if (name.toLowerCase() === 'set-cookie') all.push(value)
  })
  return all
}

describe('resolveSafeDestination', () => {
  const origin = 'https://app.example.com'
  const loginPath = '/auth/login'

  // Null/empty input → loginPath. This is the common case when the
  // silent-refresh URL is invoked without a `redirect` query param.
  it('returns loginPath when the candidate is null', () => {
    expect(resolveSafeDestination(null, origin, loginPath)).toBe(loginPath)
  })

  it('returns loginPath when the candidate is empty', () => {
    expect(resolveSafeDestination('', origin, loginPath)).toBe(loginPath)
  })

  // A plain relative path is the happy case.
  it('returns a safe same-origin path unchanged', () => {
    expect(resolveSafeDestination('/dashboard', origin, loginPath)).toBe('/dashboard')
  })

  it('preserves query strings and fragments on a safe path', () => {
    expect(resolveSafeDestination('/dashboard?x=1#frag', origin, loginPath)).toBe(
      '/dashboard?x=1#frag'
    )
  })

  // Open-redirect vectors — each must fall back to loginPath. These
  // are the exact cases NEST-177's JSDoc promises to block.
  it('rejects a protocol-relative URL (//evil.com)', () => {
    expect(resolveSafeDestination('//evil.com', origin, loginPath)).toBe(loginPath)
  })

  it('rejects an absolute URL (https://evil.com)', () => {
    expect(resolveSafeDestination('https://evil.com', origin, loginPath)).toBe(loginPath)
  })

  it('rejects a path containing a backslash', () => {
    expect(resolveSafeDestination('/\\evil.com', origin, loginPath)).toBe(loginPath)
  })

  it('rejects a path containing CR/LF/NUL bytes', () => {
    expect(resolveSafeDestination('/path\rinjected', origin, loginPath)).toBe(loginPath)
    expect(resolveSafeDestination('/path\ninjected', origin, loginPath)).toBe(loginPath)
    expect(resolveSafeDestination('/path\0injected', origin, loginPath)).toBe(loginPath)
  })

  it('accepts `/` as a same-origin destination', () => {
    // `/` resolves to the same origin as expected; we keep this
    // minimal sanity check alongside the richer rejection cases
    // above.
    expect(resolveSafeDestination('/', origin, loginPath)).toBe('/')
  })

  // Falling through the `new URL()` parser with an input that throws
  // is hard to trigger because the browser URL parser is very
  // permissive, but an entire surrogate pair block or a caller that
  // monkey-patches `URL` can cause it. We exercise the catch branch
  // by swapping the global `URL` constructor for one that throws.
  it('returns loginPath when the URL parser throws', () => {
    const realURL = globalThis.URL
    ;(globalThis as unknown as { URL: typeof URL }).URL = function () {
      throw new TypeError('forced')
    } as unknown as typeof URL

    try {
      expect(resolveSafeDestination('/ok', origin, loginPath)).toBe(loginPath)
    } finally {
      ;(globalThis as unknown as { URL: typeof URL }).URL = realURL
    }
  })

  // A bare relative reference WITHOUT a leading slash resolves to the
  // same origin, so only the `startsWith('/')` guard rejects it. Drops
  // back to loginPath. Kills the `if (false)` and `startsWith("")`
  // mutants on that guard (an absolute URL would still be caught by the
  // origin check, so it cannot distinguish them).
  it('rejects a same-origin relative reference that lacks a leading slash', () => {
    expect(resolveSafeDestination('relative/path', origin, loginPath)).toBe(loginPath)
  })

  // A protocol-relative reference whose host equals the request host
  // resolves back to the SAME origin, so only the `startsWith('//')`
  // guard rejects it. This isolates that guard from the origin check
  // and kills both its `if (false)` removal and the `endsWith('//')`
  // method swap.
  it('rejects a protocol-relative reference even when its host matches the origin', () => {
    expect(resolveSafeDestination('//app.example.com/dashboard', origin, loginPath)).toBe(loginPath)
  })
})

describe('createSilentRefreshHandler', () => {
  let fetchSpy: jest.SpyInstance

  beforeEach(() => {
    fetchSpy = jest.spyOn(globalThis, 'fetch' as never) as jest.SpyInstance
  })

  // Success path: backend 2xx with cookies → redirect to destination
  // with Set-Cookie propagated (deduped).
  it('redirects to the destination with deduplicated Set-Cookie on success', async () => {
    fetchSpy.mockResolvedValueOnce(
      stubUpstreamResponse({
        status: 200,
        setCookies: [
          'access_token=new-access; Path=/; HttpOnly',
          'refresh_token=new-refresh; Path=/api/auth; HttpOnly'
        ]
      })
    )

    const handler = createSilentRefreshHandler({ ...BASE_CONFIG, loginPath: '/auth/login' })
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/silent-refresh?redirect=/dashboard'
    })

    const response = await handler(request as never)
    expect(response.status).toBe(307)
    expect(response.headers.get('location')).toContain('/dashboard')
    const cookies = getSetCookies(response)
    expect(cookies.some((c) => c.startsWith('access_token=new-access'))).toBe(true)
    expect(cookies.some((c) => c.startsWith('refresh_token=new-refresh'))).toBe(true)
  })

  // Failure path: backend 401 → redirect to loginPath?reason=expired
  // with all 3 cookies cleared (Max-Age=0).
  it('redirects to loginPath?reason=expired and clears 3 cookies on upstream 401', async () => {
    fetchSpy.mockResolvedValueOnce(stubUpstreamResponse({ status: 401 }))

    const handler = createSilentRefreshHandler({ ...BASE_CONFIG, loginPath: '/auth/login' })
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/silent-refresh?redirect=/dashboard'
    })

    const response = await handler(request as never)
    const location = new URL(response.headers.get('location') ?? '', RELATIVE_BASE)
    expect(location.pathname).toBe('/auth/login')
    expect(location.searchParams.get('reason')).toBe('expired')
    const cookies = getSetCookies(response)
    expect(cookies.filter((c) => /Max-Age=0/i.test(c))).toHaveLength(3)
  })

  // Fetch throws (network error) → same failure-path as 401: clear
  // cookies and redirect to loginPath?reason=expired.
  it('handles a fetch throw as upstream failure', async () => {
    fetchSpy.mockRejectedValueOnce(new Error('connection reset'))

    const handler = createSilentRefreshHandler({ ...BASE_CONFIG, loginPath: '/auth/login' })
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/silent-refresh?redirect=/dashboard'
    })

    const response = await handler(request as never)
    const location = new URL(response.headers.get('location') ?? '', RELATIVE_BASE)
    expect(location.searchParams.get('reason')).toBe('expired')
  })

  // 2xx with no Set-Cookie → treated as failure. Without this guard
  // the proxy would redirect back into another refresh attempt.
  it('treats a 2xx with no Set-Cookie as failure', async () => {
    fetchSpy.mockResolvedValueOnce(stubUpstreamResponse({ status: 200 }))

    const handler = createSilentRefreshHandler({ ...BASE_CONFIG, loginPath: '/auth/login' })
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/silent-refresh'
    })

    const response = await handler(request as never)
    const location = new URL(response.headers.get('location') ?? '', RELATIVE_BASE)
    expect(location.searchParams.get('reason')).toBe('expired')
  })

  // Open-redirect: external redirect target must fall back to
  // loginPath. The proxy already sanitises before reaching here; the
  // handler must ALSO defend independently.
  it('falls back to loginPath when the redirect param is an external URL', async () => {
    fetchSpy.mockResolvedValueOnce(
      stubUpstreamResponse({
        status: 200,
        setCookies: ['access_token=new; Path=/']
      })
    )

    const handler = createSilentRefreshHandler({ ...BASE_CONFIG, loginPath: '/auth/login' })
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/silent-refresh?redirect=https://evil.com/steal'
    })

    const response = await handler(request as never)
    const raw = response.headers.get('location') ?? ''
    // The `Location` names no origin at all, so an external `?redirect=` cannot survive as a
    // destination and a forged `Host` cannot substitute one — see `redirectToPath`.
    expect(raw.startsWith('/')).toBe(true)
    expect(raw.startsWith('//')).toBe(false)
    const location = new URL(raw, RELATIVE_BASE)
    expect(location.pathname).toBe('/auth/login')
  })

  // Cookie deduplication — two upstream Set-Cookies with the same
  // (name, domain) collapse to one on the forwarded response.
  it('deduplicates Set-Cookie by (name, domain) — last writer wins', async () => {
    fetchSpy.mockResolvedValueOnce(
      stubUpstreamResponse({
        status: 200,
        setCookies: [
          'access_token=first; Path=/; Domain=example.com; HttpOnly',
          'access_token=second; Path=/; Domain=example.com; HttpOnly'
        ]
      })
    )

    const handler = createSilentRefreshHandler({ ...BASE_CONFIG, loginPath: '/auth/login' })
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/silent-refresh?redirect=/dashboard'
    })

    const response = await handler(request as never)
    const accessCookies = getSetCookies(response).filter((c) => c.startsWith('access_token='))
    expect(accessCookies).toHaveLength(1)
    expect(accessCookies[0]).toContain('access_token=second')
  })

  // Factory-time validation: loginPath must be a same-origin path.
  it('throws at factory time when loginPath is protocol-relative', () => {
    expect(() => createSilentRefreshHandler({ ...BASE_CONFIG, loginPath: '//evil.com' })).toThrow(
      /loginPath/
    )
  })

  // Factory-time validation: apiBase must be absolute HTTP(S).
  it('throws at factory time when apiBase is a relative URL', () => {
    expect(() =>
      createSilentRefreshHandler({
        ...BASE_CONFIG,
        apiBase: '/relative',
        loginPath: '/auth/login'
      })
    ).toThrow(/apiBase/)
  })

  // Upstream call shape: the handler MUST POST to the refresh URL with
  // the inbound cookie forwarded, an `application/json` accept header,
  // and `redirect: 'manual'` so an upstream 3xx is never auto-followed.
  // Pins each field so emptying the fetch init/headers object or
  // blanking the method/accept literals is caught.
  it('POSTs to the upstream refresh URL forwarding cookie, accept, and redirect:manual', async () => {
    fetchSpy.mockResolvedValueOnce(
      stubUpstreamResponse({ status: 200, setCookies: ['access_token=new; Path=/'] })
    )

    const handler = createSilentRefreshHandler({ ...BASE_CONFIG, loginPath: '/auth/login' })
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/silent-refresh?redirect=/dashboard',
      headers: { cookie: 'access_token=stale; has_session=1' }
    })

    await handler(request as never)
    const [calledUrl, init] = fetchSpy.mock.calls[0] as [string, RequestInit]
    expect(calledUrl).toBe('https://api.example.com/auth/refresh')
    expect(init.method).toBe('POST')
    expect(init.redirect).toBe('manual')
    const headers = init.headers as Record<string, string>
    expect(headers.cookie).toBe('access_token=stale; has_session=1')
    expect(headers.accept).toBe('application/json')
  })

  // When the inbound request carries no cookie header the forwarded
  // `cookie` value MUST be the empty string (the `?? ''` fallback), not
  // a placeholder — kills the StringLiteral mutant on the nullish
  // coalescing default.
  it('forwards an empty cookie string when the request has no cookie header', async () => {
    fetchSpy.mockResolvedValueOnce(
      stubUpstreamResponse({ status: 200, setCookies: ['access_token=new; Path=/'] })
    )

    const handler = createSilentRefreshHandler({ ...BASE_CONFIG, loginPath: '/auth/login' })
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/silent-refresh?redirect=/dashboard'
    })

    await handler(request as never)
    const init = fetchSpy.mock.calls[0]?.[1] as RequestInit
    const headers = init.headers as Record<string, string>
    expect(headers.cookie).toBe('')
  })

  // An opaque-redirect response that is otherwise a 2xx WITH cookies
  // must still fail. The dedicated `type === 'opaqueredirect'` guard is
  // load-bearing: removing it would let `.ok` accept the redirect as a
  // success. We assert `reason=expired` (failure path) rather than a
  // success redirect to `/dashboard`.
  it('treats an opaque-redirect 2xx-with-cookies as failure (not success)', async () => {
    fetchSpy.mockResolvedValueOnce(
      stubUpstreamResponse({
        status: 200,
        opaqueRedirect: true,
        setCookies: ['access_token=new; Path=/']
      })
    )

    const handler = createSilentRefreshHandler({ ...BASE_CONFIG, loginPath: '/auth/login' })
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/silent-refresh?redirect=/dashboard'
    })

    const response = await handler(request as never)
    const location = new URL(response.headers.get('location') ?? '', RELATIVE_BASE)
    expect(location.pathname).toBe('/auth/login')
    expect(location.searchParams.get('reason')).toBe('expired')
    // Refreshed cookies must NOT be propagated on the failure path.
    const cookies = getSetCookies(response)
    expect(cookies.some((c) => c.startsWith('access_token=new'))).toBe(false)
  })

  // A non-ok response (401) that DOES carry Set-Cookie must still fail.
  // This isolates the `!upstream.ok` guard: with cookies present,
  // dropping the guard would let the success path propagate them.
  it('treats a non-ok response as failure even when it carries Set-Cookie', async () => {
    fetchSpy.mockResolvedValueOnce(
      stubUpstreamResponse({ status: 401, setCookies: ['access_token=evil; Path=/'] })
    )

    const handler = createSilentRefreshHandler({ ...BASE_CONFIG, loginPath: '/auth/login' })
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/silent-refresh?redirect=/dashboard'
    })

    const response = await handler(request as never)
    const location = new URL(response.headers.get('location') ?? '', RELATIVE_BASE)
    expect(location.searchParams.get('reason')).toBe('expired')
    const cookies = getSetCookies(response)
    // All three cleared (Max-Age=0); the upstream cookie is not forwarded.
    expect(cookies.filter((c) => /Max-Age=0/i.test(c))).toHaveLength(3)
    expect(cookies.some((c) => c.startsWith('access_token=evil'))).toBe(false)
  })

  // Success response carries `Cache-Control: no-store, no-cache` to stop
  // a CDN replaying a stale redirect with someone else's cookies.
  it('sets Cache-Control: no-store, no-cache on the success redirect', async () => {
    fetchSpy.mockResolvedValueOnce(
      stubUpstreamResponse({ status: 200, setCookies: ['access_token=new; Path=/'] })
    )

    const handler = createSilentRefreshHandler({ ...BASE_CONFIG, loginPath: '/auth/login' })
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/silent-refresh?redirect=/dashboard'
    })

    const response = await handler(request as never)
    expect(response.headers.get('cache-control')).toBe('no-store, no-cache')
  })

  // The logout/failure redirect also carries the exact Cache-Control
  // value and clears the access + hasSession cookies on path `/`. Pins
  // both the header value and the `'/'` path argument of the clears.
  it('sets Cache-Control and clears access/hasSession on path / on the failure redirect', async () => {
    fetchSpy.mockResolvedValueOnce(stubUpstreamResponse({ status: 401 }))

    const handler = createSilentRefreshHandler({ ...BASE_CONFIG, loginPath: '/auth/login' })
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/silent-refresh'
    })

    const response = await handler(request as never)
    expect(response.headers.get('cache-control')).toBe('no-store, no-cache')
    const cookies = getSetCookies(response)
    const access = cookies.find((c) => c.startsWith('access_token='))
    const hasSession = cookies.find((c) => c.startsWith('has_session='))
    expect(access).toContain('Path=/;')
    expect(hasSession).toContain('Path=/;')
    // The refresh cookie clears on its dedicated /api/auth scope.
    const refresh = cookies.find((c) => c.startsWith('refresh_token='))
    expect(refresh).toContain('Path=/api/auth;')
  })

  // Factory-time validation messages are namespaced by the factory name
  // AND name the offending field, so a developer can locate the bad
  // config key. Pins both the `createSilentRefreshHandler` context and
  // the per-field label string in each thrown message.
  it('names the factory and field in the apiBase validation error', () => {
    expect(() =>
      createSilentRefreshHandler({ ...BASE_CONFIG, apiBase: 'ftp://x', loginPath: '/auth/login' })
    ).toThrow(/createSilentRefreshHandler: apiBase/)
  })

  it('names the factory and refreshPath label when refreshPath is unsafe', () => {
    expect(() =>
      createSilentRefreshHandler({
        ...BASE_CONFIG,
        loginPath: '/auth/login',
        refreshPath: 'no-leading-slash'
      })
    ).toThrow(/createSilentRefreshHandler: refreshPath/)
  })

  it('names the factory and cookieNames.access label when the access cookie name is invalid', () => {
    expect(() =>
      createSilentRefreshHandler({
        apiBase: 'https://api.example.com',
        loginPath: '/auth/login',
        cookieNames: { access: 'bad name', refresh: 'refresh_token', hasSession: 'has_session' }
      })
    ).toThrow(/createSilentRefreshHandler:.*cookieNames\.access/)
  })

  it('names the factory and cookieNames.refresh label when the refresh cookie name is invalid', () => {
    expect(() =>
      createSilentRefreshHandler({
        apiBase: 'https://api.example.com',
        loginPath: '/auth/login',
        cookieNames: { access: 'access_token', refresh: 'bad name', hasSession: 'has_session' }
      })
    ).toThrow(/createSilentRefreshHandler:.*cookieNames\.refresh/)
  })

  it('names the factory and cookieNames.hasSession label when the hasSession cookie name is invalid', () => {
    expect(() =>
      createSilentRefreshHandler({
        apiBase: 'https://api.example.com',
        loginPath: '/auth/login',
        cookieNames: { access: 'access_token', refresh: 'refresh_token', hasSession: 'bad name' }
      })
    ).toThrow(/createSilentRefreshHandler:.*cookieNames\.hasSession/)
  })

  it('names the factory and refreshCookiePath label when the refresh cookie path is unsafe', () => {
    expect(() =>
      createSilentRefreshHandler({
        ...BASE_CONFIG,
        loginPath: '/auth/login',
        refreshCookiePath: 'no-leading-slash'
      })
    ).toThrow(/createSilentRefreshHandler:.*refreshCookiePath/)
  })
})

describe('createClientRefreshHandler', () => {
  let fetchSpy: jest.SpyInstance

  beforeEach(() => {
    fetchSpy = jest.spyOn(globalThis, 'fetch' as never) as jest.SpyInstance
  })

  // Happy path: 200 response with Set-Cookie attached.
  it('returns 200 with Set-Cookie on upstream success', async () => {
    fetchSpy.mockResolvedValueOnce(
      stubUpstreamResponse({
        status: 200,
        setCookies: ['access_token=new; Path=/; HttpOnly']
      })
    )

    const handler = createClientRefreshHandler({ apiBase: 'https://api.example.com' })
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/client-refresh',
      method: 'POST'
    })

    const response = await handler(request as never)
    expect(response.status).toBe(200)
    expect(response.headers.get('cache-control')).toMatch(/no-store/)
    const cookies = getSetCookies(response)
    expect(cookies.some((c) => c.startsWith('access_token=new'))).toBe(true)
  })

  // Failure path: 401 empty body.
  it('returns 401 with empty body on upstream 401', async () => {
    fetchSpy.mockResolvedValueOnce(stubUpstreamResponse({ status: 401 }))

    const handler = createClientRefreshHandler({ apiBase: 'https://api.example.com' })
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/client-refresh',
      method: 'POST'
    })

    const response = await handler(request as never)
    expect(response.status).toBe(401)
    expect(await response.text()).toBe('')
  })

  // 2xx with no cookies → 401 (same contract as silent-refresh). A
  // retry-with-stale-token loop is more damaging than a false-
  // negative logout.
  it('returns 401 when upstream 200 omits Set-Cookie', async () => {
    fetchSpy.mockResolvedValueOnce(stubUpstreamResponse({ status: 200 }))

    const handler = createClientRefreshHandler({ apiBase: 'https://api.example.com' })
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/client-refresh',
      method: 'POST'
    })

    const response = await handler(request as never)
    expect(response.status).toBe(401)
  })

  // Method guard: GET is rejected with 405 + Allow: POST.
  it('rejects non-POST methods with 405 Method Not Allowed', async () => {
    const handler = createClientRefreshHandler({ apiBase: 'https://api.example.com' })
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/client-refresh',
      method: 'GET'
    })

    const response = await handler(request as never)
    expect(response.status).toBe(405)
    expect(response.headers.get('allow')).toBe('POST')
  })

  // Upstream call shape: POST to the refresh URL, forward the inbound
  // cookie, send `accept: application/json`, and `redirect: 'manual'`.
  // Pins every field so emptying the init/headers object or blanking
  // the method/accept literals is caught.
  it('POSTs to the upstream refresh URL forwarding cookie, accept, and redirect:manual', async () => {
    fetchSpy.mockResolvedValueOnce(
      stubUpstreamResponse({ status: 200, setCookies: ['access_token=new; Path=/'] })
    )

    const handler = createClientRefreshHandler({ apiBase: 'https://api.example.com' })
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/client-refresh',
      method: 'POST',
      headers: { cookie: 'access_token=stale' }
    })

    await handler(request as never)
    const [calledUrl, init] = fetchSpy.mock.calls[0] as [string, RequestInit]
    expect(calledUrl).toBe('https://api.example.com/auth/refresh')
    expect(init.method).toBe('POST')
    expect(init.redirect).toBe('manual')
    const headers = init.headers as Record<string, string>
    expect(headers.cookie).toBe('access_token=stale')
    expect(headers.accept).toBe('application/json')
  })

  // No inbound cookie → forwarded `cookie` MUST be the empty string
  // (the `?? ''` fallback), not a placeholder.
  it('forwards an empty cookie string when the request has no cookie header', async () => {
    fetchSpy.mockResolvedValueOnce(
      stubUpstreamResponse({ status: 200, setCookies: ['access_token=new; Path=/'] })
    )

    const handler = createClientRefreshHandler({ apiBase: 'https://api.example.com' })
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/client-refresh',
      method: 'POST'
    })

    await handler(request as never)
    const init = fetchSpy.mock.calls[0]?.[1] as RequestInit
    const headers = init.headers as Record<string, string>
    expect(headers.cookie).toBe('')
  })

  // A non-ok response that carries Set-Cookie must still yield 401 — the
  // `!upstream.ok` arm of the failure guard must short-circuit before
  // the cookie payload is propagated. Kills the `||`→`&&`, guard
  // removal, and empty-block mutants on that condition.
  it('returns 401 on a non-ok response even when it carries Set-Cookie', async () => {
    fetchSpy.mockResolvedValueOnce(
      stubUpstreamResponse({ status: 401, setCookies: ['access_token=evil; Path=/'] })
    )

    const handler = createClientRefreshHandler({ apiBase: 'https://api.example.com' })
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/client-refresh',
      method: 'POST'
    })

    const response = await handler(request as never)
    expect(response.status).toBe(401)
    expect(getSetCookies(response).some((c) => c.startsWith('access_token=evil'))).toBe(false)
  })

  // An opaque-redirect response with ok:true and cookies must STILL be
  // 401. This isolates the `type === 'opaqueredirect'` arm of the
  // failure guard (an upstream 3xx must never be treated as a refresh
  // success even if `.ok` is true). Kills the `false || !ok` partial and
  // the `||`→`&&` mutant.
  it('returns 401 on an opaque-redirect response even with ok:true and Set-Cookie', async () => {
    fetchSpy.mockResolvedValueOnce(
      stubUpstreamResponse({
        status: 200,
        opaqueRedirect: true,
        setCookies: ['access_token=new; Path=/']
      })
    )

    const handler = createClientRefreshHandler({ apiBase: 'https://api.example.com' })
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/client-refresh',
      method: 'POST'
    })

    const response = await handler(request as never)
    expect(response.status).toBe(401)
    expect(getSetCookies(response).some((c) => c.startsWith('access_token=new'))).toBe(false)
  })

  // The 405 response carries Allow: POST AND Cache-Control:
  // no-store, no-cache. Pins the Cache-Control value on the method-guard
  // branch (a cached 405 would break legitimate POSTs after a CDN flush).
  it('sets Cache-Control: no-store, no-cache on the 405 response', async () => {
    const handler = createClientRefreshHandler({ apiBase: 'https://api.example.com' })
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/client-refresh',
      method: 'GET'
    })

    const response = await handler(request as never)
    expect(response.status).toBe(405)
    expect(response.headers.get('cache-control')).toBe('no-store, no-cache')
  })

  // Factory-time validation error is namespaced by the factory name so
  // a developer can locate the misconfigured handler.
  it('names the factory in the apiBase validation error', () => {
    expect(() => createClientRefreshHandler({ apiBase: 'ftp://x' })).toThrow(
      /createClientRefreshHandler: apiBase/
    )
  })

  // Exported canonical route constant — consumers rely on this to
  // register the route file once.
  it('exports the canonical client-refresh route constant', () => {
    expect(CLIENT_REFRESH_ROUTE).toBe('/api/auth/client-refresh')
  })
})

describe('createLogoutHandler', () => {
  let fetchSpy: jest.SpyInstance

  beforeEach(() => {
    fetchSpy = jest.spyOn(globalThis, 'fetch' as never) as jest.SpyInstance
  })

  // Redirect mode: 302 to loginPath + 3 cookies cleared regardless
  // of upstream response.
  it('clears cookies and redirects to loginPath in redirect mode on upstream success', async () => {
    fetchSpy.mockResolvedValueOnce(stubUpstreamResponse({ status: 200 }))

    const handler = createLogoutHandler({
      ...BASE_CONFIG,
      mode: 'redirect',
      loginPath: '/auth/login'
    })
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/logout',
      method: 'POST'
    })

    const response = await handler(request as never)
    const location = new URL(response.headers.get('location') ?? '', RELATIVE_BASE)
    expect(location.pathname).toBe('/auth/login')
    expect(getSetCookies(response).filter((c) => /Max-Age=0/i.test(c))).toHaveLength(3)
  })

  // Upstream failure: cookies STILL cleared. This is the one
  // guarantee logout absolutely must preserve.
  it('clears cookies even when the upstream fetch throws', async () => {
    fetchSpy.mockRejectedValueOnce(new Error('network down'))

    const handler = createLogoutHandler({
      ...BASE_CONFIG,
      mode: 'redirect',
      loginPath: '/auth/login'
    })
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/logout',
      method: 'POST'
    })

    const response = await handler(request as never)
    expect(getSetCookies(response).filter((c) => /Max-Age=0/i.test(c))).toHaveLength(3)
  })

  // Status mode: 200 empty body + cookies cleared.
  it('returns 200 with cookies cleared in status mode', async () => {
    fetchSpy.mockResolvedValueOnce(stubUpstreamResponse({ status: 200 }))

    const handler = createLogoutHandler({ ...BASE_CONFIG, mode: 'status' })
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/logout',
      method: 'POST'
    })

    const response = await handler(request as never)
    expect(response.status).toBe(200)
    expect(getSetCookies(response)).toHaveLength(3)
  })

  // Method guard.
  it('rejects non-POST methods with 405', async () => {
    const handler = createLogoutHandler({ ...BASE_CONFIG, mode: 'status' })
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/logout',
      method: 'GET'
    })

    const response = await handler(request as never)
    expect(response.status).toBe(405)
  })

  // Forwards `cookie` and `accept` to the upstream. In bearer-mode tokenDelivery
  // the access token lives in the `Authorization` header, not a cookie — without
  // forwarding it the upstream JwtAuthGuard rejects the request and the
  // access-token JTI is never added to the revocation list.
  it('forwards Authorization header to upstream when present (bearer-mode tokenDelivery)', async () => {
    fetchSpy.mockResolvedValueOnce(stubUpstreamResponse({ status: 200 }))

    const handler = createLogoutHandler({ ...BASE_CONFIG, mode: 'status' })
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/logout',
      method: 'POST',
      headers: { authorization: 'Bearer abc.def.ghi', cookie: 'access_token=ck' }
    })

    await handler(request as never)
    const fetchInit = fetchSpy.mock.calls[0]?.[1] as RequestInit | undefined
    const sentHeaders = fetchInit?.headers as Record<string, string>
    expect(sentHeaders.authorization).toBe('Bearer abc.def.ghi')
    expect(sentHeaders.cookie).toBe('access_token=ck')
  })

  // The Authorization header is OMITTED when not present on the incoming request,
  // so the upstream receives only the cookie/accept pair (cookie-mode tokenDelivery).
  it('omits Authorization header from upstream call when caller did not send one', async () => {
    fetchSpy.mockResolvedValueOnce(stubUpstreamResponse({ status: 200 }))

    const handler = createLogoutHandler({ ...BASE_CONFIG, mode: 'status' })
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/logout',
      method: 'POST',
      headers: { cookie: 'access_token=ck' }
    })

    await handler(request as never)
    const fetchInit = fetchSpy.mock.calls[0]?.[1] as RequestInit | undefined
    const sentHeaders = fetchInit?.headers as Record<string, string>
    expect(sentHeaders).not.toHaveProperty('authorization')
    expect(sentHeaders.cookie).toBe('access_token=ck')
  })

  // Upstream URL composition: apiBase + default logout path. Pins the
  // exact outbound URL so blanking the template literal, swapping the
  // `?? DEFAULT_LOGOUT_PATH` for `&&`, or emptying DEFAULT_LOGOUT_PATH
  // is caught (each would change or break the upstream target).
  it('POSTs to apiBase + /auth/logout by default', async () => {
    fetchSpy.mockResolvedValueOnce(stubUpstreamResponse({ status: 200 }))

    const handler = createLogoutHandler({ ...BASE_CONFIG, mode: 'status' })
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/logout',
      method: 'POST'
    })

    await handler(request as never)
    const [calledUrl, init] = fetchSpy.mock.calls[0] as [string, RequestInit]
    expect(calledUrl).toBe('https://api.example.com/auth/logout')
    expect(init.method).toBe('POST')
    const headers = init.headers as Record<string, string>
    expect(headers.accept).toBe('application/json')
  })

  // A custom logoutPath override is honoured verbatim — confirms the
  // `?? DEFAULT_LOGOUT_PATH` nullish coalescing keeps the provided
  // value (the `&&` mutant would discard it for the default).
  it('POSTs to a custom logoutPath when provided', async () => {
    fetchSpy.mockResolvedValueOnce(stubUpstreamResponse({ status: 200 }))

    const handler = createLogoutHandler({
      ...BASE_CONFIG,
      mode: 'status',
      logoutPath: '/auth/sign-out'
    })
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/logout',
      method: 'POST'
    })

    await handler(request as never)
    const calledUrl = fetchSpy.mock.calls[0]?.[0] as string
    expect(calledUrl).toBe('https://api.example.com/auth/sign-out')
  })

  // No inbound cookie → forwarded `cookie` MUST be the empty string
  // (the `?? ''` fallback), not a placeholder.
  it('forwards an empty cookie string when the request has no cookie header', async () => {
    fetchSpy.mockResolvedValueOnce(stubUpstreamResponse({ status: 200 }))

    const handler = createLogoutHandler({ ...BASE_CONFIG, mode: 'status' })
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/logout',
      method: 'POST'
    })

    await handler(request as never)
    const init = fetchSpy.mock.calls[0]?.[1] as RequestInit
    const headers = init.headers as Record<string, string>
    expect(headers.cookie).toBe('')
  })

  // The 405 response advertises Allow: POST AND carries
  // Cache-Control: no-store, no-cache. Pins both header values on the
  // method-guard branch.
  it('sets Allow: POST and Cache-Control on the 405 response', async () => {
    const handler = createLogoutHandler({ ...BASE_CONFIG, mode: 'status' })
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/logout',
      method: 'GET'
    })

    const response = await handler(request as never)
    expect(response.status).toBe(405)
    expect(response.headers.get('allow')).toBe('POST')
    expect(response.headers.get('cache-control')).toBe('no-store, no-cache')
  })

  // Redirect-mode response carries the exact Cache-Control value and a
  // 307 redirect to loginPath. Pins the header value and clears
  // access/hasSession on path `/`.
  it('sets Cache-Control and clears access/hasSession on path / in redirect mode', async () => {
    fetchSpy.mockResolvedValueOnce(stubUpstreamResponse({ status: 200 }))

    const handler = createLogoutHandler({
      ...BASE_CONFIG,
      mode: 'redirect',
      loginPath: '/auth/login'
    })
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/logout',
      method: 'POST'
    })

    const response = await handler(request as never)
    expect(response.headers.get('cache-control')).toBe('no-store, no-cache')
    const cookies = getSetCookies(response)
    expect(cookies.find((c) => c.startsWith('access_token='))).toContain('Path=/;')
    expect(cookies.find((c) => c.startsWith('has_session='))).toContain('Path=/;')
    expect(cookies.find((c) => c.startsWith('refresh_token='))).toContain('Path=/api/auth;')
  })

  // Status-mode response also carries the exact Cache-Control value.
  // Pins the header on the 200 branch so emptying the Response init or
  // blanking the value is caught.
  it('sets Cache-Control: no-store, no-cache on the status-mode 200', async () => {
    fetchSpy.mockResolvedValueOnce(stubUpstreamResponse({ status: 200 }))

    const handler = createLogoutHandler({ ...BASE_CONFIG, mode: 'status' })
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/logout',
      method: 'POST'
    })

    const response = await handler(request as never)
    expect(response.status).toBe(200)
    expect(response.headers.get('cache-control')).toBe('no-store, no-cache')
    const cookies = getSetCookies(response)
    expect(cookies.find((c) => c.startsWith('access_token='))).toContain('Path=/;')
    expect(cookies.find((c) => c.startsWith('has_session='))).toContain('Path=/;')
  })

  // Factory-time validation messages name both the factory and the
  // offending field. Each test triggers exactly one validation failure
  // so the per-call context/label string is the load-bearing token.
  it('names the factory in the apiBase validation error', () => {
    expect(() =>
      createLogoutHandler({ ...BASE_CONFIG, apiBase: 'ftp://x', mode: 'status' })
    ).toThrow(/createLogoutHandler: apiBase/)
  })

  it('names the factory and logoutPath label when logoutPath is unsafe', () => {
    expect(() =>
      createLogoutHandler({ ...BASE_CONFIG, mode: 'status', logoutPath: 'no-leading-slash' })
    ).toThrow(/createLogoutHandler:.*logoutPath/)
  })

  it('names the factory and cookieNames.access label when the access cookie name is invalid', () => {
    expect(() =>
      createLogoutHandler({
        apiBase: 'https://api.example.com',
        mode: 'status',
        cookieNames: { access: 'bad name', refresh: 'refresh_token', hasSession: 'has_session' }
      })
    ).toThrow(/createLogoutHandler:.*cookieNames\.access/)
  })

  it('names the factory and cookieNames.refresh label when the refresh cookie name is invalid', () => {
    expect(() =>
      createLogoutHandler({
        apiBase: 'https://api.example.com',
        mode: 'status',
        cookieNames: { access: 'access_token', refresh: 'bad name', hasSession: 'has_session' }
      })
    ).toThrow(/createLogoutHandler:.*cookieNames\.refresh/)
  })

  it('names the factory and cookieNames.hasSession label when the hasSession cookie name is invalid', () => {
    expect(() =>
      createLogoutHandler({
        apiBase: 'https://api.example.com',
        mode: 'status',
        cookieNames: { access: 'access_token', refresh: 'refresh_token', hasSession: 'bad name' }
      })
    ).toThrow(/createLogoutHandler:.*cookieNames\.hasSession/)
  })

  it('names the factory and refreshCookiePath label when the refresh cookie path is unsafe', () => {
    expect(() =>
      createLogoutHandler({ ...BASE_CONFIG, mode: 'status', refreshCookiePath: 'no-leading-slash' })
    ).toThrow(/createLogoutHandler:.*refreshCookiePath/)
  })

  // Canonical route constant.
  it('exports the canonical logout route constant', () => {
    expect(LOGOUT_ROUTE).toBe('/api/auth/logout')
  })

  // Canonical silent-refresh constant (sanity check from this suite
  // for coverage continuity).
  it('exports the canonical silent-refresh route constant', () => {
    expect(SILENT_REFRESH_ROUTE).toBe('/api/auth/silent-refresh')
  })
})

// ---------------------------------------------------------------------------
// Cross-site refusal — the three handlers as a group
// ---------------------------------------------------------------------------

/**
 * Every one of these handlers ends by writing `Set-Cookie`, so a cross-site caller does not
 * need to read the response to get something out of it. That is what made them exploitable
 * without any CORS cooperation:
 *
 *   - `POST /api/auth/logout` from an attacker's page sends no session cookie under `Lax`, so
 *     the upstream revocation is a no-op — but the handler answered with three `Max-Age=0`
 *     cookies regardless, and a form POST is a top-level navigation, so the browser applied
 *     them first-party. Any page could sign a visitor out, repeatably.
 *   - `GET /api/auth/silent-refresh` is the same shape reachable from an `<img>`: cookies
 *     withheld, upstream 401, `buildLogoutRedirect` clears all three.
 *   - `POST /api/auth/client-refresh` had a method guard written specifically against a
 *     cross-origin `<img src>` GET, which covered only the GET half.
 *
 * The refusal is keyed on `Sec-Fetch-Site`, which a page cannot forge. `Origin` cannot decide
 * it: a same-origin request sends one too, and a route handler has no configured notion of its
 * own origin — `request.nextUrl.origin` comes from `Host`.
 */
describe('cross-site callers are refused before any cookie is written', () => {
  let fetchSpy: jest.SpyInstance

  beforeEach(() => {
    fetchSpy = jest.spyOn(globalThis, 'fetch' as never) as jest.SpyInstance
  })

  afterEach(() => {
    fetchSpy.mockRestore()
  })

  const cookieNames = {
    access: 'access_token',
    refresh: 'refresh_token',
    hasSession: 'has_session'
  }

  const handlers = {
    logout: () =>
      createLogoutHandler({ apiBase: 'https://api.example.com', mode: 'status', cookieNames }),
    silentRefresh: () =>
      createSilentRefreshHandler({
        apiBase: 'https://api.example.com',
        loginPath: '/login',
        cookieNames
      }),
    clientRefresh: () => createClientRefreshHandler({ apiBase: 'https://api.example.com' })
  }

  const methodFor = { logout: 'POST', silentRefresh: 'GET', clientRefresh: 'POST' } as const

  const cases = (['logout', 'silentRefresh', 'clientRefresh'] as const).flatMap((name) =>
    (['cross-site', 'same-site'] as const).map((site) => [name, site] as const)
  )

  it.each(cases)('%s refuses a %s caller with 403 and no Set-Cookie', async (name, site) => {
    const handler = handlers[name]()
    const request = makeMockRequest({
      method: methodFor[name],
      url: 'https://app.example.com/api/auth/x',
      headers: { 'sec-fetch-site': site }
    })

    const response = await handler(request as never)

    expect(response.status).toBe(403)
    // The whole point: nothing to apply, so nothing the caller achieved.
    expect(response.headers.get('set-cookie')).toBeNull()
    // And no upstream call, so the handler is not an amplifier either.
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it.each(['same-origin', 'none'] as const)('logout still serves a %s caller', async (site) => {
    fetchSpy.mockResolvedValue(new Response(null, { status: 204 }))
    const handler = handlers.logout()
    const request = makeMockRequest({
      method: 'POST',
      url: 'https://app.example.com/api/auth/logout',
      headers: { 'sec-fetch-site': site }
    })

    const response = await handler(request as never)

    expect(response.status).toBe(200)
    expect(response.headers.get('set-cookie')).toContain('Max-Age=0')
  })

  // A browser too old to send `Sec-Fetch-Site`, or a non-browser client, is admitted — the same
  // shape the server-side `TrustedOriginGuard` admits, and for the same reason: no page can
  // make a browser omit the header, so its absence is evidence rather than an opening.
  it('logout still serves a caller that sends no Sec-Fetch-Site at all', async () => {
    fetchSpy.mockResolvedValue(new Response(null, { status: 204 }))
    const handler = handlers.logout()
    const request = makeMockRequest({
      method: 'POST',
      url: 'https://app.example.com/api/auth/logout'
    })

    const response = await handler(request as never)

    expect(response.status).toBe(200)
  })
})

// ---------------------------------------------------------------------------
// The cookie Domain is validated at construction
// ---------------------------------------------------------------------------

/**
 * `serializeClearCookie` interpolates the domain straight into a `Set-Cookie` header, and its
 * JSDoc states the same pre-condition the name and the path carry: the value must have been
 * validated at factory-construction time, because the helper performs no sanitisation of its
 * own. The field was added without that check.
 *
 * `cookieDomain` is consumer configuration rather than request input, so reaching it needs a
 * mistake in the host app rather than an attacker — but a `;` closes the `Domain` attribute and
 * appends another, and a CR/LF ends the header and starts a new one. Validating at construction
 * turns both into a startup error the developer sees immediately instead of a header the
 * browser reads.
 */
describe('cookieDomain is rejected at factory construction, not at request time', () => {
  const cookieNames = {
    access: 'access_token',
    refresh: 'refresh_token',
    hasSession: 'has_session'
  }

  // Spread rather than passed as `cookieDomain: undefined` — `exactOptionalPropertyTypes` is
  // on, so an explicit `undefined` is not the same type as an absent key, and "absent" is the
  // case the last assertion below is about.
  const factories = {
    logout: (cookieDomain?: string) =>
      createLogoutHandler({
        apiBase: 'https://api.example.com',
        mode: 'status',
        cookieNames,
        ...(cookieDomain === undefined ? {} : { cookieDomain })
      }),
    silentRefresh: (cookieDomain?: string) =>
      createSilentRefreshHandler({
        apiBase: 'https://api.example.com',
        loginPath: '/login',
        cookieNames,
        ...(cookieDomain === undefined ? {} : { cookieDomain })
      })
  }

  const cases = (['logout', 'silentRefresh'] as const).flatMap((name) =>
    (['example.com; Path=/', 'example.com\r\nSet-Cookie: a=b', 'example .com', ''] as const).map(
      (domain) => [name, domain] as const
    )
  )

  it.each(cases)('%s refuses the domain %j', (name, domain) => {
    expect(() => factories[name](domain)).toThrow(/invalid cookie domain/)
  })

  it.each(['logout', 'silentRefresh'] as const)('%s accepts a real shared-domain value', (name) => {
    expect(() => factories[name]('.example.com')).not.toThrow()
  })

  // Optional means optional: omitting it must not trip the check.
  it.each(['logout', 'silentRefresh'] as const)('%s accepts an absent domain', (name) => {
    expect(() => factories[name]()).not.toThrow()
  })
})
