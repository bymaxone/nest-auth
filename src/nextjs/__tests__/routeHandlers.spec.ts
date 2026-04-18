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
    const location = new URL(response.headers.get('location') ?? '')
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
    const location = new URL(response.headers.get('location') ?? '')
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
    const location = new URL(response.headers.get('location') ?? '')
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
    const location = new URL(response.headers.get('location') ?? '')
    expect(location.origin).toBe('https://app.example.com')
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
    const location = new URL(response.headers.get('location') ?? '')
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
