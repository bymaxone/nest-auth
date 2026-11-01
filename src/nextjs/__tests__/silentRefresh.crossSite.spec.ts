/**
 * @fileoverview A cross-site (or cross-origin) caller of the silent-refresh route is redirected to
 * the login page, with no refresh attempted and no cookie written.
 */

import { createSilentRefreshHandler } from '..'
import { makeMockRequest } from './_testHelpers'

describe('createSilentRefreshHandler — a refused caller is sent to the login page', () => {
  let fetchSpy: jest.SpyInstance

  beforeEach(() => {
    fetchSpy = jest.spyOn(globalThis, 'fetch' as never) as jest.SpyInstance
  })

  afterEach(() => {
    fetchSpy.mockRestore()
  })

  const handler = createSilentRefreshHandler({
    apiBase: 'https://api.example.com',
    loginPath: '/login',
    cookieNames: { access: 'access_token', refresh: 'refresh_token', hasSession: 'has_session' }
  })

  // Scenario: a user follows a link from another site (or another origin on the same site) into
  // the app after the access token expired, so the proxy sends the browser here and the browser
  // states the navigation is not same-origin. Expected: a redirect to the login page carrying the
  // signal that breaks the proxy's loop guard, with no Set-Cookie, no upstream call and a
  // response no cache may keep. Why: a bare 403 is a dead end for a real user, while this keeps
  // the property the refusal exists for — the caller causes no refresh and no cookie write.
  it.each(['cross-site', 'same-site'] as const)(
    'redirects a %s caller to the login page and does nothing else',
    async (site) => {
      const request = makeMockRequest({
        method: 'GET',
        url: 'https://app.example.com/api/auth/silent-refresh?redirect=/dashboard',
        headers: { 'sec-fetch-site': site }
      })

      const response = await handler(request as never)

      expect(response.status).toBe(307)
      expect(response.headers.get('location')).toBe('/login?reason=expired')
      expect(response.headers.get('set-cookie')).toBeNull()
      expect(fetchSpy).not.toHaveBeenCalled()
      expect(response.headers.get('cache-control')).toBe('no-store, no-cache')
    }
  )

  // Scenario: the caller is admitted and the upstream refresh fails. Expected: a redirect to the
  // login page that clears the access, refresh and has_session cookies. Why: a failed refresh
  // must end the session in the browser, otherwise the proxy sends it straight back here.
  it('clears the three cookies when an admitted refresh fails', async () => {
    fetchSpy.mockResolvedValue(new Response(null, { status: 401 }))
    const request = makeMockRequest({
      method: 'GET',
      url: 'https://app.example.com/api/auth/silent-refresh?redirect=/dashboard',
      headers: { 'sec-fetch-site': 'same-origin' }
    })

    const response = await handler(request as never)

    expect(response.headers.get('location')).toBe('/login?reason=expired')
    expect(response.headers.get('set-cookie')).toContain('Max-Age=0')
  })
})
