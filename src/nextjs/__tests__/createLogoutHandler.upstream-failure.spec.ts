/**
 * `createLogoutHandler` — what the browser is told when the upstream logout did not complete.
 *
 * A logout the server could not complete answers a 5xx and leaves the session alive, so the
 * handler keeps the cookies and answers the failure: that is the only way the client can retry
 * the same logout. An answer the server gave below 500 is final, so the cookies are cleared.
 * Kept apart from `routeHandlers.spec.ts` because that file is over the size limit.
 */

import { createLogoutHandler } from '..'
import { makeMockRequest } from './_testHelpers'

const BASE_CONFIG = {
  apiBase: 'https://api.example.com',
  cookieNames: {
    access: 'access_token',
    refresh: 'refresh_token',
    hasSession: 'has_session'
  }
} as const

type Mode = 'status' | 'redirect'

/** A handler for `mode`, so every case runs against both response modes. */
function handlerFor(mode: Mode) {
  return mode === 'redirect'
    ? createLogoutHandler({ ...BASE_CONFIG, mode: 'redirect', loginPath: '/auth/login' })
    : createLogoutHandler({ ...BASE_CONFIG, mode: 'status' })
}

/** The minimal upstream answer the handler reads: a status and no body. */
function upstreamAnswering(status: number): Response {
  return { ok: status >= 200 && status < 300, status } as unknown as Response
}

/** Every `Set-Cookie` the response carries. */
function setCookies(response: Response): string[] {
  const all: string[] = []
  response.headers.forEach((value, name) => {
    if (name.toLowerCase() === 'set-cookie') all.push(value)
  })
  return all
}

/** Runs one logout POST through `mode`'s handler. */
async function logout(mode: Mode): Promise<Response> {
  const request = makeMockRequest({
    url: 'https://app.example.com/api/auth/logout',
    method: 'POST',
    headers: { cookie: 'refresh_token=rt; access_token=at; has_session=1' }
  })
  return handlerFor(mode)(request as never)
}

describe('createLogoutHandler — an upstream logout that did not complete', () => {
  let fetchSpy: jest.SpyInstance

  beforeEach(() => {
    fetchSpy = jest.spyOn(globalThis, 'fetch' as never) as jest.SpyInstance
  })

  afterEach(() => {
    fetchSpy.mockRestore()
  })

  // Scenario: the server answers a 5xx, which it does when a revocation write failed and the
  // session is still alive. Expected: the same status comes back, no cookie is touched and
  // nothing redirects. Why: clearing the cookies would drop the only handle the client has to
  // retry the logout, leaving a live session the user believes is gone.
  it.each([
    ['status', 500],
    ['status', 503],
    ['redirect', 500],
    ['redirect', 503]
  ] as const)(
    'answers the upstream 5xx and keeps the cookies in %s mode (%i)',
    async (mode, code) => {
      fetchSpy.mockResolvedValueOnce(upstreamAnswering(code))

      const response = await logout(mode)

      expect(response.status).toBe(code)
      expect(setCookies(response)).toEqual([])
      expect(response.headers.get('location')).toBeNull()
      expect(response.headers.get('cache-control')).toBe('no-store, no-cache')
    }
  )

  // Scenario: the upstream is unreachable or times out. Expected: 502, no cookie touched, no
  // redirect. Why: the same as for a 5xx — the server never confirmed the logout.
  it.each(['status', 'redirect'] as const)(
    'answers 502 and keeps the cookies when the upstream is unreachable in %s mode',
    async (mode) => {
      fetchSpy.mockRejectedValueOnce(new Error('network down'))

      const response = await logout(mode)

      expect(response.status).toBe(502)
      expect(setCookies(response)).toEqual([])
      expect(response.headers.get('location')).toBeNull()
      expect(response.headers.get('cache-control')).toBe('no-store, no-cache')
    }
  )

  // Scenario: the server answers below 500. Expected: the three cookies are cleared. Why: a
  // 2xx completed the logout and a 4xx (an expired or already-revoked session) is a final
  // answer that a retry would only repeat.
  it.each([200, 204, 302, 400, 401, 403, 404, 429, 499])(
    'clears the cookies when the upstream answers %i',
    async (code) => {
      fetchSpy.mockResolvedValueOnce(upstreamAnswering(code))

      const response = await logout('status')

      expect(response.status).toBe(200)
      expect(setCookies(response).filter((c) => /Max-Age=0/i.test(c))).toHaveLength(3)
    }
  )

  // Scenario: the answer is below 500 in redirect mode. Expected: the redirect to the login
  // page is unchanged.
  it('redirects to the login path when the upstream answers 401 in redirect mode', async () => {
    fetchSpy.mockResolvedValueOnce(upstreamAnswering(401))

    const response = await logout('redirect')

    expect(response.headers.get('location')).toBe('/auth/login')
    expect(setCookies(response).filter((c) => /Max-Age=0/i.test(c))).toHaveLength(3)
  })

  // Scenario: a retry after the failure, once the server recovers. Expected: the second POST
  // is forwarded with the cookies the first one left in place and clears them on success.
  it('lets a retry complete the logout after an upstream failure', async () => {
    fetchSpy.mockResolvedValueOnce(upstreamAnswering(503))
    fetchSpy.mockResolvedValueOnce(upstreamAnswering(204))

    const failed = await logout('status')
    const retried = await logout('status')

    expect(failed.status).toBe(503)
    expect(setCookies(failed)).toEqual([])
    expect(retried.status).toBe(200)
    expect(setCookies(retried).filter((c) => /Max-Age=0/i.test(c))).toHaveLength(3)
    const forwarded = fetchSpy.mock.calls.map(
      (call) => ((call[1] as RequestInit).headers as Record<string, string>).cookie
    )
    expect(forwarded).toEqual([
      'refresh_token=rt; access_token=at; has_session=1',
      'refresh_token=rt; access_token=at; has_session=1'
    ])
  })
})
