/**
 * Redirect-loop-prevention tests for `createAuthProxy`.
 *
 * These scenarios validate the anti-redirect-loop defence-in-depth
 * discovered in production on bymax-fitness-ai: the proxy must NEVER
 * issue an infinite chain of silent-refresh redirects. Two guards
 * stop the loop:
 *
 *   1. `_r` counter reaching `maxRefreshAttempts` (proxy-side cap).
 *   2. `reason=expired` query parameter set by the silent-refresh
 *      handler on its final fallback redirect.
 *
 * EITHER guard alone is NOT sufficient because `_r` is attacker-
 * controllable (a crafted `_r=0` resets the counter) and
 * `reason=expired` is set by a separate handler that could fail to
 * emit it. Both must be present.
 *
 * The tests below also cover the `_r` lifecycle: the counter rides
 * on the DESTINATION so the silent-refresh handler's redirect-back
 * preserves it; it is incremented ONCE per proxy pass; and it is
 * stripped via `NextResponse.rewrite` when the user is finally
 * authenticated on a protected route.
 */

import { NextResponse } from 'next/server'

import { createAuthProxy } from '../createAuthProxy'
import { DEFAULT_PROXY_CONFIG, extractRedirectParam, makeMockRequest } from './_testHelpers'

describe('createAuthProxy — redirect loop prevention', () => {
  describe('public route (e.g. /auth/login) with has_session cookie', () => {
    // The proxy must redirect to silent-refresh when _r is absent AND
    // has_session is present AND reason is NOT expired. The first
    // attempt counter on the destination must be 1.
    it('issues a silent-refresh redirect with _r=1 on the destination when no counter is present', async () => {
      const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
      const request = makeMockRequest({
        url: 'https://app.example.com/auth/login',
        cookies: { has_session: '1' }
      })

      const response = await proxy(request as never)

      expect(response.status).toBe(307)
      const location = response.headers.get('location')
      expect(location).not.toBeNull()
      const destination = extractRedirectParam(location ?? '')
      expect(destination).toBe('/auth/login?_r=1')
    })

    // The counter increments by exactly one on each proxy pass — this
    // guards against subtle off-by-one errors that would let _r stay
    // stuck at 1 and never reach the cap.
    it('increments _r from 1 to 2 on the second attempt', async () => {
      const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
      const request = makeMockRequest({
        url: 'https://app.example.com/auth/login?_r=1',
        cookies: { has_session: '1' }
      })

      const response = await proxy(request as never)

      expect(response.status).toBe(307)
      const destination = extractRedirectParam(response.headers.get('location') ?? '')
      expect(destination).toBe('/auth/login?_r=2')
    })

    // Guard #4: once _r reaches maxRefreshAttempts the proxy stops
    // redirecting and lets the page render. Without this guard a
    // crafted _r=0 reset would allow unbounded redirects.
    it('stops redirecting and renders the page when _r reaches maxRefreshAttempts', async () => {
      const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
      const request = makeMockRequest({
        url: 'https://app.example.com/auth/login?_r=2',
        cookies: { has_session: '1' }
      })

      const response = await proxy(request as never)

      // `NextResponse.next()` has no `location` header and a 200-ish
      // status; distinguishing it from a redirect is enough here.
      expect(response.headers.get('location')).toBeNull()
    })

    // The counter clamp means values ABOVE the cap also break the
    // loop — clamp-on-read is defence-in-depth against overflow or
    // attacker-supplied huge values.
    it('stops redirecting when _r is supplied ABOVE maxRefreshAttempts', async () => {
      const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
      const request = makeMockRequest({
        url: 'https://app.example.com/auth/login?_r=9999',
        cookies: { has_session: '1' }
      })

      const response = await proxy(request as never)

      expect(response.headers.get('location')).toBeNull()
    })

    // Guard #3: `reason=expired` alone stops the loop, independent
    // of the counter. The silent-refresh handler emits this on its
    // final fallback and the proxy MUST honour it.
    it('stops redirecting when reason=expired is set, even if _r is 0', async () => {
      const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
      const request = makeMockRequest({
        url: 'https://app.example.com/auth/login?reason=expired',
        cookies: { has_session: '1' }
      })

      const response = await proxy(request as never)

      expect(response.headers.get('location')).toBeNull()
    })

    // Combination test — both guards simultaneously. Either would
    // break the loop on its own; together they must not somehow
    // conspire to re-enable a redirect.
    it('stops redirecting when BOTH guards fire (defence-in-depth)', async () => {
      const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
      const request = makeMockRequest({
        url: 'https://app.example.com/auth/login?_r=2&reason=expired',
        cookies: { has_session: '1' }
      })

      const response = await proxy(request as never)

      expect(response.headers.get('location')).toBeNull()
    })

    // No `has_session` cookie → no refresh attempt, page renders as-is.
    // This is the base case that proves the refresh branch is gated
    // on the cookie, not just on the counter.
    it('does NOT issue a silent-refresh when the has_session cookie is absent', async () => {
      const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
      const request = makeMockRequest({
        url: 'https://app.example.com/auth/login'
      })

      const response = await proxy(request as never)

      expect(response.headers.get('location')).toBeNull()
    })

    // The destination that rides on `redirect=` must NOT carry the
    // old `_r` or `reason` values from the inbound URL — otherwise
    // attacker-controlled query params could survive the round trip
    // and re-enter the proxy, re-triggering the guards in unexpected
    // ways.
    it('strips existing _r and reason from the destination so they cannot be polluted', async () => {
      const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
      const request = makeMockRequest({
        url: 'https://app.example.com/auth/login?_r=0&reason=something&other=keep',
        cookies: { has_session: '1' }
      })

      const response = await proxy(request as never)

      const destination = extractRedirectParam(response.headers.get('location') ?? '') ?? ''
      expect(destination).toContain('other=keep')
      expect(destination).not.toContain('reason=something')
      // The counter is the incremented value, not the original 0.
      expect(destination).toMatch(/_r=1/)
    })
  })

  describe('protected route with stale token and has_session cookie', () => {
    // Mirror of the public-route counter mechanics on protected
    // routes: the same _r counter guard fires; when exhausted the
    // proxy redirects to loginPath with reason=expired so the next
    // visit to a public route instantly breaks the loop there too.
    it('stops the refresh chain and redirects to login?reason=expired when _r >= max', async () => {
      const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
      const request = makeMockRequest({
        url: 'https://app.example.com/dashboard?_r=2',
        cookies: { has_session: '1' }
      })

      const response = await proxy(request as never)

      const location = response.headers.get('location')
      expect(location).not.toBeNull()
      const url = new URL(location ?? '')
      expect(url.pathname).toBe('/auth/login')
      expect(url.searchParams.get('reason')).toBe('expired')
    })

    // reason=expired on a protected-route entry must ALSO break the
    // refresh chain immediately — same policy as the counter cap.
    it('stops the refresh chain when reason=expired is already set', async () => {
      const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
      const request = makeMockRequest({
        url: 'https://app.example.com/dashboard?reason=expired',
        cookies: { has_session: '1' }
      })

      const response = await proxy(request as never)

      const url = new URL(response.headers.get('location') ?? '')
      expect(url.pathname).toBe('/auth/login')
      expect(url.searchParams.get('reason')).toBe('expired')
    })

    // When has_session AND the counter is still under the cap, the
    // proxy attempts the silent refresh with the incremented counter
    // baked into the destination.
    it('attempts a silent refresh with counter incremented on the destination', async () => {
      const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
      const request = makeMockRequest({
        url: 'https://app.example.com/dashboard?_r=1',
        cookies: { has_session: '1' }
      })

      const response = await proxy(request as never)

      const location = response.headers.get('location')
      const silentRefreshUrl = new URL(location ?? '')
      expect(silentRefreshUrl.pathname).toBe('/api/auth/silent-refresh')
      const destination = silentRefreshUrl.searchParams.get('redirect') ?? ''
      expect(destination).toMatch(/_r=2/)
    })

    // No cookies at all → straight to login, no refresh attempt. The
    // hasCookie + has_session discriminator lives in NEST-174; this
    // test proves the protected-route handler honours it.
    it('redirects straight to login when neither access nor has_session cookies are present', async () => {
      const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
      const request = makeMockRequest({
        url: 'https://app.example.com/dashboard'
      })

      const response = await proxy(request as never)

      const url = new URL(response.headers.get('location') ?? '')
      expect(url.pathname).toBe('/auth/login')
      // No reason signal here — this is a "never logged in" case,
      // not an expiry case, so the loop-break hint is absent.
      expect(url.searchParams.get('reason')).toBeNull()
    })
  })

  describe('NextResponse import contract', () => {
    // Sanity check that the symbol from next/server is wired into
    // `createAuthProxy` — if a future refactor accidentally re-breaks
    // the dynamic import fallback, every other redirect-loop assertion
    // above would misbehave in the same way, making this a fast fail.
    it('uses NextResponse.redirect (307/308) for its redirects', async () => {
      const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
      const request = makeMockRequest({
        url: 'https://app.example.com/auth/login',
        cookies: { has_session: '1' }
      })

      const response = await proxy(request as never)
      expect(response).toBeInstanceOf(NextResponse)
      expect([307, 308]).toContain(response.status)
    })
  })
})
