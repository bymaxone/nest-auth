/**
 * Pins what a `'/'` entry means in the proxy's route lists.
 *
 * A route string that ends in `/` matches by PREFIX, so `'/'` matches every path, not only the
 * root. That is harmless in `publicRoutes` — protected patterns are tried first, and a path no
 * list names is already treated as public — and it is the opposite in
 * `publicRoutesRedirectIfAuthenticated`, where it sends a signed-in user off every page that is
 * not protected. The documentation tells a host which of the two it is writing; these cases are
 * what keeps that statement true.
 */

import { createAuthProxy } from '../createAuthProxy'
import type { ResolvedAuthProxyConfig } from '../createAuthProxy'
import { classifyRoute, matchesPublicRoute } from '../internal/routeClassifier'
import { DEFAULT_PROXY_CONFIG, makeMockRequest, signHs256Token } from './_testHelpers'

const RELATIVE_BASE = 'https://placeholder.invalid'
const TEST_SECRET = DEFAULT_PROXY_CONFIG.jwtSecret ?? 'test-secret-must-be-long-enough'

describe("a '/' entry in the proxy route lists", () => {
  describe('the matcher', () => {
    // Scenario: '/' as the configured route. Expected: it matches any pathname. Why: a route
    // ending in '/' is a prefix, and every path starts with '/'.
    it.each(['/', '/dashboard', '/pricing', '/a/b/c'])('matches %s as a prefix', (pathname) => {
      expect(matchesPublicRoute(pathname, '/')).toBe(true)
    })

    // Scenario: a route written with a wildcard. Expected: no match. Why: public routes take no
    // wildcards, so '/auth/*' names a directory that does not exist; '/auth' is the form that
    // covers '/auth/login'.
    it('does not give a public route a wildcard, and matches the bare segment instead', () => {
      expect(matchesPublicRoute('/auth/login', '/auth/*')).toBe(false)
      expect(matchesPublicRoute('/auth/login', '/auth')).toBe(true)
    })
  })

  describe('in publicRoutes', () => {
    const config = {
      ...DEFAULT_PROXY_CONFIG,
      publicRoutes: ['/']
    } as ResolvedAuthProxyConfig

    // Scenario: '/' is public and a protected pattern covers /dashboard. Expected: /dashboard is
    // still classified protected. Why: protected patterns are tried before the public list.
    it('never classifies a protected route as public', () => {
      expect(classifyRoute('/dashboard', config).kind).toBe('protected')
      expect(classifyRoute('/admin/users', config).kind).toBe('protected')
      expect(classifyRoute('/pricing', config).kind).toBe('public')
    })

    // Scenario: the same configuration, an anonymous request to a protected page. Expected: the
    // login redirect, not a pass-through. Why: the observable guarantee behind the classification.
    it('still sends an anonymous request for a protected route to the login page', async () => {
      const { proxy } = createAuthProxy(config)
      const response = await proxy(
        makeMockRequest({ url: 'https://app.example.com/dashboard' }) as never
      )

      const location = new URL(response.headers.get('location') ?? '', RELATIVE_BASE)
      expect(location.pathname).toBe('/auth/login')
    })
  })

  describe('in publicRoutesRedirectIfAuthenticated', () => {
    // Scenario: '/' in the redirect list. Expected: a signed-in user is sent to their dashboard
    // from a public page that is not the root. Why: the entry matches every path, which is the
    // reason the documentation tells a host not to write it.
    it('sends a signed-in user away from every unprotected page', async () => {
      const token = await signHs256Token(
        { type: 'dashboard', sub: 'u1', role: 'member', exp: Math.floor(Date.now() / 1000) + 600 },
        TEST_SECRET
      )
      const { proxy } = createAuthProxy({
        ...DEFAULT_PROXY_CONFIG,
        publicRoutes: ['/'],
        publicRoutesRedirectIfAuthenticated: ['/']
      })

      const response = await proxy(
        makeMockRequest({
          url: 'https://app.example.com/pricing',
          cookies: { access_token: token }
        }) as never
      )

      const location = new URL(response.headers.get('location') ?? '', RELATIVE_BASE)
      expect(location.pathname).toBe('/dashboard')
    })
  })
})
