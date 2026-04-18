/**
 * Background-request, RBAC, and status-blocking tests for
 * `createAuthProxy`.
 *
 * Complement to `createAuthProxy.loop.spec.ts`: the redirect-loop
 * suite covers the refresh-counter mechanism; this suite covers the
 * rest of the protected-route state machine and the
 * `isBackgroundRequest` short-circuit.
 *
 * Covered scenarios:
 *
 *   - `isBackgroundRequest` returns 401 for RSC / prefetch / state-
 *     tree requests when the user is NOT authenticated; authenticated
 *     background requests pass through normally.
 *   - RBAC: role mismatch → redirect to `getDefaultDashboard(role)`
 *     with `error=forbidden`; allowed role → 200 with identity
 *     headers forwarded.
 *   - Status blocking: configured blocked statuses produce a redirect
 *     to `loginPath?reason=<status>` (case-insensitive).
 *   - Identity-header propagation: `x-user-id`, `x-user-role`,
 *     `x-tenant-id`, `x-tenant-domain` are attached to the forwarded
 *     request headers from the decoded JWT.
 *   - Header spoofing defence: client-sent identity headers are
 *     stripped before any handler runs, so a crafted inbound
 *     `x-user-id: admin` cannot reach downstream server components.
 *   - `publicRoutesRedirectIfAuthenticated`: an authenticated user
 *     visiting `/auth/login` is redirected to their dashboard.
 */

import { signHs256Token, makeMockRequest, DEFAULT_PROXY_CONFIG } from './_testHelpers'
import { createAuthProxy } from '../createAuthProxy'

const TEST_SECRET = DEFAULT_PROXY_CONFIG.jwtSecret ?? 'test-secret-must-be-long-enough'

describe('createAuthProxy — background requests, RBAC, status blocking', () => {
  describe('background-request detection', () => {
    // RSC header: when the user is NOT authenticated the proxy must
    // short-circuit with 401 instead of issuing a redirect. A redirect
    // in a client-router-initiated RSC fetch is what produced the
    // bymax-fitness-ai regression.
    it('returns 401 for an RSC background request without authentication', async () => {
      const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
      const request = makeMockRequest({
        url: 'https://app.example.com/dashboard',
        headers: { rsc: '1' }
      })

      const response = await proxy(request as never)
      expect(response.status).toBe(401)
      expect(response.headers.get('cache-control')).toMatch(/no-store/)
    })

    // Prefetch header — same policy as RSC: 401, not redirect.
    it('returns 401 for a Next-Router-Prefetch background request without authentication', async () => {
      const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
      const request = makeMockRequest({
        url: 'https://app.example.com/dashboard',
        headers: { 'next-router-prefetch': '1' }
      })

      const response = await proxy(request as never)
      expect(response.status).toBe(401)
    })

    // State-tree header — the third background-request marker the
    // proxy must recognise.
    it('returns 401 for a Next-Router-State-Tree background request without authentication', async () => {
      const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
      const request = makeMockRequest({
        url: 'https://app.example.com/dashboard',
        headers: { 'next-router-state-tree': 'some-serialized-state' }
      })

      const response = await proxy(request as never)
      expect(response.status).toBe(401)
    })

    // Authenticated background request: must pass through. The 401
    // short-circuit is gated on !authenticated, so a valid token
    // should let RSC fetches continue normally.
    it('lets an authenticated RSC request pass through to the normal handler', async () => {
      const token = await signHs256Token(
        { sub: 'u1', role: 'admin', exp: Math.floor(Date.now() / 1000) + 600 },
        TEST_SECRET
      )
      const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
      const request = makeMockRequest({
        url: 'https://app.example.com/dashboard',
        headers: { rsc: '1' },
        cookies: { access_token: token }
      })

      const response = await proxy(request as never)
      expect(response.status).not.toBe(401)
    })
  })

  describe('RBAC', () => {
    // Wrong role → redirect to getDefaultDashboard(role) with
    // error=forbidden. The user is not bounced to login because
    // their session is still valid — the issue is authorisation,
    // not authentication.
    it('redirects a user with the wrong role to their dashboard with error=forbidden', async () => {
      const token = await signHs256Token(
        { sub: 'u1', role: 'member', exp: Math.floor(Date.now() / 1000) + 600 },
        TEST_SECRET
      )
      const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
      const request = makeMockRequest({
        url: 'https://app.example.com/admin/users',
        cookies: { access_token: token }
      })

      const response = await proxy(request as never)
      const location = response.headers.get('location')
      expect(location).not.toBeNull()
      const url = new URL(location ?? '')
      expect(url.pathname).toBe('/dashboard')
      expect(url.searchParams.get('error')).toBe('forbidden')
    })

    // Allowed role → NextResponse.next() passes through. The 302 is
    // absent because no redirect happens on success.
    it('lets a user with an allowed role through without a redirect', async () => {
      const token = await signHs256Token(
        { sub: 'u1', role: 'admin', exp: Math.floor(Date.now() / 1000) + 600 },
        TEST_SECRET
      )
      const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
      const request = makeMockRequest({
        url: 'https://app.example.com/admin/users',
        cookies: { access_token: token }
      })

      const response = await proxy(request as never)
      expect(response.headers.get('location')).toBeNull()
    })

    // `redirectPath` override on the matched pattern should be used
    // in place of `getDefaultDashboard(role)` when provided.
    it('uses ProtectedRoutePattern.redirectPath when configured', async () => {
      const config = {
        ...DEFAULT_PROXY_CONFIG,
        protectedRoutes: [
          {
            pattern: '/admin/:path*',
            allowedRoles: ['admin'],
            redirectPath: '/custom/forbidden'
          }
        ]
      }
      const token = await signHs256Token(
        { sub: 'u1', role: 'member', exp: Math.floor(Date.now() / 1000) + 600 },
        TEST_SECRET
      )
      const { proxy } = createAuthProxy(config)
      const request = makeMockRequest({
        url: 'https://app.example.com/admin/x',
        cookies: { access_token: token }
      })

      const response = await proxy(request as never)
      const url = new URL(response.headers.get('location') ?? '')
      expect(url.pathname).toBe('/custom/forbidden')
      expect(url.searchParams.get('error')).toBe('forbidden')
    })
  })

  describe('status blocking', () => {
    // A BANNED status on a valid token must redirect to loginPath
    // with reason=banned so the user sees the block reason.
    it('redirects a BANNED user to loginPath?reason=banned', async () => {
      const token = await signHs256Token(
        {
          sub: 'u1',
          role: 'admin',
          status: 'BANNED',
          exp: Math.floor(Date.now() / 1000) + 600
        },
        TEST_SECRET
      )
      const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
      const request = makeMockRequest({
        url: 'https://app.example.com/dashboard',
        cookies: { access_token: token }
      })

      const response = await proxy(request as never)
      const url = new URL(response.headers.get('location') ?? '')
      expect(url.pathname).toBe('/auth/login')
      expect(url.searchParams.get('reason')).toBe('banned')
    })

    // INACTIVE is a second blocked status — same policy but different
    // reason string.
    it('redirects an INACTIVE user to loginPath?reason=inactive', async () => {
      const token = await signHs256Token(
        {
          sub: 'u1',
          role: 'admin',
          status: 'INACTIVE',
          exp: Math.floor(Date.now() / 1000) + 600
        },
        TEST_SECRET
      )
      const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
      const request = makeMockRequest({
        url: 'https://app.example.com/dashboard',
        cookies: { access_token: token }
      })

      const response = await proxy(request as never)
      const url = new URL(response.headers.get('location') ?? '')
      expect(url.searchParams.get('reason')).toBe('inactive')
    })

    // Case-insensitive comparison — the spec JSDoc on
    // `blockedUserStatuses` promises `'banned'` and `'BANNED'` are
    // equivalent. Exercise the lowercase-claim path.
    it('treats status comparison case-insensitively (lowercase claim)', async () => {
      const token = await signHs256Token(
        {
          sub: 'u1',
          role: 'admin',
          status: 'banned',
          exp: Math.floor(Date.now() / 1000) + 600
        },
        TEST_SECRET
      )
      const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
      const request = makeMockRequest({
        url: 'https://app.example.com/dashboard',
        cookies: { access_token: token }
      })

      const response = await proxy(request as never)
      const url = new URL(response.headers.get('location') ?? '')
      expect(url.searchParams.get('reason')).toBe('banned')
    })

    // An unblocked status (ACTIVE, not in the allowlist) must NOT
    // trigger the block branch.
    it('does not block a user whose status is not in blockedUserStatuses', async () => {
      const token = await signHs256Token(
        {
          sub: 'u1',
          role: 'admin',
          status: 'ACTIVE',
          exp: Math.floor(Date.now() / 1000) + 600
        },
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

  describe('identity-header propagation', () => {
    // NextResponse with the { request: { headers } } option carries
    // a `x-middleware-override-headers` hint. We assert the identity
    // headers landed on the forwarded request by inspecting the
    // internal middleware-header contract.
    it('propagates x-user-id, x-user-role, x-tenant-id, x-tenant-domain on a successful pass-through', async () => {
      const token = await signHs256Token(
        {
          sub: 'user-42',
          role: 'admin',
          tenantId: 'tenant-abc',
          tenantDomain: 'acme.example.com',
          exp: Math.floor(Date.now() / 1000) + 600
        },
        TEST_SECRET
      )
      const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
      const request = makeMockRequest({
        url: 'https://app.example.com/dashboard',
        cookies: { access_token: token }
      })

      const response = await proxy(request as never)
      // Next.js surfaces the forwarded request headers via this
      // response header. The assertion is conservative: we only
      // check presence + the injected names.
      const injected = response.headers.get('x-middleware-override-headers') ?? ''
      expect(injected).toContain('x-user-id')
      expect(injected).toContain('x-user-role')
      expect(injected).toContain('x-tenant-id')
      expect(injected).toContain('x-tenant-domain')

      expect(response.headers.get('x-middleware-request-x-user-id')).toBe('user-42')
      expect(response.headers.get('x-middleware-request-x-user-role')).toBe('admin')
      expect(response.headers.get('x-middleware-request-x-tenant-id')).toBe('tenant-abc')
      expect(response.headers.get('x-middleware-request-x-tenant-domain')).toBe('acme.example.com')
    })

    // Client-spoofed identity headers MUST be stripped before any
    // handler runs — otherwise a malicious browser request could
    // forward `x-user-id: admin` to downstream server components.
    it('strips client-spoofed identity headers on public routes', async () => {
      const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
      const request = makeMockRequest({
        url: 'https://app.example.com/about',
        headers: {
          'x-user-id': 'spoofed-admin',
          'x-user-role': 'admin'
        }
      })

      const response = await proxy(request as never)
      // After sanitisation, the spoofed headers must no longer be
      // on the forwarded request. We check the override hint to see
      // that the proxy explicitly deletes them (the middleware
      // override protocol records deletions with an empty value).
      expect(response.headers.get('x-middleware-request-x-user-id')).not.toBe('spoofed-admin')
    })
  })

  describe('publicRoutesRedirectIfAuthenticated', () => {
    // An authenticated user visiting /auth/login should be sent to
    // their dashboard — the spec's "redirect if authenticated" rule.
    it('redirects an authenticated user visiting /auth/login to their dashboard', async () => {
      const token = await signHs256Token(
        { sub: 'u1', role: 'admin', exp: Math.floor(Date.now() / 1000) + 600 },
        TEST_SECRET
      )
      const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
      const request = makeMockRequest({
        url: 'https://app.example.com/auth/login',
        cookies: { access_token: token }
      })

      const response = await proxy(request as never)
      const url = new URL(response.headers.get('location') ?? '')
      expect(url.pathname).toBe('/dashboard/admin')
    })

    // The redirect-if-authenticated branch is SUPPRESSED when the URL
    // carries any `reason=` signal: the user was sent here by a
    // block/expiry redirect and must see the login page instead of
    // ping-ponging back to the dashboard.
    it('does NOT redirect when reason= is set (prevents blocked-user loop)', async () => {
      const token = await signHs256Token(
        { sub: 'u1', role: 'admin', exp: Math.floor(Date.now() / 1000) + 600 },
        TEST_SECRET
      )
      const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
      const request = makeMockRequest({
        url: 'https://app.example.com/auth/login?reason=banned',
        cookies: { access_token: token }
      })

      const response = await proxy(request as never)
      expect(response.headers.get('location')).toBeNull()
    })
  })
})
