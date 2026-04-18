/**
 * Shared test fixtures for the Next.js subpath test suite.
 *
 * Exposes:
 *   - {@link makeMockRequest} — fabricates a structural stand-in for
 *     `NextRequest` with configurable pathname, search params, cookies,
 *     and headers. The proxy and route handlers only read a narrow
 *     slice of `NextRequest`, so a plain object is enough to exercise
 *     every code path without pulling the full `next/server` runtime
 *     into the test harness.
 *   - {@link signHs256Token} — produces a real HS256 JWT using Web
 *     Crypto so `verifyJwtToken` accepts it. This is the only way to
 *     generate a signature that passes the HMAC check; relying on a
 *     hand-crafted token would only exercise the decode-only path.
 *   - {@link base64UrlEncode} — a small helper used by
 *     {@link signHs256Token} and by tests that need to inject malformed
 *     tokens (e.g., `alg: none`, RS256).
 *   - {@link DEFAULT_PROXY_CONFIG} — a realistic `AuthProxyConfig`
 *     with sane defaults so each test only overrides the fields it
 *     cares about.
 *
 * All fixtures are deliberately Edge-Runtime-safe (Web Crypto only)
 * because the code under test must be Edge-Runtime-safe too.
 *
 * This helper lives under `__tests__/` and is excluded from coverage
 * by the root `collectCoverageFrom` config.
 */

import type { AuthProxyConfig } from '../createAuthProxy'

/**
 * Minimal structural shape accepted by `createAuthProxy`. Matches
 * `NextRequest` closely enough that each field the proxy reads is
 * satisfied; anything unused is omitted.
 */
export interface MockRequest {
  readonly method: string
  readonly url: string
  readonly nextUrl: URL & { searchParams: URLSearchParams }
  readonly headers: Headers
  readonly cookies: {
    get(name: string): { value: string } | undefined
  }
}

/** Options accepted by {@link makeMockRequest}. */
export interface MakeMockRequestOptions {
  readonly url?: string
  readonly method?: string
  readonly cookies?: Readonly<Record<string, string>>
  readonly headers?: Readonly<Record<string, string>>
}

/**
 * Build a mock request suitable for feeding into `createAuthProxy`'s
 * returned proxy function. `new URL(url)` gives us a real `URL` which
 * exposes `pathname`, `searchParams`, and `origin` exactly as the
 * real `NextRequest.nextUrl` would.
 */
export function makeMockRequest(options: MakeMockRequestOptions = {}): MockRequest {
  const url = options.url ?? 'https://app.example.com/dashboard'
  const nextUrl = new URL(url) as URL & { searchParams: URLSearchParams }
  const headers = new Headers(options.headers)
  const cookies = options.cookies ?? {}

  return {
    method: options.method ?? 'GET',
    url,
    nextUrl,
    headers,
    cookies: {
      get(name: string): { value: string } | undefined {
        // eslint-disable-next-line security/detect-object-injection -- `name` is a cookie name from the code under test, not attacker-controlled input.
        const value = cookies[name]
        return value === undefined ? undefined : { value }
      }
    }
  }
}

/**
 * URL-safe base64-encode an ArrayBuffer or string, matching the JWT
 * base64url convention (no padding, `-`/`_` in place of `+`/`/`).
 */
export function base64UrlEncode(input: ArrayBuffer | string): string {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : new Uint8Array(input)
  let binary = ''
  for (let i = 0; i < bytes.length; i += 1) {
    // eslint-disable-next-line security/detect-object-injection -- i is a bounded numeric loop counter over a typed array we just created.
    binary += String.fromCharCode(bytes[i] ?? 0)
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/**
 * Sign a payload with HS256 using Web Crypto and return the compact
 * JWT representation. Exported so tests that exercise the real
 * verify path can generate tokens the verifier accepts.
 */
export async function signHs256Token(
  payload: Readonly<Record<string, unknown>>,
  secret: string
): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' }
  const headerSegment = base64UrlEncode(JSON.stringify(header))
  const payloadSegment = base64UrlEncode(JSON.stringify(payload))
  const signingInput = `${headerSegment}.${payloadSegment}`

  const key = await globalThis.crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )
  const signature = await globalThis.crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(signingInput)
  )
  return `${signingInput}.${base64UrlEncode(signature)}`
}

/**
 * Default proxy configuration used by the majority of test cases.
 * Individual tests override the specific fields they want to exercise.
 */
export const DEFAULT_PROXY_CONFIG: AuthProxyConfig = {
  publicRoutes: ['/', '/auth/login', '/about'],
  publicRoutesRedirectIfAuthenticated: ['/auth/login'],
  protectedRoutes: [
    { pattern: '/dashboard/:path*', allowedRoles: ['admin', 'member'] },
    { pattern: '/admin/:path*', allowedRoles: ['admin'] }
  ],
  loginPath: '/auth/login',
  getDefaultDashboard: (role) => (role === 'admin' ? '/dashboard/admin' : '/dashboard'),
  apiBase: 'https://api.example.com',
  jwtSecret: 'test-secret-must-be-long-enough',
  maxRefreshAttempts: 2,
  cookieNames: {
    access: 'access_token',
    refresh: 'refresh_token',
    hasSession: 'has_session'
  },
  userHeaders: {
    userId: 'x-user-id',
    role: 'x-user-role',
    tenantId: 'x-tenant-id',
    tenantDomain: 'x-tenant-domain'
  },
  blockedUserStatuses: ['BANNED', 'INACTIVE', 'EXPIRED']
}

/**
 * Extract the `redirect` query param from a silent-refresh URL so
 * tests can assert the proxy encoded the destination correctly.
 */
export function extractRedirectParam(silentRefreshUrl: string): string | null {
  return new URL(silentRefreshUrl).searchParams.get('redirect')
}
