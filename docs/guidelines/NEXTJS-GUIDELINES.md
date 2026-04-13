# Next.js 16 Guidelines — @bymax-one/nest-auth

> **Audience:** AI agents and developers working on this codebase.
> **Stack:** Next.js 16+, App Router, React 19, TypeScript
> **Rule:** Follow these guidelines for all Next.js code in this project.

---

## Table of Contents

1. [Next.js 16 Architecture](#1-nextjs-16-architecture)
2. [Route Handlers](#2-route-handlers)
3. [Auth Proxy Pattern](#3-auth-proxy-pattern)
4. [Cookie Management](#4-cookie-management)
5. [JWT Helpers for Server Side](#5-jwt-helpers-for-server-side)
6. [Silent Refresh Flow](#6-silent-refresh-flow)
7. [Proxy Integration](#7-proxy-integration)
8. [Server Components and Auth](#8-server-components-and-auth)
9. [TypeScript for Next.js](#9-typescript-for-nextjs)
10. [Anti-Patterns](#10-anti-patterns)
11. [Quick Reference Checklist](#quick-reference-checklist)

---

## 1. Next.js 16 Architecture

### 1.1 App Router Fundamentals

Next.js 16 uses the **App Router** exclusively. All routing is file-system based inside the `app/` directory. The Pages Router is in maintenance mode and must never be used for new code in this project.

Key architectural points:

- **Layouts and pages** are Server Components by default.
- **Client Components** require the `'use client'` directive at the top of the file.
- **Route Handlers** are defined in `route.ts` files inside `app/` and handle API endpoints.
- **Proxy** (formerly middleware) runs before routes are rendered. The `proxy.ts` file replaces the deprecated `middleware.ts` convention as of Next.js 16.

### 1.2 Server Components vs Client Components

**Server Components** (default):
- Render on the server, ship zero client-side JavaScript.
- Can access server-side resources: environment variables, secrets, databases.
- Can use `async/await` directly at the component level.
- Cannot use state (`useState`), effects (`useEffect`), or browser APIs.
- Cannot use event handlers (`onClick`, `onChange`).

**Client Components** (`'use client'`):
- Render on the server (prerender), then hydrate on the client.
- Can use state, effects, event handlers, and browser APIs (`localStorage`, `window`).
- Must receive serializable props from Server Components.
- Should be kept as small interactive "islands" within a Server Component tree.

**Decision matrix for this library:**

| Need | Component Type |
|------|---------------|
| Display auth state from headers | Server Component |
| Login/register form with validation | Client Component |
| Conditional UI based on role (static) | Server Component |
| Toggle visibility, modals, dropdowns | Client Component |
| Reading cookies for display | Server Component |
| Calling `useSession()` or `useAuth()` | Client Component |

### 1.3 Rendering Model

On initial page load:
1. Server Components render into RSC Payload (compact binary format).
2. Client Components prerender HTML alongside the RSC Payload.
3. Browser receives HTML for fast non-interactive preview.
4. React hydrates Client Components to make the page interactive.

On subsequent navigations:
1. RSC Payload is prefetched and cached for instant navigation.
2. Client Components render entirely on the client.

### 1.4 Environment Variables

- Variables prefixed with `NEXT_PUBLIC_` are exposed to the client bundle.
- Variables without the prefix are server-only (replaced with empty string on client).
- For this library, `NEXT_PUBLIC_API_URL` is commonly used. `JWT_SECRET` must never be prefixed.

```typescript
// Server-only (proxy.ts, route handlers, server components)
const secret = process.env.JWT_SECRET // Available

// Client-accessible
const apiUrl = process.env.NEXT_PUBLIC_API_URL // Available everywhere
```

### 1.5 The `server-only` and `client-only` Packages

To prevent accidental cross-environment imports:

```typescript
// lib/auth-server.ts
import 'server-only'
import { verifyJwtToken } from '@bymax-one/nest-auth/nextjs'

export async function getAuthUser(token: string) {
  return verifyJwtToken(token)
}
```

Any attempt to import `lib/auth-server.ts` from a Client Component will cause a build-time error. Use this for any module that accesses `JWT_SECRET` or performs server-side token verification.

---

## 2. Route Handlers

### 2.1 Convention and Structure

Route Handlers are defined in `route.ts` files inside the `app/` directory. They use the Web `Request` and `Response` APIs, extended by Next.js with `NextRequest` and `NextResponse`.

```
app/
  api/
    auth/
      silent-refresh/
        route.ts          # GET handler
      client-refresh/
        route.ts          # POST handler
      logout/
        route.ts          # POST handler
```

**Supported HTTP methods:** `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS`.

A `route.ts` file cannot coexist with a `page.ts` at the same route segment.

### 2.2 Basic Route Handler Structure

```typescript
// app/api/auth/silent-refresh/route.ts
import { NextRequest } from 'next/server'

export async function GET(request: NextRequest) {
  // Handler logic
  return Response.json({ ok: true })
}
```

Each exported function name corresponds to its HTTP method. Only export the methods your endpoint supports.

### 2.3 Accessing Request Data

```typescript
import { NextRequest } from 'next/server'

export async function POST(request: NextRequest) {
  // URL and search params
  const { searchParams } = request.nextUrl
  const redirect = searchParams.get('redirect')

  // Headers
  const authorization = request.headers.get('authorization')
  const contentType = request.headers.get('content-type')

  // Cookies (via NextRequest convenience API)
  const accessToken = request.cookies.get('access_token')?.value
  const refreshToken = request.cookies.get('refresh_token')?.value

  // Body (JSON)
  const body = await request.json()

  // Body (FormData)
  const formData = await request.formData()

  return Response.json({ ok: true })
}
```

### 2.4 Returning Responses

```typescript
import { NextResponse } from 'next/server'

// JSON response
return Response.json({ data }, { status: 200 })

// Redirect
return NextResponse.redirect(new URL('/auth/login', request.url))

// Response with cookies
const response = NextResponse.redirect(new URL(redirectPath, request.url))
response.cookies.set('access_token', newAccessToken, {
  httpOnly: true,
  secure: true,
  sameSite: 'lax',
  path: '/',
  maxAge: 900, // 15 minutes
})
return response

// Empty response with status
return new NextResponse(null, { status: 204 })

// Error response
return Response.json(
  { error: 'Unauthorized' },
  { status: 401 }
)
```

### 2.5 Caching Behavior

Route Handlers are **not cached by default**. This is correct for all auth-related endpoints. Never add `export const dynamic = 'force-static'` to auth route handlers.

Auth route handlers must always be dynamic because they:
- Read cookies from the incoming request.
- Forward credentials to the backend.
- Return `Set-Cookie` headers in responses.

### 2.6 Route Context Helper (Dynamic Segments)

For route handlers with dynamic segments, use the `RouteContext` type:

```typescript
// app/api/auth/[provider]/route.ts
import type { NextRequest } from 'next/server'

export async function GET(_req: NextRequest, ctx: RouteContext<'/api/auth/[provider]'>) {
  const { provider } = await ctx.params
  // ...
}
```

Types are generated during `next dev`, `next build`, or `next typegen`.

### 2.7 Using Route Handlers with This Library

The `@bymax-one/nest-auth/nextjs` subpath provides factory functions that return properly typed route handlers:

```typescript
// app/api/auth/silent-refresh/route.ts
import { createSilentRefreshHandler } from '@bymax-one/nest-auth/nextjs'
export const GET = createSilentRefreshHandler()

// app/api/auth/client-refresh/route.ts
import { createClientRefreshHandler } from '@bymax-one/nest-auth/nextjs'
export const POST = createClientRefreshHandler()

// app/api/auth/logout/route.ts
import { createLogoutHandler } from '@bymax-one/nest-auth/nextjs'
export const POST = createLogoutHandler()
```

These handlers encapsulate cookie forwarding, header propagation, error handling, and Set-Cookie deduplication. Consuming applications should use the factories directly rather than writing custom handlers.

---

## 3. Auth Proxy Pattern

### 3.1 Overview

The `createAuthProxy` factory is the centerpiece of the Next.js integration. It generates a `proxy` function and a `config` object that are exported from the root `proxy.ts` file. The proxy intercepts every matched request, performs authentication checks, and handles redirects, silent refresh, and RBAC before the route renders.

### 3.2 Proxy File Convention (Next.js 16)

As of Next.js 16, the `middleware.ts` convention is **deprecated** and renamed to `proxy.ts`. The file must be placed at the project root (or inside `src/` if using the `src` directory pattern), at the same level as `app/` or `pages/`.

```
project-root/
  proxy.ts              # <-- Auth proxy lives here
  app/
    api/
      auth/
        silent-refresh/
          route.ts
        client-refresh/
          route.ts
        logout/
          route.ts
    (protected)/
      dashboard/
        page.tsx
    auth/
      login/
        page.tsx
```

The proxy function is exported as a named export `proxy` (not `middleware`):

```typescript
// proxy.ts
import { createAuthProxy } from '@bymax-one/nest-auth/nextjs'

const { proxy, config } = createAuthProxy({
  publicRoutes: ['/', '/welcome', '/auth/*', '/privacy'],
  publicRoutesRedirectIfAuthenticated: [
    '/', '/welcome', '/auth/login', '/auth/register',
    '/auth/forgot-password', '/auth/reset-password', '/auth/verify-otp',
  ],
  protectedRoutes: [
    { pattern: /^\/admin\/.*/, allowedRoles: ['ADMIN'], redirectPath: '/app/dashboard' },
    { pattern: /^\/app\/.*/, allowedRoles: ['USER', 'ADMIN'], redirectPath: '/auth/login' },
  ],
  getDefaultDashboard: (role) => role === 'ADMIN' ? '/admin/dashboard' : '/app/dashboard',
})

export { proxy, config }
```

### 3.3 AuthProxyConfig Interface

```typescript
interface AuthProxyConfig {
  /** Routes that do not require authentication */
  publicRoutes?: string[] | ((pathname: string) => boolean)

  /** Public routes that redirect to dashboard if user is already authenticated */
  publicRoutesRedirectIfAuthenticated?: string[]

  /** Protected routes with role-based access control */
  protectedRoutes: Array<{
    pattern: RegExp
    allowedRoles: string[]
    redirectPath: string
  }>

  /** Login page path. Default: '/auth/login' */
  loginPath?: string

  /** Returns the default dashboard URL for a given role */
  getDefaultDashboard: (role: string) => string

  /** Backend API base URL. Default: process.env.NEXT_PUBLIC_API_URL */
  apiBase?: string

  /** JWT secret for HS256 verification. Default: process.env.JWT_SECRET */
  jwtSecret?: string

  /** Maximum silent refresh attempts before giving up. Default: 2 */
  maxRefreshAttempts?: number

  /** Cookie name overrides. Defaults from @bymax-one/nest-auth/shared */
  cookieNames?: {
    access?: string    // default: 'access_token'
    refresh?: string   // default: 'refresh_token'
    hasSession?: string // default: 'has_session'
  }

  /** Header names propagated to server components after verification */
  userHeaders?: {
    userId?: string       // default: 'x-user-id'
    userRole?: string     // default: 'x-user-role'
    tenantId?: string     // default: 'x-tenant-id'
    tenantDomain?: string // default: 'x-tenant-domain'
  }

  /** User statuses that are blocked at the proxy level.
   *  Default: ['BANNED', 'INACTIVE', 'EXPIRED'] */
  blockedUserStatuses?: string[]
}
```

### 3.4 Proxy Execution Flow

The proxy runs **before** every matched route renders. Its execution follows this sequence:

1. **Static asset exclusion:** The `config.matcher` excludes `_next/static`, `_next/image`, `favicon.ico`, etc.
2. **Background request detection:** Checks for RSC headers (`RSC: 1`, `Next-Router-Prefetch: 1`, `Next-Router-State-Tree`). Background requests receive `401` responses instead of redirects to prevent race conditions.
3. **Public route check:** If the pathname matches `publicRoutes`, allows the request through. If the user is authenticated and the route is in `publicRoutesRedirectIfAuthenticated`, redirects to the dashboard.
4. **Token extraction:** Reads `access_token` from cookies.
5. **Token verification:** Verifies the JWT using HS256 via Web Crypto API (`crypto.subtle`).
6. **User status check:** Compares `tokenData.status` against `blockedUserStatuses`.
7. **RBAC check:** Matches `tokenData.role` against `protectedRoutes[].allowedRoles`.
8. **Header propagation:** Sets `x-user-id`, `x-user-role`, `x-tenant-id`, `x-tenant-domain` headers on the request for downstream server components.
9. **Silent refresh (on token expiry):** If the token is expired but `has_session` cookie exists, redirects to `/api/auth/silent-refresh` with a `_r` counter.

### 3.5 Background Request Detection

Next.js sends parallel requests during navigation (RSC payload fetches, prefetches, router state updates). These must be handled differently from main navigation requests.

Detection headers:
- `RSC: 1` -- RSC payload request
- `Next-Router-Prefetch: 1` -- Link prefetch
- `Next-Router-State-Tree` -- Client-side navigation RSC fetch

For background requests, the proxy returns `new NextResponse(null, { status: 401 })` instead of a redirect. Redirecting background requests would cause race conditions because the refresh token could be consumed by the main navigation while the background request follows its own redirect.

### 3.6 Redirect Loop Prevention

The proxy implements **defense-in-depth** against redirect loops using two independent mechanisms:

**Mechanism 1: `_r` counter**

A query parameter `_r` is incremented on each silent-refresh attempt. When `_r >= maxRefreshAttempts` (default: 2), the proxy stops retrying and either shows the public page or redirects to login.

This exists because browsers may not process `Set-Cookie` headers from a redirect before following the redirect. The `has_session` cookie might not be cleared in time, causing the proxy to attempt another refresh.

Known Next.js issues that motivate this pattern:
- [vercel/next.js#49442](https://github.com/vercel/next.js/issues/49442)
- [vercel/next.js#72170](https://github.com/vercel/next.js/discussions/72170)

**Mechanism 2: `reason=expired` guard**

On public routes, if `url.searchParams.get('reason') === 'expired'`, the proxy knows a previous silent refresh already failed and does not attempt another one.

Both mechanisms operate independently. The `reason=expired` guard is the primary defense; the `_r` counter is the backup.

### 3.7 Header Propagation to Server Components

After successful JWT verification, the proxy sets request headers that downstream server components and route handlers can read:

```typescript
// In a Server Component
import { headers } from 'next/headers'

export default async function DashboardPage() {
  const headersList = await headers()
  const userId = headersList.get('x-user-id')
  const userRole = headersList.get('x-user-role')
  const tenantId = headersList.get('x-tenant-id')

  return <div>Welcome, user {userId}</div>
}
```

**Security warning:** These headers exist for UI convenience only. They must never be used for authorization decisions. All access control must go through the NestJS backend.

### 3.8 Matcher Configuration

The proxy `config` object includes a matcher that excludes static assets and API routes that should not be intercepted:

```typescript
export const config = {
  matcher: [
    '/((?!api|_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)',
  ],
}
```

The `createAuthProxy` function generates this matcher automatically. API routes under `app/api/auth/` are excluded because they handle their own authentication (cookie forwarding to backend).

---

## 4. Cookie Management

### 4.1 Cookie Architecture

This library uses three cookies for session management:

| Cookie | Default Name | HttpOnly | Path | Purpose |
|--------|-------------|----------|------|---------|
| Access Token | `access_token` | Yes | `/` | Short-lived JWT for authentication |
| Refresh Token | `refresh_token` | Yes | `/api/auth` | Long-lived token for session renewal |
| Session Signal | `has_session` | No | `/` | Non-sensitive flag (`"1"`) indicating an active session |

The refresh token cookie has a restricted path (`/api/auth`) so the browser only sends it to the silent-refresh and client-refresh endpoints. This limits exposure of the refresh token.

The `has_session` cookie is intentionally **not** HttpOnly. It can be read by client-side JavaScript (and by the proxy) to determine whether a silent refresh should be attempted, without exposing the actual refresh token.

### 4.2 Reading Cookies in Server Components

The `cookies()` function from `next/headers` is **async** in Next.js 16. It returns a promise that must be awaited:

```typescript
import { cookies } from 'next/headers'

export default async function Page() {
  const cookieStore = await cookies()

  // Read a single cookie
  const accessToken = cookieStore.get('access_token')?.value

  // Check if a cookie exists
  const hasSession = cookieStore.has('has_session')

  // Read all cookies
  const allCookies = cookieStore.getAll()

  return <div>{hasSession ? 'Logged in' : 'Not logged in'}</div>
}
```

**Limitation:** Setting or deleting cookies is **not supported** during Server Component rendering. Cookie mutations must happen in Route Handlers or Server Functions where response headers can be set.

### 4.3 Cookies in Route Handlers

Route Handlers can both read and write cookies:

```typescript
import { cookies } from 'next/headers'
import { NextResponse } from 'next/server'

export async function POST(request: Request) {
  const cookieStore = await cookies()

  // Read
  const refreshToken = cookieStore.get('refresh_token')?.value

  // Write (via cookies API)
  cookieStore.set('access_token', newToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    path: '/',
    maxAge: 900,
  })

  // Delete
  cookieStore.delete('access_token')

  // Alternative: delete by setting maxAge to 0
  cookieStore.set('access_token', '', { maxAge: 0 })

  return Response.json({ ok: true })
}
```

### 4.4 Cookies in the Proxy

The proxy uses the `NextRequest` and `NextResponse` cookie APIs, which are synchronous (unlike the `cookies()` function from `next/headers`):

```typescript
// Reading cookies from the request
const accessToken = request.cookies.get('access_token')?.value
const hasSession = request.cookies.has('has_session')

// Setting cookies on the response
const response = NextResponse.next()
response.cookies.set('access_token', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'lax',
  path: '/',
})

// Deleting cookies on the response
response.cookies.delete('access_token')
```

### 4.5 Cookie Forwarding to Backend

When the Next.js route handlers call the NestJS backend, they must forward cookies from the original browser request. The library handles this automatically, but the pattern is:

```typescript
// Inside a route handler (conceptual — the library does this internally)
const cookieHeader = request.headers.get('cookie') ?? ''

const backendResponse = await fetch(`${apiBase}/auth/refresh`, {
  method: 'POST',
  headers: {
    Cookie: cookieHeader,
    'Content-Type': 'application/json',
    'X-Tenant-Domain': request.headers.get('x-tenant-domain') ?? '',
  },
})
```

The `Cookie` header from the browser is forwarded as-is. The backend sees the same cookies it set originally, including the HttpOnly `refresh_token`.

### 4.6 Set-Cookie Header Deduplication

The backend may send multiple `Set-Cookie` headers for the same cookie name (clear-then-set pattern during token rotation). In multi-domain setups, the same cookie name is sent for multiple domains.

The `dedupeSetCookieHeaders` utility resolves this:

```typescript
import { dedupeSetCookieHeaders } from '@bymax-one/nest-auth/nextjs'

// Raw Set-Cookie headers from backend response
const setCookieHeaders = backendResponse.headers.getSetCookie()

// Deduplicate by (name + domain), last writer wins
const deduplicated = dedupeSetCookieHeaders(setCookieHeaders)

// Apply to the Next.js response
const response = NextResponse.redirect(destination)
for (const header of deduplicated) {
  response.headers.append('Set-Cookie', header)
}
```

Deduplication uses `(name + domain)` as the key, not just `name`. This prevents discarding cookie variants intended for different domains.

### 4.7 Cookie Options Reference

When setting cookies in this library, always use these defaults unless overridden by configuration:

```typescript
// Access token cookie
{
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax' as const,
  path: '/',
  maxAge: 900, // 15 minutes (matches jwt.accessCookieMaxAgeMs / 1000)
}

// Refresh token cookie
{
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax' as const,
  path: '/api/auth', // Restricted path
  maxAge: 604800, // 7 days
}

// Session signal cookie
{
  httpOnly: false, // Intentionally readable by client JS
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax' as const,
  path: '/',
  maxAge: 604800, // Same as refresh token
}
```

### 4.8 Clearing Cookies on Logout

When a refresh fails or the user logs out, all three cookies must be cleared with their correct paths:

```typescript
// Clear access token (path: '/')
response.cookies.set('access_token', '', { path: '/', maxAge: 0 })

// Clear refresh token (path: '/api/auth')
response.cookies.set('refresh_token', '', { path: '/api/auth', maxAge: 0 })

// Clear session signal (path: '/')
response.cookies.set('has_session', '', { path: '/', maxAge: 0 })
```

The path must match exactly. A `delete` call without the correct path will silently fail to clear the cookie.

---

## 5. JWT Helpers for Server Side

### 5.1 Overview

The `@bymax-one/nest-auth/nextjs` subpath exports two JWT helper functions designed for use in the proxy, route handlers, and server components:

- `decodeJwtToken(token)` -- Decodes without signature verification.
- `verifyJwtToken(token)` -- Verifies HS256 signature using Web Crypto API.

These functions do **not** depend on `@nestjs/jwt` or `jsonwebtoken`. They use `crypto.subtle` (Web Crypto API), which is available in Node.js and Edge runtimes.

### 5.2 `decodeJwtToken`

Decodes a JWT without verifying the signature. Use for client-side UX where you need to display user info from the token but do not need cryptographic proof of authenticity.

```typescript
import { decodeJwtToken } from '@bymax-one/nest-auth/nextjs'

const payload = decodeJwtToken(accessToken)
// { sub: 'user-id', role: 'USER', tenantId: 'tenant-id', exp: 1234567890, ... }
```

**When to use:**
- Displaying user name or role in the UI.
- Checking token expiry on the client side.
- Pre-filling forms with user data.

**When NOT to use:**
- Any authorization decision.
- Any server-side access control.

### 5.3 `verifyJwtToken`

Verifies the JWT signature using HS256 via the Web Crypto API (`crypto.subtle`). This function:

1. Parses the JWT header and validates `alg === 'HS256'` (prevents algorithm confusion attacks).
2. Imports the `JWT_SECRET` as a `CryptoKey`.
3. Verifies the HMAC-SHA256 signature.
4. Validates the `exp` claim.
5. Returns the decoded payload if valid.

```typescript
import { verifyJwtToken } from '@bymax-one/nest-auth/nextjs'

// In a route handler or proxy
const payload = await verifyJwtToken(accessToken)
if (!payload) {
  // Token is invalid or expired
  return Response.json({ error: 'Unauthorized' }, { status: 401 })
}
```

**Fallback behavior:** If `JWT_SECRET` is not available in the environment, falls back to `decodeJwtToken` (decode without verification). This allows development environments without the secret to function, but logs a warning.

**When to use:**
- In the proxy for authentication and RBAC decisions.
- In route handlers that need to validate the caller.
- In server components that need trusted user data.

### 5.4 Why Web Crypto API Instead of `jsonwebtoken`

The proxy in Next.js 16 defaults to the Node.js runtime (Edge runtime is no longer the default for proxy). However, the Web Crypto API was chosen because:

1. **Zero dependencies:** No need for `jsonwebtoken` or `jose` packages.
2. **Cross-runtime compatibility:** Works in both Node.js and Edge runtimes.
3. **Security:** The `crypto.subtle` API enforces correct usage patterns (no raw key exposure).
4. **Algorithm pinning:** The implementation explicitly checks `alg === 'HS256'`, preventing algorithm confusion attacks where an attacker forges a token with `alg: 'none'`.

### 5.5 JWT Payload Structure

The JWT tokens issued by the NestJS backend follow this claims structure:

```typescript
interface JwtPayload {
  sub: string       // User ID
  role: string      // User role (e.g., 'USER', 'ADMIN')
  tenantId: string  // Tenant ID for multi-tenant isolation
  status: string    // User status (e.g., 'ACTIVE', 'BANNED')
  email: string     // User email
  iat: number       // Issued at (Unix timestamp)
  exp: number       // Expiration (Unix timestamp)
}
```

### 5.6 Token Verification in Different Contexts

```typescript
// In proxy.ts (synchronous cookie access, async verification)
export async function proxy(request: NextRequest) {
  const token = request.cookies.get('access_token')?.value
  if (token) {
    const payload = await verifyJwtToken(token)
    // Use payload for routing decisions
  }
}

// In a Route Handler
export async function GET(request: NextRequest) {
  const token = request.cookies.get('access_token')?.value
  const payload = token ? await verifyJwtToken(token) : null
  // Use payload
}

// In a Server Component (read-only, for UI purposes)
import { cookies } from 'next/headers'
import { decodeJwtToken } from '@bymax-one/nest-auth/nextjs'

export default async function Page() {
  const cookieStore = await cookies()
  const token = cookieStore.get('access_token')?.value
  const user = token ? decodeJwtToken(token) : null
  // Display user info (not for authorization)
}
```

---

## 6. Silent Refresh Flow

### 6.1 Overview

Silent refresh is the mechanism that renews an expired access token without requiring the user to log in again. It operates transparently through a redirect chain involving the proxy and a dedicated route handler.

### 6.2 Server-Side Silent Refresh (Proxy-Initiated)

This flow is triggered when the proxy detects an expired access token but finds a `has_session` cookie:

```
Browser Request        Proxy (proxy.ts)            Route Handler               NestJS Backend
     |                      |                           |                          |
     |--- GET /dashboard -->|                           |                          |
     |                      | Token expired,            |                          |
     |                      | has_session exists         |                          |
     |                      |                           |                          |
     |<-- 302 /api/auth/    |                           |                          |
     |    silent-refresh    |                           |                          |
     |    ?redirect=/dashboard&_r=1                     |                          |
     |                      |                           |                          |
     |--- GET /api/auth/silent-refresh?redirect=... --->|                          |
     |                      |                           |--- POST /auth/refresh -->|
     |                      |                           |<-- 200 + Set-Cookie -----|
     |                      |                           |                          |
     |<-- 302 /dashboard + Set-Cookie (new tokens) -----|                          |
     |                      |                           |                          |
     |--- GET /dashboard -->| Token valid               |                          |
     |<-- 200 (page) -------|                           |                          |
```

### 6.3 `createSilentRefreshHandler`

Factory that creates the GET handler for `/api/auth/silent-refresh`:

```typescript
// app/api/auth/silent-refresh/route.ts
import { createSilentRefreshHandler } from '@bymax-one/nest-auth/nextjs'
export const GET = createSilentRefreshHandler()
```

The handler:

1. Reads the `redirect` query parameter (the original destination).
2. Forwards all cookies to the NestJS backend `POST /auth/refresh`.
3. Includes `Cookie`, `X-Tenant-Domain`, and `Content-Type` headers.
4. **On success:** Redirects to the original destination with `Set-Cookie` headers from the backend, processed through `dedupeSetCookieHeaders()`.
5. **On failure:** Redirects to `/auth/login?reason=expired` and explicitly clears all three auth cookies with their correct paths.
6. **Open redirect protection:** Validates that the `redirect` parameter starts with `/`, does not start with `//`, and after URL resolution the origin matches the request origin.

### 6.4 Client-Side Refresh

For client-side refresh (e.g., when an API call returns 401), the flow uses `createClientRefreshHandler`:

```
Browser (SPA)           Next.js Route Handler        NestJS Backend
     |                        |                          |
     |-- GET /api/users ----->|--- GET /users ---------->|
     |<-- 401 ----------------|<-- 401 ------------------|
     |                        |                          |
     |  [Client interceptor]  |                          |
     |                        |                          |
     |-- POST /api/auth/      |                          |
     |   client-refresh ----->|--- POST /auth/refresh -->|
     |                        |<-- 200 + Set-Cookie -----|
     |<-- 200 + Set-Cookie ---|                          |
     |                        |                          |
     |  [Retry original]      |                          |
     |-- GET /api/users ----->|--- GET /users ---------->|
     |<-- 200 + data ---------|<-- 200 + data -----------|
```

### 6.5 `createClientRefreshHandler`

Factory that creates the POST handler for `/api/auth/client-refresh`:

```typescript
// app/api/auth/client-refresh/route.ts
import { createClientRefreshHandler } from '@bymax-one/nest-auth/nextjs'
export const POST = createClientRefreshHandler()
```

This handler exists as a same-origin bridge because:

1. The `refresh_token` cookie has `Path=/api/auth` -- the browser only sends it to requests matching this path.
2. The NestJS backend may be on a different domain (cross-origin).
3. HttpOnly cross-origin cookies can be blocked by Safari ITP and Firefox ETP.

### 6.6 `createLogoutHandler`

Factory that creates the POST handler for `/api/auth/logout`:

```typescript
// app/api/auth/logout/route.ts
import { createLogoutHandler } from '@bymax-one/nest-auth/nextjs'
export const POST = createLogoutHandler()
```

The handler forwards the logout request to the NestJS backend and clears all auth cookies on the response.

### 6.7 The 500ms Redirect Delay

After a client-side refresh fails, the client schedules a redirect to login with `setTimeout(500ms)` instead of navigating immediately. This resolves a race condition:

If the proxy (server-side) simultaneously renewed the session via a 302 redirect, the browser navigates to the destination, destroying the JS context and canceling the timeout. The redirect to login **never happens**. Without the delay, `window.location.href = '/auth/login'` would execute before the 302 from the proxy completes.

### 6.8 Complete Route Handler Setup

Every consuming Next.js application needs these three route handlers:

```
app/
  api/
    auth/
      silent-refresh/
        route.ts      # export const GET = createSilentRefreshHandler()
      client-refresh/
        route.ts      # export const POST = createClientRefreshHandler()
      logout/
        route.ts      # export const POST = createLogoutHandler()
```

These are one-line files. All logic is encapsulated in the factory functions.

---

## 7. Proxy Integration

### 7.1 Proxy vs Middleware (Naming)

Next.js 16 renamed `middleware.ts` to `proxy.ts`. The exported function is named `proxy` instead of `middleware`. A codemod is available for migration:

```bash
npx @next/codemod@canary middleware-to-proxy .
```

The `createAuthProxy` factory already uses the new naming convention. When consuming this library, export `proxy` and `config` (not `middleware`):

```typescript
// proxy.ts
import { createAuthProxy } from '@bymax-one/nest-auth/nextjs'
const { proxy, config } = createAuthProxy({ /* ... */ })
export { proxy, config }
```

### 7.2 Proxy Runtime

Next.js 16 proxy defaults to the **Node.js runtime**. The Edge runtime is no longer the default. The `runtime` config option is not available in proxy files and setting it will throw an error.

This is beneficial for this library because:
- Full Node.js API availability.
- No restrictions from Edge runtime limitations.
- `crypto.subtle` (Web Crypto API) is still available in Node.js for JWT verification.

### 7.3 Proxy Execution Order

The proxy runs within Next.js's request processing pipeline:

1. `headers` from `next.config.js`
2. `redirects` from `next.config.js`
3. **Proxy** (rewrites, redirects, etc.)
4. `beforeFiles` (rewrites) from `next.config.js`
5. Filesystem routes (`public/`, `_next/static/`, `pages/`, `app/`, etc.)
6. `afterFiles` (rewrites) from `next.config.js`
7. Dynamic Routes (`/blog/[slug]`)
8. `fallback` (rewrites) from `next.config.js`

### 7.4 Matcher Patterns

The `config.matcher` controls which routes the proxy intercepts:

```typescript
// Generated by createAuthProxy — typical pattern
export const config = {
  matcher: [
    '/((?!api|_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)',
  ],
}
```

**Important:** Even when `_next/data` is excluded in a negative matcher, the proxy still runs for `_next/data` routes. This is intentional to prevent security gaps where a page is protected but its data route is not.

For more granular control, use object-form matchers:

```typescript
export const config = {
  matcher: [
    {
      source: '/((?!api|_next/static|_next/image|favicon.ico).*)',
      missing: [
        { type: 'header', key: 'next-router-prefetch' },
        { type: 'header', key: 'purpose', value: 'prefetch' },
      ],
    },
  ],
}
```

### 7.5 Setting Headers in Proxy

The proxy sets request headers for downstream consumption. Use `NextResponse.next()` with the `request.headers` option:

```typescript
export function proxy(request: NextRequest) {
  const requestHeaders = new Headers(request.headers)
  requestHeaders.set('x-user-id', userId)
  requestHeaders.set('x-user-role', userRole)

  const response = NextResponse.next({
    request: {
      headers: requestHeaders,
    },
  })

  return response
}
```

Note the distinction:
- `NextResponse.next({ request: { headers } })` -- makes headers available **upstream** (to server components, route handlers).
- `NextResponse.next({ headers })` -- makes headers available to **clients** (in the response).

### 7.6 Proxy Cookie Operations

In the proxy, cookie operations are synchronous (unlike `cookies()` from `next/headers`):

```typescript
// Read from request
const token = request.cookies.get('access_token')?.value
const all = request.cookies.getAll()
const exists = request.cookies.has('has_session')

// Write to response
const response = NextResponse.next()
response.cookies.set('name', 'value', { httpOnly: true, path: '/' })
response.cookies.delete('name')
```

### 7.7 RSC Requests in Proxy

During RSC (React Server Components) requests, Next.js strips internal Flight headers from the `request` instance. Headers like `rsc`, `next-router-state-tree`, and `next-router-prefetch` are not exposed through `request.headers`.

However, for background request detection, the library checks these headers at a lower level. The `isBackgroundRequest` helper detects these requests to avoid redirect-based responses for parallel fetches.

### 7.8 Server Functions and Proxy

Server Functions (Server Actions) are handled as POST requests to the route where they are used. A proxy matcher that excludes a path will also skip Server Function calls on that path.

**Important:** Always verify authentication and authorization inside each Server Function rather than relying on the proxy alone. The proxy provides a first line of defense, but Server Functions must independently validate permissions:

```typescript
'use server'

import { cookies } from 'next/headers'
import { verifyJwtToken } from '@bymax-one/nest-auth/nextjs'

export async function updateProfile(formData: FormData) {
  const cookieStore = await cookies()
  const token = cookieStore.get('access_token')?.value
  const payload = token ? await verifyJwtToken(token) : null

  if (!payload) {
    throw new Error('Unauthorized')
  }

  // Proceed with update via backend API
}
```

---

## 8. Server Components and Auth

### 8.1 Reading Auth State in Server Components

Server Components can read auth state from two sources:

**Source 1: Headers set by the proxy**

```typescript
import { headers } from 'next/headers'

export default async function DashboardLayout({
  children,
}: {
  children: React.ReactNode
}) {
  const headersList = await headers()
  const userId = headersList.get('x-user-id')
  const userRole = headersList.get('x-user-role')
  const tenantId = headersList.get('x-tenant-id')

  return (
    <div>
      <nav>Role: {userRole}</nav>
      <main>{children}</main>
    </div>
  )
}
```

**Source 2: Decoding the JWT directly**

```typescript
import { cookies } from 'next/headers'
import { decodeJwtToken } from '@bymax-one/nest-auth/nextjs'

export default async function ProfilePage() {
  const cookieStore = await cookies()
  const token = cookieStore.get('access_token')?.value
  const user = token ? decodeJwtToken(token) : null

  if (!user) {
    return <div>Not authenticated</div>
  }

  return <div>Welcome, {user.email}</div>
}
```

**Recommendation:** Prefer headers from the proxy for consistency. The proxy has already verified the token; reading headers avoids redundant decoding.

### 8.2 Passing Auth Data to Client Components

Server Components cannot share context with Client Components. Use props to pass auth data down:

```typescript
// app/dashboard/page.tsx (Server Component)
import { headers } from 'next/headers'
import DashboardClient from './dashboard-client'

export default async function DashboardPage() {
  const headersList = await headers()
  const userId = headersList.get('x-user-id') ?? ''
  const userRole = headersList.get('x-user-role') ?? ''

  return <DashboardClient userId={userId} userRole={userRole} />
}
```

```typescript
// app/dashboard/dashboard-client.tsx (Client Component)
'use client'

interface Props {
  userId: string
  userRole: string
}

export default function DashboardClient({ userId, userRole }: Props) {
  // Can use state, effects, event handlers
  return <div>User: {userId}, Role: {userRole}</div>
}
```

### 8.3 Auth Provider Pattern

For applications using the `@bymax-one/nest-auth/react` hooks (`useSession`, `useAuth`), wrap the app in an `AuthProvider`. Since providers use context (a client feature), the provider is a Client Component:

```typescript
// app/providers.tsx
'use client'

import { AuthProvider } from '@bymax-one/nest-auth/react'

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <AuthProvider>
      {children}
    </AuthProvider>
  )
}
```

```typescript
// app/layout.tsx (Server Component)
import { Providers } from './providers'

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  )
}
```

Render providers as deep as possible in the tree to maximize the static portion of the Server Component tree.

### 8.4 Route Groups for Auth Layouts

Use route groups to separate authenticated and unauthenticated layouts:

```
app/
  (public)/
    auth/
      login/
        page.tsx
      register/
        page.tsx
    layout.tsx          # Minimal layout, no auth checks
  (protected)/
    dashboard/
      page.tsx
    settings/
      page.tsx
    layout.tsx          # Layout with sidebar, user info from headers
  layout.tsx            # Root layout with providers
```

The proxy handles the actual authentication gate. Route groups are for organizing layouts, not for enforcing security.

### 8.5 Loading and Error States

Use `loading.tsx` and `error.tsx` for Suspense boundaries in auth-protected routes:

```typescript
// app/(protected)/dashboard/loading.tsx
export default function Loading() {
  return <div>Loading dashboard...</div>
}

// app/(protected)/dashboard/error.tsx
'use client'

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  return (
    <div>
      <h2>Something went wrong</h2>
      <button onClick={() => reset()}>Try again</button>
    </div>
  )
}
```

---

## 9. TypeScript for Next.js

### 9.1 Route Handler Types

```typescript
import type { NextRequest } from 'next/server'
import { NextResponse } from 'next/server'

// Basic route handler
export async function GET(request: NextRequest): Promise<Response> {
  return Response.json({ ok: true })
}

// Route handler with dynamic params
export async function GET(
  request: NextRequest,
  ctx: RouteContext<'/api/auth/[provider]'>
): Promise<Response> {
  const { provider } = await ctx.params
  return Response.json({ provider })
}

// POST handler with body
export async function POST(request: NextRequest): Promise<Response> {
  const body = await request.json() as { email: string; password: string }
  return Response.json({ ok: true })
}
```

### 9.2 Proxy Types

```typescript
// proxy.ts
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

export function proxy(request: NextRequest): NextResponse | Response {
  return NextResponse.next()
}

// Alternative: using the NextProxy type for automatic inference
import type { NextProxy } from 'next/server'

export const proxy: NextProxy = (request, event) => {
  event.waitUntil(Promise.resolve())
  return NextResponse.next()
}
```

### 9.3 Cookie Types

```typescript
import type { RequestCookie } from 'next/dist/compiled/@edge-runtime/cookies'

// RequestCookie shape
interface RequestCookie {
  name: string
  value: string
}

// Cookie options for setting
interface CookieOptions {
  name?: string
  value?: string
  expires?: Date
  maxAge?: number
  domain?: string
  path?: string
  secure?: boolean
  httpOnly?: boolean
  sameSite?: boolean | 'lax' | 'strict' | 'none'
  priority?: 'low' | 'medium' | 'high'
  partitioned?: boolean
}
```

### 9.4 Library-Specific Types

The `@bymax-one/nest-auth/nextjs` subpath exports these types:

```typescript
import type { AuthProxyConfig } from '@bymax-one/nest-auth/nextjs'

// AuthProxyConfig — configuration for createAuthProxy
// See Section 3.3 for full interface definition
```

### 9.5 Server Component Types

```typescript
// Page component with params
export default async function Page({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const { id } = await params
  return <div>{id}</div>
}

// Page component with search params
export default async function Page({
  searchParams,
}: {
  searchParams: Promise<{ [key: string]: string | string[] | undefined }>
}) {
  const sp = await searchParams
  const query = sp.q as string | undefined
  return <div>{query}</div>
}

// Layout component
export default function Layout({
  children,
}: {
  children: React.ReactNode
}) {
  return <div>{children}</div>
}
```

Note: In Next.js 16, `params` and `searchParams` are **Promises** that must be awaited.

### 9.6 Headers and Cookies Type Usage

```typescript
import { headers, cookies } from 'next/headers'

// Both are async functions returning ReadonlyHeaders / ReadonlyRequestCookies
export default async function Page() {
  const headersList = await headers()   // ReadonlyHeaders
  const cookieStore = await cookies()   // ReadonlyRequestCookies

  // Type-safe header access
  const userId: string | null = headersList.get('x-user-id')

  // Type-safe cookie access
  const cookie: { name: string; value: string } | undefined =
    cookieStore.get('access_token')

  return <div />
}
```

### 9.7 Module Augmentation

If you need to extend Next.js types for this library (e.g., adding custom properties to `NextRequest`), use module augmentation:

```typescript
// types/next.d.ts
declare module 'next/server' {
  interface NextRequest {
    authUser?: {
      id: string
      role: string
      tenantId: string
    }
  }
}
```

Place this in a `.d.ts` file included in your `tsconfig.json`.

### 9.8 Strict TypeScript Configuration

The recommended `tsconfig.json` settings for consuming applications:

```json
{
  "compilerOptions": {
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "moduleResolution": "bundler",
    "module": "esnext",
    "target": "es2022",
    "jsx": "preserve",
    "paths": {
      "@/*": ["./src/*"]
    }
  }
}
```

---

## 10. Anti-Patterns

### 10.1 WRONG: Using `jsonwebtoken` in the Proxy

```typescript
// WRONG -- jsonwebtoken may not work in all runtimes
import jwt from 'jsonwebtoken'

export function proxy(request: NextRequest) {
  const token = request.cookies.get('access_token')?.value
  const payload = jwt.verify(token!, process.env.JWT_SECRET!)
}
```

```typescript
// CORRECT -- use the library's Web Crypto API-based helper
import { verifyJwtToken } from '@bymax-one/nest-auth/nextjs'

export async function proxy(request: NextRequest) {
  const token = request.cookies.get('access_token')?.value
  const payload = token ? await verifyJwtToken(token) : null
}
```

### 10.2 WRONG: Redirecting Background Requests

```typescript
// WRONG -- causes race conditions with parallel RSC fetches
export function proxy(request: NextRequest) {
  const token = request.cookies.get('access_token')?.value
  if (!token) {
    return NextResponse.redirect(new URL('/auth/login', request.url))
  }
}
```

```typescript
// CORRECT -- return 401 for background requests, redirect only for main navigation
export function proxy(request: NextRequest) {
  const token = request.cookies.get('access_token')?.value
  if (!token) {
    if (isBackgroundRequest(request)) {
      return new NextResponse(null, { status: 401 })
    }
    return NextResponse.redirect(new URL('/auth/login', request.url))
  }
}
```

### 10.3 WRONG: Setting Cookies in Server Components

```typescript
// WRONG -- cookies cannot be set during Server Component rendering
import { cookies } from 'next/headers'

export default async function Page() {
  const cookieStore = await cookies()
  cookieStore.set('theme', 'dark') // This will throw an error
  return <div />
}
```

```typescript
// CORRECT -- set cookies in a Server Function or Route Handler
'use server'

import { cookies } from 'next/headers'

export async function setTheme(theme: string) {
  const cookieStore = await cookies()
  cookieStore.set('theme', theme, { path: '/' })
}
```

### 10.4 WRONG: Synchronous `cookies()` Call

```typescript
// WRONG -- cookies() is async in Next.js 16
import { cookies } from 'next/headers'

export default function Page() {
  const cookieStore = cookies() // Missing await
  const token = cookieStore.get('access_token') // Error: get is not a function
}
```

```typescript
// CORRECT -- await the cookies() call
import { cookies } from 'next/headers'

export default async function Page() {
  const cookieStore = await cookies()
  const token = cookieStore.get('access_token')?.value
  return <div />
}
```

### 10.5 WRONG: Using Auth Headers for Authorization

```typescript
// WRONG -- proxy headers are for UI convenience, not authorization
import { headers } from 'next/headers'

export async function deleteUser(userId: string) {
  const headersList = await headers()
  const role = headersList.get('x-user-role')
  if (role === 'ADMIN') {
    await db.user.delete({ where: { id: userId } }) // Dangerous!
  }
}
```

```typescript
// CORRECT -- always delegate authorization to the NestJS backend
export async function deleteUser(userId: string) {
  const cookieStore = await cookies()
  const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/admin/users/${userId}`, {
    method: 'DELETE',
    headers: {
      Cookie: cookieStore.toString(),
    },
  })
  // The backend validates the JWT and checks permissions
  return response.json()
}
```

### 10.6 WRONG: Clearing Cookies Without Matching Paths

```typescript
// WRONG -- path mismatch means the cookie will not be cleared
response.cookies.delete('refresh_token')
// This sets maxAge=0 with default path '/', but the cookie was set with path '/api/auth'
```

```typescript
// CORRECT -- match the path exactly
response.cookies.set('refresh_token', '', { path: '/api/auth', maxAge: 0 })
```

### 10.7 WRONG: Writing Custom Route Handlers Instead of Using Factories

```typescript
// WRONG -- reimplementing logic that the library handles
export async function GET(request: NextRequest) {
  const cookieHeader = request.headers.get('cookie') ?? ''
  const response = await fetch(`${API_URL}/auth/refresh`, {
    method: 'POST',
    headers: { Cookie: cookieHeader },
  })
  // Missing: deduplication, open redirect protection, cookie clearing on failure, etc.
}
```

```typescript
// CORRECT -- use the factory
import { createSilentRefreshHandler } from '@bymax-one/nest-auth/nextjs'
export const GET = createSilentRefreshHandler()
```

### 10.8 WRONG: Exporting `middleware` Instead of `proxy`

```typescript
// WRONG -- deprecated convention in Next.js 16
// middleware.ts
export function middleware(request: NextRequest) { /* ... */ }
```

```typescript
// CORRECT -- use the proxy convention
// proxy.ts
import { createAuthProxy } from '@bymax-one/nest-auth/nextjs'
const { proxy, config } = createAuthProxy({ /* ... */ })
export { proxy, config }
```

### 10.9 WRONG: Using `export const dynamic = 'force-static'` on Auth Routes

```typescript
// WRONG -- auth route handlers must be dynamic
// app/api/auth/silent-refresh/route.ts
export const dynamic = 'force-static'
export const GET = createSilentRefreshHandler()
```

```typescript
// CORRECT -- do not set caching directives on auth routes
// app/api/auth/silent-refresh/route.ts
import { createSilentRefreshHandler } from '@bymax-one/nest-auth/nextjs'
export const GET = createSilentRefreshHandler()
```

### 10.10 WRONG: Importing Server-Only Code in Client Components

```typescript
// WRONG -- verifyJwtToken uses JWT_SECRET, must not be in client bundle
'use client'
import { verifyJwtToken } from '@bymax-one/nest-auth/nextjs'

export function AuthButton() {
  // verifyJwtToken will fail on client — JWT_SECRET is server-only
}
```

```typescript
// CORRECT -- use decodeJwtToken for client-side display, or fetch from server
'use client'
import { decodeJwtToken } from '@bymax-one/nest-auth/nextjs'

export function AuthButton() {
  // decodeJwtToken does not need secrets — safe for client
}
```

### 10.11 WRONG: Placing `proxy.ts` Inside the `app/` Directory

```typescript
// WRONG -- proxy.ts must be at the project root or in src/
// app/proxy.ts  <-- Will not be recognized
```

```typescript
// CORRECT -- place at the same level as app/
// proxy.ts (project root)
// OR src/proxy.ts (if using src directory)
```

### 10.12 WRONG: Not Handling the `_r` Counter

```typescript
// WRONG -- infinite redirect loop when Set-Cookie is not processed in time
export function proxy(request: NextRequest) {
  const token = request.cookies.get('access_token')?.value
  const hasSession = request.cookies.has('has_session')

  if (!token && hasSession) {
    // Always redirects to silent-refresh, no escape hatch
    return NextResponse.redirect(new URL('/api/auth/silent-refresh', request.url))
  }
}
```

```typescript
// CORRECT -- use createAuthProxy which implements _r counter and reason=expired guard
import { createAuthProxy } from '@bymax-one/nest-auth/nextjs'
const { proxy, config } = createAuthProxy({ /* ... */ })
export { proxy, config }
```

---

## Quick Reference Checklist

### Project Setup

- [ ] Install peer dependencies: `next ^16`, `react ^19`
- [ ] Install library: `npm install @bymax-one/nest-auth`
- [ ] Set environment variables: `NEXT_PUBLIC_API_URL`, `JWT_SECRET`
- [ ] Create `proxy.ts` at project root (not inside `app/`)
- [ ] Export `proxy` and `config` from `proxy.ts` (not `middleware`)

### Route Handlers

- [ ] Create `app/api/auth/silent-refresh/route.ts` with `createSilentRefreshHandler()`
- [ ] Create `app/api/auth/client-refresh/route.ts` with `createClientRefreshHandler()`
- [ ] Create `app/api/auth/logout/route.ts` with `createLogoutHandler()`
- [ ] No `dynamic = 'force-static'` on auth routes
- [ ] Each route handler exports only the needed HTTP method

### Proxy Configuration

- [ ] Define `publicRoutes` for unauthenticated pages
- [ ] Define `publicRoutesRedirectIfAuthenticated` for login/register pages
- [ ] Define `protectedRoutes` with RBAC patterns
- [ ] Implement `getDefaultDashboard` for role-based redirects
- [ ] Config matcher excludes `_next/static`, `_next/image`, `favicon.ico`

### Cookie Handling

- [ ] `access_token`: HttpOnly, path `/`
- [ ] `refresh_token`: HttpOnly, path `/api/auth`
- [ ] `has_session`: NOT HttpOnly, path `/`
- [ ] Always match cookie path when clearing
- [ ] Use `dedupeSetCookieHeaders` when forwarding backend Set-Cookie headers

### Security

- [ ] Never use proxy headers (`x-user-id`, `x-user-role`) for authorization
- [ ] Always delegate authorization to the NestJS backend
- [ ] Never expose `JWT_SECRET` to the client (no `NEXT_PUBLIC_` prefix)
- [ ] Use `verifyJwtToken` (not `decodeJwtToken`) for server-side auth decisions
- [ ] Validate redirect parameters against open redirect attacks
- [ ] Verify auth inside Server Functions independently of proxy

### TypeScript

- [ ] `params` and `searchParams` are Promises in Next.js 16 (must await)
- [ ] `cookies()` and `headers()` are async (must await)
- [ ] Use `RouteContext<'/path/[param]'>` for typed dynamic route params
- [ ] Use `server-only` package for modules with secrets

### Component Patterns

- [ ] Default to Server Components; only use `'use client'` when needed
- [ ] Keep Client Components small (interactive islands)
- [ ] Pass serializable props from Server to Client Components
- [ ] Place `AuthProvider` in a Client Component wrapper, import in root layout
- [ ] Render context providers as deep as possible in the tree
