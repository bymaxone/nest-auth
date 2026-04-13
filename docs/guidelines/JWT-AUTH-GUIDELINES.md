# JWT Authentication Guidelines — @bymax-one/nest-auth

> **Audience:** AI agents and developers working on this codebase.
> **Stack:** @nestjs/jwt ^11, Node.js crypto, ioredis
> **Rule:** Follow these guidelines for all JWT-related code in this project.

---

## Table of Contents

1. [Token Architecture](#1-token-architecture)
2. [Token Signing and Verification](#2-token-signing-and-verification)
3. [Token Delivery Modes](#3-token-delivery-modes)
4. [Cookie Security](#4-cookie-security)
5. [Refresh Token Flow](#5-refresh-token-flow)
6. [Token Blacklisting](#6-token-blacklisting)
7. [JWT Payload Design](#7-jwt-payload-design)
8. [Guard Implementation](#8-guard-implementation)
9. [Security Best Practices](#9-security-best-practices)
10. [Anti-Patterns](#10-anti-patterns)
11. [Quick Reference Checklist](#quick-reference-checklist)

---

## 1. Token Architecture

### 1.1 Overview

The `@bymax-one/nest-auth` package uses a multi-token architecture to serve different authentication contexts. Every token has a strict purpose, a defined lifetime, and a typed payload. Understanding which token does what is essential before writing any JWT-related code.

| Token Type | Format | Lifetime | Transport | Purpose |
|---|---|---|---|---|
| **Access Token (Dashboard)** | JWT (signed) | 15 minutes (default) | Cookie or `Authorization: Bearer` header | Authenticates dashboard/tenant users on every request |
| **Access Token (Platform)** | JWT (signed) | 15 minutes (default) | Cookie or `Authorization: Bearer` header | Authenticates platform administrators |
| **Refresh Token** | Opaque UUID v4 | 7 days (default) | HttpOnly cookie (path-scoped) or request body | Reissues access tokens without re-authentication |
| **MFA Temp Token** | JWT (signed) | 5 minutes (fixed) | Response body only | Short-lived token for the MFA challenge window |

### 1.2 Access Tokens

Access tokens are standard JWTs signed with HS256. They carry authorization claims (role, tenant, status, MFA state) and are verified on every authenticated request by the guards. Access tokens are **stateless** — the guard does not query a database to validate them. The only server-side check is the blacklist lookup in Redis (for revoked tokens).

Key properties:
- Short-lived (default 15 minutes, configurable via `jwt.accessExpiresIn`).
- Contain a `jti` claim (UUID v4) used for blacklisting on logout.
- Contain a `type` claim (`"dashboard"` or `"platform"`) to prevent cross-context token reuse.
- Never store sensitive data (passwords, secrets, PII beyond what is needed for authorization).

### 1.3 Refresh Tokens

Refresh tokens are **not JWTs**. They are opaque UUID v4 strings stored in Redis. This is a deliberate design decision:

- An opaque token cannot be decoded or verified without the Redis store, making it useless if intercepted without server access.
- Revocation is instantaneous (delete the Redis key).
- Rotation is simple (generate a new UUID, store it, delete the old one).

Storage key pattern: `auth:rt:{sha256(token)}` (dashboard) or `auth:prt:{sha256(token)}` (platform).

The raw token is never stored in Redis. Only its SHA-256 hash is used as the key. This means that even if the Redis store is compromised, the actual token values are not exposed.

### 1.4 MFA Temporary Tokens

When a user with MFA enabled provides correct credentials at login, the server does **not** issue access/refresh tokens. Instead, it returns an MFA temp token — a short-lived JWT with `type: "mfa_challenge"`. The client must present this token along with the TOTP code at the `/auth/mfa/challenge` endpoint to complete authentication.

Key properties:
- Expires in exactly 5 minutes.
- Contains a `context` claim (`"dashboard"` or `"platform"`) so the MFA service knows which repository and token-issuing path to use.
- Stored in Redis (`auth:mfa:{sha256(token)}`) and consumed (deleted) after successful verification — single-use.

### 1.5 Platform Admin Tokens

Platform admin tokens use the same JWT format and signing mechanism as dashboard tokens. Isolation between dashboard and platform contexts is achieved through the `type` claim, **not** through separate signing keys.

- `JwtAuthGuard` accepts only `type: "dashboard"`.
- `JwtPlatformGuard` accepts only `type: "platform"`.
- A platform token presented to `JwtAuthGuard` is rejected with `auth.token_invalid`.
- A dashboard token presented to `JwtPlatformGuard` is rejected with `auth.platform_auth_required`.

This approach keeps key management simple (one secret) while maintaining strict separation of privilege domains.

---

## 2. Token Signing and Verification

### 2.1 @nestjs/jwt JwtService

All JWT operations go through the `JwtService` provided by `@nestjs/jwt ^11`. The package registers `JwtModule` internally — consuming applications do not register it themselves.

```typescript
import { JwtService } from '@nestjs/jwt';

// JwtService is injected into TokenManagerService
constructor(private readonly jwtService: JwtService) {}
```

### 2.2 Signing Access Tokens

When signing a token, always provide the secret and algorithm explicitly at call-site. Never rely on module-level defaults for security-critical options.

```typescript
// CORRECT — explicit secret and algorithm at sign-time
const accessToken = this.jwtService.sign(payload, {
  secret: this.options.jwt.secret,
  algorithm: 'HS256',
  expiresIn: this.options.jwt.accessExpiresIn, // default: '15m'
});
```

The payload passed to `sign()` must be a plain object. The `jti`, `iat`, and `exp` claims are managed as follows:
- `jti`: Generated as UUID v4 by `TokenManagerService` before signing. Always include it.
- `iat`: Automatically set by `@nestjs/jwt` (do not set manually).
- `exp`: Controlled by the `expiresIn` option (do not set the `exp` claim in the payload manually).

### 2.3 Signing MFA Temp Tokens

MFA temp tokens are signed the same way but with a fixed short expiration:

```typescript
const mfaTempToken = this.jwtService.sign(
  { sub: userId, jti: uuidv4(), type: 'mfa_challenge', context },
  {
    secret: this.options.jwt.secret,
    algorithm: 'HS256',
    expiresIn: '5m', // fixed, not configurable
  },
);
```

### 2.4 Verifying Tokens

**Algorithm pinning is mandatory.** Every call to `jwtService.verify()` must include `algorithms: ['HS256']`. This prevents algorithm confusion attacks (CVE-2015-9235) where an attacker sends a token with `alg: "none"` or `alg: "RS256"` using the HMAC secret as an RSA public key.

```typescript
// CORRECT — algorithm pinned at verification time
const payload = this.jwtService.verify<DashboardJwtPayload>(token, {
  secret: this.options.jwt.secret,
  algorithms: ['HS256'],  // MANDATORY — never omit this
});
```

**Never call `verify()` without the `algorithms` array.** The `@nestjs/jwt` library passes options through to `jsonwebtoken`, which by default accepts whatever algorithm the token header specifies. Pinning the algorithm closes this attack vector.

### 2.5 Decoding Without Verification

For specific internal operations (such as extracting the `jti` from an expired token during logout to add it to the blacklist), use `decode()`:

```typescript
// decode() does NOT verify the signature or expiration
const payload = this.jwtService.decode(token);
```

**Rules for `decode()`:**
- Never use the output of `decode()` for authorization decisions.
- Only use it when you need claims from a token you know is expired or when you need the `jti` to perform a blacklist operation.
- Mark any method that uses `decode()` as `@internal` to signal it should not be used in authorization paths.

### 2.6 Sign and Verify Options Reference

| Option | Sign | Verify | Required | Description |
|---|---|---|---|---|
| `secret` | Yes | Yes | Always | The HMAC secret. Minimum 32 characters, validated at startup. |
| `algorithm` | Yes | No | Always at sign | Must be `'HS256'`. The only supported algorithm. |
| `algorithms` | No | Yes | Always at verify | Must be `['HS256']`. Pins the accepted algorithm. |
| `expiresIn` | Yes | No | Always at sign | String like `'15m'`, `'5m'`, `'7d'`. Controls `exp` claim. |
| `ignoreExpiration` | No | Yes | Never | Do not use. If you need claims from expired tokens, use `decode()`. |

### 2.7 JwtModule Registration

The package registers `JwtModule` with sensible defaults. The consuming application does not need to import `JwtModule`:

```typescript
// Internal to the package — DO NOT duplicate in the host application
JwtModule.register({
  secret: options.jwt.secret,
  signOptions: {
    algorithm: 'HS256',
    expiresIn: options.jwt.accessExpiresIn ?? '15m',
  },
});
```

Even though module-level defaults are set, all guards and services pass `secret` and `algorithms`/`algorithm` explicitly at call-site as defense in depth.

---

## 3. Token Delivery Modes

### 3.1 Configuration

The `tokenDelivery` option in `BymaxAuthModuleOptions` controls how tokens reach the client:

```typescript
tokenDelivery?: 'cookie' | 'bearer' | 'both';
// Default: 'cookie'
```

### 3.2 Cookie Mode (Default)

**When to use:** Web applications and SPAs served from the same domain as the API.

Behavior:
- **Login/Register:** Sets `access_token` and `refresh_token` as HttpOnly cookies. Response body contains only `{ user }`.
- **Refresh:** Clears old cookies, sets new ones. Response body is empty `{}`.
- **Logout:** Clears all auth cookies.
- **Guards:** Extract the access token from `req.cookies[accessTokenName]`.

```typescript
// Cookie mode response example
// HTTP/1.1 200 OK
// Set-Cookie: access_token=eyJhbG...; HttpOnly; Secure; SameSite=Lax; Path=/
// Set-Cookie: refresh_token=f47ac10b-...; HttpOnly; Secure; SameSite=Strict; Path=/auth
// Set-Cookie: has_session=1; Secure; SameSite=Lax; Path=/
//
// Body: { "user": { "id": "...", "email": "...", ... } }
```

### 3.3 Bearer Mode

**When to use:** React Native, mobile apps, desktop clients, or any client that does not support cookies natively.

Behavior:
- **Login/Register:** No cookies are set. Response body contains `{ user, accessToken, refreshToken }`.
- **Refresh:** Response body contains `{ accessToken, refreshToken }`. Client sends refresh token in `req.body.refreshToken`.
- **Logout:** Server-side revocation only (blacklist + Redis cleanup). No cookies to clear.
- **Guards:** Extract the access token from `Authorization: Bearer <token>` header.

```typescript
// Bearer mode response example
// HTTP/1.1 200 OK
//
// Body: {
//   "user": { "id": "...", "email": "...", ... },
//   "accessToken": "eyJhbG...",
//   "refreshToken": "f47ac10b-..."
// }
```

**Client responsibilities in bearer mode:**
- Store the access token in memory (not localStorage — see Anti-Patterns).
- Store the refresh token in a secure platform-specific store (iOS Keychain, Android Keystore, Electron safeStorage).
- Attach `Authorization: Bearer <accessToken>` to every authenticated request.
- Send refresh token in the POST body when refreshing.

### 3.4 Both Mode

**When to use:** When the same backend serves both web (cookie-based) and mobile (bearer-based) clients.

Behavior:
- **Login/Register:** Sets cookies AND returns tokens in the body.
- **Refresh:** Sets new cookies AND returns new tokens in the body.
- **Guards:** Try cookie first, then fall back to `Authorization: Bearer` header.

```typescript
// Token extraction order in 'both' mode
extractAccessToken(req: Request): string | null {
  // 1. Try cookie first
  const cookieToken = req.cookies?.[this.accessTokenName];
  if (cookieToken) return cookieToken;

  // 2. Fall back to Authorization header
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith('Bearer ')) {
    return authHeader.slice(7);
  }

  return null;
}
```

### 3.5 TokenDeliveryService

All token delivery logic is encapsulated in `TokenDeliveryService`. Controllers and guards never read cookies or headers directly — they delegate to this service.

| Method | Purpose |
|---|---|
| `deliverAuthResponse(res, req, authResult)` | Delivers tokens after login/register |
| `deliverRefreshResponse(res, req, authResult)` | Delivers tokens after refresh |
| `extractAccessToken(req)` | Extracts access token from cookie or header |
| `extractRefreshToken(req)` | Extracts refresh token from cookie or body |
| `clearAuthSession(res, req)` | Clears cookies (no-op in bearer mode) |

**Rule:** Never access `req.cookies` or `req.headers.authorization` directly in controllers or guards. Always go through `TokenDeliveryService`.

---

## 4. Cookie Security

### 4.1 Cookie Configuration Table

| Cookie | Default Name | Path | HttpOnly | Secure | SameSite | Max-Age | Purpose |
|---|---|---|---|---|---|---|---|
| Access Token | `access_token` | `/` | Yes | Yes (prod) | `Lax` | 900,000 ms (15 min) | Carries the JWT on every HTTP request |
| Refresh Token | `refresh_token` | `/auth` | Yes | Yes (prod) | `Strict` | 7 days (604,800,000 ms) | Token rotation at the refresh endpoint only |
| Session Signal | `has_session` | `/` | **No** | Yes (prod) | `Lax` | Same as refresh | Non-sensitive flag (`"1"`) readable by JavaScript/proxy |

### 4.2 HttpOnly

Both `access_token` and `refresh_token` cookies are `HttpOnly`. This means JavaScript running in the browser cannot read them via `document.cookie`. This is the primary defense against XSS-based token theft.

The `has_session` cookie is intentionally **not** HttpOnly. It contains only the value `"1"` (no token, no sensitive data). Its purpose is to let client-side JavaScript and Next.js middleware detect whether a session exists without exposing any token material.

### 4.3 Secure Flag

In production (`NODE_ENV === 'production'`), all cookies are set with `Secure: true`, ensuring they are only transmitted over HTTPS. In development, the `Secure` flag may be omitted to allow `http://localhost` workflows.

### 4.4 SameSite Policy

- **Access token: `Lax`** — Sent on top-level navigations and same-site requests. This allows the cookie to be included when a user clicks a link to your site from an external page, while still blocking most cross-site request forgery vectors.
- **Refresh token: `Strict`** — Sent only on same-site requests. Never sent on cross-site navigations. Combined with path scoping, this ensures the refresh token is only sent to the refresh endpoint from same-origin requests.

### 4.5 Path Scoping for Refresh Token

The refresh token cookie is scoped to `path=/auth` (or whatever `cookies.refreshCookiePath` is configured to). This means the browser only sends the refresh token cookie when making requests to paths that start with `/auth`.

**Why this matters:** If the refresh token cookie had `path=/`, it would be sent on every request to the API, increasing the exposure window. By restricting it to the auth prefix, the refresh token is only transmitted when the client explicitly calls the refresh endpoint.

**Important:** If you change `routePrefix` from the default `'auth'`, you must update `cookies.refreshCookiePath` to match. Otherwise the browser will not send the refresh token to the correct endpoint.

```typescript
// If routePrefix is changed, refreshCookiePath must match
BymaxAuthModule.register({
  routePrefix: 'api/v1/auth',
  cookies: {
    refreshCookiePath: '/api/v1/auth', // MUST match routePrefix
  },
  // ...
});
```

### 4.6 Domain Resolution

For multi-domain deployments (e.g., `api.example.com` and `app.example.com`), cookies need to be set on the correct domain.

```typescript
cookies: {
  resolveDomains: (requestDomain: string) => {
    const ALLOWED_DOMAINS = ['.example.com', 'localhost'];

    // Validate that requestDomain is in the allowlist
    const isAllowed = ALLOWED_DOMAINS.some(d =>
      requestDomain === d.replace(/^\./, '') || requestDomain.endsWith(d)
    );

    if (!isAllowed) {
      // Return safe default — NEVER trust requestDomain blindly
      return ['.example.com'];
    }

    return [`.${requestDomain.split('.').slice(-2).join('.')}`];
  },
}
```

**Security warning:** The `requestDomain` parameter comes from `req.hostname`, which is derived from the HTTP `Host` header. In environments where the `Host` header is not validated by a reverse proxy or load balancer, an attacker can manipulate it to inject arbitrary domains. Always validate against an allowlist.

### 4.7 Shared Cookie Constants

Cookie names and paths are exported from `@bymax-one/nest-auth/shared` to ensure consistency between server and client:

```typescript
// @bymax-one/nest-auth/shared
export const AUTH_ACCESS_COOKIE_NAME = 'access_token';
export const AUTH_REFRESH_COOKIE_NAME = 'refresh_token';
export const AUTH_HAS_SESSION_COOKIE_NAME = 'has_session';
export const AUTH_REFRESH_COOKIE_PATH = '/auth';
```

The `./client`, `./react`, and `./nextjs` subpath exports import these constants internally, eliminating manual synchronization between backend and frontend.

---

## 5. Refresh Token Flow

### 5.1 Rotation Strategy

This package implements **refresh token rotation**: every time a refresh token is used, it is invalidated and a new one is issued. This limits the damage window if a refresh token is compromised — the attacker can use it at most once before it becomes invalid.

Flow:
1. Client sends the current refresh token to `POST /auth/refresh`.
2. `TokenManagerService.reissueTokens()` looks up `auth:rt:{sha256(oldToken)}` in Redis.
3. If found, the old key is deleted atomically and a new refresh token (UUID v4) is generated.
4. The new refresh token is stored in Redis at `auth:rt:{sha256(newToken)}`.
5. A rotation pointer is created at `auth:rp:{sha256(oldToken)} → newRawToken` with a grace window TTL.
6. A new access token JWT is signed and returned alongside the new refresh token.

### 5.2 Grace Window for Concurrent Requests

When the access token expires, multiple in-flight requests may attempt to refresh simultaneously using the same refresh token. Without a grace window, only the first request succeeds and all others fail, causing a poor user experience.

The grace window (default: 30 seconds, configurable via `jwt.refreshGraceWindowSeconds`) solves this:

- When a refresh token is rotated, a pointer key `auth:rp:{sha256(oldToken)}` is created, pointing to the new raw token.
- If a second request arrives with the old token within the grace window, the system detects the pointer and returns the already-issued new token instead of failing.
- After the grace window expires, the pointer is deleted and the old token is fully invalidated.

### 5.3 Atomic Rotation via Lua Script

The rotation operation is performed atomically using a Redis Lua script to prevent race conditions:

```lua
-- Atomic refresh token rotation
local old_key = KEYS[1]              -- auth:rt:{sha256(old)}
local new_key = KEYS[2]              -- auth:rt:{sha256(new)}
local pointer_key = KEYS[3]          -- auth:rp:{sha256(old)}
local new_session_data = ARGV[1]     -- JSON session data
local new_raw_token = ARGV[2]        -- new raw token (for pointer)
local refresh_ttl = tonumber(ARGV[3])  -- TTL in seconds
local grace_ttl = tonumber(ARGV[4])  -- grace window seconds

-- Step 1: Try to get and delete the old session atomically
local session_data = redis.call('GET', old_key)
if session_data then
  redis.call('DEL', old_key)
  -- Step 2: Create rotation pointer (grace window)
  redis.call('SET', pointer_key, new_raw_token, 'EX', grace_ttl)
  -- Step 3: Create new session
  redis.call('SET', new_key, new_session_data, 'EX', refresh_ttl)
  return session_data
end

-- Step 4: If not found, check grace window (concurrent request)
local pointed_token = redis.call('GET', pointer_key)
if pointed_token then
  return 'GRACE:' .. pointed_token
end

-- Step 5: Token invalid or expired
return nil
```

**Why Lua:** Without atomicity, two concurrent requests with the same refresh token could both pass the GET check before either executes the DEL, creating two valid sessions. The Lua script executes as a single atomic operation in Redis.

### 5.4 Redis Storage for Refresh Tokens

| Key Pattern | Value | TTL |
|---|---|---|
| `auth:rt:{sha256(token)}` | JSON: `{ userId, tenantId, role, device, ip, createdAt }` | `refreshExpiresInDays` in seconds |
| `auth:rp:{sha256(oldToken)}` | New raw token string | `refreshGraceWindowSeconds` (default: 30s) |
| `auth:prt:{sha256(token)}` | JSON: `{ userId, role, device, ip, createdAt }` (platform) | `refreshExpiresInDays` in seconds |
| `auth:prp:{sha256(oldToken)}` | New raw token string (platform) | `refreshGraceWindowSeconds` (default: 30s) |

### 5.5 Refresh Token Security Rules

1. **Always hash before storage.** The raw refresh token is never stored in Redis. Only `sha256(token)` is used as the key.
2. **Always rotate.** Never reuse a refresh token. Every successful refresh produces a new token.
3. **Always set TTL.** Refresh token keys must have a TTL matching `refreshExpiresInDays`. Never create a key without expiration.
4. **Revoke on logout.** When a user logs out, delete the refresh token key from Redis immediately.
5. **Revoke all on password change.** When a user changes their password, revoke all refresh sessions to force re-authentication.

---

## 6. Token Blacklisting

### 6.1 Purpose

Access tokens are stateless JWTs — once signed, they are valid until they expire. When a user logs out, the access token remains cryptographically valid for its remaining lifetime. The blacklist bridges this gap by recording revoked tokens in Redis so guards can reject them.

### 6.2 How It Works

On logout:
1. Extract the `jti` claim from the access token (via `decode()`, since the token may already be expired).
2. Store the `jti` in Redis: `SET auth:rv:{jti} "1" EX {remaining_seconds}`.
3. The TTL is calculated as `token.exp - now()` — the blacklist entry only needs to live as long as the token would have been valid.

On every authenticated request:
1. The guard verifies the JWT signature and expiration.
2. If verification succeeds, the guard checks `auth:rv:{payload.jti}` in Redis.
3. If the key exists, the token has been revoked — throw `UnauthorizedException` with `AUTH_ERROR_CODES.TOKEN_REVOKED`.

### 6.3 Key Pattern

```
Key:   auth:rv:{jti}
Value: "1"
TTL:   Remaining seconds until token.exp
```

If for any reason the `jti` claim is not available, the fallback is to use the SHA-256 hash of the entire JWT string as the key: `auth:rv:{sha256(jwt)}`. However, this is more expensive (hashing the full JWT) and should be avoided. Always include `jti` in token payloads.

### 6.4 TTL Strategy

The blacklist entry TTL must match the remaining lifetime of the token, not the full token lifetime. If a token was issued at T and expires at T+15m, and the user logs out at T+10m, the blacklist entry only needs to live for 5 minutes.

```typescript
// Calculate remaining TTL for blacklist
const now = Math.floor(Date.now() / 1000);
const remainingSeconds = payload.exp - now;

if (remainingSeconds > 0) {
  await this.redis.set(
    `${this.namespace}:rv:${payload.jti}`,
    '1',
    'EX',
    remainingSeconds,
  );
}
```

If the token is already expired (`remainingSeconds <= 0`), there is no need to blacklist it — it will fail signature verification anyway.

### 6.5 Blacklist Check in Guards

```typescript
// Inside JwtAuthGuard.canActivate()
if (payload.jti && await this.authRedis.isBlacklisted(payload.jti)) {
  throw new UnauthorizedException(AUTH_ERROR_CODES.TOKEN_REVOKED);
}
```

The `isBlacklisted()` method performs a single `GET` operation on Redis — O(1) with negligible latency. This check runs on every authenticated request, so performance is critical.

### 6.6 When to Blacklist

| Event | Action |
|---|---|
| User logout | Blacklist the current access token's `jti` |
| Password change | Blacklist current token + revoke all refresh sessions |
| Account ban/suspension | Blacklist current token (if available) + user status check catches future requests |
| Admin force-logout | Blacklist the target user's token + revoke refresh sessions |

---

## 7. JWT Payload Design

### 7.1 DashboardJwtPayload

The access token for dashboard/tenant users contains the following claims:

```typescript
export interface DashboardJwtPayload {
  /** Subject — user ID */
  sub: string;

  /** JWT ID — unique token identifier (UUID v4), used for blacklisting */
  jti: string;

  /** Tenant ID the user belongs to */
  tenantId: string;

  /** User's role within the tenant (e.g., 'OWNER', 'ADMIN', 'MEMBER') */
  role: string;

  /** Token type — always 'dashboard' to differentiate from platform tokens */
  type: 'dashboard';

  /** Current user status (e.g., 'ACTIVE', 'PENDING_APPROVAL') */
  status: string;

  /**
   * Whether MFA has been verified in this session.
   * - true: user completed the MFA challenge
   * - false: user has MFA enabled but did not verify in this session
   */
  mfaVerified: boolean;

  /** Issued At — automatically set by @nestjs/jwt */
  iat: number;

  /** Expiration — automatically set based on accessExpiresIn */
  exp: number;
}
```

**Example decoded payload:**

```json
{
  "sub": "clx1abc2def3ghi4jkl",
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "tenantId": "tenant_bymax_finance",
  "role": "OWNER",
  "type": "dashboard",
  "status": "ACTIVE",
  "mfaVerified": true,
  "iat": 1712678400,
  "exp": 1712679300
}
```

### 7.2 PlatformJwtPayload

The access token for platform administrators:

```typescript
export interface PlatformJwtPayload {
  /** Subject — admin ID */
  sub: string;

  /** JWT ID — unique token identifier (UUID v4), used for blacklisting */
  jti: string;

  /** Platform role (e.g., 'SUPER_ADMIN', 'ADMIN', 'SUPPORT') */
  role: string;

  /** Token type — always 'platform' */
  type: 'platform';

  /** Whether MFA has been verified (if enabled for this admin) */
  mfaVerified: boolean;

  /** Issued At */
  iat: number;

  /** Expiration */
  exp: number;
}
```

**Key difference from DashboardJwtPayload:** No `tenantId` or `status` claims. Platform admins operate across all tenants.

### 7.3 MfaTempPayload

The temporary token issued during the MFA challenge window:

```typescript
export interface MfaTempPayload {
  /** Subject — user ID who needs to complete MFA */
  sub: string;

  /** JWT ID — unique token identifier */
  jti: string;

  /** Token type — always 'mfa_challenge' */
  type: 'mfa_challenge';

  /** Origin context: 'dashboard' for tenant users, 'platform' for admins */
  context: 'dashboard' | 'platform';

  /** Issued At */
  iat: number;

  /** Expiration — 5 minutes after issuance */
  exp: number;
}
```

### 7.4 Claim Design Rules

1. **Always include `sub`** — the user/admin ID. This is the standard JWT subject claim.
2. **Always include `jti`** — a UUID v4 generated at sign time. Required for blacklisting.
3. **Always include `type`** — discriminates between `"dashboard"`, `"platform"`, and `"mfa_challenge"`. Guards check this claim first after signature verification.
4. **Never include passwords, secrets, or encryption keys** in the payload.
5. **Never include email addresses** unless absolutely required for authorization logic. In this package, the email is not needed in the JWT — it can be fetched from the database using `sub`.
6. **Keep payloads small.** Every byte in the JWT increases cookie size and network overhead on every request. Include only what guards and middleware need.
7. **Use strings for IDs.** The `sub`, `tenantId`, and `jti` claims are always strings. Do not use numeric IDs.
8. **`iat` and `exp` are managed by `@nestjs/jwt`.** Do not set them manually in the payload object.

### 7.5 Type Discrimination Pattern

Guards use the `type` claim as the first validation step after signature verification:

```typescript
// JwtAuthGuard — accepts only dashboard tokens
if (payload.type !== 'dashboard') {
  throw new UnauthorizedException(AUTH_ERROR_CODES.TOKEN_INVALID);
}

// JwtPlatformGuard — accepts only platform tokens
if (payload.type !== 'platform') {
  throw new UnauthorizedException(AUTH_ERROR_CODES.PLATFORM_AUTH_REQUIRED);
}
```

This prevents a platform admin from using their token to access tenant-scoped endpoints (and vice versa), even though both token types are signed with the same secret.

---

## 8. Guard Implementation

### 8.1 Design Principle: No Passport

This package implements JWT guards natively using `@nestjs/jwt` JwtService directly, without any dependency on Passport.js. This eliminates three dependencies (`passport`, `passport-jwt`, `@nestjs/passport`) and makes the authentication flow more transparent, debuggable, and controllable.

### 8.2 JwtAuthGuard (Dashboard)

The primary guard for all dashboard/tenant endpoints:

```typescript
@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly jwtService: JwtService,
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions,
    private readonly authRedis: AuthRedisService,
    private readonly tokenDelivery: TokenDeliveryService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Step 1: Check @Public() decorator
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) return true;

    // Step 2: Extract token via TokenDeliveryService
    const request = context.switchToHttp().getRequest();
    const token = this.tokenDelivery.extractAccessToken(request);
    if (!token) {
      throw new UnauthorizedException(AUTH_ERROR_CODES.TOKEN_MISSING);
    }

    try {
      // Step 3: Verify signature with pinned algorithm
      const payload = this.jwtService.verify<DashboardJwtPayload>(token, {
        secret: this.options.jwt.secret,
        algorithms: ['HS256'],  // MANDATORY — prevents algorithm confusion
      });

      // Step 4: Validate token type
      if (payload.type !== 'dashboard') {
        throw new UnauthorizedException(AUTH_ERROR_CODES.TOKEN_INVALID);
      }

      // Step 5: Check blacklist
      if (payload.jti && await this.authRedis.isBlacklisted(payload.jti)) {
        throw new UnauthorizedException(AUTH_ERROR_CODES.TOKEN_REVOKED);
      }

      // Step 6: Populate request.user
      request.user = payload;
      return true;
    } catch (error) {
      if (error instanceof UnauthorizedException) throw error;
      // Any other error (expired, malformed, bad signature) → generic invalid
      throw new UnauthorizedException(AUTH_ERROR_CODES.TOKEN_INVALID);
    }
  }
}
```

### 8.3 Guard Execution Order

Guards are applied in a specific order via `@UseGuards()`. The order matters because each guard depends on the previous one having run:

```
JwtAuthGuard        →  Extracts and verifies JWT, populates request.user
  ↓
UserStatusGuard     →  Checks user status against blockedStatuses (uses request.user.sub)
  ↓
MfaRequiredGuard    →  Checks mfaVerified claim (uses request.user.mfaVerified)
  ↓
RolesGuard          →  Checks role hierarchy (uses request.user.role)
```

```typescript
// Correct guard ordering
@Controller('users')
@UseGuards(JwtAuthGuard, UserStatusGuard, RolesGuard)
export class UsersController {
  // ...
}
```

### 8.4 Token Extraction Logic

The guard delegates token extraction to `TokenDeliveryService`, which behaves differently based on the configured `tokenDelivery` mode:

| Mode | Access Token Source | Refresh Token Source |
|---|---|---|
| `'cookie'` | `req.cookies[accessTokenName]` | `req.cookies[refreshTokenName]` |
| `'bearer'` | `Authorization: Bearer <token>` header | `req.body.refreshToken` |
| `'both'` | Cookie first, then `Authorization` header | Cookie first, then `req.body` |

### 8.5 All Guards Reference

| Guard | Validates | Rejects With | Notes |
|---|---|---|---|
| `JwtAuthGuard` | Dashboard JWT (`type: "dashboard"`) | `TOKEN_MISSING`, `TOKEN_INVALID`, `TOKEN_REVOKED` | Respects `@Public()` |
| `JwtPlatformGuard` | Platform JWT (`type: "platform"`) | `TOKEN_MISSING`, `PLATFORM_AUTH_REQUIRED`, `TOKEN_REVOKED` | Same logic, different type check |
| `UserStatusGuard` | User status not in `blockedStatuses` | `ACCOUNT_BANNED`, `ACCOUNT_INACTIVE`, `ACCOUNT_SUSPENDED` | Checks Redis cache, then DB |
| `MfaRequiredGuard` | `mfaVerified === true` | `MFA_REQUIRED` | Respects `@SkipMfa()` |
| `RolesGuard` | Role hierarchy via `@Roles()` metadata | `FORBIDDEN` | Hierarchical: OWNER > ADMIN > MEMBER |
| `PlatformRolesGuard` | Platform role hierarchy | `FORBIDDEN` | Uses `platformHierarchy` config |
| `SelfOrAdminGuard` | `params.userId === user.sub` OR admin role | `FORBIDDEN` | Prevents IDOR attacks |
| `OptionalAuthGuard` | JWT if present, null if absent | Never throws | For public endpoints with optional auth |
| `WsJwtGuard` | JWT from WebSocket handshake `Authorization` header | Disconnects client | Never uses query params (security) |

### 8.6 WebSocket Guard

The `WsJwtGuard` extracts the JWT from the WebSocket handshake `Authorization` header, never from query parameters. Tokens in query parameters are logged in plaintext by proxies, CDNs, and web server access logs, making them a security risk.

```typescript
// WsJwtGuard extraction
const authHeader = client.handshake?.headers?.authorization;
if (!authHeader?.startsWith('Bearer ')) {
  throw new WsException('Unauthorized');
}
const token = authHeader.slice(7);
```

### 8.7 Decorators for Guard Integration

| Decorator | Target | Description |
|---|---|---|
| `@CurrentUser()` | Method parameter | Extracts `request.user`. Supports property access: `@CurrentUser('sub')` |
| `@Roles(...roles)` | Method or class | Sets required roles for `RolesGuard` |
| `@PlatformRoles(...roles)` | Method or class | Sets required platform roles for `PlatformRolesGuard` |
| `@Public()` | Method or class | Marks endpoint as public — `JwtAuthGuard` skips validation |
| `@SkipMfa()` | Method or class | Allows access without MFA verification (e.g., MFA setup endpoint) |

### 8.8 Error Handling in Guards

Guards must distinguish between specific error conditions:

```typescript
// Correct error handling
try {
  const payload = this.jwtService.verify(token, {
    secret: this.options.jwt.secret,
    algorithms: ['HS256'],
  });
  // ... type check, blacklist check ...
} catch (error) {
  // Re-throw our own UnauthorizedExceptions (specific error codes)
  if (error instanceof UnauthorizedException) throw error;

  // Catch-all for jsonwebtoken errors:
  // - TokenExpiredError → token has expired
  // - JsonWebTokenError → malformed token, bad signature
  // - NotBeforeError → token not yet valid
  // Map all to TOKEN_INVALID — do not leak internal error details
  throw new UnauthorizedException(AUTH_ERROR_CODES.TOKEN_INVALID);
}
```

**Never expose the underlying error message** (e.g., "jwt expired", "invalid signature") to the client. These details help attackers understand the token validation pipeline. Use generic error codes.

---

## 9. Security Best Practices

### 9.1 Secret Strength Validation

The JWT secret is validated at module startup. The package rejects weak secrets with the following criteria:

1. **Minimum length:** 32 characters.
2. **Minimum Shannon entropy:** 3.5 bits per character.
3. **Pattern rejection:** Rejects strings where all characters are identical (e.g., `'aaaa...'`) or that follow repetitive patterns.
4. **Recommended generation:** `crypto.randomBytes(32).toString('base64')` produces a 44-character string with approximately 5.9 bits of entropy per character.

```typescript
// Generating a strong JWT secret
import { randomBytes } from 'node:crypto';

const secret = randomBytes(32).toString('base64');
// Example: "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols="
// Length: 44 chars, Entropy: ~5.9 bits/char
```

The same validation criteria apply to `mfa.encryptionKey`.

### 9.2 Algorithm Restriction

This package exclusively uses **HS256** (HMAC-SHA256). No other algorithms are supported or should be added.

Why HS256 only:
- Single shared secret simplifies key management.
- No need for RSA/ECDSA key pairs (this is a library consumed by a single backend, not a distributed system with multiple verifiers).
- Algorithm confusion attacks are prevented by pinning `algorithms: ['HS256']` at verification time.
- The `algorithm` option in `BymaxAuthModuleOptions.jwt` only accepts the literal type `"HS256"` — it cannot be set to any other value at the TypeScript level.

### 9.3 Timing-Safe Comparison

When comparing token values (e.g., verifying that a refresh token matches a stored value), always use constant-time comparison to prevent timing attacks:

```typescript
import { timingSafeEqual } from 'node:crypto';

function safeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
```

Note: JWT signature verification through `@nestjs/jwt` / `jsonwebtoken` already uses timing-safe comparison internally. This guidance applies to any custom token comparison logic you write.

### 9.4 No Sensitive Data in Payloads

JWT payloads are base64url-encoded, **not encrypted**. Anyone with the token can decode it and read the claims. Never include:

- Passwords or password hashes
- Encryption keys or secrets
- Email addresses (unless required for authorization)
- Phone numbers
- Physical addresses
- Financial information
- Any data that would cause harm if exposed

The payload should contain only the minimum claims needed for authorization decisions: user ID, tenant ID, role, status, MFA state, and token metadata.

### 9.5 Token Storage on the Client

| Storage Location | Acceptable For | Security Notes |
|---|---|---|
| HttpOnly cookie (automatic) | Access token, refresh token | Best option for web. JavaScript cannot access. |
| In-memory variable | Access token (bearer mode) | Lost on page refresh. Acceptable for SPAs that refresh from the refresh token. |
| iOS Keychain | Refresh token (bearer mode) | Platform-secured storage. Appropriate for native iOS apps. |
| Android Keystore | Refresh token (bearer mode) | Platform-secured storage. Appropriate for native Android apps. |
| `localStorage` | **NEVER** | Accessible to any JavaScript on the page. XSS leads to token theft. |
| `sessionStorage` | **NEVER** | Same XSS risk as localStorage. |
| URL query parameters | **NEVER** | Logged by servers, proxies, CDNs. Visible in browser history. |

### 9.6 HTTPS Requirement

All JWT-based authentication must be served over HTTPS in production. The `Secure` cookie flag prevents transmission over unencrypted connections, but this is only effective if the server enforces HTTPS. Configure your reverse proxy or load balancer to redirect HTTP to HTTPS.

### 9.7 Token ID (jti) Generation

The `jti` claim must be a UUID v4 generated using a cryptographically secure random number generator:

```typescript
import { randomUUID } from 'node:crypto';

const jti = randomUUID();
```

Do not use incrementing counters, timestamps, or non-random values for `jti`. The `jti` serves as the blacklist key and must be unpredictable.

### 9.8 Hashing Tokens Before Storage

All tokens stored in Redis are identified by their SHA-256 hash, never the raw token value:

```typescript
import { createHash } from 'node:crypto';

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// Storage key: auth:rt:{hashToken(refreshToken)}
```

This ensures that if the Redis store is compromised, the raw token values remain secret.

### 9.9 Multi-Tenant Security

In multi-tenant environments with subdomain-based routing:
- The `JwtAuthGuard` should validate that the `tenantId` in the JWT matches the tenant of the current request.
- Using `domain='.example.com'` for cookies sends them to all subdomains, which could enable cross-subdomain token leakage.
- Prefer specific subdomain cookie domains when possible.
- Implement tenant validation middleware in the host application.

---

## 10. Anti-Patterns

### 10.1 Storing Tokens in localStorage

```typescript
// WRONG — XSS vulnerability, token accessible to any script on the page
localStorage.setItem('accessToken', token);
const token = localStorage.getItem('accessToken');

// CORRECT — Use HttpOnly cookies (automatic in cookie/both mode)
// Or in-memory storage for bearer mode:
let accessToken: string | null = null; // module-scoped variable
accessToken = response.accessToken;
```

### 10.2 Omitting Algorithm Pinning at Verification

```typescript
// WRONG — Accepts whatever algorithm the token header specifies
const payload = this.jwtService.verify(token, {
  secret: this.options.jwt.secret,
  // Missing algorithms: ['HS256'] ← VULNERABLE to algorithm confusion
});

// CORRECT — Algorithm pinned explicitly
const payload = this.jwtService.verify(token, {
  secret: this.options.jwt.secret,
  algorithms: ['HS256'],
});
```

### 10.3 Using ignoreExpiration

```typescript
// WRONG — Defeats the purpose of token expiration
const payload = this.jwtService.verify(token, {
  secret: this.options.jwt.secret,
  algorithms: ['HS256'],
  ignoreExpiration: true, // NEVER do this
});

// CORRECT — Use decode() when you need claims from expired tokens
const payload = this.jwtService.decode(token);
// But NEVER use decoded payload for authorization decisions
```

### 10.4 Skipping Blacklist Check

```typescript
// WRONG — Revoked tokens are accepted until they expire
async canActivate(context: ExecutionContext): Promise<boolean> {
  const payload = this.jwtService.verify(token, { ... });
  request.user = payload;
  return true; // Missing blacklist check!
}

// CORRECT — Always check the blacklist after verification
async canActivate(context: ExecutionContext): Promise<boolean> {
  const payload = this.jwtService.verify(token, { ... });

  if (payload.jti && await this.authRedis.isBlacklisted(payload.jti)) {
    throw new UnauthorizedException(AUTH_ERROR_CODES.TOKEN_REVOKED);
  }

  request.user = payload;
  return true;
}
```

### 10.5 Skipping Token Type Validation

```typescript
// WRONG — A platform admin could access tenant endpoints
const payload = this.jwtService.verify(token, { ... });
request.user = payload; // No type check!

// CORRECT — Validate the type claim
const payload = this.jwtService.verify(token, { ... });
if (payload.type !== 'dashboard') {
  throw new UnauthorizedException(AUTH_ERROR_CODES.TOKEN_INVALID);
}
request.user = payload;
```

### 10.6 Setting exp Manually in Payload

```typescript
// WRONG — Conflicts with expiresIn option, unpredictable behavior
const token = this.jwtService.sign(
  { sub: user.id, exp: Math.floor(Date.now() / 1000) + 900, ... },
  { secret, algorithm: 'HS256', expiresIn: '15m' },
);

// CORRECT — Let expiresIn handle the exp claim
const token = this.jwtService.sign(
  { sub: user.id, jti: randomUUID(), type: 'dashboard', ... },
  { secret, algorithm: 'HS256', expiresIn: '15m' },
);
```

### 10.7 Extracting Tokens Directly from Request

```typescript
// WRONG — Bypasses delivery mode logic, breaks when mode changes
const token = req.cookies?.['access_token'];
// or
const token = req.headers.authorization?.split(' ')[1];

// CORRECT — Use TokenDeliveryService
const token = this.tokenDelivery.extractAccessToken(req);
```

### 10.8 Returning JWT Error Details to Client

```typescript
// WRONG — Leaks internal error information to attackers
catch (error) {
  throw new UnauthorizedException(error.message);
  // Exposes: "jwt expired", "invalid signature", "jwt malformed"
}

// CORRECT — Use generic error codes
catch (error) {
  if (error instanceof UnauthorizedException) throw error;
  throw new UnauthorizedException(AUTH_ERROR_CODES.TOKEN_INVALID);
}
```

### 10.9 Storing Raw Refresh Tokens in Redis

```typescript
// WRONG — If Redis is compromised, raw tokens are exposed
await this.redis.set(`auth:rt:${refreshToken}`, sessionData);

// CORRECT — Hash the token before using as key
const hash = createHash('sha256').update(refreshToken).digest('hex');
await this.redis.set(`auth:rt:${hash}`, sessionData);
```

### 10.10 Sending Tokens in WebSocket Query Parameters

```typescript
// WRONG — Query params are logged by proxies, CDNs, and access logs
const socket = io('wss://api.example.com?token=eyJhbG...');

// CORRECT — Use Authorization header in handshake
const socket = io('wss://api.example.com', {
  extraHeaders: {
    Authorization: `Bearer ${accessToken}`,
  },
});
```

### 10.11 Creating Refresh Tokens Without TTL

```typescript
// WRONG — Key lives forever in Redis, never cleaned up
await this.redis.set(`auth:rt:${hash}`, sessionData);

// CORRECT — Always set TTL
const ttlSeconds = this.options.jwt.refreshExpiresInDays * 86400;
await this.redis.set(`auth:rt:${hash}`, sessionData, 'EX', ttlSeconds);
```

### 10.12 Using a Weak JWT Secret

```typescript
// WRONG — Easily guessable or brutable
jwt: {
  secret: 'mysecret',          // Too short
  secret: 'password123456789012345678901234', // Low entropy
  secret: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', // Repetitive
}

// CORRECT — Cryptographically random, high entropy
jwt: {
  secret: crypto.randomBytes(32).toString('base64'),
  // "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols="
}
```

### 10.13 Trusting req.hostname Without Validation in resolveDomains

```typescript
// WRONG — Host header injection leads to cookie tossing
cookies: {
  resolveDomains: (requestDomain) => [requestDomain], // Attacker controls this!
}

// CORRECT — Validate against allowlist
cookies: {
  resolveDomains: (requestDomain) => {
    const ALLOWED = ['.example.com', 'localhost'];
    const isAllowed = ALLOWED.some(d =>
      requestDomain === d.replace(/^\./, '') || requestDomain.endsWith(d)
    );
    if (!isAllowed) return ['.example.com'];
    return [`.${requestDomain.split('.').slice(-2).join('.')}`];
  },
}
```

---

## Quick Reference Checklist

Use this checklist when writing or reviewing JWT-related code in this project.

### Signing

- [ ] Always pass `secret` explicitly to `jwtService.sign()`.
- [ ] Always pass `algorithm: 'HS256'` to `jwtService.sign()`.
- [ ] Always pass `expiresIn` to `jwtService.sign()`. Never set `exp` in the payload.
- [ ] Always generate `jti` as `randomUUID()` before signing.
- [ ] Always include the `type` claim (`'dashboard'`, `'platform'`, or `'mfa_challenge'`).
- [ ] Never include sensitive data (passwords, secrets, PII) in the payload.

### Verification

- [ ] Always pass `algorithms: ['HS256']` to `jwtService.verify()`. Never omit this.
- [ ] Always pass `secret` explicitly to `jwtService.verify()`.
- [ ] Never use `ignoreExpiration: true`.
- [ ] Always validate the `type` claim after verification.
- [ ] Always check the blacklist (`auth:rv:{jti}`) after verification.
- [ ] Never expose internal error messages to the client.

### Token Delivery

- [ ] Always use `TokenDeliveryService` to extract tokens. Never read `req.cookies` or `req.headers.authorization` directly.
- [ ] Always use `TokenDeliveryService` to deliver tokens. Never set cookies or response body fields directly.
- [ ] For bearer mode, document that the client must use secure storage (Keychain, Keystore, safeStorage).

### Cookies

- [ ] Access token cookie: `HttpOnly`, `Secure` (prod), `SameSite=Lax`, `Path=/`.
- [ ] Refresh token cookie: `HttpOnly`, `Secure` (prod), `SameSite=Strict`, `Path=/auth`.
- [ ] Session signal cookie: NOT HttpOnly, value `"1"` only.
- [ ] If `routePrefix` changes, update `refreshCookiePath` to match.
- [ ] Validate `resolveDomains` input against an allowlist.

### Refresh Tokens

- [ ] Refresh tokens are opaque UUIDs, never JWTs.
- [ ] Always hash refresh tokens with SHA-256 before using as Redis keys.
- [ ] Always rotate refresh tokens on use (never reuse).
- [ ] Always set TTL on refresh token Redis keys.
- [ ] Use Lua script for atomic rotation to prevent race conditions.
- [ ] Implement grace window for concurrent refresh requests.

### Blacklisting

- [ ] Blacklist access tokens on logout using the `jti` claim.
- [ ] Set blacklist TTL to the remaining token lifetime, not the full lifetime.
- [ ] Do not blacklist already-expired tokens.

### Guards

- [ ] `JwtAuthGuard`: Verify signature, check type `"dashboard"`, check blacklist, populate `request.user`.
- [ ] `JwtPlatformGuard`: Same flow, check type `"platform"`.
- [ ] Guard order: `JwtAuthGuard` > `UserStatusGuard` > `MfaRequiredGuard` > `RolesGuard`.
- [ ] `WsJwtGuard`: Extract from handshake `Authorization` header, never from query params.
- [ ] `OptionalAuthGuard`: Set `request.user = null` if no token, never throw.

### Secrets

- [ ] JWT secret: minimum 32 characters, high entropy (>3.5 bits/char).
- [ ] Generate with `crypto.randomBytes(32).toString('base64')`.
- [ ] Validate secret strength at module startup.
- [ ] Store secrets in environment variables, never in source code.

### Redis Key Patterns

| Prefix | Key Pattern | Purpose |
|---|---|---|
| `rt` | `auth:rt:{sha256(token)}` | Dashboard refresh session |
| `rv` | `auth:rv:{jti}` | Access token blacklist |
| `rp` | `auth:rp:{sha256(oldToken)}` | Refresh rotation grace pointer |
| `prt` | `auth:prt:{sha256(token)}` | Platform refresh session |
| `prp` | `auth:prp:{sha256(oldToken)}` | Platform rotation grace pointer |
| `mfa` | `auth:mfa:{sha256(token)}` | MFA temp token (single-use) |
| `us` | `auth:us:{userId}` | User status cache |
| `sess` | `auth:sess:{userId}` | Session SET (all active sessions) |
| `sd` | `auth:sd:{sessionHash}` | Session details |

---

*This document is the authoritative reference for JWT authentication in `@bymax-one/nest-auth`. When in doubt, consult this file. When this file and code diverge, update the code to match these guidelines.*
