# @bymax-one/nest-auth - Complete Technical Specification

> **Version:** 1.0.0
> **Last updated:** 2026-04-09
> **Status:** Draft for implementation
> **Type:** Public npm package (`@bymax-one/nest-auth`)

---

## Table of Contents

1. [Overview and Value Proposition](#1-overview-and-value-proposition)
2. [Architecture](#2-architecture)
3. [Package Structure](#3-package-structure)
4. [Configuration API](#4-configuration-api)
5. [Repository Contracts](#5-repository-contracts)
6. [Services](#6-services)
7. [Controllers](#7-controllers)
8. [Guards and Decorators](#8-guards-and-decorators)
9. [Hooks System](#9-hooks-system)
10. [Email Provider Interface](#10-email-provider-interface)
11. [OAuth System](#11-oauth-system)
12. [Redis Strategy](#12-redis-strategy)
13. [JWT Claims Structure](#13-jwt-claims-structure)
14. [Cookie Management](#14-cookie-management)
15. [Error Codes Catalog](#15-error-codes-catalog)
16. [Rate Limiting](#16-rate-limiting)
17. [What is NOT in the Package](#17-what-is-not-in-the-package)
18. [Dependencies](#18-dependencies)
19. [Implementation Phases](#19-implementation-phases)
20. [Known Limitations](#20-known-limitations)
21. [Frontend Integration](#21-frontend-integration)

---

## 1. Overview and Value Proposition

### 1.1 What `@bymax-one/nest-auth` is

`@bymax-one/nest-auth` is a **full-stack public npm package** for authentication and authorization in the Bymax SaaS ecosystem. It encapsulates all authentication logic — registration, login, JWT, refresh tokens, MFA, sessions, OAuth, password reset, invitations, and platform administration — in a single package with **subpath exports** that cover backend (NestJS), framework-agnostic client (native fetch), React hooks, and Next.js 16 integration (proxy, route handlers, JWT helpers).

Following the Better Auth pattern, the package is distributed as a single `npm install` with multiple entry points:

- `@bymax-one/nest-auth` — NestJS backend module (guards, services, controllers)
- `@bymax-one/nest-auth/shared` — Shared types and constants (zero deps)
- `@bymax-one/nest-auth/client` — Fetch-based auth client (zero deps)
- `@bymax-one/nest-auth/react` — React hooks (useSession, useAuth, AuthProvider)
- `@bymax-one/nest-auth/nextjs` — Proxy factory, route handlers, JWT helpers for Next.js 16

### 1.2 Why it exists

In a multi-tenant SaaS architecture, each application in the Bymax ecosystem needs robust authentication. Instead of reimplementing the same logic in each service, `@bymax-one/nest-auth` centralizes that responsibility in a shared package that:

- **Eliminates code duplication** across ecosystem services
- **Ensures consistency** in authentication behavior
- **Reduces development time** for new services to minutes
- **Maintains uniform security standards** (hashing, tokens, MFA, brute-force)
- **Simplifies maintenance** — security fixes are propagated with a single `npm update`

### 1.3 Who uses it

- **SaaS applications in the Bymax ecosystem** (tenant dashboards, internal APIs)
- **Platform administration panel** (super-admins who manage tenants)
- **Any NestJS application** that needs complete and configurable authentication
- **Frontend applications** (React, Next.js) that consume the `./client`, `./react`, and `./nextjs` subpaths

### 1.4 Distribution model

| Aspect    | Detail                                                       |
| --------- | ------------------------------------------------------------ |
| Registry  | public npm (`@bymax-one/nest-auth`)                          |
| Cost      | Zero — open source package                                   |
| License   | MIT                                                          |
| Runtime   | Node.js 24+                                                  |
| Framework | NestJS 11+ (server), Next.js 16+ (nextjs), React 19+ (react) |
| Subpaths  | `.` (server), `./shared`, `./client`, `./react`, `./nextjs`  |

### 1.5 Design principles

1. **Configuration over convention**: Everything is configurable, but sensible defaults are present
2. **Dependency inversion**: The package defines interfaces; the host application provides implementations
3. **Separation of concerns**: Authentication in the package, persistence and email in the application
4. **Security by default**: scrypt (`node:crypto`), AES-256-GCM, HttpOnly cookies, token blacklist, brute-force protection
5. **Zero opinion on persistence**: The package defines contracts (TypeScript interfaces) and never imports any ORM. The consuming app implements the repositories with the technology of its choice. Developed and tested with Prisma — compatible with TypeORM, Drizzle, and other SQL ORMs by design. Document ORMs (Mongoose) require extra mapping to the `AuthUser` contract
6. **Full-stack by design**: Server and client share types and cookie constants via `./shared`, eliminating manual synchronization and ensuring end-to-end consistency between backend and frontend
7. **Zero external cryptography dependencies**: All hashing (scrypt), TOTP (HMAC-SHA1), encryption (AES-256-GCM), and OAuth functionality use native `node:crypto` and `fetch` — no third-party packages with C++ bindings or supply chain risk

### 1.6 Module categorization

The package organizes its functionality into four layers with distinct activation levels:

#### Core (always active)

Functionality that is registered automatically and cannot be disabled:

| Module                   | Responsibility                                                       |
| ------------------------ | -------------------------------------------------------------------- |
| **AuthService**          | Registration, login, logout, refresh, me                             |
| **PasswordService**      | Password hashing and comparison (native scrypt)                      |
| **TokenManagerService**  | JWT issuance and verification                                        |
| **TokenDeliveryService** | Token delivery (cookies, body, or both) according to `tokenDelivery` |
| **BruteForceService**    | Brute-force protection by email                                      |
| **AuthRedisService**     | Redis operations (blacklist, refresh sessions)                       |
| **JwtAuthGuard**         | JWT validation in cookie or `Authorization: Bearer` header           |
| **RolesGuard**           | Role-based access control                                            |
| **UserStatusGuard**      | Blocking of inactive/banned users                                    |
| **PasswordResetService** | Password reset flow                                                  |

#### Security Extensions (opt-in via configuration)

Enabled when the corresponding configuration is provided:

| Module             | Activation                                                                    | Responsibility                      |
| ------------------ | ----------------------------------------------------------------------------- | ----------------------------------- |
| **MfaService**     | `mfa: { ... }`                                                                | TOTP, recovery codes, MFA challenge |
| **SessionService** | `sessions: { enabled: true }`                                                 | Session tracking, FIFO eviction     |
| **OtpService**     | `passwordReset: { method: 'otp' }` or `emailVerification: { required: true }` | OTP codes by email                  |

#### Platform Extensions (opt-in via configuration)

Functionality for platform administration:

| Module                  | Activation                       | Responsibility                    |
| ----------------------- | -------------------------------- | --------------------------------- |
| **PlatformAuthService** | `platform: { enabled: true }`    | Login and JWT for platform admins |
| **InvitationService**   | `invitations: { enabled: true }` | User invitations by email         |

#### Integrations (opt-in via configuration)

External authentication providers:

| Module             | Activation                   | Responsibility        |
| ------------------ | ---------------------------- | --------------------- |
| **Google OAuth**   | `oauth: { google: { ... } }` | Login via Google      |
| _Future providers_ | `oauth: { github: { ... } }` | Extensible via plugin |

> **Principle:** When an opt-in module is not configured, its controllers, guards, and services are **not registered** in the NestJS container. This ensures zero overhead and no unnecessary dependencies.

---

## 2. Architecture

### 2.1 NestJS dynamic module pattern

`@bymax-one/nest-auth` uses the NestJS **Dynamic Module** pattern. This means it **is not a separate service** — it runs **inside each SaaS application** as an imported module. The host application controls:

- The database connection (via injected repositories)
- Email sending (via injected email provider)
- The Redis instance (via injected Redis client)
- Lifecycle hooks (via injected hooks)

```
┌──────────────────────────────────────────────┐
│              Host Application (SaaS)          │
│                                              │
│  ┌────────────────────────────────────────┐  │
│  │           @bymax-one/nest-auth module           │  │
│  │                                        │  │
│  │  Controllers ←→ Services ←→ Redis      │  │
│  │       ↕              ↕                 │  │
│  │   Guards          Strategies           │  │
│  │       ↕              ↕                 │  │
│  │  Decorators      Token Manager         │  │
│  └────────┬───────────┬──────────────────┘  │
│           │           │                      │
│    ┌──────▼──┐  ┌─────▼──────┐              │
│    │ IUser   │  │ IEmail     │              │
│    │ Repo    │  │ Provider   │              │
│    │(Prisma) │  │ (Resend)   │              │
│    └─────────┘  └────────────┘              │
│                                              │
│    ┌──────────┐  ┌───────────┐              │
│    │ Redis    │  │ IAuth     │              │
│    │ Client   │  │ Hooks     │              │
│    │(ioredis) │  │ (custom)  │              │
│    └──────────┘  └───────────┘              │
└──────────────────────────────────────────────┘
```

### 2.2 Initialization flow

1. The host application calls `BymaxAuthModule.registerAsync({ ... })`
2. The module resolves the configuration options via `ConfigService` or factory
3. The injected providers (repositories, email, Redis, hooks) are validated
4. Controllers are registered conditionally based on the `controllers.*` options
5. Strategies and guards are configured automatically
6. The module is ready to process requests

### 2.3 Flow of an authenticated request

```
HTTP request
    │
    ▼
JwtAuthGuard (extracts JWT from cookie/header)
    │
    ▼
UserStatusGuard (checks Redis cache → user status)
    │
    ▼
MfaRequiredGuard (checks whether MFA was completed, if required)
    │
    ▼
RolesGuard (checks role hierarchy)
    │
    ▼
Controller → Service → Repository (via interface)
    │
    ▼
HTTP response
```

---

## 3. Package Structure

### 3.1 Complete directory tree

The package is organized into 5 subpaths with distinct responsibilities:

```
@bymax-one/nest-auth/
├── package.json
├── tsconfig.json
├── tsconfig.build.json
├── src/
│   ├── server/                              # NestJS backend
│   │   ├── index.ts                         # Barrel export (server)
│   │   ├── bymax-auth.module.ts    # Root dynamic module
│   │   ├── bymax-auth.constants.ts # Injection tokens
│   │   ├── interfaces/
│   │   │   ├── auth-module-options.interface.ts
│   │   │   ├── user-repository.interface.ts
│   │   │   ├── platform-user-repository.interface.ts
│   │   │   ├── email-provider.interface.ts
│   │   │   ├── auth-hooks.interface.ts
│   │   │   ├── oauth-provider.interface.ts  # Interface with native fetch
│   │   │   ├── jwt-payload.interface.ts
│   │   │   ├── auth-result.interface.ts
│   │   │   └── authenticated-request.interface.ts
│   │   ├── config/
│   │   │   ├── default-options.ts
│   │   │   └── resolved-options.ts
│   │   ├── services/
│   │   │   ├── auth.service.ts
│   │   │   ├── password.service.ts          # scrypt (node:crypto)
│   │   │   ├── token-manager.service.ts
│   │   │   ├── session.service.ts
│   │   │   ├── mfa.service.ts               # Native TOTP (node:crypto HMAC-SHA1)
│   │   │   ├── password-reset.service.ts
│   │   │   ├── otp.service.ts
│   │   │   ├── brute-force.service.ts
│   │   │   ├── platform-auth.service.ts
│   │   │   ├── invitation.service.ts
│   │   │   └── token-delivery.service.ts
│   │   ├── constants/
│   │   │   ├── index.ts
│   │   │   ├── throttle-configs.ts
│   │   │   └── error-codes.ts
│   │   ├── redis/
│   │   │   ├── auth-redis.service.ts
│   │   │   └── auth-redis.module.ts
│   │   ├── controllers/
│   │   │   ├── auth.controller.ts
│   │   │   ├── mfa.controller.ts
│   │   │   ├── password-reset.controller.ts
│   │   │   ├── session.controller.ts
│   │   │   ├── platform-auth.controller.ts
│   │   │   └── invitation.controller.ts
│   │   ├── guards/                          # Native JWT guards (no Passport)
│   │   │   ├── jwt-auth.guard.ts
│   │   │   ├── jwt-platform.guard.ts
│   │   │   ├── roles.guard.ts
│   │   │   ├── platform-roles.guard.ts
│   │   │   ├── user-status.guard.ts
│   │   │   ├── mfa-required.guard.ts
│   │   │   ├── ws-jwt.guard.ts
│   │   │   ├── self-or-admin.guard.ts
│   │   │   └── optional-auth.guard.ts
│   │   ├── decorators/
│   │   │   ├── current-user.decorator.ts
│   │   │   ├── roles.decorator.ts
│   │   │   ├── platform-roles.decorator.ts
│   │   │   ├── public.decorator.ts
│   │   │   └── skip-mfa.decorator.ts
│   │   ├── oauth/
│   │   │   ├── oauth.module.ts
│   │   │   ├── oauth.service.ts
│   │   │   └── google/
│   │   │       └── google-oauth.plugin.ts   # native fetch (no Passport)
│   │   ├── providers/
│   │   │   └── no-op-email.provider.ts
│   │   ├── hooks/
│   │   │   └── no-op-auth.hooks.ts
│   │   ├── dto/
│   │   │   ├── register.dto.ts
│   │   │   ├── login.dto.ts
│   │   │   ├── forgot-password.dto.ts
│   │   │   ├── reset-password.dto.ts
│   │   │   ├── mfa-verify.dto.ts
│   │   │   ├── mfa-challenge.dto.ts
│   │   │   ├── mfa-disable.dto.ts
│   │   │   ├── platform-login.dto.ts
│   │   │   ├── accept-invitation.dto.ts
│   │   │   └── create-invitation.dto.ts
│   │   ├── crypto/
│   │   │   ├── aes-gcm.ts                  # AES-256-GCM encryption
│   │   │   ├── secure-token.ts             # Secure token generation
│   │   │   ├── scrypt.ts                   # Password hashing (node:crypto)
│   │   │   └── totp.ts                     # Native TOTP/HOTP (RFC 4226/6238)
│   │   ├── utils/
│   │   │   ├── sleep.ts                     # Delay utility for timing normalization
│   │   │   └── roles.util.ts               # hasRole() helper for role hierarchy
│   │   └── errors/
│   │       ├── auth-error-codes.ts
│   │       └── auth-exception.ts
│   │
│   ├── shared/                              # Types and constants (zero deps)
│   │   ├── index.ts
│   │   ├── types/
│   │   │   ├── auth-user.types.ts           # AuthUser subset for client
│   │   │   ├── auth-result.types.ts         # Response shapes
│   │   │   ├── auth-error.types.ts          # Error codes and error shapes
│   │   │   ├── jwt-payload.types.ts         # DashboardJwtPayload, PlatformJwtPayload
│   │   │   └── auth-config.types.ts         # Cookie names, paths, role types
│   │   └── constants/
│   │       ├── error-codes.ts               # AUTH_ERROR_CODES
│   │       ├── cookie-defaults.ts           # Default cookie names and paths
│   │       └── routes.ts                    # Auth endpoint paths
│   │
│   ├── client/                              # Native fetch client (zero deps)
│   │   ├── index.ts
│   │   ├── createAuthClient.ts              # Main factory
│   │   ├── createAuthFetch.ts               # Fetch wrapper with automatic refresh
│   │   └── types.ts                         # AuthClientConfig, AuthSession
│   │
│   ├── react/                               # React hooks
│   │   ├── index.ts
│   │   ├── types.ts                         # AuthProviderProps, SessionState, AuthContextValue
│   │   ├── AuthProvider.tsx                  # Context provider
│   │   ├── useSession.ts                    # Hook: session data, loading, error
│   │   ├── useAuth.ts                       # Hook: login(), logout(), register()
│   │   └── useAuthStatus.ts                 # Hook: isAuthenticated, isLoading
│   │
│   └── nextjs/                              # Next.js 16 integration
│       ├── index.ts
│       ├── createAuthProxy.ts               # Factory for proxy.ts
│       ├── createSilentRefreshHandler.ts    # GET /api/auth/silent-refresh
│       ├── createClientRefreshHandler.ts    # POST /api/auth/client-refresh
│       ├── createLogoutHandler.ts           # POST /api/auth/logout
│       └── helpers/
│           ├── buildSilentRefreshUrl.ts
│           ├── isBackgroundRequest.ts
│           ├── dedupeSetCookieHeaders.ts
│           └── jwt.ts                       # decodeJwtToken, verifyJwtToken
```

**Dependency graph between subpaths:**

```
   shared (zero deps — types + constants)
   ↗    ↖
server    client (depends on shared)
            ↑
          react (depends on client + shared)
            ↑
         nextjs (depends on client + shared, peerDep: next)
```

### 3.2 Subpath exports

The package uses the `exports` field of `package.json` to expose multiple entry points with automatic tree-shaking:

| Subpath      | Entry point            | Description                                 | Dependencies        |
| ------------ | ---------------------- | ------------------------------------------- | ------------------- |
| `.` (server) | `dist/server/index.js` | NestJS module, guards, decorators, services | NestJS, ioredis     |
| `./shared`   | `dist/shared/index.js` | Types, constants, error codes               | Zero                |
| `./client`   | `dist/client/index.js` | Fetch-based auth client                     | Zero (native fetch) |
| `./react`    | `dist/react/index.js`  | React hooks and AuthProvider                | react ^19           |
| `./nextjs`   | `dist/nextjs/index.js` | Proxy factory, route handlers, JWT helpers  | next ^16, react ^19 |

```json
{
  "exports": {
    ".": {
      "types": "./dist/server/index.d.ts",
      "import": "./dist/server/index.mjs",
      "require": "./dist/server/index.cjs"
    },
    "./shared": {
      "types": "./dist/shared/index.d.ts",
      "import": "./dist/shared/index.mjs",
      "require": "./dist/shared/index.cjs"
    },
    "./client": {
      "types": "./dist/client/index.d.ts",
      "import": "./dist/client/index.mjs",
      "require": "./dist/client/index.cjs"
    },
    "./react": {
      "types": "./dist/react/index.d.ts",
      "import": "./dist/react/index.mjs",
      "require": "./dist/react/index.cjs"
    },
    "./nextjs": {
      "types": "./dist/nextjs/index.d.ts",
      "import": "./dist/nextjs/index.mjs",
      "require": "./dist/nextjs/index.cjs"
    }
  }
}
```

### 3.3 Exports per subpath

**Server (`@bymax-one/nest-auth`):**

```typescript
// Main module
export { BymaxAuthModule } from './bymax-auth.module'
// Injection constants
export {
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_USER_REPOSITORY,
  BYMAX_AUTH_PLATFORM_USER_REPOSITORY,
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_REDIS_CLIENT
} from './bymax-auth.constants'
// Interfaces (types)
export type {
  BymaxAuthModuleOptions,
  IUserRepository,
  AuthUser,
  IPlatformUserRepository,
  AuthPlatformUser,
  IEmailProvider,
  IAuthHooks,
  OAuthProviderPlugin,
  DashboardJwtPayload,
  PlatformJwtPayload,
  AuthenticatedRequest
} from './interfaces'
// Guards
export {
  JwtAuthGuard,
  JwtPlatformGuard,
  RolesGuard,
  PlatformRolesGuard,
  UserStatusGuard,
  MfaRequiredGuard,
  WsJwtGuard,
  SelfOrAdminGuard,
  OptionalAuthGuard
} from './guards'
// Decorators
export { CurrentUser, Roles, PlatformRoles, Public, SkipMfa } from './decorators'
// Services (public API only)
export { AuthService } from './services/auth.service'
// Errors, DTOs, providers
export { AuthException, AUTH_ERROR_CODES, AUTH_THROTTLE_CONFIGS } from './constants'
export { NoOpEmailProvider } from './providers/no-op-email.provider'
export { NoOpAuthHooks } from './hooks/no-op-auth.hooks'
```

**Shared (`@bymax-one/nest-auth/shared`):**

```typescript
// Shared types (zero deps)
export type {
  DashboardJwtPayload,
  PlatformJwtPayload,
  MfaTempPayload
} from './types/jwt-payload.types'
export type {
  AuthUserClient,
  AuthClientResponse,
  MfaChallengeResult
} from './types/auth-result.types'
export type { AuthErrorResponse } from './types/auth-error.types'
// Constants
export { AUTH_ERROR_CODES } from './constants/error-codes'
export {
  AUTH_ACCESS_COOKIE_NAME,
  AUTH_REFRESH_COOKIE_NAME,
  AUTH_HAS_SESSION_COOKIE_NAME,
  AUTH_REFRESH_COOKIE_PATH
} from './constants/cookie-defaults'
export { AUTH_ROUTES } from './constants/routes'
```

**Client (`@bymax-one/nest-auth/client`):**

```typescript
export { createAuthClient } from './createAuthClient'
export { createAuthFetch } from './createAuthFetch'
export type { AuthClientConfig, AuthSession } from './types'
```

**React (`@bymax-one/nest-auth/react`):**

```typescript
export { AuthProvider } from './AuthProvider'
export { useSession } from './useSession'
export { useAuth } from './useAuth'
export { useAuthStatus } from './useAuthStatus'
```

**Next.js (`@bymax-one/nest-auth/nextjs`):**

```typescript
export { createAuthProxy } from './createAuthProxy'
export { createSilentRefreshHandler } from './createSilentRefreshHandler'
export { createClientRefreshHandler } from './createClientRefreshHandler'
export { createLogoutHandler } from './createLogoutHandler'
export { decodeJwtToken, verifyJwtToken } from './helpers/jwt'
export { dedupeSetCookieHeaders, parseSetCookieHeader } from './helpers/dedupeSetCookieHeaders'
export type { AuthProxyConfig } from './createAuthProxy'
```

> **Public vs internal API:** Only the services below are exported for direct use by the host application. The remaining services are internal and must not be accessed directly.
>
> **Public services:** `AuthService` (for programmatic auth operations)
> **Protected services:** All other services are internal to the module. Use the controllers and hooks to interact with the package.

---

## 4. Configuration API

### 4.1 `BymaxAuthModuleOptions` interface

This is the main interface that controls all module behavior. The host application provides these options when registering the module.

```typescript
export interface BymaxAuthModuleOptions {
  /**
   * JWT configuration.
   * The secret is REQUIRED and must be at least 32 characters long.
   */
  jwt: {
    /**
     * Secret key for JWT signing. REQUIRED.
     * Requirements:
     * - Minimum 32 characters
     * - Must be generated with cryptographic entropy (e.g.: crypto.randomBytes(32).toString('base64'))
     * - The module validates at startup and rejects weak secrets with the following criteria:
     *   1. Minimum length of 32 characters
     *   2. Minimum Shannon entropy estimated at 3.5 bits/char
     *   3. Rejects strings with all identical characters (e.g.: 'aaaa...') or repetitive patterns
     *   4. Recommended: crypto.randomBytes(32).toString('base64') — 44 chars, ~5.9 bits/char
     * - The same criterion applies to `mfa.encryptionKey`
     */
    secret: string

    /** Access token expiration time. Default: '15m' */
    accessExpiresIn?: string

    /** Max-age of the access token cookie in milliseconds. Default: 900_000 (15 minutes) */
    accessCookieMaxAgeMs?: number

    /** Refresh token expiration time in days. Default: 7 */
    refreshExpiresInDays?: number

    /** Signing algorithm. Default: 'HS256' */
    algorithm?: 'HS256'

    /** Tolerance window for refresh token rotation in seconds. Default: 30 */
    refreshGraceWindowSeconds?: number
  }

  /**
   * Password hashing configuration.
   */
  password?: {
    /** Cost factor N for scrypt. Default: 2^15 (32768) */
    costFactor?: number
    /** Block size r for scrypt. Default: 8 */
    blockSize?: number
    /** Parallelization factor p for scrypt. Default: 1 */
    parallelization?: number
  }

  /**
   * JWT token delivery mode.
   *
   * - `'cookie'`  — tokens in HTTP-only cookies (default — recommended for web/SPA on the same domain)
   * - `'bearer'`  — tokens returned in the response body; guards extract from the `Authorization: Bearer` header
   *                 (recommended for React Native, mobile apps, and clients that do not manage cookies)
   * - `'both'`    — sets cookies AND returns tokens in the body; guards accept cookie and `Authorization: Bearer` header
   *                 (useful when the same backend serves web and mobile)
   *
   * Default: `'cookie'`
   */
  tokenDelivery?: 'cookie' | 'bearer' | 'both'

  /**
   * HTTP cookie configuration.
   * Ignored when `tokenDelivery: 'bearer'`.
   */
  cookies?: {
    /** Access token cookie name. Default: 'access_token' */
    accessTokenName?: string

    /** Refresh token cookie name. Default: 'refresh_token' */
    refreshTokenName?: string

    /** Session signal cookie name. Default: 'has_session' */
    sessionSignalName?: string

    /** Refresh cookie path. Default: '/auth' */
    refreshCookiePath?: string

    /**
     * Function to resolve cookie domains from the request domain.
     * Useful for multi-domain support (e.g.: api.example.com and app.example.com).
     * Returns an array of domains where the cookies must be set.
     */
    resolveDomains?: (requestDomain: string) => string[]
  }

  /**
   * Multi-factor authentication (MFA) configuration.
   * If enabled, encryptionKey and issuer are REQUIRED.
   */
  mfa?: {
    /**
     * AES-256-GCM encryption key for TOTP secrets. REQUIRED if MFA enabled.
     * Must be exactly 32 bytes (e.g.: crypto.randomBytes(32).toString('base64') → 44 base64 characters).
     * Validated at startup — the module rejects keys with incorrect length.
     */
    encryptionKey: string

    /** Application name displayed in the authenticator app. REQUIRED. */
    issuer: string

    /** Number of recovery codes generated. Default: 8 */
    recoveryCodeCount?: number

    /** TOTP tolerance window (30s periods). Default: 1 */
    totpWindow?: number
  }

  /**
   * Session system configuration.
   */
  sessions?: {
    /** Enables session management. Default: false */
    enabled?: boolean

    /** Maximum number of simultaneous sessions per user. Default: 5 */
    defaultMaxSessions?: number

    /**
     * Function to resolve the session limit per user.
     * Allows different limits per plan/role.
     */
    maxSessionsResolver?: (user: AuthUser) => number | Promise<number>

    /** Eviction strategy when the limit is reached. Default: 'fifo' */
    evictionStrategy?: 'fifo'
  }

  /**
   * Brute-force protection configuration.
   */
  bruteForce?: {
    /** Maximum number of attempts before lockout. Default: 5 */
    maxAttempts?: number

    /** Time window in seconds for counting attempts. Default: 900 (15 minutes) */
    windowSeconds?: number
  }

  /**
   * Password reset configuration.
   */
  passwordReset?: {
    /** Reset method: token (link by email) or otp (numeric code). Default: 'token' */
    method?: 'token' | 'otp'

    /** Reset token TTL in seconds. Default: 3600 (1 hour) */
    tokenTtlSeconds?: number

    /** Reset OTP TTL in seconds. Default: 600 (10 minutes) */
    otpTtlSeconds?: number

    /** OTP code length. Default: 6 */
    otpLength?: number
  }

  /**
   * Email verification configuration.
   */
  emailVerification?: {
    /** If true, users must verify email before logging in. Default: false */
    required?: boolean

    /** Verification OTP TTL in seconds. Default: 600 (10 minutes) */
    otpTtlSeconds?: number
  }

  /**
   * Platform administration module configuration.
   */
  platform?: {
    /** Enables platform admin endpoints and logic. Default: false */
    enabled?: boolean
  }

  /**
   * Invitation system configuration.
   */
  invitations?: {
    /** Enables invitation system. Default: false */
    enabled?: boolean

    /** Invitation token TTL in seconds. Default: 604800 (7 days) */
    tokenTtlSeconds?: number
  }

  /**
   * Roles and hierarchy configuration.
   */
  roles: {
    /**
     * Role hierarchy of the dashboard/tenant.
     * Each role inherits the permissions of the listed roles.
     * REQUIRED.
     *
     * Example:
     * {
     *   OWNER: ['ADMIN', 'MEMBER', 'VIEWER'],
     *   ADMIN: ['MEMBER', 'VIEWER'],
     *   MEMBER: ['VIEWER'],
     *   VIEWER: []
     * }
     */
    hierarchy: Record<string, string[]>

    /**
     * Platform role hierarchy (super-admins).
     * Optional — required only if platform.enabled = true.
     */
    platformHierarchy?: Record<string, string[]>
  }

  /**
   * List of statuses that block access.
   * Default: ['BANNED', 'INACTIVE', 'SUSPENDED']
   */
  blockedStatuses?: string[]

  /**
   * Namespace for Redis keys. Default: 'auth'
   * All keys will be prefixed with this namespace.
   */
  redisNamespace?: string

  /**
   * OAuth providers configuration.
   */
  oauth?: {
    google?: {
      clientId: string
      clientSecret: string
      callbackUrl: string
    }
  }

  /**
   * Prefix for all module routes. Default: 'auth'
   * Example: with prefix 'auth', the routes will be /auth/login, /auth/register, etc.
   */
  routePrefix?: string

  /**
   * Function to resolve the tenantId from the request.
   * If provided, the package uses the resolved tenantId and IGNORES the tenantId from the body.
   * This prevents tenant spoofing where a client sends the tenantId of another tenant.
   *
   * Examples:
   * - Resolution by subdomain: (req) => req.hostname.split('.')[0]
   * - Resolution by header: (req) => req.headers['x-tenant-id']
   * - Resolution by path: (req) => req.params.tenantId
   *
   * If not provided, the package uses the tenantId from the request body/DTO.
   * In this case, the host application is responsible for validating the tenantId.
   */
  tenantIdResolver?: (req: import('express').Request) => string | Promise<string>

  /**
   * Granular control over which controllers are registered.
   * Allows disabling endpoints that are not needed.
   */
  controllers?: {
    /** Enables AuthController (register, login, logout, refresh, me). Default: true */
    auth?: boolean

    /** Enables MfaController. Default: true (if mfa configured) */
    mfa?: boolean

    /** Enables PasswordResetController. Default: true */
    passwordReset?: boolean

    /** Enables SessionController. Default: true (if sessions.enabled) */
    sessions?: boolean

    /** Enables PlatformAuthController. Default: true (if platform.enabled) */
    platform?: boolean

    /** Enables InvitationController. Default: true (if invitations.enabled) */
    invitations?: boolean
  }

  /**
   * User status cache TTL in seconds. Default: 60
   * The status is cached in Redis to avoid database queries on every request.
   */
  userStatusCacheTtlSeconds?: number
}
```

### 4.2 Options table with default values

| Option                            | Type                             | Required    | Default                               | Description                                                                                                                                                                                                         |
| --------------------------------- | -------------------------------- | ----------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tokenDelivery`                   | `'cookie' \| 'bearer' \| 'both'` | No          | `'cookie'`                            | Token delivery mode (web, mobile, or both)                                                                                                                                                                          |
| `jwt.secret`                      | `string`                         | Yes         | —                                     | JWT secret key, min 32 characters                                                                                                                                                                                   |
| `jwt.accessExpiresIn`             | `string`                         | No          | `'15m'`                               | Access token expiration                                                                                                                                                                                             |
| `jwt.accessCookieMaxAgeMs`        | `number`                         | No          | `900_000`                             | Max-age of the access cookie                                                                                                                                                                                        |
| `jwt.refreshExpiresInDays`        | `number`                         | No          | `7`                                   | Refresh token expiration in days                                                                                                                                                                                    |
| `jwt.algorithm`                   | `'HS256'`                        | No          | `'HS256'`                             | JWT signature algorithm                                                                                                                                                                                             |
| `jwt.refreshGraceWindowSeconds`   | `number`                         | No          | `30`                                  | Grace window for refresh rotation                                                                                                                                                                                   |
| `jwt.absoluteSessionLifetimeDays` | `number`                         | No          | `30`                                  | Caps how long one login can be extended by rotation; `0` disables the cap                                                                                                                                           |
| `password.costFactor`             | `number`                         | No          | `32768`                               | scrypt cost factor N                                                                                                                                                                                                |
| `password.blockSize`              | `number`                         | No          | `8`                                   | scrypt block size r                                                                                                                                                                                                 |
| `password.parallelization`        | `number`                         | No          | `1`                                   | scrypt parallelization factor p                                                                                                                                                                                     |
| `cookies.accessTokenName`         | `string`                         | No          | `'access_token'`                      | Access cookie name                                                                                                                                                                                                  |
| `cookies.refreshTokenName`        | `string`                         | No          | `'refresh_token'`                     | Refresh cookie name                                                                                                                                                                                                 |
| `cookies.sessionSignalName`       | `string`                         | No          | `'has_session'`                       | Signal cookie name                                                                                                                                                                                                  |
| `cookies.refreshCookiePath`       | `string`                         | No          | `'/auth'`                             | Refresh cookie path                                                                                                                                                                                                 |
| `cookies.sameSite`                | `'lax' \| 'strict' \| 'none'`    | No          | `'lax'`                               | `'none'` requires `secureCookies` **and** a non-empty `trustedOrigins`                                                                                                                                              |
| `cookies.trustedOrigins`          | `string[]`                       | Conditional | `[]`                                  | Origins allowed to make cookie-authenticated cross-site writes; required under `sameSite: 'none'`, refused otherwise. Compared verbatim against the `Origin` header, so each entry is a bare `scheme://host[:port]` |
| `cookies.resolveDomains`          | `function`                       | No          | `undefined`                           | Multi-domain domain resolver                                                                                                                                                                                        |
| `mfa.encryptionKey`               | `string`                         | Conditional | —                                     | AES-256-GCM key (required if MFA)                                                                                                                                                                                   |
| `mfa.issuer`                      | `string`                         | Conditional | —                                     | App name in the authenticator                                                                                                                                                                                       |
| `mfa.recoveryCodeCount`           | `number`                         | No          | `8`                                   | Number of recovery codes                                                                                                                                                                                            |
| `mfa.totpWindow`                  | `number`                         | No          | `1`                                   | TOTP tolerance window                                                                                                                                                                                               |
| `sessions.enabled`                | `boolean`                        | No          | `false`                               | Enables session management                                                                                                                                                                                          |
| `sessions.defaultMaxSessions`     | `number`                         | No          | `5`                                   | Maximum simultaneous sessions                                                                                                                                                                                       |
| `sessions.maxSessionsResolver`    | `function`                       | No          | `undefined`                           | Custom limit resolver                                                                                                                                                                                               |
| `sessions.evictionStrategy`       | `'fifo'`                         | No          | `'fifo'`                              | Session eviction strategy                                                                                                                                                                                           |
| `bruteForce.maxAttempts`          | `number`                         | No          | `5`                                   | Attempts before lockout — aligned with the per-IP throttle; raising it widens the credential brute-force window                                                                                                     |
| `bruteForce.windowSeconds`        | `number`                         | No          | `900`                                 | Counting window (15 min)                                                                                                                                                                                            |
| `rateLimit.enabled`               | `boolean`                        | No          | `true`                                | Per-IP fixed-window limits enforced by the library over Redis, per route                                                                                                                                            |
| `passwordReset.method`            | `'token' \| 'otp'`               | No          | `'token'`                             | Reset method                                                                                                                                                                                                        |
| `passwordReset.tokenTtlSeconds`   | `number`                         | No          | `3600`                                | Reset token TTL                                                                                                                                                                                                     |
| `passwordReset.otpTtlSeconds`     | `number`                         | No          | `600`                                 | Reset OTP TTL                                                                                                                                                                                                       |
| `passwordReset.otpLength`         | `number`                         | No          | `6`                                   | OTP length                                                                                                                                                                                                          |
| `emailVerification.required`      | `boolean`                        | No          | `false`                               | Requires email verification                                                                                                                                                                                         |
| `emailVerification.otpTtlSeconds` | `number`                         | No          | `600`                                 | Verification OTP TTL                                                                                                                                                                                                |
| `platform.enabled`                | `boolean`                        | No          | `false`                               | Enables platform admin                                                                                                                                                                                              |
| `invitations.enabled`             | `boolean`                        | No          | `false`                               | Enables invitation system                                                                                                                                                                                           |
| `invitations.tokenTtlSeconds`     | `number`                         | No          | `604800`                              | Invitation token TTL (7 days)                                                                                                                                                                                       |
| `roles.hierarchy`                 | `Record<string, string[]>`       | Yes         | —                                     | Role hierarchy                                                                                                                                                                                                      |
| `roles.platformHierarchy`         | `Record<string, string[]>`       | No          | `undefined`                           | Platform role hierarchy                                                                                                                                                                                             |
| `blockedStatuses`                 | `string[]`                       | No          | `['BANNED', 'INACTIVE', 'SUSPENDED']` | Statuses that block access                                                                                                                                                                                          |
| `redisNamespace`                  | `string`                         | No          | `'auth'`                              | Redis key namespace                                                                                                                                                                                                 |
| `oauth.google.clientId`           | `string`                         | Conditional | —                                     | Google OAuth Client ID                                                                                                                                                                                              |
| `oauth.google.clientSecret`       | `string`                         | Conditional | —                                     | Google OAuth Client Secret                                                                                                                                                                                          |
| `oauth.google.callbackUrl`        | `string`                         | Conditional | —                                     | Google OAuth callback URL                                                                                                                                                                                           |
| `routePrefix`                     | `string`                         | No          | `'auth'`                              | Route prefix                                                                                                                                                                                                        |
| `tenantIdResolver`                | `function`                       | No          | `undefined`                           | tenantId resolver (prevents spoofing)                                                                                                                                                                               |
| `controllers.auth`                | `boolean`                        | No          | `true`                                | Enables AuthController                                                                                                                                                                                              |
| `controllers.mfa`                 | `boolean`                        | No          | `true`                                | Enables MfaController                                                                                                                                                                                               |
| `controllers.passwordReset`       | `boolean`                        | No          | `true`                                | Enables PasswordResetController                                                                                                                                                                                     |
| `controllers.sessions`            | `boolean`                        | No          | `true`                                | Enables SessionController                                                                                                                                                                                           |
| `controllers.platformAuth`        | `boolean`                        | No          | `true`                                | Enables PlatformAuthController                                                                                                                                                                                      |
| `controllers.invitations`         | `boolean`                        | No          | `true`                                | Enables InvitationController                                                                                                                                                                                        |
| `userStatusCacheTtlSeconds`       | `number`                         | No          | `60`                                  | Status cache TTL                                                                                                                                                                                                    |

### 4.3 Registration example with `registerAsync`

```typescript
// app.module.ts
import { Module } from '@nestjs/common'
import { ConfigModule, ConfigService } from '@nestjs/config'
import { ThrottlerModule } from '@nestjs/throttler'
import {
  BymaxAuthModule,
  BYMAX_AUTH_USER_REPOSITORY,
  BYMAX_AUTH_PLATFORM_USER_REPOSITORY,
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_REDIS_CLIENT
} from '@bymax-one/nest-auth'

import { PrismaUserRepository } from './auth/repositories/prisma-user.repository'
import { PrismaPlatformUserRepository } from './auth/repositories/prisma-platform-user.repository'
import { ResendEmailProvider } from './auth/providers/resend-email.provider'
import { AppAuthHooks } from './auth/hooks/app-auth.hooks'
import { RedisService } from './redis/redis.service'

@Module({
  imports: [
    ConfigModule.forRoot(),
    ThrottlerModule.forRoot([{ ttl: 60_000, limit: 100 }]),

    BymaxAuthModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        jwt: {
          secret: config.getOrThrow<string>('JWT_SECRET'),
          accessExpiresIn: '15m',
          refreshExpiresInDays: 7
        },
        password: {
          costFactor: 32768,
          blockSize: 8,
          parallelization: 1
        },
        cookies: {
          resolveDomains: (domain: string) => {
            // Multi-domain support: api.example.com → ['.example.com']
            const parts = domain.split('.')
            if (parts.length >= 2) {
              return ['.' + parts.slice(-2).join('.')]
            }
            return [domain]
          }
        },
        mfa: {
          encryptionKey: config.getOrThrow<string>('MFA_ENCRYPTION_KEY'),
          issuer: 'Example App'
        },
        sessions: {
          enabled: true,
          defaultMaxSessions: 5,
          maxSessionsResolver: async (user) => {
            // Premium plans allow more sessions
            return user.role === 'OWNER' ? 10 : 5
          }
        },
        bruteForce: {
          maxAttempts: 10,
          windowSeconds: 900
        },
        passwordReset: {
          method: 'otp',
          otpLength: 6,
          otpTtlSeconds: 600
        },
        emailVerification: {
          required: true
        },
        platform: {
          enabled: true
        },
        invitations: {
          enabled: true,
          tokenTtlSeconds: 604800
        },
        roles: {
          hierarchy: {
            OWNER: ['ADMIN', 'MEMBER', 'VIEWER'],
            ADMIN: ['MEMBER', 'VIEWER'],
            MEMBER: ['VIEWER'],
            VIEWER: []
          },
          platformHierarchy: {
            SUPER_ADMIN: ['ADMIN', 'SUPPORT'],
            ADMIN: ['SUPPORT'],
            SUPPORT: []
          }
        },
        blockedStatuses: ['BANNED', 'INACTIVE', 'SUSPENDED'],
        oauth: {
          google: {
            clientId: config.getOrThrow<string>('GOOGLE_CLIENT_ID'),
            clientSecret: config.getOrThrow<string>('GOOGLE_CLIENT_SECRET'),
            callbackUrl: config.getOrThrow<string>('GOOGLE_CALLBACK_URL')
          }
        },
        routePrefix: 'auth'
        // tenantIdResolver: (req) => req.hostname.split('.')[0], // uncomment to resolve tenantId by subdomain
      }),
      providers: [
        {
          provide: BYMAX_AUTH_USER_REPOSITORY,
          useClass: PrismaUserRepository
        },
        {
          provide: BYMAX_AUTH_PLATFORM_USER_REPOSITORY,
          useClass: PrismaPlatformUserRepository
        },
        {
          provide: BYMAX_AUTH_EMAIL_PROVIDER,
          useClass: ResendEmailProvider
        },
        {
          provide: BYMAX_AUTH_HOOKS,
          useClass: AppAuthHooks
        },
        {
          provide: BYMAX_AUTH_REDIS_CLIENT,
          useFactory: (redisService: RedisService) => redisService.getClient(),
          inject: [RedisService]
        }
      ]
    })
  ]
})
export class AppModule {}
```

### 4.4 Injection tokens

The package defines injection constants that the host application must provide:

```typescript
// bymax-auth.constants.ts

/** Token for the module's resolved options */
export const BYMAX_AUTH_OPTIONS = Symbol('BYMAX_AUTH_OPTIONS')

/**
 * Token for the dashboard/tenant user repository.
 * The host application MUST provide an implementation of IUserRepository.
 */
export const BYMAX_AUTH_USER_REPOSITORY = Symbol('BYMAX_AUTH_USER_REPOSITORY')

/**
 * Token for the platform user repository.
 * Required only if platform.enabled = true.
 */
export const BYMAX_AUTH_PLATFORM_USER_REPOSITORY = Symbol('BYMAX_AUTH_PLATFORM_USER_REPOSITORY')

/**
 * Token for the email provider.
 * The host application MUST provide an implementation of IEmailProvider.
 */
export const BYMAX_AUTH_EMAIL_PROVIDER = Symbol('BYMAX_AUTH_EMAIL_PROVIDER')

/**
 * Token for the lifecycle hooks.
 * Optional — if not provided, a NoOpAuthHooks is used.
 */
export const BYMAX_AUTH_HOOKS = Symbol('BYMAX_AUTH_HOOKS')

/**
 * Token for the Redis client instance (ioredis).
 * The host application MUST provide a Redis instance.
 */
export const BYMAX_AUTH_REDIS_CLIENT = Symbol('BYMAX_AUTH_REDIS_CLIENT')
```

**Summary of required and optional providers:**

| Token                                 | Interface                 | Required    | Description                              |
| ------------------------------------- | ------------------------- | ----------- | ---------------------------------------- |
| `BYMAX_AUTH_USER_REPOSITORY`          | `IUserRepository`         | Yes         | User repository                          |
| `BYMAX_AUTH_PLATFORM_USER_REPOSITORY` | `IPlatformUserRepository` | Conditional | Admin repository (if `platform.enabled`) |
| `BYMAX_AUTH_EMAIL_PROVIDER`           | `IEmailProvider`          | Yes         | Email sending provider                   |
| `BYMAX_AUTH_HOOKS`                    | `IAuthHooks`              | No          | Lifecycle hooks                          |
| `BYMAX_AUTH_REDIS_CLIENT`             | `Redis` (ioredis)         | Yes         | Redis client instance                    |

---

## 5. Repository Contracts

### 5.1 `AuthUser` interface

This interface defines the minimal shape of a user that the module expects. The host application may have additional fields in its database model, but must map to this interface when implementing the repository.

```typescript
export interface AuthUser {
  /** Unique identifier of the user (UUID or string) */
  id: string

  /** User email (unique per tenant) */
  email: string

  /**
   * scrypt hash of the password. Null for users who registered via OAuth.
   * When null, password login is blocked.
   */
  passwordHash: string | null

  /** Full name of the user */
  name: string

  /** User role in the tenant (e.g.: 'OWNER', 'ADMIN', 'MEMBER', 'VIEWER') */
  role: string

  /** Account status (e.g.: 'ACTIVE', 'PENDING_APPROVAL', 'BANNED', 'INACTIVE', 'SUSPENDED') */
  status: string

  /** Whether the email was verified */
  emailVerified: boolean

  mfaEnabled?: boolean // Optional — present only when MFA is enabled in the configuration

  mfaSecret?: string | null // Optional — encrypted TOTP secret (AES-256-GCM)

  mfaRecoveryCodes?: string[] | null // Optional — Recovery codes hashed with scrypt

  /** Timestamp of the last login */
  lastLoginAt: Date | null

  /** ID of the tenant the user belongs to */
  tenantId: string

  /** Soft delete timestamp. Null if not deleted. */
  deletedAt: Date | null

  /** Creation timestamp */
  createdAt: Date

  /** Last update timestamp */
  updatedAt: Date
}
```

> **Note on MFA fields:** The `mfaEnabled`, `mfaSecret`, and `mfaRecoveryCodes` fields are optional in the interface. When the `mfa` configuration is not provided to the module, the package ignores these fields completely. The host application only needs to include them in the database schema if it enables MFA.

### 5.2 `IUserRepository` interface

```typescript
export interface IUserRepository {
  /**
   * Finds a user by ID.
   * Must ignore users with deletedAt != null.
   * @returns The user or null if not found
   */
  findById(id: string): Promise<AuthUser | null>

  /**
   * Finds a user by email within a tenant.
   * Must ignore users with deletedAt != null.
   * @returns The user or null if not found
   */
  findByEmail(email: string, tenantId: string): Promise<AuthUser | null>

  /**
   * Creates a new user in the database.
   * Null for users created via OAuth or invitation without a password.
   * @param data Data of the new user
   * @returns The created user
   */
  create(data: {
    email: string
    passwordHash: string | null
    name: string
    role: string
    status: string
    emailVerified: boolean
    tenantId: string
  }): Promise<AuthUser>

  /**
   * Updates the password hash of a user.
   * Must also update updatedAt.
   */
  updatePassword(userId: string, passwordHash: string): Promise<void>

  /**
   * Updates a user's MFA settings.
   * Used to enable, disable, and update recovery codes.
   */
  updateMfa(
    userId: string,
    data: {
      mfaEnabled: boolean
      mfaSecret: string | null
      mfaRecoveryCodes: string[] | null
    }
  ): Promise<void>

  /**
   * Updates the last login timestamp.
   */
  updateLastLogin(userId: string): Promise<void>

  /**
   * Updates a user's status.
   */
  updateStatus(userId: string, status: string): Promise<void>

  /**
   * Marks the email as verified.
   */
  updateEmailVerified(userId: string, verified: boolean): Promise<void>

  /**
   * Finds a user by OAuth provider ID (e.g.: Google ID).
   * @param provider Provider name (e.g.: 'google')
   * @param providerId User ID at the provider
   * @param tenantId Tenant ID
   * @returns The user or null if not found
   */
  findByOAuthId(provider: string, providerId: string, tenantId: string): Promise<AuthUser | null>

  /**
   * Links an OAuth account to an existing user.
   * Saves the provider and providerId in the OAuth links table.
   */
  linkOAuth(userId: string, provider: string, providerId: string): Promise<void>

  /**
   * Creates a new user via OAuth (without a password).
   * @returns The created user
   */
  createWithOAuth(data: {
    email: string
    name: string
    role: string
    status: string
    emailVerified: boolean
    tenantId: string
    provider: string
    providerId: string
  }): Promise<AuthUser>
}
```

> **Note:** The package automatically invalidates the user status cache in Redis (`auth:us:{userId}`) after any call to `updateStatus()`. The host application does **not** need to manage the package's Redis cache.

### 5.3 `AuthPlatformUser` interface

Platform users (super-admins) have a simpler structure, as they do not belong to a specific tenant.

```typescript
export interface AuthPlatformUser {
  /** Unique identifier of the admin */
  id: string

  /** Admin email */
  email: string

  /** scrypt hash of the password */
  passwordHash: string

  /** Full name */
  name: string

  /** Role on the platform (e.g.: 'SUPER_ADMIN', 'ADMIN', 'SUPPORT') */
  role: string

  /** Account status */
  status: string

  /** Whether MFA is enabled */
  mfaEnabled: boolean

  /** Encrypted TOTP secret */
  mfaSecret: string | null

  /** Hashed recovery codes */
  mfaRecoveryCodes: string[] | null

  /** Timestamp of the last login */
  lastLoginAt: Date | null

  /** Creation timestamp */
  createdAt: Date

  /** Last update timestamp */
  updatedAt: Date

  /**
   * Logical deletion (soft-delete) timestamp.
   * Admins with `deletedAt != null` must be treated as nonexistent:
   * - `IPlatformUserRepository.findById()` and `findByEmail()` MUST return `null`
   * - The `JwtPlatformGuard` will reject access since the repository will not find the admin
   * - When deleting an admin, the host application MUST call `PlatformAuthService.revokeAllPlatformSessions()`
   *   to invalidate all active tokens immediately
   */
  deletedAt: Date | null
}
```

### 5.4 `IPlatformUserRepository` interface

```typescript
export interface IPlatformUserRepository {
  /**
   * Finds a platform admin by ID.
   */
  findById(id: string): Promise<AuthPlatformUser | null>

  /**
   * Finds a platform admin by email.
   */
  findByEmail(email: string): Promise<AuthPlatformUser | null>

  /**
   * Updates the last login timestamp.
   */
  updateLastLogin(userId: string): Promise<void>

  /**
   * Updates the MFA settings.
   */
  updateMfa(
    userId: string,
    data: {
      mfaEnabled: boolean
      mfaSecret: string | null
      mfaRecoveryCodes: string[] | null
    }
  ): Promise<void>

  /**
   * Updates the password (hash) of a platform admin.
   */
  updatePassword(userId: string, passwordHash: string): Promise<void>

  /**
   * Updates the status of a platform admin.
   */
  updateStatus(userId: string, status: string): Promise<void>
}
```

### 5.5 `IEmailProvider` interface

```typescript
export interface IEmailProvider {
  /**
   * Sends an email with a password reset token (link).
   * Used when passwordReset.method = 'token'.
   */
  sendPasswordResetToken(email: string, token: string, name: string, locale?: string): Promise<void>

  /**
   * Sends an email with a password reset OTP (numeric code).
   * Used when passwordReset.method = 'otp'.
   */
  sendPasswordResetOtp(email: string, otp: string, name: string, locale?: string): Promise<void>

  /**
   * Sends an email with an email verification OTP.
   */
  sendEmailVerificationOtp(email: string, otp: string, name: string, locale?: string): Promise<void>

  /**
   * Notifies the user that MFA was enabled.
   */
  sendMfaEnabledNotification(email: string, name: string, locale?: string): Promise<void>

  /**
   * Notifies the user that MFA was disabled.
   */
  sendMfaDisabledNotification(email: string, name: string, locale?: string): Promise<void>

  /**
   * Alerts the user about a new login/session.
   * Includes device and IP information.
   */
  sendNewSessionAlert(
    email: string,
    name: string,
    sessionInfo: { device: string; ip: string; timestamp: Date },
    locale?: string
  ): Promise<void>

  /**
   * Sends an invitation email to a new user.
   * Includes the invitation token and inviter information.
   */
  sendInvitation(
    email: string,
    data: {
      inviterName: string
      tenantName: string
      role: string
      token: string
      expiresAt: Date
    },
    locale?: string
  ): Promise<void>
}
```

**Important note:** The `IEmailProvider` is **abstract and template-agnostic**. It defines **what** to send, not **how** to render it. The host application decides the template, the email service (Resend, SendGrid, SES, etc.), and the layout. This allows complete freedom in presentation.

> **Internationalization:** All methods accept an optional `locale` parameter (e.g., `'pt-BR'`, `'en'`, `'es'`). The package passes the user's locale (when available in `AuthUser`) so that the host application renders templates in the correct language.

---

## 6. Services

### 6.1 AuthService

Central service that orchestrates registration, login, logout, refresh, and email verification.

```typescript
class AuthService {
  /**
   * Registers a new user.
   *
   * Flow:
   * 1. Runs the beforeRegister hook (can modify data or reject)
   * 2. Checks whether the email already exists in the tenant
   * 3. Hashes the password with scrypt
   * 4. Creates the user via IUserRepository.create()
   * 5. If emailVerification.required, sends a verification OTP
   * 6. Generates JWT tokens (access + refresh)
   * 7. Runs the afterRegister hook
   * 8. Returns AuthResult with tokens and user data
   *
   * @designDecision Registration ALWAYS issues tokens, even when `emailVerification.required = true`.
   * This is intentional to allow the user to see the "Verify your email" screen within the app
   * (requires being authenticated). The next login after the access token expires will be blocked with
   * `AUTH_ERROR_CODES.EMAIL_NOT_VERIFIED` if the email is not verified.
   * The host application can use the `afterRegister` hook or the `emailVerified` field of the `AuthUser` object
   * (returned in `AuthResult.user`) to redirect the user to the verification screen
   * immediately after registration. Note: `emailVerified` is NOT a JWT claim — check it
   * via `AuthUser.emailVerified` in the registration response or in the `/me` endpoint.
   * Maximum access window without verification: `accessExpiresIn` (default: 15 minutes).
   *
   * @throws AUTH_ERROR_CODES.EMAIL_ALREADY_EXISTS if email already registered
   */
  register(dto: RegisterDto, ipAddress: string, userAgent: string): Promise<AuthResult>

  /**
   * Authenticates a user with email and password.
   *
   * Flow:
   * 1. Checks brute-force lockout
   * 2. Finds the user by email and tenant
   * 3. Compares the password with scrypt + timingSafeEqual (constant-time)
   * 4. If it fails, records the attempt and returns a generic error
   * 5. If the user has MFA enabled:
   *    a. Issues mfaTempToken (5 min JWT)
   *    b. Returns { mfaRequired: true, mfaTempToken }
   * 6. If MFA is not enabled:
   *    a. Resets the brute-force counter
   *    b. Generates JWT tokens (access + refresh)
   *    c. Creates a session (if enabled)
   *    d. Runs the afterLogin hook
   *    e. Updates lastLoginAt
   * 7. Returns AuthResult with tokens and user data
   *
   * @throws AUTH_ERROR_CODES.INVALID_CREDENTIALS (generic message, never reveals whether the email exists)
   * @throws AUTH_ERROR_CODES.ACCOUNT_LOCKED if brute-force active
   * @throws AUTH_ERROR_CODES.ACCOUNT_INACTIVE / SUSPENDED / BANNED
   * @throws AUTH_ERROR_CODES.EMAIL_NOT_VERIFIED if verification required and email not verified
   */
  login(
    dto: LoginDto,
    ipAddress: string,
    userAgent: string
  ): Promise<AuthResult | MfaChallengeResult>

  /**
   * Logs the user out.
   *
   * Flow:
   * 1. Adds the access JWT to the blacklist (Redis, TTL = remaining time of the JWT)
   * 2. Revokes the refresh token in Redis
   * 3. Removes the session (if enabled)
   * 4. Runs the afterLogout hook
   * 5. Returns void — the controller delivers the response via TokenDeliveryService
   */
  logout(accessToken: string, refreshToken: string): Promise<void>

  /**
   * Renews the access token using the refresh token from the cookie.
   *
   * Flow:
   * 1. Extracts the refresh token from the cookie
   * 2. Finds the session in Redis via sha256(refreshToken)
   * 3. If not found, checks the rotation pointer (30s grace window)
   * 4. Generates a new refresh token (rotation)
   * 5. Creates a rotation pointer: oldToken → newToken (30s TTL)
   * 6. Stores the new refresh token in Redis
   * 7. Removes the old refresh token
   * 8. Returns AuthResult with new tokens — the controller delivers via TokenDeliveryService
   *
   * @throws AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID if token invalid or expired
   */
  refresh(rawRefreshToken: string, ipAddress: string, userAgent: string): Promise<AuthResult>

  /**
   * Returns the authenticated user's data.
   * Looks it up in the repository by ID (extracted from the JWT).
   *
   * @throws AUTH_ERROR_CODES.TOKEN_INVALID if user not found
   */
  getMe(userId: string): Promise<AuthUser>

  /**
   * Verifies the user's email with an OTP.
   *
   * Flow:
   * 1. Validates the OTP in Redis (tenantId required for scoped lookup)
   * 2. Marks the email as verified via the repository
   * 3. Runs the afterEmailVerified hook
   *
   * @param email User email
   * @param otp OTP code
   * @param tenantId Tenant ID (required for scoped lookup)
   * @throws AUTH_ERROR_CODES.OTP_INVALID / OTP_EXPIRED / OTP_MAX_ATTEMPTS
   */
  verifyEmail(email: string, otp: string, tenantId: string): Promise<void>

  /**
   * Resends the email verification OTP.
   * Generates a new OTP and stores it in Redis.
   * Sends it via IEmailProvider.sendEmailVerificationOtp().
   */
  resendVerificationEmail(email: string, tenantId: string): Promise<void>
}
```

**Return types:**

```typescript
interface AuthResult {
  user: AuthUser
  accessToken: string
  rawRefreshToken: string
  /** Session hash (sha256 of the refresh token). Present when sessions.enabled = true. */
  sessionHash?: string
}

interface MfaChallengeResult {
  mfaRequired: true
  mfaTempToken: string
}
```

> **Separation of concerns:** Services **never** manipulate the Express `Response`. They return objects with tokens and data via `AuthResult`. The **controllers** are responsible for calling `TokenDeliveryService` which, based on the configured `tokenDelivery`, sets cookies on the response (`'cookie'`), returns tokens in the body (`'bearer'`), or does both (`'both'`). This ensures that services are independent of the HTTP transport and can be reused in contexts such as WebSocket, CLI, or unit tests.

### 6.2 PasswordService

Service responsible for hashing and comparing passwords using native `node:crypto` scrypt.

> **OWASP 2026** recommends Argon2id > scrypt > bcrypt for new systems. scrypt is native to Node.js (`node:crypto`), eliminating dependencies with native C++ bindings and supply chain risks. Unlike bcrypt, scrypt **does not truncate long passwords** (bcrypt silently truncated above 72 bytes).

**scrypt parameters:**

| Parameter           | Config key                 | Default                         | Description               |
| ------------------- | -------------------------- | ------------------------------- | ------------------------- |
| N (cost factor)     | `password.costFactor`      | 2^15 (32768)                    | Memory/CPU cost factor    |
| r (block size)      | `password.blockSize`       | 8                               | Block size                |
| p (parallelization) | `password.parallelization` | 1                               | Parallelization factor    |
| keyLen              | —                          | 64                              | Derived key size in bytes |
| salt                | —                          | 16 bytes (`crypto.randomBytes`) | Random salt per password  |

**Storage format:** `scrypt:{salt_hex}:{derived_hex}`

```typescript
class PasswordService {
  /**
   * Generates a scrypt hash of the password using node:crypto.
   * Salt: 16 random bytes. Format: scrypt:{salt}:{hash}
   *
   * @param plainPassword Plain-text password
   * @returns scrypt hash in the format scrypt:{salt_hex}:{derived_hex}
   */
  hash(plainPassword: string): Promise<string>

  /**
   * Compares a plain-text password with a stored scrypt hash.
   * Extracts the salt from the hash, derives the key with the same parameters and compares
   * using crypto.timingSafeEqual to prevent timing attacks.
   *
   * @param plainPassword Plain-text password
   * @param hash Stored scrypt hash
   * @returns true if they match
   */
  compare(plainPassword: string, hash: string): Promise<boolean>
}
```

**Reference implementation:**

```typescript
import { scrypt, randomBytes, timingSafeEqual } from 'node:crypto'
import { promisify } from 'node:util'

const scryptAsync = promisify(scrypt)

async hash(plainPassword: string): Promise<string> {
  const salt = randomBytes(16)
  const derived = await scryptAsync(plainPassword, salt, 64, {
    N: this.options.password.costFactor,   // default: 2^15
    r: this.options.password.blockSize,     // default: 8
    p: this.options.password.parallelization // default: 1
  }) as Buffer
  return `scrypt:${salt.toString('hex')}:${derived.toString('hex')}`
}

async compare(plainPassword: string, storedHash: string): Promise<boolean> {
  const [prefix, saltHex, hashHex] = storedHash.split(':')
  if (prefix !== 'scrypt' || !saltHex || !hashHex) return false

  const salt = Buffer.from(saltHex, 'hex')
  const stored = Buffer.from(hashHex, 'hex')
  const derived = await scryptAsync(plainPassword, salt, 64, {
    N: this.options.password.costFactor,
    r: this.options.password.blockSize,
    p: this.options.password.parallelization
  }) as Buffer

  return timingSafeEqual(stored, derived)
}
```

### 6.3 TokenManagerService

Central service for issuance, verification, and management of all JWT and opaque tokens.

```typescript
class TokenManagerService {
  /**
   * Issues a JWT access token.
   *
   * @param payload JWT claims (sub, tenantId, role, type, status, mfaVerified)
   * @returns Signed JWT string
   */
  issueAccess(payload: Omit<DashboardJwtPayload, 'jti' | 'iat' | 'exp'>): string

  /**
   * Issues access + refresh tokens.
   *
   * Flow:
   * 1. Generates access JWT with complete claims
   * 2. Generates opaque refresh token (UUID v4)
   * 3. Stores refresh token in Redis with session data
   *
   * Does NOT manipulate Response — the controller uses TokenDeliveryService to deliver.
   *
   * @returns AuthResult with tokens and user data
   */
  issueTokens(
    user: AuthUser,
    ipAddress: string,
    userAgent: string,
    options?: { mfaVerified?: boolean }
  ): Promise<AuthResult>

  /**
   * Reissues tokens using an existing refresh token.
   * Implements refresh token rotation with grace window.
   *
   * Does NOT manipulate Response — the controller uses TokenDeliveryService to deliver.
   *
   * @param refreshToken Opaque token (extracted by the controller via TokenDeliveryService)
   * @returns AuthResult with new tokens
   */
  reissueTokens(refreshToken: string, ipAddress: string, userAgent: string): Promise<AuthResult>

  /**
   * Issues access + refresh tokens for a platform admin.
   *
   * Flow:
   * 1. Generates access JWT with claims per `PlatformJwtPayload` (type: 'platform')
   * 2. Generates opaque refresh token (UUID v4)
   * 3. Stores refresh token in Redis with prefix `prt:` and session data
   * 4. Updates the platform session index — `psess:{hmac_sha256(hmacKey, "platform:{userId}")}`
   *    — and details `psd:{sessionHash}`
   *
   * @returns PlatformAuthResult with tokens and admin data
   */
  issuePlatformTokens(
    admin: AuthPlatformUser,
    ipAddress: string,
    userAgent: string,
    options?: { mfaVerified?: boolean }
  ): Promise<PlatformAuthResult>

  /**
   * Reissues platform tokens using an existing refresh token.
   * Same rotation logic as `reissueTokens` but with prefixes `prt:`/`prp:`/`psess:`/`psd:`.
   *
   * @returns PlatformAuthResult with new tokens
   */
  reissuePlatformTokens(
    refreshToken: string,
    ipAddress: string,
    userAgent: string
  ): Promise<PlatformAuthResult>

  /**
   * Decodes and verifies a JWT without validating expiration.
   * Useful for extracting claims from expired tokens (e.g., blacklist).
   * @internal — NEVER use for authorization decisions.
   */
  decodeToken(token: string): DashboardJwtPayload | PlatformJwtPayload | null

  /**
   * Issues a temporary token for the MFA flow.
   * JWT with type: 'mfa_challenge' and a 5-minute expiration.
   *
   * @param userId ID of the user/admin who needs to complete MFA
   * @param context Origin context: 'dashboard' for tenant users, 'platform' for admins
   * @returns JWT string of the MFA temp token (includes the `context` claim in the payload)
   */
  issueMfaTempToken(userId: string, context: 'dashboard' | 'platform'): string

  /**
   * Verifies and extracts userId and context from an MFA temp token.
   * Validates in Redis that the token has not been used.
   *
   * @returns `{ userId, context }` — the `context` indicates the origin of the MFA challenge
   *          ('dashboard' for tenant users, 'platform' for admins).
   *          Required so that `MfaService.challenge()` knows which repository
   *          and result type to use.
   * @throws AUTH_ERROR_CODES.MFA_TEMP_TOKEN_INVALID if invalid or expired
   */
  verifyMfaTempToken(token: string): Promise<{ userId: string; context: 'dashboard' | 'platform' }>
}
```

### 6.4 SessionService

Management of user sessions with support for configurable limits and the FIFO strategy.

```typescript
class SessionService {
  /**
   * Creates a new session for the user.
   *
   * Flow:
   * 1. Generates a session hash from the refresh token
   * 2. Stores session details in Redis (device, IP, timestamps)
   * 3. Adds the hash to the user's session SET
   * 4. Checks the session limit
   * 5. If exceeded, applies the eviction strategy (FIFO)
   * 6. Notifies via email (if configured) about the new session
   * 7. Runs the onNewSession hook
   *
   * @param userId User ID
   * Takes an OBJECT, not positional arguments: most of these fields are `string`, so any two of
   * them can be swapped without the compiler noticing. `listSessions(userId, currentHash)` type
   * checked against the earlier positional form and treated the hash as the tenant, returning an
   * empty listing indistinguishable from "this user has no sessions".
   *
   * @param params See CreateSessionParams — userId, tenantId, rawRefreshToken, ip, userAgent
   */
  createSession(params: CreateSessionParams): Promise<string>

  /**
   * Lists all of the user's active sessions.
   *
   * @param params See ListSessionsParams — userId, tenantId, currentSessionHash?
   * @returns Array of sessions with device, IP, timestamps, and a current-session indicator
   */
  listSessions(params: ListSessionsParams): Promise<SessionInfo[]>

  /**
   * Revokes a specific session.
   *
   * Flow:
   * 1. Verifies that sessionHash belongs to the user via SISMEMBER on the derived session
   *    index — `auth:sess:{hmac_sha256(hmacKey, "dashboard:{utf8ByteLength(tenantId)}:{tenantId}:{userId}")}`, not the
   *    bare-id key this document described before the index was tenant-scoped
   * 2. If it does not belong, throws SESSION_NOT_FOUND (prevents BOLA/IDOR)
   * 3. Removes the refresh token, the session from the SET, and the session details
   *
   * @throws AUTH_ERROR_CODES.SESSION_NOT_FOUND if session not found
   */
  revokeSession(params: RevokeSessionParams): Promise<void>

  /**
   * Revokes all sessions except the current one.
   * Useful for "log out of all other devices".
   */
  revokeAllExceptCurrent(params: RevokeAllExceptCurrentParams): Promise<void>

  /**
   * Applies the session limit using the FIFO strategy.
   * Removes the oldest session when the limit is exceeded.
   *
   * Limit resolution follows this order:
   * 1. maxSessionsResolver(user) if provided — requires the full AuthUser object
   * 2. defaultMaxSessions from the configuration
   * 3. Default: 5
   *
   * @param userId User ID
   * @param user Full AuthUser object (required for `maxSessionsResolver`)
   *             If `maxSessionsResolver` is not configured, it can be omitted (null)
   */
  enforceSessionLimit(userId: string, user: AuthUser | null): Promise<void>
}
```

**`SessionInfo` interface:**

```typescript
interface SessionInfo {
  sessionHash: string
  device: string
  ip: string
  createdAt: Date
  lastActivityAt: Date
  isCurrent: boolean
}
```

### 6.5 MfaService

Multi-factor authentication service based on TOTP (Time-based One-Time Password) with a native implementation using `node:crypto` HMAC-SHA1, following RFC 4226 (HOTP) and RFC 6238 (TOTP). It uses no external dependencies — the generation and verification of TOTP codes is done entirely with native Node.js APIs.

**Native TOTP implementation (reference):**

```typescript
import { createHmac, randomBytes } from 'node:crypto'

/** Decodes a Base32 string (RFC 4648) into a Buffer. */
function base32Decode(encoded: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const stripped = encoded.replace(/=+$/, '').toUpperCase()
  let bits = ''
  for (const char of stripped) {
    const val = alphabet.indexOf(char)
    if (val === -1) throw new Error(`Invalid base32 character: ${char}`)
    bits += val.toString(2).padStart(5, '0')
  }
  const bytes = new Uint8Array(Math.floor(bits.length / 8))
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2)
  }
  return Buffer.from(bytes)
}

/** Generates an HOTP code (RFC 4226) from a secret and counter. */
function generateHOTP(secret: Buffer, counter: number, digits = 6): string {
  const buf = Buffer.alloc(8)
  buf.writeBigUInt64BE(BigInt(counter))

  const hmac = createHmac('sha1', secret).update(buf).digest()
  const offset = hmac[hmac.length - 1] & 0xf
  const code = (hmac.readUInt32BE(offset) & 0x7fffffff) % 10 ** digits
  return code.toString().padStart(digits, '0')
}

/** Generates a TOTP code (RFC 6238) for the current moment. */
function generateTOTP(secret: Buffer, period = 30, digits = 6): string {
  const counter = Math.floor(Date.now() / 1000 / period)
  return generateHOTP(secret, counter, digits)
}

/** Verifies a TOTP code with a tolerance window. */
function verifyTOTP(secret: Buffer, code: string, window = 1, period = 30, digits = 6): boolean {
  const counter = Math.floor(Date.now() / 1000 / period)
  for (let i = -window; i <= window; i++) {
    if (generateHOTP(secret, counter + i, digits) === code) return true
  }
  return false
}

/** Generates a URI for a QR code (otpauth:// standard) */
function buildTotpUri(secret: string, account: string, issuer: string): string {
  const encodedIssuer = encodeURIComponent(issuer)
  const encodedAccount = encodeURIComponent(account)
  return `otpauth://totp/${encodedIssuer}:${encodedAccount}?secret=${secret}&issuer=${encodedIssuer}&algorithm=SHA1&digits=6&period=30`
}
```

```typescript
class MfaService {
  /**
   * Starts MFA setup for a user.
   *
   * Flow:
   * 1. Checks whether MFA is already enabled
   * 2. Generates a random TOTP secret
   * 3. Encrypts the secret with AES-256-GCM
   * 4. Generates recovery codes
   * 5. Temporarily stores the encrypted secret and hashed recovery codes
   * 6. Returns the secret, QR code URI, and recovery codes in plaintext
   *
   * @throws AUTH_ERROR_CODES.MFA_ALREADY_ENABLED if already enabled
   * @returns MfaSetupResult with secret, QR code, and recovery codes
   */
  setup(userId: string): Promise<MfaSetupResult>

  /**
   * Verifies the TOTP code and enables MFA.
   *
   * Flow:
   * 1. Decrypts the temporary secret
   * 2. Validates the TOTP code against the secret
   * 3. If valid, persists MFA in the database (via updateMfa)
   * 4. Sends an email notification
   * 5. Runs the afterMfaEnabled hook
   *
   * @throws AUTH_ERROR_CODES.MFA_INVALID_CODE if code incorrect
   * @throws AUTH_ERROR_CODES.MFA_SETUP_REQUIRED if setup was not performed
   */
  verifyAndEnable(userId: string, code: string): Promise<void>

  /**
   * Processes the MFA challenge during login.
   *
   * Flow:
   * 1. Verifies the mfaTempToken
   * 2. Checks brute-force lockout via BruteForceService.isLockedOut(sha256(userId))
   * 3. Fetches the user and decrypts the secret
   * 4. Validates the TOTP code or recovery code
   * 5. If invalid, records the failure via BruteForceService.recordFailure(sha256(userId))
   * 6. After 5 consecutive failures, revokes the mfaTempToken from Redis (forces re-authentication)
   * 7. If a recovery code was used, removes it from the list
   * 8. Resets the brute-force counter via BruteForceService.resetFailures()
   * 9. Issues tokens (access JWT with mfaVerified: true + refresh)
   * 10. Creates a session (if enabled)
   *
   * Does NOT manipulate Response — the controller uses TokenDeliveryService to deliver.
   *
   * The method reads the `context` claim from the `MfaTempPayload` to determine the return type:
   * - `context === 'dashboard'` → returns `AuthResult` (tenant user tokens)
   * - `context === 'platform'`  → returns `PlatformAuthResult` (platform admin tokens)
   *
   * @param mfaTempToken Temporary token issued at login (contains `context` in the payload)
   * @param code 6-digit TOTP code or recovery code
   * @param ipAddress Request IP
   * @param userAgent Request User-Agent
   * @throws AUTH_ERROR_CODES.MFA_INVALID_CODE / RECOVERY_CODE_INVALID
   */
  challenge(
    mfaTempToken: string,
    code: string,
    ipAddress: string,
    userAgent: string
  ): Promise<AuthResult | PlatformAuthResult>

  /**
   * Disables MFA for a user.
   *
   * Flow:
   * 1. Verifies the current TOTP code to confirm identity
   * 2. Removes the secret and recovery codes from the database
   * 3. Sends an email notification
   * 4. Runs the afterMfaDisabled hook
   *
   * @throws AUTH_ERROR_CODES.MFA_NOT_ENABLED if not enabled
   * @throws AUTH_ERROR_CODES.MFA_INVALID_CODE if code incorrect
   */
  disable(userId: string, code: string): Promise<void>

  /**
   * Encrypts a TOTP secret with AES-256-GCM.
   * Uses the encryptionKey from the configuration.
   *
   * IV: crypto.randomBytes(12) generated fresh per operation (NEVER reuse).
   * Format: base64(iv) + ':' + base64(authTag) + ':' + base64(ciphertext)
   *
   * @returns String in the format "iv:authTag:ciphertext" (base64)
   */
  encryptSecret(secret: string): string

  /**
   * Decrypts a TOTP secret.
   * @returns TOTP secret in plaintext
   */
  decryptSecret(encrypted: string): string

  /**
   * Generates and hashes the recovery codes.
   * @returns { plainCodes: string[], hashedCodes: string[] }
   */
  hashRecoveryCodes(count: number): {
    plainCodes: string[]
    hashedCodes: string[]
  }

  /**
   * Verifies a recovery code against the list of hashes.
   * Uses constant-time comparison.
   * @returns Index of the code if valid, -1 if invalid
   */
  verifyRecoveryCode(code: string, hashedCodes: string[]): Promise<number>
}

// Dependencies injected by MfaService:
// - BYMAX_AUTH_OPTIONS (module configuration)
// - IUserRepository (fetch user for dashboard challenge)
// - IPlatformUserRepository (fetch admin for platform challenge, when platform.enabled)
// - AuthRedisService (store/retrieve temporary secrets, mark recovery codes used)
// - TokenManagerService (issue tokens after MFA completed)
// - SessionService (create session after MFA, when sessions.enabled)
// - BruteForceService (lockout by userId in case of consecutive failures)
// - PasswordService (hash recovery codes with scrypt)
// - IEmailProvider (notifications for MFA enabled/disabled)
// - IAuthHooks (afterMfaEnabled, afterMfaDisabled)
```

**`MfaSetupResult` type:**

```typescript
interface MfaSetupResult {
  /** TOTP secret in plaintext (display only once to the user) */
  secret: string

  /** URI for QR code generation (otpauth://totp/...) */
  qrCodeUri: string

  /** Recovery codes in plaintext (display only once — user must store them) */
  recoveryCodes: string[]
}
```

### 6.6 PasswordResetService

Password reset service with support for two methods: token (link by email) and OTP (numeric code).

```typescript
class PasswordResetService {
  /**
   * Starts the password reset process.
   *
   * Flow:
   * 1. Fetches the user by email (does NOT reveal whether it exists or not)
   * 2. If method = 'token':
   *    a. Generates a secure token (crypto.randomBytes)
   *    b. Stores sha256(token) → userId in Redis
   *    c. Sends an email with a link containing the token
   * 3. If method = 'otp':
   *    a. Generates a numeric OTP via OtpService
   *    b. Stores it in Redis
   *    c. Sends an email with the OTP
   * 4. Returns success (always, regardless of whether the user exists)
   *
   * Security: Never returns an error if the email does not exist (prevents enumeration).
   */
  initiateReset(email: string, tenantId: string): Promise<void>

  /**
   * Resets the password using a token or OTP.
   *
   * Flow (token):
   * 1. Fetches userId via sha256(token) in Redis
   * 2. Hashes the new password
   * 3. Updates the password via the repository
   * 4. Removes the token from Redis
   * 5. Revokes all of the user's sessions
   * 6. Runs the afterPasswordReset hook
   *
   * Flow (OTP):
   * 1. Verifies the OTP via OtpService
   * 2. Same steps 2-6 above
   *
   * @throws AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID / EXPIRED
   * @throws AUTH_ERROR_CODES.OTP_INVALID / EXPIRED / MAX_ATTEMPTS
   */
  resetPassword(dto: ResetPasswordDto): Promise<void>

  /**
   * Verifies an OTP and issues a temporary verification token.
   * Used in the 2-step flow: first verify the OTP, then show the new-password form.
   *
   * Flow:
   * 1. Validates the OTP via OtpService.verify() (CONSUMES the OTP)
   * 2. Generates a temporary verification token (UUID)
   * 3. Stores in Redis: auth:prv:{sha256(token)} → { email, tenantId }, TTL 5 minutes
   * 4. Returns the verification token
   *
   * resetPassword validates that the request's tenantId matches the
   * tenantId stored in the token, preventing cross-tenant reset.
   *
   * The resetPassword endpoint accepts this token instead of the original OTP,
   * eliminating the race-condition window between verification and reset.
   *
   * @throws AUTH_ERROR_CODES.OTP_INVALID / EXPIRED / MAX_ATTEMPTS
   * @returns Temporary verification token (5 minutes of validity)
   */
  verifyOtp(email: string, otp: string, tenantId: string): Promise<{ verifiedToken: string }>

  /**
   * Resends the password reset OTP.
   * Generates a new OTP, stores it in Redis, and sends it via IEmailProvider.
   * Security: Returns success even if the email does not exist (prevents enumeration).
   *
   * @param email User's email
   * @param tenantId Tenant ID
   */
  resendOtp(email: string, tenantId: string): Promise<void>
}
```

### 6.7 OtpService

Generic service for generating and verifying OTPs (One-Time Passwords).

```typescript
class OtpService {
  /**
   * Generates a cryptographically secure numeric OTP.
   *
   * MANDATORY implementation: use `crypto.randomInt(0, 10 ** length)` (Node.js built-in).
   * NEVER use `Math.random()` — it is not cryptographically secure and produces predictable OTPs.
   *
   * @param length OTP length (default: 6). Recommended maximum: 8
   * @returns Numeric string with leading zeros if needed (e.g., '048291' for length=6)
   */
  generate(length?: number): string

  /**
   * Stores an OTP in Redis.
   * @param purpose Purpose of the OTP (e.g., 'password_reset', 'email_verification')
   * @param identifier sha256(tenantId + ":" + email) — scoped per tenant
   * @param code OTP code
   * @param ttlSeconds TTL in seconds
   */
  store(purpose: string, identifier: string, code: string, ttlSeconds: number): Promise<void>

  /**
   * Verifies an OTP.
   *
   * Flow:
   * 1. Fetches the OTP from Redis by purpose + identifier (already contains hash of tenantId + email)
   * 2. If not found, throws OTP_EXPIRED
   * 3. Checks the attempt counter
   * 4. If it exceeded the maximum (5), throws OTP_MAX_ATTEMPTS
   * 5. Compares the code (constant-time)
   * 6. If valid, removes it from Redis
   * 7. If invalid, increments the attempts
   *
   * @throws AUTH_ERROR_CODES.OTP_INVALID / OTP_EXPIRED / OTP_MAX_ATTEMPTS
   */
  verify(purpose: string, identifier: string, code: string): Promise<void>

  /**
   * Increments the failed-attempt counter of an OTP.
   * Called internally by verify() in case of failure.
   */
  incrementAttempts(purpose: string, identifier: string): Promise<void>
}
```

### 6.8 BruteForceService

Protection against brute-force attacks using counters in Redis.

```typescript
class BruteForceService {
  /**
   * Checks whether an identifier is locked out.
   *
   * @param identifier sha256(tenantId + ":" + email) — scoped per tenant to avoid cross-tenant lockout
   * @returns true if the number of attempts exceeded maxAttempts
   */
  isLockedOut(identifier: string): Promise<boolean>

  /**
   * Records a failed attempt.
   * Increments the counter in Redis and sets TTL = windowSeconds.
   *
   * @param identifier sha256(tenantId + ":" + email) — scoped per tenant to avoid cross-tenant lockout
   */
  recordFailure(identifier: string): Promise<void>

  /**
   * Resets the failed-attempt counter.
   * Called after a successful login.
   *
   * @param identifier sha256(tenantId + ":" + email) — scoped per tenant to avoid cross-tenant lockout
   */
  resetFailures(identifier: string): Promise<void>

  /**
   * Returns the remaining lockout time in seconds.
   * Uses the Redis TTL command on the `lf` key.
   * Returns 0 if not locked out.
   *
   * @param identifier sha256(tenantId + ":" + email)
   * @returns Remaining lockout seconds
   */
  getRemainingLockoutSeconds(identifier: string): Promise<number>
}
```

### 6.9 PlatformAuthService

Authentication service for platform administrators (super-admins).

```typescript
class PlatformAuthService {
  /**
   * Authenticates a platform admin.
   *
   * Flow:
   * 1. Checks brute-force lockout
   * 2. Fetches the admin by email via IPlatformUserRepository
   * 3. Compares the password
   * 4. If MFA enabled, issues an mfaTempToken
   * 5. If not, issues a platform JWT (type: 'platform')
   * 6. Updates lastLoginAt
   *
   * @throws AUTH_ERROR_CODES.INVALID_CREDENTIALS
   * @throws AUTH_ERROR_CODES.ACCOUNT_LOCKED
   * @throws AUTH_ERROR_CODES.ACCOUNT_BANNED / ACCOUNT_INACTIVE / ACCOUNT_SUSPENDED
   */
  login(
    dto: PlatformLoginDto,
    ipAddress: string,
    userAgent: string
  ): Promise<PlatformAuthResult | MfaChallengeResult>

  /**
   * Returns the authenticated admin's data.
   */
  getMe(userId: string): Promise<AuthPlatformUser>

  /**
   * Logs out the platform admin.
   *
   * Flow:
   * 1. Adds the access JWT to the blacklist (Redis, TTL = remaining JWT time)
   * 2. Revokes the refresh token in Redis (prefix `prt`)
   * 3. Runs the afterLogout hook
   *
   * @throws AUTH_ERROR_CODES.TOKEN_INVALID if token invalid
   */
  logout(accessToken: string, refreshToken: string): Promise<void>

  /**
   * Renews the platform admin's tokens.
   *
   * Flow:
   * 1. Extracts the refresh token (cookie or body according to tokenDelivery)
   * 2. Fetches the session in Redis via sha256(refreshToken) with prefix `prt`
   * 3. Refresh token rotation with grace window
   * 4. Returns PlatformAuthResult with new tokens
   *
   * @throws AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID
   */
  refresh(
    rawRefreshToken: string,
    ipAddress: string,
    userAgent: string
  ): Promise<PlatformAuthResult>

  /**
   * Revokes ALL active refresh tokens of a platform admin.
   *
   * Should be called by the host application when:
   * - Deleting/deactivating a platform admin
   * - Forcing re-authentication for security reasons
   * - Detecting an account compromise
   *
   * Flow:
   * 1. Fetches all session hashes via `SMEMBERS` on the derived platform index,
   *    `auth:psess:{hmac_sha256(hmacKey, "platform:{userId}")}`
   * 2. For each hash: deletes `auth:prt:{hash}` and `auth:psd:{hash}`
   * 3. Removes that same derived platform session SET
   *
   * Note: Does not invalidate active access tokens (JWTs are stateless with a 15min TTL).
   * For immediate access token invalidation, add the `jti` to the blacklist (`rv`).
   *
   * @param userId Platform admin ID
   */
  revokeAllPlatformSessions(userId: string): Promise<void>
}
```

**Return types:**

```typescript
interface PlatformAuthResult {
  admin: AuthPlatformUser
  accessToken: string
  rawRefreshToken: string
}
```

### 6.10 InvitationService

Invitation system for adding users to a tenant.

```typescript
class InvitationService {
  /**
   * Creates and sends an invitation.
   *
   * Flow:
   * 1. Generates a secure token
   * 2. Validates that the inviter is authorized to grant the requested role
   *    (inviter.role must be equal to or higher than the role in the hierarchy)
   * 3. Stores in Redis: sha256(token) → { email, role, tenantId, inviterId }
   * 4. Sends an invitation email via IEmailProvider.sendInvitation()
   *
   * Security: The tenantId is extracted from the inviter's JWT by the controller,
   * NOT from the request body, preventing cross-tenant invitation injection.
   *
   * @param inviterId ID of the user who is inviting
   * @param email Email of the invitee
   * @param role Role the invitee will have in the tenant
   * @param tenantId Tenant ID
   * @throws AUTH_ERROR_CODES.INSUFFICIENT_ROLE if the inviter cannot grant the role
   */
  invite(inviterId: string, email: string, role: string, tenantId: string): Promise<void>

  /**
   * Accepts an invitation and creates the user.
   *
   * Flow:
   * 1. Fetches the invitation in Redis via sha256(token)
   * 2. If not found, throws INVALID_INVITATION_TOKEN
   * 3. Checks whether the email already exists in the tenant
   * 4. Creates the user with the role and tenant from the invitation
   * 5. Removes the invitation from Redis
   * 6. Issues tokens (access + refresh)
   * 7. Runs the afterInvitationAccepted hook
   *
   * Does NOT manipulate Response — the controller uses TokenDeliveryService to deliver.
   *
   * @throws AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN
   * @throws AUTH_ERROR_CODES.EMAIL_ALREADY_EXISTS
   */
  acceptInvitation(
    dto: AcceptInvitationDto,
    ipAddress: string,
    userAgent: string
  ): Promise<AuthResult>
}
```

### 6.11 TokenDeliveryService

Service responsible for delivering tokens to the client according to the configured `tokenDelivery`. It encapsulates all the cookie and body response logic — controllers and guards delegate to it without knowing the active mode.

**Return types of the delivery methods:**

```typescript
/** Return of deliverAuthResponse — discriminated by delivery mode */
type AuthResponseBody =
  | { user: AuthUser } // 'cookie' mode
  | { user: AuthUser; accessToken: string; refreshToken: string } // 'bearer' mode
  | { user: AuthUser; accessToken: string; refreshToken: string } // 'both' mode
  | { admin: AuthPlatformUser } // 'cookie' mode (platform)
  | { admin: AuthPlatformUser; accessToken: string; refreshToken: string } // 'bearer'/'both' mode (platform)

/** Return of deliverRefreshResponse — discriminated by delivery mode */
type RefreshResponseBody =
  | Record<string, never> // 'cookie' mode (empty body)
  | { accessToken: string; refreshToken: string } // 'bearer' or 'both' mode
```

```typescript
class TokenDeliveryService {
  /**
   * Delivers the authentication tokens to the client.
   *
   * Behavior per mode:
   * - 'cookie': sets HttpOnly cookies on the response, returns only `{ user }`
   * - 'bearer': does not set cookies, returns `{ user, accessToken, refreshToken }`
   * - 'both': sets cookies AND returns tokens in the body
   *
   * @param res Express Response
   * @param req Express Request (to resolve cookie domains)
   * @param authResult Authentication result (tokens + user/admin)
   * @returns Object to send in the response body
   *
   * Accepts both `AuthResult` (dashboard) and `PlatformAuthResult` (platform)
   * via the generic type `{ accessToken, rawRefreshToken, [user|admin] }`.
   */
  deliverAuthResponse(
    res: Response,
    req: Request,
    authResult: AuthResult | PlatformAuthResult
  ): AuthResponseBody

  /**
   * Delivers new tokens after a refresh.
   *
   * Behavior per mode:
   * - 'cookie': sets new cookies, clears old ones, returns `{}`
   * - 'bearer': returns `{ accessToken, refreshToken }`
   * - 'both': sets cookies AND returns tokens
   *
   * Accepts both `AuthResult` (dashboard) and `PlatformAuthResult` (platform).
   */
  deliverRefreshResponse(
    res: Response,
    req: Request,
    authResult: AuthResult | PlatformAuthResult
  ): RefreshResponseBody

  /**
   * Extracts the access token from the request.
   *
   * Behavior per mode:
   * - 'cookie': reads from `req.cookies[accessTokenName]`
   * - 'bearer': reads from `Authorization: Bearer <token>`
   * - 'both': tries cookie first, then header
   *
   * @returns JWT string or null if not found
   */
  extractAccessToken(req: Request): string | null

  /**
   * Extracts the refresh token from the request.
   *
   * Behavior per mode:
   * - 'cookie': reads from `req.cookies[refreshTokenName]`
   * - 'bearer': reads from `req.body.refreshToken`
   * - 'both': tries cookie first, then body
   *
   * @returns Refresh token string or null if not found
   */
  extractRefreshToken(req: Request): string | null

  /**
   * Clears the client's authentication session.
   *
   * Behavior per mode:
   * - 'cookie': clears all authentication cookies
   * - 'bearer': no-op (the client is responsible for discarding tokens)
   * - 'both': clears cookies (the client discards the tokens from the body)
   */
  clearAuthSession(res: Response, req: Request): void

  /**
   * Sets the access token cookie (internal use).
   * Ignored when `tokenDelivery: 'bearer'`.
   */
  private setAccessCookie(res: Response, token: string): void

  /**
   * Sets the refresh token cookie (internal use).
   * Ignored when `tokenDelivery: 'bearer'`.
   */
  private setRefreshCookie(res: Response, token: string): void

  /**
   * Resolves all the domains where cookies should be set.
   * Uses resolveDomains from the configuration or extractDomain as a fallback.
   */
  resolveCookieDomains(req: Request): string[]

  /**
   * Extracts the base domain from the request's hostname.
   * E.g.: 'api.example.com' → '.example.com'
   */
  extractDomain(hostname: string): string
}
```

---

## 7. Controllers

### 7.1 AuthController

**Prefix:** `/{routePrefix}` (default: `/auth`)

| Method | Route                  | Auth          | Guards         | Body                       | Description                                                        |
| ------ | ---------------------- | ------------- | -------------- | -------------------------- | ------------------------------------------------------------------ |
| `POST` | `/register`            | Public        | —              | `RegisterDto`              | Registers a new user                                               |
| `POST` | `/login`               | Public        | —              | `LoginDto`                 | Authenticates user with email/password                             |
| `POST` | `/logout`              | JWT           | `JwtAuthGuard` | —                          | Logs out user, revokes tokens (cookie or header)                   |
| `POST` | `/refresh`             | Cookie/Bearer | —              | `{ refreshToken? }`        | Renews tokens; accepts cookie or body according to `tokenDelivery` |
| `GET`  | `/me`                  | JWT           | `JwtAuthGuard` | —                          | Returns the authenticated user's data                              |
| `POST` | `/verify-email`        | Public        | —              | `{ email, otp, tenantId }` | Verifies email with OTP                                            |
| `POST` | `/resend-verification` | Public        | —              | `{ email, tenantId }`      | Resends verification OTP                                           |

**DTOs:**

```typescript
// register.dto.ts
export class RegisterDto {
  @IsEmail()
  email: string

  @IsString()
  @MinLength(8)
  @MaxLength(128) // Practical limit for passwords
  password: string

  @IsString()
  @MinLength(2)
  name: string

  @IsString()
  tenantId: string
}

// login.dto.ts
export class LoginDto {
  @IsEmail()
  email: string

  @IsString()
  @MaxLength(128) // Practical limit for passwords
  password: string

  @IsString()
  tenantId: string
}
```

### 7.2 MfaController

**Prefix:** `/{routePrefix}/mfa` (default: `/auth/mfa`)

| Method | Route        | Auth                  | Guards         | Body              | Description                          |
| ------ | ------------ | --------------------- | -------------- | ----------------- | ------------------------------------ |
| `POST` | `/setup`     | JWT                   | `JwtAuthGuard` | —                 | Starts MFA setup, returns QR code    |
| `POST` | `/verify`    | JWT                   | `JwtAuthGuard` | `MfaVerifyDto`    | Verifies code and enables MFA        |
| `POST` | `/challenge` | Public + mfaTempToken | —              | `MfaChallengeDto` | Completes MFA challenge during login |
| `POST` | `/disable`   | JWT                   | `JwtAuthGuard` | `MfaDisableDto`   | Disables MFA                         |

**DTOs:**

```typescript
// mfa-verify.dto.ts
export class MfaVerifyDto {
  @IsString()
  @Length(6, 6)
  code: string
}

// mfa-challenge.dto.ts
export class MfaChallengeDto {
  @IsString()
  mfaTempToken: string

  @IsString()
  @MaxLength(128) // TOTP has 6 chars; recovery codes have ~32 chars; the limit prevents hash bombing
  code: string // 6-digit TOTP or recovery code
}

// mfa-disable.dto.ts
export class MfaDisableDto {
  @IsString()
  @Length(6, 6)
  code: string
}
```

### 7.3 PasswordResetController

**Prefix:** `/{routePrefix}/password` (default: `/auth/password`)

| Method | Route              | Auth   | Guards | Body                       | Description                                             |
| ------ | ------------------ | ------ | ------ | -------------------------- | ------------------------------------------------------- |
| `POST` | `/forgot-password` | Public | —      | `ForgotPasswordDto`        | Starts password reset                                   |
| `POST` | `/reset-password`  | Public | —      | `ResetPasswordDto`         | Resets password with token or OTP                       |
| `POST` | `/verify-otp`      | Public | —      | `{ email, otp, tenantId }` | Verifies OTP and returns a temporary verification token |
| `POST` | `/resend-otp`      | Public | —      | `{ email, tenantId }`      | Resends reset OTP                                       |

**DTOs:**

```typescript
// forgot-password.dto.ts
export class ForgotPasswordDto {
  @IsEmail()
  email: string

  @IsString()
  tenantId: string
}

// reset-password.dto.ts
export class ResetPasswordDto {
  @IsEmail()
  email: string

  @IsString()
  @MinLength(8)
  @MaxLength(128) // Practical limit for passwords
  newPassword: string

  @IsOptional()
  @IsString()
  token?: string // For method = 'token'

  @IsOptional()
  @IsString()
  otp?: string // For method = 'otp'

  @IsOptional()
  @IsString()
  verifiedToken?: string // For the 2-step flow (OTP → verifiedToken → reset)

  @IsString()
  tenantId: string
}
```

### 7.4 SessionController

**Prefix:** `/{routePrefix}/sessions` (default: `/auth/sessions`)

| Method   | Route  | Auth | Guards         | Body | Description                    |
| -------- | ------ | ---- | -------------- | ---- | ------------------------------ |
| `GET`    | `/`    | JWT  | `JwtAuthGuard` | —    | Lists all active sessions      |
| `DELETE` | `/:id` | JWT  | `JwtAuthGuard` | —    | Revokes a specific session     |
| `DELETE` | `/all` | JWT  | `JwtAuthGuard` | —    | Revokes all except the current |

**Responses:**

```typescript
// GET /auth/sessions
// Response: 200 OK
{
  "sessions": [
    {
      "sessionHash": "abc123...",
      "device": "Chrome 120 on macOS",
      "ip": "189.40.xx.xx",
      "createdAt": "2026-04-01T10:30:00Z",
      "lastActivityAt": "2026-04-09T14:22:00Z",
      "isCurrent": true
    },
    {
      "sessionHash": "def456...",
      "device": "Safari on iPhone",
      "ip": "201.17.xx.xx",
      "createdAt": "2026-04-05T08:15:00Z",
      "lastActivityAt": "2026-04-08T19:45:00Z",
      "isCurrent": false
    }
  ]
}
```

### 7.5 PlatformAuthController

**Prefix:** `/{routePrefix}/platform` (default: `/auth/platform`)

| Method   | Route            | Auth                  | Guards             | Body                | Description                                                 |
| -------- | ---------------- | --------------------- | ------------------ | ------------------- | ----------------------------------------------------------- |
| `POST`   | `/login`         | Public                | —                  | `PlatformLoginDto`  | Authenticates platform admin                                |
| `POST`   | `/mfa/challenge` | Public + mfaTempToken | —                  | `MfaChallengeDto`   | Completes MFA challenge for platform admins                 |
| `GET`    | `/me`            | Platform JWT          | `JwtPlatformGuard` | —                   | Returns the admin's data                                    |
| `POST`   | `/logout`        | Platform JWT          | `JwtPlatformGuard` | —                   | Logs out admin, revokes tokens                              |
| `POST`   | `/refresh`       | Cookie/Bearer         | —                  | `{ refreshToken? }` | Renews platform admin tokens                                |
| `DELETE` | `/sessions`      | Platform JWT          | `JwtPlatformGuard` | —                   | Revokes all admin sessions (useful in compromise scenarios) |

> **Platform MFA flow:** `POST /auth/platform/login` → if MFA enabled, returns `{ mfaRequired: true, mfaTempToken }` → `POST /auth/platform/mfa/challenge` with `MfaChallengeDto` → `MfaService.challenge()` reads `context: 'platform'` from the `MfaTempPayload` → returns `PlatformAuthResult` with platform tokens.

**DTO:**

```typescript
// platform-login.dto.ts
export class PlatformLoginDto {
  @IsEmail()
  email: string

  @IsString()
  @MaxLength(128) // Practical limit for passwords
  password: string
}
```

### 7.6 InvitationController

**Prefix:** `/{routePrefix}/invitations` (default: `/auth/invitations`)

| Method | Route     | Auth           | Guards                       | Body                  | Description                                                                                |
| ------ | --------- | -------------- | ---------------------------- | --------------------- | ------------------------------------------------------------------------------------------ |
| `POST` | `/`       | JWT            | `JwtAuthGuard`, `RolesGuard` | `CreateInvitationDto` | Creates and sends invitation (tenantId extracted from JWT) (requires role >= granted role) |
| `POST` | `/accept` | Public + token | —                            | `AcceptInvitationDto` | Accepts invitation and creates account                                                     |

**DTO:**

```typescript
// accept-invitation.dto.ts
export class AcceptInvitationDto {
  @IsString()
  token: string

  @IsString()
  @MinLength(2)
  name: string

  @IsString()
  @MinLength(8)
  @MaxLength(128) // Practical limit for passwords
  password: string
}

// create-invitation.dto.ts
// Note: tenantId is NOT in the DTO — it is extracted automatically from the inviter's JWT
// to prevent cross-tenant invitation injection.
export class CreateInvitationDto {
  @IsEmail()
  email: string

  @IsString()
  // Validated dynamically against roles.hierarchy at module initialization
  // Rejects roles that do not exist in the configured hierarchy
  role: string
}
```

---

## 8. Guards and Decorators

### 8.1 Guards

| Guard | Description | Application |
| ------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- | -------------------------------------------------------------------------------- | ------ | ----------- |
| `JwtAuthGuard` | Validates the dashboard/tenant JWT in the cookie or `Authorization: Bearer` header. Checks `payload.type === 'dashboard'` — rejects `platform` and `mfa_challenge` tokens with `auth.token_invalid`. Extracts the payload and populates `request.user`. Respects the `@Public()` decorator to skip validation. | Global or per-route guard for authenticated endpoints |
| `JwtPlatformGuard` | Validates the platform JWT. Checks `payload.type === 'platform'` — rejects `dashboard` tokens with `auth.platform_auth_required`. Shares `jwt.secret` with `JwtAuthGuard` (isolation via the `type` claim, not via the key). | Platform admin endpoints |
| `RolesGuard` | Checks whether the user's role satisfies the defined hierarchy. Uses metadata set by `@Roles()`. A parent role inherits all child roles. | Endpoint, via `@Roles()` |

The per-route throttle limits the controllers apply with `@Throttle()`:

| Endpoint                              | Limit  | Window    | Description                                                                      |
| ------------------------------------- | ------ | --------- | -------------------------------------------------------------------------------- |
| `POST /auth/login`                    | 5 req  | 1 minute  | Protects against brute-force per IP                                              |
| `POST /auth/register`                 | 10 req | 1 hour    | Protects against mass account creation                                           |
| `POST /auth/refresh`                  | 10 req | 1 minute  | Limits refresh requests                                                          |
| `POST /auth/logout`                   | 20 req | 1 minute  | Public route: bounds the cost of an unauthenticated call                         |
| `POST /auth/ws-ticket`                | 20 req | 1 minute  | Bounds socket-upgrade ticket minting                                             |
| `POST /auth/password/forgot-password` | 3 req  | 5 minutes | Prevents spam of reset emails                                                    |
| `POST /auth/password/reset-password`  | 3 req  | 5 minutes | Protects the reset endpoint                                                      |
| `POST /auth/password/change`          | 5 req  | 1 minute  | Protects the authenticated change against a stolen access token                  |
| `POST /auth/password/verify-otp`      | 3 req  | 5 minutes | Protects OTP verification (aligned with the internal max. of 5 attempts per OTP) |
| `POST /auth/password/resend-otp`      | 3 req  | 5 minutes | Prevents spam of password reset OTPs                                             |
| `POST /auth/verify-email`             | 5 req  | 1 minute  | Limits email verification                                                        |
| `POST /auth/resend-verification`      | 3 req  | 5 minutes | Prevents spam of verification emails                                             |
| `POST /auth/mfa/setup`                | 5 req  | 1 minute  | Limits setup attempts                                                            |
| `POST /auth/mfa/verify-enable`        | 5 req  | 1 minute  | Limits enrolment confirmation attempts                                           |
| `POST /auth/mfa/challenge`            | 5 req  | 1 minute  | Limits MFA attempts                                                              |
| `POST /auth/mfa/disable`              | 3 req  | 5 minutes | Protects MFA deactivation                                                        |
| `POST /auth/platform/login`           | 5 req  | 1 minute  | Protects admin login                                                             |
| `POST /auth/invitations`              | 10 req | 1 hour    | Limits invitation minting                                                        |
| `POST /auth/invitations/accept`       | 5 req  | 1 minute  | Protects invitation acceptance                                                   |
| `POST /auth/invitations/revoke`       | 10 req | 1 hour    | Matches the mint, so withdrawing costs what issuing does                         |
| `POST /auth/email/change`             | 3 req  | 5 minutes | Sends mail to a caller-supplied address; matches the reset-email limits          |
| `POST /auth/email/change/confirm`     | 5 req  | 1 minute  | Bounds guessing at the address-change token                                      |
| `GET /auth/sessions`                  | 30 req | 1 minute  | Limits session listing                                                           |
| `DELETE /auth/sessions/:id`           | 10 req | 1 minute  | Limits per-session revocation                                                    |
| `POST /auth/sessions/revoke-all`      | 5 req  | 1 minute  | Limits bulk revocation                                                           |
| `GET /auth/oauth/:provider`           | 10 req | 1 minute  | Limits OAuth starts                                                              |
| `GET /auth/oauth/:provider/callback`  | 10 req | 1 minute  | Limits OAuth callbacks                                                           |

### 16.4 Usage in controllers

The controllers apply the throttle configs via the `@Throttle()` decorator:

```typescript
// auth.controller.ts
@Controller('auth')
export class AuthController {
  @Post('login')
  @Public()
  @Throttle(AUTH_THROTTLE_CONFIGS.login)
  async login(
    @Body() dto: LoginDto,
    @Res({ passthrough: true }) res: Response, // passthrough: true preserves NestJS interceptors
    @Req() req: Request
  ) {
    const result = await this.authService.login(dto, req.ip, req.headers['user-agent'])
    // deliverAuthResponse sets cookies (if cookie/both) and returns the body
    return this.tokenDeliveryService.deliverAuthResponse(res, req, result)
  }

  @Post('register')
  @Public()
  @Throttle(AUTH_THROTTLE_CONFIGS.register)
  async register(
    @Body() dto: RegisterDto,
    @Res({ passthrough: true }) res: Response, // passthrough: true preserves NestJS interceptors
    @Req() req: Request
  ) {
    // ...
  }
}
```

### 16.5 Host application prerequisite

The host application **must** configure the `ThrottlerModule` for the `@Throttle()` decorators to work:

```typescript
// app.module.ts
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler'
import { APP_GUARD } from '@nestjs/core'

@Module({
  imports: [
    ThrottlerModule.forRoot([
      {
        ttl: 60_000, // Global default: 100 req/min
        limit: 100
      }
    ])
  ],
  providers: [
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard
    }
  ]
})
export class AppModule {}
```

---

## 17. What Is NOT in the Package

The `@bymax-one/nest-auth` was designed with clear boundaries. The following items are the **responsibility of the host application** and are not included in the package:

| Item                                     | Reason                                                                                                                                                    | Where to implement                                                        |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| **Prisma schemas / database migrations** | The package is database-agnostic. It works with any ORM via interfaces.                                                                                   | In the host application, in the Prisma/TypeORM/etc. schemas.              |
| **Email templates**                      | The package is template-agnostic. It defines what to send, not how to render.                                                                             | In the host application's `IEmailProvider` implementation.                |
| **Tenant creation**                      | Business logic specific to the platform (plans, billing, onboarding).                                                                                     | The host application's tenants module.                                    |
| **Billing, plans, and subscriptions**    | Scope of `@bymax/stripe` or a billing module.                                                                                                             | The host application's billing module.                                    |
| **API key authentication**               | A different scope — for M2M integration, not for users.                                                                                                   | A separate module or middleware of the host application.                  |
| **Portal sessions (Stripe)**             | Stripe-specific, not related to authentication.                                                                                                           | Billing module.                                                           |
| **Audit logging**                        | The package provides hooks (`afterLogin`, `afterRegister`, etc.) for the host application to record.                                                      | Via `IAuthHooks` hooks and an audit module.                               |
| **CORS / Helmet / CSP**                  | Infrastructure configuration, not authentication.                                                                                                         | `main.ts` or global middleware of the host application.                   |
| **Database connections**                 | The package receives already-connected repositories via dependency injection.                                                                             | The host application's database module.                                   |
| **Additional profile fields**            | Beyond the `AuthUser` fields, profiles are the responsibility of the application.                                                                         | The host application's profiles table.                                    |
| **Tenant resolution middleware**         | How to determine the request's tenant (subdomain, header, path) is application-specific.                                                                  | Middleware or interceptor of the host application.                        |
| **Custom password validation**           | The package checks only the minimum length (8 chars). Additional rules live in the application.                                                           | Via the `beforeRegister` hook or DTO validation in the application.       |
| **Additional frontend components**       | The package provides the `./client`, `./react`, and `./nextjs` subpaths (see section 21). Specific UI components (forms, modals) live in the application. | The UI library of choice (Chakra, Material, etc.).                        |
| **OAuth state management**               | The OAuth `state` parameter (CSRF protection) is managed by the package via Redis (see section 11.5).                                                     | Automatic in the package's OAuth flow.                                    |
| **Email change flow**                    | Requires re-verification of the new email, notification on the old email — a complex, specific flow                                                       | Implement in the host application using `IEmailProvider` and `OtpService` |
| **Account deletion (GDPR erasure)**      | The right to be forgotten requires anonymization of financial data — business logic                                                                       | Implement in the host application; use hooks for auth cleanup             |

---

## 18. Dependencies

### 18.1 Peer Dependencies (Server subpath)

These dependencies must be installed in the host application that uses the server subpath. The package does not include them — it expects them to already exist.

| Package             | Version   | Reason                                             |
| ------------------- | --------- | -------------------------------------------------- |
| `@nestjs/common`    | `^11.0.0` | Framework core — decorators, exceptions, providers |
| `@nestjs/core`      | `^11.0.0` | Framework core — module system, DI container       |
| `@nestjs/jwt`       | `^11.0.0` | Issuance and verification of JWTs                  |
| `@nestjs/throttler` | `^6.0.0`  | Rate limiting via decorators                       |
| `class-transformer` | `^0.5.0`  | DTO transformation                                 |
| `class-validator`   | `^0.14.0` | DTO validation                                     |
| `ioredis`           | `^6.0.0`  | Redis client                                       |
| `reflect-metadata`  | `^0.2.0`  | Metadata reflection for decorators                 |

### 18.2 Dependencies

The package **has no direct dependencies** (`"dependencies": {}`), so it adds no supply-chain risk through its own runtime dependencies, and all cryptography features (scrypt, TOTP, AES-256-GCM) and OAuth use Node.js 24+ native `node:crypto` and `fetch` — keeping the security-critical paths free of third-party packages. The functionality the package builds on (NestJS, ioredis, class-validator, etc.) is declared as **peer dependencies** and provided by the host application.

### 18.3 Optional Peer Dependencies

| Package              | Version   | When needed                                               |
| -------------------- | --------- | --------------------------------------------------------- |
| `@nestjs/websockets` | `^11.0.0` | Only if you use `WsJwtGuard` for WebSocket authentication |

### 18.4 Peer Dependencies by Subpath

| Subpath      | Peer Dependencies                                                                                                                                                             |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `.` (server) | `@nestjs/common ^11`, `@nestjs/core ^11`, `@nestjs/jwt ^11`, `@nestjs/throttler ^6`, `ioredis ^6`, `class-transformer ^0.5`, `class-validator ^0.14`, `reflect-metadata ^0.2` |
| `./shared`   | None                                                                                                                                                                          |
| `./client`   | None                                                                                                                                                                          |
| `./react`    | `react ^19`                                                                                                                                                                   |
| `./nextjs`   | `next ^16`, `react ^19`                                                                                                                                                       |

### 18.5 Example `package.json`

```json
{
  "name": "@bymax-one/nest-auth",
  "version": "1.0.0",
  "description": "Full-stack authentication package for the Bymax SaaS ecosystem",
  "files": ["dist"],
  "exports": {
    ".": {
      "types": "./dist/server/index.d.ts",
      "import": "./dist/server/index.mjs",
      "require": "./dist/server/index.cjs"
    },
    "./shared": {
      "types": "./dist/shared/index.d.ts",
      "import": "./dist/shared/index.mjs",
      "require": "./dist/shared/index.cjs"
    },
    "./client": {
      "types": "./dist/client/index.d.ts",
      "import": "./dist/client/index.mjs",
      "require": "./dist/client/index.cjs"
    },
    "./react": {
      "types": "./dist/react/index.d.ts",
      "import": "./dist/react/index.mjs",
      "require": "./dist/react/index.cjs"
    },
    "./nextjs": {
      "types": "./dist/nextjs/index.d.ts",
      "import": "./dist/nextjs/index.mjs",
      "require": "./dist/nextjs/index.cjs"
    }
  },
  "scripts": {
    "build": "tsup",
    "lint": "eslint src",
    "test": "jest",
    "test:cov": "jest --coverage",
    "prepublishOnly": "pnpm build"
  },
  "peerDependencies": {
    "@nestjs/common": "^11.0.16",
    "@nestjs/core": "^11.1.18",
    "@nestjs/jwt": "^11.0.0",
    "@nestjs/throttler": "^6.0.0",
    "@nestjs/websockets": "^11.0.0",
    "class-transformer": "^0.5.0",
    "class-validator": "^0.14.0",
    "ioredis": "^6.0.0",
    "react": "^19.0.0",
    "next": "^16.2.11",
    "reflect-metadata": "^0.2.0"
  },
  "peerDependenciesMeta": {
    "@nestjs/websockets": { "optional": true },
    "react": { "optional": true },
    "next": { "optional": true }
  },
  "devDependencies": {
    "@nestjs/testing": "^11.0.0",
    "jest": "^29.0.0",
    "ts-jest": "^29.0.0",
    "tsup": "^8.0.0",
    "typescript": "^5.5.0"
  },
  "keywords": [
    "nestjs",
    "auth",
    "authentication",
    "jwt",
    "mfa",
    "totp",
    "oauth",
    "saas",
    "multi-tenant",
    "nextjs",
    "react"
  ],
  "license": "MIT",
  "repository": {
    "type": "git",
    "url": "https://github.com/bymaxone/nest-auth.git"
  }
}
```

> **Note on peerDependenciesMeta:** Only `@nestjs/websockets`, `react`, and `next` are marked as `optional: true` — they are dependencies of specific subpaths. The other server peerDeps (`@nestjs/common`, `@nestjs/core`, `@nestjs/jwt`, etc.) are mandatory for anyone importing the main subpath.

---

## 19. Implementation Phases

> **Testing strategy:** Unit tests must be written **together with each phase** (TDD), not accumulated in Phase 6. Phase 6 focuses on integration tests, E2E, and polish. Each phase must reach 100%+ unit coverage on the implemented services.

### 19.1 Schedule overview

| Phase | Week     | Duration | Focus                                | Deliverables                                                                                                        |
| ----- | -------- | -------- | ------------------------------------ | ------------------------------------------------------------------------------------------------------------------- |
| 1     | Week 1   | 1 week   | Core Foundation                      | Scaffold, interfaces, config, Redis, password, token manager, cookie, brute-force + unit tests                      |
| 2     | Week 2   | 1 week   | Core Authentication                  | JWT strategy, auth service/controller, roles guard, user status guard, decorators, DTOs, module wiring + unit tests |
| 3     | Week 3   | 1 week   | MFA                                  | Crypto AES-256-GCM, MFA service/controller, guard, decorator + unit tests                                           |
| 4     | Week 3-4 | 1 week   | Sessions + Password Reset            | Session service/controller, password reset service/controller, OTP, email verification + unit tests                 |
| 5     | Week 4-5 | 1 week   | Platform Admin + OAuth + Invitations | PlatformAuth, OAuth module, Google plugin, Invitation service/controller + unit tests                               |
| 6     | Week 5-6 | 1 week   | Integration + Polish                 | WsJwtGuard, E2E integration tests, complete error codes, JSDoc, README                                              |
| 7     | Week 6-7 | 1 week   | Shared + Client Subpath              | Extract shared types/constants, implement createAuthClient with native fetch, tests                                 |
| 8     | Week 7   | 0.5 week | React Subpath                        | AuthProvider, useSession, useAuth, useAuthStatus, tests with React Testing Library                                  |
| 9     | Week 7-8 | 1 week   | Next.js Subpath                      | createAuthProxy, route handlers, JWT helpers, cookie utils, proxy and redirect loop tests                           |

> **Estimate:** ~8-9 weeks for 1 developer + an AI agent (6 weeks server + 3 weeks frontend). With rigorous human review, add a 20% buffer (~11 weeks total).

### 19.2 Phase 1 — Foundation and Infrastructure (Week 1)

**Objective:** Create the base structure of the package with all the foundational building blocks.

**Deliverables:**

1. **Project scaffold**
   - `package.json` with peer dependencies
   - `tsconfig.json` and `tsconfig.build.json`
   - Directory structure (`src/`, subdirectories)
   - `src/index.ts` (initial barrel export)

2. **Base interfaces**
   - `auth-module-options.interface.ts` — Complete configuration interface
   - `user-repository.interface.ts` — `AuthUser` and `IUserRepository`
   - `platform-user-repository.interface.ts` — `AuthPlatformUser` and `IPlatformUserRepository`
   - `email-provider.interface.ts` — `IEmailProvider`
   - `auth-hooks.interface.ts` — `IAuthHooks` and auxiliary interfaces
   - `jwt-payload.interface.ts` — JWT payloads
   - `authenticated-request.interface.ts` — Typed request

3. **Configuration**
   - `bymax-auth.constants.ts` — Injection tokens
   - `config/default-options.ts` — Default values
   - `config/resolved-options.ts` — Options merge

4. **Redis**
   - `redis/auth-redis.service.ts` — Wrapper over ioredis with namespace
   - `redis/auth-redis.module.ts` — Internal Redis module

5. **Foundational services**
   - `services/password.service.ts` — scrypt hash and comparison (node:crypto)
   - `services/token-manager.service.ts` — Issuance and verification of JWTs
   - `services/token-delivery.service.ts` — Token delivery (cookie/bearer/both)
   - `services/brute-force.service.ts` — Brute-force protection

6. **Crypto**
   - `crypto/aes-gcm.ts` — AES-256-GCM cryptography functions
   - `crypto/secure-token.ts` — Secure token generation

7. **Errors**
   - `errors/auth-error-codes.ts` — Code constants
   - `errors/auth-exception.ts` — AuthException class

8. **Unit tests**
   - Tests for `PasswordService`, `TokenManagerService`, `TokenDeliveryService`, `BruteForceService`
   - Tests for `AuthRedisService` (mock Redis)
   - Minimum coverage: 100%

### 19.3 Phase 2 — Core Authentication (Week 2)

**Objective:** Implement the complete authentication flow (registration, login, logout, refresh).

**Deliverables:**

1. **JWT Strategy**
   - `guards/jwt-auth.guard.ts` — Native JWT guard for dashboard with cookie + Authorization header extraction
   - Validation and population of `request.user`

2. **Guards**
   - `guards/jwt-auth.guard.ts` — Standard JWT guard with support for `@Public()`
   - `guards/roles.guard.ts` — Roles guard with hierarchy
   - `guards/user-status.guard.ts` — Status verification via Redis cache

3. **Decorators**
   - `decorators/current-user.decorator.ts`
   - `decorators/roles.decorator.ts`
   - `decorators/public.decorator.ts`

4. **DTOs**
   - `dto/register.dto.ts`
   - `dto/login.dto.ts`

5. **Auth Service and Controller**
   - `services/auth.service.ts` — Complete implementation (register, login, logout, refresh, getMe)
   - `controllers/auth.controller.ts` — Endpoints with decorators and throttle

6. **Dynamic module**
   - `bymax-auth.module.ts` — `registerAsync()`, provider registration, conditional controller loading

7. **Unit tests**
   - Tests for `AuthService` (register, login, logout, refresh)
   - Tests for guards (JwtAuthGuard, RolesGuard, UserStatusGuard)
   - Minimum coverage: 100%

### 19.4 Phase 3 — Multi-Factor Authentication (MFA) (Week 3)

**Objective:** Implement complete multi-factor authentication with TOTP.

**Deliverables:**

1. **Crypto AES-256-GCM**
   - Implementation of `encrypt()` and `decrypt()` in `crypto/aes-gcm.ts`
   - Format: `iv:authTag:ciphertext` (base64)

2. **MFA Service**
   - `services/mfa.service.ts` — setup, verifyAndEnable, challenge, disable
   - Generation of recovery codes with scrypt hash
   - Encryption/decryption of TOTP secrets

3. **MFA Controller**
   - `controllers/mfa.controller.ts` — setup, verify, challenge, disable endpoints

4. **MFA DTOs**
   - `dto/mfa-verify.dto.ts`
   - `dto/mfa-challenge.dto.ts`
   - `dto/mfa-disable.dto.ts`

5. **Guards and Decorators**
   - `guards/mfa-required.guard.ts`
   - `decorators/skip-mfa.decorator.ts`

6. **Unit tests**
   - Tests for `MfaService` (setup, verify, challenge, disable, recovery codes)
   - Tests for `AES-256-GCM` (encrypt/decrypt round-trip)
   - Tests for `MfaRequiredGuard`
   - Minimum coverage: 100%

### 19.5 Phase 4 — Sessions and Password Reset (Week 3-4)

**Objective:** Implement session management and the password reset flow.

**Deliverables:**

1. **Session Service and Controller**
   - `services/session.service.ts` — createSession, listSessions, revokeSession, revokeAllExceptCurrent, enforceSessionLimit
   - `controllers/session.controller.ts` — list, revoke, revokeAll endpoints

2. **Password Reset Service and Controller**
   - `services/password-reset.service.ts` — initiateReset, resetPassword, verifyOtp
   - `controllers/password-reset.controller.ts` — forgot, reset, verifyOtp, resendOtp endpoints

3. **OTP Service**
   - `services/otp.service.ts` — generate, store, verify, incrementAttempts

4. **Email Verification**
   - Integration in `auth.service.ts` — verifyEmail, resendVerificationEmail
   - Endpoints in `auth.controller.ts`

5. **DTOs**
   - `dto/forgot-password.dto.ts`
   - `dto/reset-password.dto.ts`

6. **Unit tests**
   - Tests for `SessionService` (create, list, revoke, FIFO eviction)
   - Tests for `PasswordResetService` (token and OTP methods)
   - Tests for `OtpService` (moved to Phase 2)
   - Minimum coverage: 100%

### 19.6 Phase 5 — Platform, OAuth, and Invitations (Week 4-5)

**Objective:** Implement platform authentication, OAuth, and the invitation system.

**Deliverables:**

1. **Platform Auth**
   - `guards/jwt-platform.guard.ts` — Separate guard for platform JWTs
   - `guards/platform-roles.guard.ts`
   - `decorators/platform-roles.decorator.ts`
   - `services/platform-auth.service.ts`
   - `controllers/platform-auth.controller.ts`
   - `dto/platform-login.dto.ts`

2. **OAuth Module**
   - `oauth/oauth.module.ts` — Dynamic module for OAuth providers
   - `oauth/oauth.service.ts` — handleCallback, plugin registration
   - `oauth/google/google-oauth.plugin.ts`
   - `oauth/google/google.strategy.ts`
   - `oauth/google/google-auth.guard.ts`
   - Interfaces: `oauth-provider.interface.ts`

3. **Invitations**
   - `services/invitation.service.ts` — invite, acceptInvitation
   - `controllers/invitation.controller.ts`
   - `dto/accept-invitation.dto.ts`

4. **Unit tests**
   - Tests for `PlatformAuthService`
   - Tests for `InvitationService`
   - Tests for `OAuthService` and the Google plugin (mock fetch for OAuth)
   - Minimum coverage: 100%

### 19.7 Phase 6 — Integration, Polish, and Publishing (Week 5-6)

**Objective:** Finalize the package with WebSocket support, documentation, and tests.

**Deliverables:**

1. **WebSocket Guard**
   - `guards/ws-jwt.guard.ts` — JWT authentication for the WebSocket handshake
   - Token extraction via the `Authorization` header only (not query param — tokens in query params are logged in plaintext by proxies)

2. **Additional guards**
   - `guards/self-or-admin.guard.ts`
   - `guards/optional-auth.guard.ts`

3. **Complete Error Codes**
   - Messages in Portuguese for all codes
   - Mapping of codes to HTTP status

4. **Documentation**
   - JSDoc on all public methods
   - README.md with a quick-start guide
   - Integration examples

5. **Tests**
   - Unit tests for all services
   - Integration tests for complete flows (register → login → refresh → logout)
   - Tests for MFA (setup → verify → challenge → disable)
   - Tests for brute-force, sessions, password reset
   - Minimum coverage: 100%

6. **Polish**
   - Review of barrel exports (`index.ts`)
   - Validation of options at module initialization
   - Structured logs with the NestJS `Logger`
   - Publishing to npm

### 19.8 Phase 7 — Shared + Client Subpath (Week 6-7)

**Objective:** Extract shared types and constants into `src/shared/` and implement a framework-agnostic authentication client with native `fetch`.

**Deliverables:**

1. `./shared` subpath — types (`AuthUserClient`, `AuthClientResponse`, `AuthErrorResponse`, JWT payloads) and constants (cookie names, error codes, auth routes)
2. `./client` subpath — `createAuthClient` factory, `createAuthFetch` wrapper with single-flight refresh dedup and `shouldSkipRefreshOnUrl`
3. Zero external dependencies in both subpaths
4. Unit tests with a fetch mock

### 19.9 Phase 8 — React Subpath (Week 7)

**Objective:** Implement React hooks and a context provider for managing authentication state.

**Deliverables:**

1. `AuthProvider`, `useSession`, `useAuth`, `useAuthStatus`
2. Tests with React Testing Library
3. Peer dependency: `react ^19`

### 19.10 Phase 9 — Next.js Subpath (Week 7-8)

**Objective:** Implement complete integration with Next.js 16 including proxy, route handlers, and JWT helpers.

**Deliverables:**

1. `createAuthProxy` with redirect loop protection (`_r` counter + `reason=expired`), background request detection, RBAC, and status-based blocking
2. `createSilentRefreshHandler`, `createClientRefreshHandler`, `createLogoutHandler`
3. JWT helpers with HS256 verification via Web Crypto API
4. Cookie utilities with `dedupeSetCookieHeaders`
5. Tests with 100%+ coverage on the critical paths of the proxy
6. Peer dependencies: `next ^16`, `react ^19`

---

## 20. Known Limitations

This section documents technical and architectural limitations of the package that should be considered before adoption.

### 20.1 Framework

| Limitation       | Impact                                                                    | Alternative                                                   |
| ---------------- | ------------------------------------------------------------------------- | ------------------------------------------------------------- |
| **NestJS only**  | Does not work with plain Express, standalone Fastify, or other frameworks | Extract services into an agnostic package in a future version |
| **Node.js only** | No support for Deno, Bun, or other runtimes                               | No support plan                                               |

### 20.2 Authentication

| Limitation                      | Impact                                                                               | Alternative                                                         |
| ------------------------------- | ------------------------------------------------------------------------------------ | ------------------------------------------------------------------- |
| **HS256 only (symmetric)**      | Does not support RS256/ES256 for distributed verification without sharing the secret | Planned for a future version                                        |
| **No WebAuthn/passkeys**        | Does not support authentication via biometrics or security keys                      | Out of scope for v1                                                 |
| **No magic links/passwordless** | Does not support login via a link sent by email                                      | Out of scope for v1                                                 |
| **scrypt is not the strongest** | Argon2id is more resistant to GPU attacks but requires a native package              | scrypt is native in Node.js — an acceptable trade-off for zero deps |
| **React 19+ only**              | The `./react` subpath requires React 19 with hooks                                   | No plan for earlier versions                                        |
| **Next.js 16+ only**            | The `./nextjs` subpath uses the Proxy API (renamed from Middleware in Next.js 16)    | No support for Next.js 15 or earlier                                |

### 20.3 Infrastructure

| Limitation                                     | Impact                                                                           | Alternative                                                      |
| ---------------------------------------------- | -------------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| **Redis is a single point of failure**         | If Redis goes down, refresh, logout, brute-force, MFA, and sessions fail         | Replication with Sentinel. **Not Cluster** — see below           |
| **Single-region**                              | No discussion of multi-region Redis replication or JWT validation across regions | A multi-region **Sentinel** topology; Cluster is unsupported     |
| **No key rotation for the JWT secret**         | If the secret is compromised, all tokens are compromised                         | Resetting the secret invalidates all tokens; no dual-key support |
| **No key rotation for the MFA encryption key** | If the AES key is compromised, all TOTP secrets are exposed                      | No automatic re-encryption mechanism                             |

#### Redis Cluster is not supported

Sentinel and plain replication are. Cluster is not, and the reason is structural
rather than a missing feature.

The session keyspaces are keyed by different things on purpose. A rotation touches
`rt:{oldHash}`, `rt:{newHash}`, `rp:{oldHash}`, `cf:{oldHash}`, `fam:{familyId}`
and the derived session index
`sess:{hmac_sha256(hmacKey, "dashboard:{utf8ByteLength(tenantId)}:{tenantId}:{userId}")}`
in one atomic step — six keys derived from four unrelated
identifiers, with no hash tag among them. Cluster assigns slots by key, so those
six land on up to six nodes and the script is refused with `CROSSSLOT Keys in
request don't hash to the same slot`. Family revocation and the revoke-all sweep
additionally rebuild keys from set members _inside_ the script, which Cluster
rejects as `Script attempted to access a non-local key` however the slots fall.

The failure mode is what makes this worth stating rather than leaving to be
discovered. Login works — those are single-key writes that the client routes
individually — so a Cluster deployment comes up healthy and stays healthy until
the first access token expires, about fifteen minutes in, at which point every
refresh in the deployment fails at once. "Log out everywhere" is worse: it errors
where nobody is looking, so a password reset reports success while the sessions it
promised to end are still alive.

Making Cluster work would mean a `{userId}` hash tag across `rt:`, `rp:`, `cf:`,
`fam:`, `sess:` and `sd:`. That is a change to the shared keyspace, so it has to
land in `conformance/wire-contract.json` and in rust-auth in the same breath, with
a migration for data already written — not something to reach for without a
deployment that needs it.

### 20.4 Multi-tenancy

| Limitation               | Impact                                                                  | Alternative                                                      |
| ------------------------ | ----------------------------------------------------------------------- | ---------------------------------------------------------------- |
| **Single-tenant JWT**    | A user who belongs to multiple tenants needs separate sessions          | The host application manages tenant switching                    |
| **No tenant resolution** | The package does not resolve the tenant from subdomain, header, or body | The host application must resolve the tenant before calling auth |

### 20.5 Missing features

| Feature                           | Status       | Forecast                              |
| --------------------------------- | ------------ | ------------------------------------- |
| Login via API key (Bearer header) | Not included | Responsibility of each SaaS           |
| Portal sessions (temporary token) | Not included | Responsibility of each SaaS           |
| Email change flow                 | Not included | Future version                        |
| Account deletion (GDPR erasure)   | Not included | Responsibility of each SaaS via hooks |
| Recovery code regeneration        | Not included | Future version                        |
| OAuth account unlinking           | Not included | Future version                        |

---

## Appendix A: Detailed Flows

### A.1 Complete registration flow

```
Client                     AuthController              AuthService                 Repository/Redis
  │                            │                          │                            │
  │ POST /auth/register        │                          │                            │
  │ { email, password,         │                          │                            │
  │   name, tenantId }         │                          │                            │
  │────────────────────────────>│                          │                            │
  │                            │ register(dto, res, req)  │                            │
  │                            │─────────────────────────>│                            │
  │                            │                          │ hooks.beforeRegister()      │
  │                            │                          │─────┐                      │
  │                            │                          │<────┘ { allowed: true }     │
  │                            │                          │                            │
  │                            │                          │ findByEmail(email, tenant)  │
  │                            │                          │───────────────────────────>│
  │                            │                          │<───────────────────────────│ null
  │                            │                          │                            │
  │                            │                          │ hash(password)              │
  │                            │                          │─────┐                      │
  │                            │                          │<────┘ passwordHash          │
  │                            │                          │                            │
  │                            │                          │ create({ ... })             │
  │                            │                          │───────────────────────────>│
  │                            │                          │<───────────────────────────│ user
  │                            │                          │                            │
  │                            │                          │ [If emailVerification.required]
  │                            │                          │ otpService.generate()       │
  │                            │                          │ otpService.store()          │
  │                            │                          │ emailProvider.sendVerificationOtp()
  │                            │                          │                            │
  │                            │                          │ tokenManager.issueTokens()
  │                            │                          │───────────────────────────>│ SET rt:...
  │                            │                          │                            │
  │                            │                          │ hooks.afterRegister()       │
  │                            │                          │─────┐                      │
  │                            │                          │<────┘                      │
  │                            │                          │                            │
  │                            │<─────────────────────────│ AuthResult                  │
  │                            │ tokenDelivery.deliverAuthResponse()                    │
  │<────────────────────────────│ 201 Created (cookie/body per tokenDelivery)            │
```

### A.2 Complete login flow with MFA

```
Client                     AuthController              AuthService                 Redis/MFA
  │                            │                          │                          │
  │ POST /auth/login           │                          │                          │
  │ { email, password, tid }   │                          │                          │
  │────────────────────────────>│                          │                          │
  │                            │ login(dto, res, req)     │                          │
  │                            │─────────────────────────>│                          │
  │                            │                          │ bruteForce.isLockedOut()  │
  │                            │                          │─────────────────────────>│
  │                            │                          │<─────────────────────────│ false
  │                            │                          │                          │
  │                            │                          │ findByEmail() → user      │
  │                            │                          │ password.compare() → true │
  │                            │                          │                          │
  │                            │                          │ user.mfaEnabled = true    │
  │                            │                          │ issueMfaTempToken(userId) │
  │                            │                          │─────────────────────────>│ SET mfa:...
  │                            │<─────────────────────────│                          │
  │<────────────────────────────│ 200 { mfaRequired, token }                        │
  │                            │                          │                          │
  │ POST /auth/mfa/challenge   │                          │                          │
  │ { mfaTempToken, code }     │                          │                          │
  │────────────────────────────>│                          │                          │
  │                            │ MfaController            │                          │
  │                            │─────────────────────────>│ mfa.challenge()          │
  │                            │                          │ verifyMfaTempToken()     │
  │                            │                          │─────────────────────────>│ GET mfa:...
  │                            │                          │<─────────────────────────│ userId
  │                            │                          │                          │
  │                            │                          │ decryptSecret()          │
  │                            │                          │ verifyTOTP(secret, code) │
  │                            │                          │                          │
  │                            │                          │ tokenManager.issueTokens()
  │                            │                          │ (mfaVerified: true)      │
  │                            │                          │─────────────────────────>│ SET rt:...
  │                            │                          │                          │
  │                            │                          │ hooks.afterLogin()       │
  │                            │<─────────────────────────│ user                     │
  │                            │ tokenDelivery.deliverAuthResponse()                  │
  │<────────────────────────────│ 200 (cookie/body per tokenDelivery)                  │
```

### A.3 Refresh flow with rotation

```
Client                     AuthController              TokenManager               Redis
  │                            │                          │                          │
  │ POST /auth/refresh         │                          │                          │
  │ (cookie or body per        │                          │                          │
  │  tokenDelivery)            │                          │                          │
  │────────────────────────────>│                          │                          │
  │                            │ refresh(req, res)        │                          │
  │                            │─────────────────────────>│                          │
  │                            │                          │ GET rt:{sha256(OLD)}      │
  │                            │                          │─────────────────────────>│
  │                            │                          │<─────────────────────────│ sessionData
  │                            │                          │                          │
  │                            │                          │ Generate NEW = UUID v4    │
  │                            │                          │                          │
  │                            │                          │ SET rp:{sha256(OLD)} = NEW│
  │                            │                          │ EX 30                     │
  │                            │                          │─────────────────────────>│ (grace window)
  │                            │                          │                          │
  │                            │                          │ SET rt:{sha256(NEW)} = ...│
  │                            │                          │─────────────────────────>│ (new session)
  │                            │                          │                          │
  │                            │                          │ DEL rt:{sha256(OLD)}      │
  │                            │                          │─────────────────────────>│
  │                            │                          │                          │
  │                            │                          │ issueAccess(payload)      │
  │                            │                          │ returns AuthResult        │
  │                            │<─────────────────────────│                          │
  │                            │ tokenDelivery.deliverRefreshResponse()              │
  │<────────────────────────────│ 200 + tokens (cookie/body per tokenDelivery)       │
```

### A.4 Password reset flow (token)

```
User             Controller              PasswordResetService      Redis           EmailProvider       UserRepository
  |                   |                          |                    |                  |                   |
  |--- POST /auth/forgot-password (email) ------>|                    |                  |                   |
  |                   |                          |--- findByEmail ----|------------------|------------------>|
  |                   |                          |<--- user or null --|------------------|-------------------|
  |                   |                          |                    |                  |                   |
  |                   |                          |  [Always returns 200 — does not reveal if email exists]  |
  |                   |                          |                    |                  |                   |
  |                   |                          |  [If user exists:]  |                  |                   |
  |                   |                          |--- SET auth:pr:{hash} → userId, TTL 1h -->|              |
  |                   |                          |--- sendPasswordResetToken(email, token) -->|              |
  |                   |                          |                    |                  |                   |
  |<-- 200 { message: "If the email exists..." }-|                    |                  |                   |
  |                   |                          |                    |                  |                   |
  |--- POST /auth/reset-password (token, newPassword) --------------->|                    |                   |
  |                   |                          |--- GET auth:pr:{hash} --------------->|                   |
  |                   |                          |<--- userId --------|                  |                   |
  |                   |                          |--- DEL auth:pr:{hash} --------------->|                   |
  |                   |                          |--- hash(newPassword) ----------------->|                   |
  |                   |                          |--- updatePassword(userId, hash) -------|------------------>|
  |                   |                          |--- [Invalidate all sessions] -------->|                   |
  |                   |                          |--- hook.afterPasswordReset() -------->                    |
  |<-- 200 { message: "Password reset" } --------|                    |                  |                   |
```

### A.5 Logout flow

```
User             Controller        AuthService         TokenDeliveryService  Redis
  |                   |                  |                    |                 |
  |--- POST /auth/logout (cookie/header) -->|                    |                 |
  |                   |                  |--- blacklist access JWT ----------->|
  |                   |                  |    SET auth:rv:{hash} TTL remaining |
  |                   |                  |--- delete refresh session --------->|
  |                   |                  |    DEL auth:rt:{hash}              |
  |                   |                  |--- remove from session SET -------->|
  |                   |                  |    SREM auth:sess:{hmac(subject)}  |
  |                   |                  |--- hook.afterLogout() -->           |
  |                   |--- clearAuthSession() -->|                            |
  |<-- 200 (session cleared per tokenDelivery)   |                            |
```

---

## Appendix B: Security Checklist

| Item                                            | Implementation                                                           |
| ----------------------------------------------- | ------------------------------------------------------------------------ |
| Passwords hashed with scrypt (N=2^15, r=8, p=1) | `PasswordService.hash()` via `node:crypto`                               |
| Constant-time comparison of passwords           | `crypto.timingSafeEqual()` to prevent timing attacks                     |
| TOTP secrets encrypted at rest                  | AES-256-GCM in `MfaService.encryptSecret()`                              |
| Recovery codes hashed individually              | scrypt hash of each code via `PasswordService`                           |
| Opaque refresh tokens (not JWT)                 | UUID v4, stored in Redis                                                 |
| Refresh token rotation                          | New token on each refresh, old one invalidated                           |
| Grace window for rotation                       | 30s `rp:` pointer for concurrent requests                                |
| Access token blacklist                          | Redis key `rv:{sha256(jwt)}` on logout                                   |
| HttpOnly cookies (cookie/both mode)             | Access and refresh tokens never accessible via JS                        |
| Secure storage (bearer mode)                    | Mobile uses the OS `SecureStore`/`Keychain` — inaccessible by other apps |
| SameSite Strict on refresh (cookie mode)        | Prevents CSRF on the refresh endpoint                                    |
| Restricted path on the refresh cookie           | `/auth` — not sent on other routes (cookie/both mode)                    |
| Brute-force protection                          | Lockout per email after N attempts                                       |
| Rate limiting per IP                            | `@Throttle()` on all sensitive endpoints                                 |
| Does not reveal the existence of a user         | Generic message in login and forgot-password                             |
| PII masked in logs                              | `sha256(email).substring(0, 8)` for reference                            |
| Status cache with TTL                           | Redis cache of 60s avoids excessive queries                              |
| Tokens with SHA-256 as the Redis key            | Tokens never stored in plain text in Redis                               |
| MFA temp token with short TTL                   | 5 minutes validity                                                       |
| OTP with attempt limit                          | Maximum 5 attempts per OTP                                               |
| Invitations with TTL                            | 7 days validity by default                                               |

---

## 21. Frontend Integration

The package provides frontend subpaths that encapsulate all client-side authentication logic, including session management, automatic token refresh, redirect loop protection, and integration with Next.js 16. It currently supports React and Next.js, with a structure prepared for future subpaths (Vue, Svelte, Expo).

### 21.1 `./shared` subpath

Types and constants shared between server and client with **zero external dependencies**.

**Exports:**

```typescript
// JWT types (shared with server)
export interface DashboardJwtPayload {
  sub: string // User ID
  jti: string // Token ID (for blacklist)
  tenantId: string
  role: string
  type: 'dashboard'
  status: string
  mfaVerified: boolean
  iat: number
  exp: number
}

export interface PlatformJwtPayload {
  sub: string
  jti: string
  role: string // SUPER_ADMIN | ADMIN | SUPPORT
  type: 'platform'
  mfaVerified: boolean
  iat: number
  exp: number
}

// Subset of AuthUser for client-side consumption (without sensitive fields)
export interface AuthUserClient {
  id: string
  email: string
  name: string
  role: string
  tenantId?: string
  status: string
  mfaEnabled: boolean
  avatarUrl?: string
}

// Response shapes
export interface AuthClientResponse {
  user: AuthUserClient
  accessToken?: string // Present only in bearer/both mode
  refreshToken?: string // Present only in bearer/both mode
}

export interface MfaChallengeResult {
  mfaRequired: true
  mfaTempToken: string
}

// Standardized error response
export interface AuthErrorResponse {
  message: string
  error: string
  statusCode: number
  code?: string // AUTH_ERROR_CODES key
}

// Cookie constants
export const AUTH_ACCESS_COOKIE_NAME = 'access_token'
export const AUTH_REFRESH_COOKIE_NAME = 'refresh_token'
export const AUTH_HAS_SESSION_COOKIE_NAME = 'has_session'
export const AUTH_REFRESH_COOKIE_PATH = '/auth'

// Error codes (same object as the server)
export const AUTH_ERROR_CODES = {/* ... */} as const

// Paths of the auth endpoints
export const AUTH_ROUTES = {
  SIGN_IN: '/auth/sign-in',
  SIGN_UP: '/auth/sign-up',
  REFRESH: '/auth/refresh',
  LOGOUT: '/auth/logout',
  ME: '/auth/me',
  FORGOT_PASSWORD: '/auth/forgot-password',
  RESET_PASSWORD: '/auth/reset-password',
  VERIFY_EMAIL: '/auth/verify-email',
  MFA_CHALLENGE: '/auth/mfa/challenge'
} as const
```

---

### 21.2 `./client` subpath

A framework-agnostic authentication client using native `fetch` — **zero external dependencies** (no axios).

#### 21.2.1 `createAuthClient(config)`

```typescript
interface AuthClientConfig {
  /** Backend base URL (e.g.: 'https://api.example.com') */
  baseUrl: string
  /** Same-origin endpoint for refresh. Default: '/api/auth/client-refresh' */
  refreshEndpoint?: string
  /** Credentials policy for fetch. Default: 'include' */
  credentials?: RequestCredentials
  /** Extra headers on each request */
  defaultHeaders?: Record<string, string>
  /** Callback when the session expires definitively (refresh failed) */
  onSessionExpired?: () => void
  /** Timeout in ms. Default: 15000 */
  timeout?: number
}
```

**Returned methods:**

```typescript
interface AuthClient {
  login(
    email: string,
    password: string,
    options?: { tenantId?: string }
  ): Promise<AuthClientResponse>
  register(data: RegisterData): Promise<AuthClientResponse>
  logout(): Promise<void>
  refresh(): Promise<boolean>
  getMe(): Promise<AuthUserClient>
  mfaChallenge(tempToken: string, code: string): Promise<AuthClientResponse>
  forgotPassword(email: string, tenantId?: string): Promise<void>
  resetPassword(token: string, otp: string, newPassword: string): Promise<void>
  /** Fetch wrapper with automatic refresh for generic calls */
  fetch: typeof fetch
}
```

#### 21.2.2 `createAuthFetch` — Fetch wrapper with automatic refresh

The internal core of the client that implements 401 interception with single-flight refresh:

```typescript
function createAuthFetch(config: AuthClientConfig) {
  /** Single in-flight refresh so that concurrent 401s share one request */
  let refreshPromise: Promise<boolean> | null = null

  /** URLs of auth endpoints that should NOT trigger a refresh on 401 */
  const AUTH_PATHS = [
    '/auth/sign-in',
    '/auth/sign-up',
    '/auth/refresh',
    '/api/auth/client-refresh',
    '/api/auth/silent-refresh',
    '/auth/forgot-password',
    '/auth/verify',
    '/auth/reset-password'
  ]

  function shouldSkipRefreshOnUrl(url: string): boolean {
    return AUTH_PATHS.some((path) => url.includes(path))
  }

  async function refreshSession(): Promise<boolean> {
    const res = await fetch(config.refreshEndpoint ?? '/api/auth/client-refresh', {
      method: 'POST',
      credentials: 'include'
    })
    return res.ok
  }

  async function authFetch(input: string | URL, init?: RequestInit): Promise<Response> {
    const url =
      typeof input === 'string'
        ? input.startsWith('http')
          ? input
          : `${config.baseUrl}${input}`
        : input.toString()

    const response = await fetch(url, {
      ...init,
      credentials: config.credentials ?? 'include',
      headers: { ...config.defaultHeaders, ...init?.headers }
    })

    // Not a 401, or it is an auth endpoint — return as is
    if (response.status !== 401 || shouldSkipRefreshOnUrl(url)) {
      return response
    }

    // 401 on a non-auth endpoint — try refresh (single-flight)
    if (!refreshPromise) {
      refreshPromise = refreshSession().finally(() => {
        refreshPromise = null
      })
    }
    const refreshed = await refreshPromise

    if (refreshed) {
      // Retry with renewed cookies
      return fetch(url, {
        ...init,
        credentials: config.credentials ?? 'include',
        headers: { ...config.defaultHeaders, ...init?.headers }
      })
    }

    // Refresh failed — session expired
    config.onSessionExpired?.()
    return response
  }

  // Convenience methods that delegate to authFetch with method/headers pre-configured
  const get = (url: string, init?: RequestInit) => authFetch(url, { ...init, method: 'GET' })
  const post = (url: string, body?: unknown, init?: RequestInit) =>
    authFetch(url, {
      ...init,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...init?.headers },
      body: body ? JSON.stringify(body) : undefined
    })
  const put = (url: string, body?: unknown, init?: RequestInit) =>
    authFetch(url, {
      ...init,
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', ...init?.headers },
      body: body ? JSON.stringify(body) : undefined
    })
  const patch = (url: string, body?: unknown, init?: RequestInit) =>
    authFetch(url, {
      ...init,
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', ...init?.headers },
      body: body ? JSON.stringify(body) : undefined
    })
  const del = (url: string, init?: RequestInit) => authFetch(url, { ...init, method: 'DELETE' })

  return { fetch: authFetch, get, post, put, patch, delete: del }
}
```

**DX — Usage example:**

```typescript
import { createAuthClient } from '@bymax-one/nest-auth/client'

const auth = createAuthClient({
  // Fallback to localhost for local development when env var is not set
  baseUrl: process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:3000',
  onSessionExpired: () => {
    window.location.href = '/auth/login'
  }
})

// Login
const result = await auth.login('user@example.com', 'password123')

// Authenticated calls (automatic refresh on 401)
const me = await auth.getMe()
const users = await auth.fetch('/api/users').then((r) => r.json())
```

---

### 21.3 `./react` subpath

React hooks and a context provider for managing authentication state.

#### `AuthProvider`

```typescript
interface AuthProviderProps {
  children: React.ReactNode
  /** Client created via createAuthClient */
  client: AuthClient
  /** Callback when the session expires */
  onSessionExpired?: () => void
  /** Revalidation interval in ms. Default: 300000 (5 min) */
  revalidateInterval?: number
}
```

#### `useSession()`

```typescript
function useSession(): {
  user: AuthUserClient | null
  status: 'authenticated' | 'unauthenticated' | 'loading'
  isLoading: boolean
  refresh: () => Promise<void>
  lastValidation: number | null
}
```

#### `useAuth()`

```typescript
function useAuth(): {
  login: (
    email: string,
    password: string,
    options?: { tenantId?: string }
  ) => Promise<AuthClientResponse>
  register: (data: RegisterData) => Promise<AuthClientResponse>
  logout: () => Promise<void>
  forgotPassword: (email: string) => Promise<void>
  resetPassword: (token: string, otp: string, newPassword: string) => Promise<void>
}
```

#### `useAuthStatus()`

```typescript
function useAuthStatus(): {
  isAuthenticated: boolean
  isLoading: boolean
}
```

**DX — Usage example:**

```typescript
// layout.tsx
import { AuthProvider } from '@bymax-one/nest-auth/react'
import { createAuthClient } from '@bymax-one/nest-auth/client'

// Fallback to localhost for local development when env var is not set
const client = createAuthClient({ baseUrl: process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:3000' })

export default function Layout({ children }) {
  return <AuthProvider client={client}>{children}</AuthProvider>
}

// Profile.tsx
import { useSession, useAuth } from '@bymax-one/nest-auth/react'

function Profile() {
  const { user, isLoading } = useSession()
  const { logout } = useAuth()
  if (isLoading) return <Spinner />
  return <Button onClick={logout}>{user?.name}</Button>
}
```

Peer dependencies: `react ^19`

---

### 21.4 `./nextjs` subpath

Complete integration with Next.js 16 including a proxy factory, route handlers, JWT helpers, and cookie utilities. It encapsulates all the logic for route protection, session refresh, and redirect loop prevention.

> **Based on a battle-tested production implementation**, where an infinite redirect loop bug was identified and fixed. All edge cases are documented and resolved in the factories below.

#### 21.4.1 `createAuthProxy(config)`

A factory that returns a `proxy` function and a `config` object ready to export from `proxy.ts`.

```typescript
interface AuthProxyConfig {
  /** Public routes (no authentication required) */
  publicRoutes?: string[] | ((pathname: string) => boolean)
  /** Public routes that redirect to dashboard if already authenticated */
  publicRoutesRedirectIfAuthenticated?: string[]
  /** Protected routes with allowed roles */
  protectedRoutes: Array<{
    pattern: RegExp
    allowedRoles: string[]
    redirectPath: string
  }>
  /** Path of the login page. Default: '/auth/login' */
  loginPath?: string
  /** Function that returns the default dashboard for each role */
  getDefaultDashboard: (role: string) => string
  /** Backend base URL. Default: process.env.NEXT_PUBLIC_API_URL */
  apiBase?: string
  /** JWT secret for HS256 verification in the proxy. Default: process.env.JWT_SECRET */
  jwtSecret?: string
  /** Maximum number of silent-refresh attempts. Default: 2 */
  maxRefreshAttempts?: number
  /** Cookie names. Default: values from ./shared */
  cookieNames?: {
    access?: string
    refresh?: string
    hasSession?: string
  }
  /** Names of the headers propagated to server components */
  userHeaders?: {
    userId?: string // default: 'x-user-id'
    userRole?: string // default: 'x-user-role'
    tenantId?: string // default: 'x-tenant-id'
    tenantDomain?: string // default: 'x-tenant-domain'
  }
  /** User statuses blocked in the proxy. Default: ['BANNED', 'INACTIVE', 'EXPIRED'] */
  blockedUserStatuses?: string[]
}
```

**Returns:** `{ proxy, config }` ready to export.

**Security patterns implemented:**

**1. `isBackgroundRequest(request)` — Detection of parallel Next.js requests:**

Detects RSC payload fetches, prefetches, and router state updates via headers:

- `RSC: 1` — RSC payload request
- `Next-Router-Prefetch: 1` — link prefetch
- `Next-Router-State-Tree` — client-side navigation RSC fetch

Returns `new NextResponse(null, { status: 401 })` instead of a redirect. **Reason:** these requests run in parallel with the main navigation. Redirecting would cause race conditions — the refresh token would be consumed by the main navigation and the parallel request would find the token already used.

**2. `_r` counter for redirect loop prevention:**

The browser may not process the `Set-Cookie` headers of a redirect before following the redirect. When the `has_session` cookie is not cleared in time:

- Numeric counter in `url.searchParams`
- Incremented on each silent-refresh attempt
- At `_r >= maxRefreshAttempts` (default 2): gives up and shows the public page or redirects to login
- Cleared from the URL after successful authentication

> **Next.js bugs that motivate this pattern:** [vercel/next.js#49442](https://github.com/vercel/next.js/issues/49442), [vercel/next.js#72170](https://github.com/vercel/next.js/discussions/72170)

**3. `reason=expired` guard:**

On public routes, if `url.searchParams.get('reason') === 'expired'`, a previous silent-refresh has already failed — it does not try again. It works as the primary guard; the `_r` counter works as backup. Defense in depth: two independent mechanisms against the same loop.

**4. `has_session` cookie signal:**

A non-sensitive cookie (value `"1"`) that indicates the existence of a session. The proxy uses it to decide whether to attempt a silent-refresh without having access to the real refresh token (which has its path restricted to `/api/auth`).

**5. Blocking by user status:**

Checks `tokenData.status` against `blockedUserStatuses`. Blocks BANNED, INACTIVE, EXPIRED in the proxy before the request reaches the backend.

**6. RBAC in the proxy:**

Checks `tokenData.role` against `protectedRoutes[].allowedRoles`. Redirects to the role's default dashboard if not allowed.

**7. User headers for Server Components:**

After HS256 verification, propagates `x-user-id`, `x-user-role`, `x-tenant-id`, `x-tenant-domain`.

> **WARNING:** These headers exist for UI convenience. They must **never** be used for authorization — every access decision must go through the NestJS backend.

**DX:**

```typescript
// proxy.ts
import { createAuthProxy } from '@bymax-one/nest-auth/nextjs'

const { proxy, config } = createAuthProxy({
  publicRoutes: ['/', '/welcome', '/auth/*', '/privacy'],
  publicRoutesRedirectIfAuthenticated: [
    '/',
    '/welcome',
    '/auth/login',
    '/auth/register',
    '/auth/forgot-password',
    '/auth/reset-password',
    '/auth/verify-otp'
  ],
  protectedRoutes: [
    { pattern: /^\/admin\/.*/, allowedRoles: ['ADMIN'], redirectPath: '/app/dashboard' },
    { pattern: /^\/app\/.*/, allowedRoles: ['USER', 'ADMIN'], redirectPath: '/auth/login' }
  ],
  getDefaultDashboard: (role) => (role === 'ADMIN' ? '/admin/dashboard' : '/app/dashboard')
})

export { proxy, config }
```

#### 21.4.2 Route Handlers

**`createSilentRefreshHandler(config?)`** — GET handler for `/api/auth/silent-refresh`

Called by the proxy via redirect when the access token has expired but `has_session` indicates that a refresh token may exist.

Flow:

1. Forwards cookies to the backend `POST /auth/refresh` with the `Cookie`, `X-Tenant-Domain`, `Content-Type` headers
2. **Success:** Redirect to the destination (`redirect` param) with Set-Cookie headers propagated via `dedupeSetCookieHeaders()`
3. **Failure:** Redirect to `/auth/login?reason=expired` with explicit clearing of the 3 cookies (access, refresh, has_session) with the correct paths
4. **Open redirect defense:** Validates that `redirect` begins with `/`, does not begin with `//`, and that after resolution the origin is the same as the request

```typescript
// app/api/auth/silent-refresh/route.ts
import { createSilentRefreshHandler } from '@bymax-one/nest-auth/nextjs'
export const GET = createSilentRefreshHandler()
```

**`createClientRefreshHandler(config?)`** — POST handler for `/api/auth/client-refresh`

A same-origin bridge for client-side refresh. Necessary because:

1. The `refresh_token` cookie has `Path=/api/auth` — the browser only sends it for requests on this path
2. The backend may be on another domain (cross-origin)
3. Cross-origin HTTP-only cookies may be blocked by ITP (Safari) or ETP (Firefox)

```typescript
// app/api/auth/client-refresh/route.ts
import { createClientRefreshHandler } from '@bymax-one/nest-auth/nextjs'
export const POST = createClientRefreshHandler()
```

#### 21.4.3 JWT Helpers

**`decodeJwtToken(token)`** — Decodes without signature verification (client-side UX).

**`verifyJwtToken(token)`** — HS256 verification via Web Crypto API (`crypto.subtle`). Pins the algorithm to HS256 to prevent algorithm confusion attacks. Falls back to decode if `JWT_SECRET` is not available.

#### 21.4.4 Cookie Utilities

**`dedupeSetCookieHeaders(headers: string[]): string[]`** — Deduplicates by `(name + domain)`, last writer wins. Essential because the backend sends clear-then-set pairs for rotated cookies. In multi-domain setups, the same cookie is sent to multiple domains — deduplicating by name alone would discard the domain variants.

**`parseSetCookieHeader(str: string): ParsedSetCookie | null`** — Parses a raw Set-Cookie into a structured object.

#### 21.4.5 Client-side refresh integration (complete flow)

```
Browser (SPA)              Next.js Route Handler       Backend (NestJS)
     │                            │                         │
     │── GET /api/users ──────────│─── GET /users ─────────>│
     │<─ 401 ─────────────────────│<── 401 ─────────────────│
     │                            │                         │
     │  [Interceptor activates]   │                         │
     │  1. shouldSkipRefreshOnUrl → no                      │
     │  2. refreshPromise? no → creates new                 │
     │                            │                         │
     │── POST /api/auth/          │                         │
     │   client-refresh ─────────>│── POST /auth/refresh ──>│
     │                            │<── 200 + Set-Cookie ────│
     │<── 200 + Set-Cookie ───────│                         │
     │                            │                         │
     │  [Retry original request]  │                         │
     │── GET /api/users ──────────│─── GET /users ─────────>│
     │<── 200 + data ─────────────│<── 200 + data ──────────│
```

**The 500ms delay on the redirect:** After a refresh fails, the client schedules a redirect to login with `setTimeout(500ms)` instead of navigating immediately. This resolves a race condition: if the proxy (server-side) renewed the session via a 302 redirect, the browser navigates to the destination, destroying the JS context and canceling the timeout — the redirect to login **never happens**. Without the delay, `window.location.href = '/auth/login'` would execute before the proxy's 302 completes.

Peer dependencies: `next ^16`, `react ^19`

---

_End of the technical specification of `@bymax-one/nest-auth`._
