<p align="center">
  <img src="https://img.shields.io/badge/%40bymax--one-nest--auth-000000?style=for-the-badge&logo=nestjs&logoColor=E0234E" alt="@bymax-one/nest-auth" />
</p>

<h1 align="center">@bymax-one/nest-auth</h1>

<p align="center">
  <strong>Full-stack authentication for NestJS, React & Next.js</strong><br />
  <sub>JWT · MFA · OAuth · Sessions · Multi-Tenant · Zero External Crypto Dependencies</sub>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@bymax-one/nest-auth"><img src="https://img.shields.io/npm/v/@bymax-one/nest-auth?style=flat-square&colorA=000000&colorB=000000" alt="npm version" /></a>
  <a href="https://www.npmjs.com/package/@bymax-one/nest-auth"><img src="https://img.shields.io/npm/dm/@bymax-one/nest-auth?style=flat-square&colorA=000000&colorB=000000" alt="npm downloads" /></a>
  <a href="https://github.com/bymaxone/nest-auth/blob/main/LICENSE"><img src="https://img.shields.io/npm/l/@bymax-one/nest-auth?style=flat-square&colorA=000000&colorB=000000" alt="license" /></a>
  <a href="https://www.typescriptlang.org/"><img src="https://img.shields.io/badge/TypeScript-strict-3178C6?style=flat-square&logo=typescript&logoColor=white" alt="TypeScript" /></a>
  <a href="https://nodejs.org/"><img src="https://img.shields.io/badge/Node.js-24%2B-339933?style=flat-square&logo=node.js&logoColor=white" alt="Node.js" /></a>
</p>

<p align="center">
  <a href="https://github.com/bymaxone/nest-auth">GitHub</a> ·
  <a href="https://github.com/bymaxone/nest-auth/issues">Issues</a> ·
  <a href="#-quick-start">Quick Start</a> ·
  <a href="#-subpath-exports">API Reference</a>
</p>

---

## ✨ Overview

`@bymax-one/nest-auth` is a **complete authentication and authorization solution** shipped as a single npm package with **5 subpath exports** — covering everything from NestJS backend guards to React hooks and Next.js route handlers.

Instead of wiring together dozens of packages for JWT, MFA, OAuth, sessions, password reset, and brute-force protection, you install one library and get a production-ready auth system that works across your entire stack.

### Why nest-auth?

- **🎯 One package, full stack** — Backend module, shared types, fetch client, React hooks, and Next.js integration all in a single `pnpm add`. Types and constants are shared automatically between server and client — no manual synchronization.
- **🔌 Your database, your rules** — The library defines TypeScript interfaces (`IUserRepository`, `IEmailProvider`). You implement them with your ORM of choice (Prisma, TypeORM, Drizzle). No vendor lock-in, no hidden database dependencies.
- **🔒 Native crypto only** — All security-critical code (password hashing, MFA encryption, TOTP, token generation) runs on `node:crypto` — zero third-party crypto packages, zero supply chain risk.
- **⚡ Pay for what you use** — Features like MFA, sessions, OAuth, and platform admin are opt-in. When not configured, their controllers and services are never registered — zero overhead in your NestJS container.
- **🏢 Multi-tenant ready** — Every operation is scoped by `tenantId`. Built for SaaS from day one, not bolted on as an afterthought.

```
pnpm add @bymax-one/nest-auth
```

---

## 🔥 Features

### 🔐 Core Authentication

- ✅ **Registration & Login** — Email/password with configurable validation
- ✅ **JWT Access + Refresh Tokens** — Automatic rotation with grace window for concurrent requests
- ✅ **Multi-Factor Authentication** — TOTP with QR code URI, recovery codes, and challenge flow
- ✅ **OAuth 2.0** — Google out of the box, extensible via plugin interface
- ✅ **Password Reset** — Token-based or OTP, configurable per deployment
- ✅ **Email Verification** — OTP-based with configurable TTL

### 🛡️ Security

- ✅ **Zero External Crypto** — All cryptography via native `node:crypto` (scrypt, AES-256-GCM, HMAC-SHA1, TOTP)
- ✅ **Brute-Force Protection** — Configurable rate limiting per email + tenant
- ✅ **Session Management** — Track active sessions with FIFO eviction and new-session alerts
- ✅ **HttpOnly Cookies** — Secure, SameSite, path-scoped refresh tokens by default
- ✅ **Timing-Safe Comparisons** — All secret comparisons use `crypto.timingSafeEqual`
- ✅ **JWT Revocation** — Instant access token revocation via Redis JTI blacklist

### 🏢 Multi-Tenant & Platform

- ✅ **Tenant Isolation** — All operations scoped by `tenantId` with configurable resolver
- ✅ **Platform Admin Auth** — Separate token context and role hierarchy for super-admins
- ✅ **User Invitations** — Invite users with role assignment and configurable expiration
- ✅ **Role-Based Access Control** — Hierarchical roles with `@Roles()` decorator

### 🧩 Developer Experience

- ✅ **Full-Stack TypeScript** — Strict types shared across server and client
- ✅ **5 Subpath Exports** — Import only what you need, tree-shakeable
- ✅ **Dynamic Module** — Configure everything via `registerAsync()`, sensible defaults included
- ✅ **Interface-Driven** — Bring your own database and email provider
- ✅ **No Passport Required** — Guards validate JWT natively via `@nestjs/jwt`

---

## 📦 Subpath Exports

One package, five entry points — import only what your app needs:

| Subpath     | Import                        | Purpose                                     |    Dependencies    |
| ----------- | ----------------------------- | ------------------------------------------- | :----------------: |
| **Server**  | `@bymax-one/nest-auth`        | NestJS module, guards, decorators, services | NestJS 11, ioredis |
| **Shared**  | `@bymax-one/nest-auth/shared` | Types, constants, error codes               |        None        |
| **Client**  | `@bymax-one/nest-auth/client` | Fetch-based auth client                     |        None        |
| **React**   | `@bymax-one/nest-auth/react`  | Hooks & AuthProvider                        |      React 19      |
| **Next.js** | `@bymax-one/nest-auth/nextjs` | Proxy, route handlers, JWT helpers          |     Next.js 16     |

```
shared (zero deps)
  ↗       ↖
server    client
            ↑
          react
            ↑
         nextjs
```

---

## 🚀 Quick Start

### 1. Install

```bash
# Using pnpm (recommended)
pnpm add @bymax-one/nest-auth

# Using npm
npm install @bymax-one/nest-auth

# Using yarn
yarn add @bymax-one/nest-auth
```

> [!IMPORTANT]
> You must also install the required **peer dependencies** for the subpaths you use:

```bash
# Server subpath (required)
pnpm add @nestjs/common @nestjs/core @nestjs/jwt @nestjs/throttler ioredis class-validator class-transformer reflect-metadata

# React subpath (optional)
pnpm add react

# Next.js subpath (optional)
pnpm add next react
```

### 2. Implement the Repository Interface

The package defines **what** it needs — your app provides **how**:

```typescript
// user.repository.ts
import { IUserRepository, AuthUser } from '@bymax-one/nest-auth'
import { PrismaService } from './prisma.service'

export class PrismaUserRepository implements IUserRepository {
  constructor(private prisma: PrismaService) {}

  async findByEmail(email: string, tenantId: string): Promise<AuthUser | null> {
    return this.prisma.user.findUnique({
      where: { email_tenantId: { email, tenantId } }
    })
  }

  async create(data: Partial<AuthUser>): Promise<AuthUser> {
    return this.prisma.user.create({ data })
  }

  // ... implement all IUserRepository methods
}
```

### 3. Register the Module

The user repository and Redis client are provided via NestJS dependency injection tokens — not as direct config fields. This follows the [NestJS custom providers pattern](https://docs.nestjs.com/fundamentals/custom-providers) and ensures the DI container manages all dependencies correctly.

```typescript
// app.module.ts
import { Module } from '@nestjs/common'
import {
  BymaxAuthModule,
  BYMAX_AUTH_USER_REPOSITORY,
  BYMAX_AUTH_REDIS_CLIENT
} from '@bymax-one/nest-auth'

@Module({
  imports: [
    BymaxAuthModule.registerAsync({
      imports: [ConfigModule, DatabaseModule, RedisModule],
      useFactory: (config: ConfigService) => ({
        jwt: {
          secret: config.get('JWT_SECRET'), // min 32 chars, high entropy
          accessExpiresIn: '15m',
          refreshExpiresInDays: 7
        },
        tokenDelivery: 'cookie', // 'cookie' | 'bearer' | 'both'
        roles: {
          hierarchy: {
            admin: ['manager', 'user'],
            manager: ['user'],
            user: []
          }
        }
      }),
      inject: [ConfigService],
      extraProviders: [
        {
          provide: BYMAX_AUTH_USER_REPOSITORY,
          useClass: PrismaUserRepository
        },
        {
          provide: BYMAX_AUTH_REDIS_CLIENT,
          useFactory: (redis: RedisService) => redis.client,
          inject: [RedisService]
        }
      ]
    })
  ]
})
export class AppModule {}
```

### 4. Protect Routes

```typescript
// users.controller.ts
import { Controller, Get, UseGuards } from '@nestjs/common'
import {
  JwtAuthGuard,
  RolesGuard,
  Roles,
  CurrentUser,
  DashboardJwtPayload
} from '@bymax-one/nest-auth'

@Controller('users')
@UseGuards(JwtAuthGuard, RolesGuard)
export class UsersController {
  @Get('me')
  getProfile(@CurrentUser() user: DashboardJwtPayload) {
    return { id: user.sub, role: user.role, tenantId: user.tenantId }
  }

  @Get()
  @Roles('admin')
  listUsers() {
    // Only accessible by admins (and above in hierarchy)
  }
}
```

### 5. Frontend Integration (React)

```tsx
// app.tsx
import { AuthProvider } from '@bymax-one/nest-auth/react'

export function App({ children }) {
  return <AuthProvider apiUrl="https://api.example.com/auth">{children}</AuthProvider>
}

// profile.tsx
import { useSession, useAuth } from '@bymax-one/nest-auth/react'

export function Profile() {
  const { user, status } = useSession()
  const { logout } = useAuth()

  if (status === 'loading') return <div>Loading...</div>
  if (status === 'unauthenticated') return <div>Please log in</div>

  return (
    <div>
      <p>Welcome, {user.name}!</p>
      <button onClick={logout}>Sign out</button>
    </div>
  )
}
```

### 6. Frontend Integration (Next.js 16)

```typescript
// proxy.ts (Next.js 16 — formerly middleware.ts)
import { createAuthProxy } from '@bymax-one/nest-auth/nextjs'

export const { proxy, config } = createAuthProxy({
  backendUrl: process.env.BACKEND_URL!,
  publicRoutes: ['/', '/login', '/register']
})
```

```typescript
// app/api/auth/silent-refresh/route.ts
import { createSilentRefreshHandler } from '@bymax-one/nest-auth/nextjs'

export const GET = createSilentRefreshHandler({
  backendUrl: process.env.BACKEND_URL!
})
```

---

## ⚙️ Configuration

All options are configurable via `registerAsync()`. Here are the key configuration groups:

| Group             | Key Options                                                                 | Default                   |
| ----------------- | --------------------------------------------------------------------------- | ------------------------- |
| **jwt**           | `secret` (required), `accessExpiresIn`, `refreshExpiresInDays`, `algorithm` | `15m`, `7d`, `HS256`      |
| **password**      | `costFactor`, `blockSize`, `parallelization`                                | scrypt N=2¹⁵, r=8, p=1    |
| **tokenDelivery** | `'cookie'` \| `'bearer'` \| `'both'`                                        | `'cookie'`                |
| **cookies**       | `secure`, `sameSite`, `httpOnly`, `refreshCookiePath`                       | `true`, `'lax'`, `true`   |
| **mfa**           | `encryptionKey`, `issuer`, `totpWindow`, `recoveryCodeCount`                | —                         |
| **sessions**      | `enabled`, `defaultMaxSessions`, `maxSessionsResolver`, `evictionStrategy`  | `false`, `5`, —, `'fifo'` |
| **bruteForce**    | `maxAttempts`, `windowSeconds`                                              | `5`, `900`                |
| **passwordReset** | `method` (`'token'` \| `'otp'`), `otpLength`, `otpTtlSeconds`               | `'token'`                 |
| **platform**      | `enabled`                                                                   | `false`                   |
| **invitations**   | `enabled`, `tokenTtlSeconds`                                                | `false`                   |
| **roles**         | `hierarchy` (required), `platformHierarchy`                                 | —                         |
| **oauth**         | `google: { clientId, clientSecret, callbackUrl }`                           | —                         |
| **controllers**   | Toggle individual controllers on/off                                        | All enabled               |

> [!NOTE]
> When a feature is not configured (e.g., `mfa`, `sessions`, `platform`), its controllers and services are **not registered** in the NestJS container — zero overhead.

---

## 🏗️ Architecture

The package runs **inside** your NestJS application as a dynamic module — not as a separate service:

```
┌─────────────────────────────────────────────┐
│           Your NestJS Application            │
│                                             │
│  ┌───────────────────────────────────────┐  │
│  │       @bymax-one/nest-auth            │  │
│  │                                       │  │
│  │  Controllers ←→ Services ←→ Redis     │  │
│  │  Guards ←→ Crypto (node:crypto)       │  │
│  │  Decorators ←→ Token Manager (JWT)    │  │
│  └──────────┬────────────┬───────────────┘  │
│             │            │                   │
│     ┌───────▼──┐  ┌──────▼───────┐          │
│     │ IUser    │  │ IEmail       │          │
│     │ Repo     │  │ Provider     │          │
│     │ (yours)  │  │ (yours)      │          │
│     └──────────┘  └──────────────┘          │
└─────────────────────────────────────────────┘
```

### Design Principles

| Principle                  | Description                                                                                             |
| -------------------------- | ------------------------------------------------------------------------------------------------------- |
| **🔌 Interface-Driven**    | Define contracts, inject implementations — works with Prisma, TypeORM, Drizzle, or any SQL ORM          |
| **🔒 Secure by Default**   | scrypt hashing, HttpOnly cookies, JWT blacklisting, brute-force protection — all enabled out of the box |
| **🪶 Zero Dependencies**   | `"dependencies": {}` — all crypto via native `node:crypto`, no supply chain risk                        |
| **🌳 Tree-Shakeable**      | `sideEffects: false`, subpath exports, ESM + CJS dual output                                            |
| **⚡ Conditional Loading** | Unconfigured features don't register — no wasted memory or startup time                                 |

---

## 🔐 Security Model

The security architecture follows established standards and industry best practices.

### JWT Token Type Discrimination

Every token carries a `type` claim that guards validate before accepting:

| Token type        | Issued when                               | Accepted by            |
| ----------------- | ----------------------------------------- | ---------------------- |
| `'dashboard'`     | Successful login or MFA challenge         | `JwtAuthGuard`         |
| `'platform'`      | Platform admin login or MFA challenge     | `JwtPlatformGuard`     |
| `'mfa_challenge'` | Login with MFA enabled (pre-verification) | MFA challenge endpoint |

This prevents **token type confusion attacks** — a class of vulnerability documented by [OWASP](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens) where a token issued for one purpose is accepted by another. The same pattern is used by AWS Cognito (`token_use` claim) and recommended by [Curity's JWT best practices guide](https://curity.io/resources/learn/jwt-best-practices/).

`JwtPlatformGuard` returns `PLATFORM_AUTH_REQUIRED` (not the generic `TOKEN_INVALID`) when a dashboard token is submitted to a platform route — so clients can distinguish wrong-context from expired/invalid errors.

### Separate Auth Contexts for Multi-Tenant SaaS

Platform admins and tenant users are fully isolated stacks — separate repositories, JWT payloads, guards, and routes. A platform admin token cannot access tenant routes, and a tenant token cannot access platform routes, regardless of role. This aligns with the architecture recommended by AWS, Logto, and WorkOS for multi-tenant SaaS platforms.

The `tenantId` is always extracted from the validated JWT — never from the request body — preventing tenant spoofing at the architecture level.

### Token Revocation via Redis JTI Blacklist

Access tokens are short-lived (default 15 minutes) and immediately revocable via a Redis JTI blacklist. Refresh tokens rotate on every use with a configurable grace window to handle concurrent requests. This is the industry-standard hybrid approach used by Auth0, Okta, and SuperTokens — combining short lifetimes for low-latency revocation with rotating refresh tokens for session continuity.

### Password Hashing

Passwords are hashed with **scrypt** via `node:crypto`, which is memory-hard and resistant to GPU-based brute-force attacks. All secret comparisons use `crypto.timingSafeEqual` for constant-time evaluation — [a requirement explicitly documented](https://nodejs.org/api/crypto.html#cryptotimingsafeequala-b) in the Node.js crypto documentation.

### No External Cryptographic Dependencies

All security-critical operations use the OpenSSL-backed `node:crypto` module — no bcrypt, argon2, otpauth, uuid, or nanoid packages. This eliminates the supply chain attack surface for the most sensitive code paths.

---

## 🛡️ Security Table

| Layer             | Implementation                                     |
| ----------------- | -------------------------------------------------- |
| Password Hashing  | `node:crypto` scrypt (N=2¹⁵, r=8, p=1, keyLen=64)  |
| MFA Encryption    | AES-256-GCM with 12-byte random IV per call        |
| TOTP              | HMAC-SHA1 per RFC 4226/6238, ±1 step window        |
| Token Generation  | `crypto.randomBytes(32)` — 256 bits of entropy     |
| Secret Comparison | `crypto.timingSafeEqual` (constant-time)           |
| JWT               | HS256 via `@nestjs/jwt`, JTI blacklist via Redis   |
| Cookies           | HttpOnly, Secure, SameSite=Lax, path-scoped        |
| Brute-Force       | Redis atomic counters per HMAC(email, jwt.secret)  |
| CSRF (OAuth)      | 64-char hex state nonce, single-use via `getdel()` |

> [!IMPORTANT]
> This package uses **zero external cryptographic dependencies**. All operations use Node.js native `node:crypto`, eliminating supply chain attack vectors for critical security code.

---

## 🧱 Tech Stack

<p>
  <img src="https://img.shields.io/badge/NestJS-11-E0234E?style=flat-square&logo=nestjs&logoColor=white" alt="NestJS" />
  <img src="https://img.shields.io/badge/TypeScript-strict-3178C6?style=flat-square&logo=typescript&logoColor=white" alt="TypeScript" />
  <img src="https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react&logoColor=black" alt="React" />
  <img src="https://img.shields.io/badge/Next.js-16-000000?style=flat-square&logo=next.js&logoColor=white" alt="Next.js" />
  <img src="https://img.shields.io/badge/Node.js-24%2B-339933?style=flat-square&logo=node.js&logoColor=white" alt="Node.js" />
  <img src="https://img.shields.io/badge/Redis-7%2B-DC382D?style=flat-square&logo=redis&logoColor=white" alt="Redis" />
  <img src="https://img.shields.io/badge/Jest-29-C21325?style=flat-square&logo=jest&logoColor=white" alt="Jest" />
</p>

---

## 📖 API Reference

### Server Guards

| Guard                | Decorator                       | Purpose                                                         |
| -------------------- | ------------------------------- | --------------------------------------------------------------- |
| `JwtAuthGuard`       | —                               | Validates JWT from cookie or `Authorization: Bearer` header     |
| `RolesGuard`         | `@Roles('admin')`               | Hierarchical role check                                         |
| `UserStatusGuard`    | —                               | Blocks inactive/banned users (Redis-cached status)              |
| `MfaRequiredGuard`   | `@SkipMfa()`                    | Enforces MFA verification on protected routes                   |
| `JwtPlatformGuard`   | —                               | Platform admin JWT validation (Bearer only)                     |
| `PlatformRolesGuard` | `@PlatformRoles('super_admin')` | Platform role hierarchy enforcement                             |
| `SelfOrAdminGuard`   | —                               | Allows access only to the resource owner or an admin            |
| `OptionalAuthGuard`  | —                               | Attaches user if authenticated, proceeds unauthenticated if not |
| `WsJwtGuard`         | —                               | WebSocket JWT validation from handshake headers                 |

### Server Decorators

| Decorator                  | Usage                                                                        |
| -------------------------- | ---------------------------------------------------------------------------- |
| `@CurrentUser()`           | Extract JWT payload from request: `@CurrentUser() user: DashboardJwtPayload` |
| `@Roles(...roles)`         | Set required roles: `@Roles('admin', 'manager')`                             |
| `@PlatformRoles(...roles)` | Set required platform roles: `@PlatformRoles('super_admin')`                 |
| `@Public()`                | Mark route as public (skip JWT guard)                                        |
| `@SkipMfa()`               | Skip MFA verification for this route                                         |

### React Hooks

| Hook              | Returns                                               |
| ----------------- | ----------------------------------------------------- |
| `useSession()`    | `{ user, status, refresh() }` — current session state |
| `useAuth()`       | `{ login(), logout(), register() }` — auth actions    |
| `useAuthStatus()` | `{ isAuthenticated, isLoading }` — derived state      |

### Next.js Factories

| Factory                        | Type         | Purpose                         |
| ------------------------------ | ------------ | ------------------------------- |
| `createAuthProxy()`            | Proxy config | Auth-aware proxy for `proxy.ts` |
| `createSilentRefreshHandler()` | GET handler  | iframe-based token refresh      |
| `createClientRefreshHandler()` | POST handler | Client-triggered token refresh  |
| `createLogoutHandler()`        | POST handler | Clear tokens and session        |

---

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines before submitting a pull request.

```bash
# Clone the repository
git clone https://github.com/bymaxone/nest-auth.git
cd nest-auth

# Install dependencies
pnpm install

# Run tests
pnpm test

# Build
pnpm build

# Type check
pnpm typecheck
```

---

## 🔒 Security Policy

If you discover a security vulnerability, please **do not** open a public issue. Instead, email us at **security@bymax.one** with details. We take security seriously and will respond promptly.

---

## 📄 License

[MIT](./LICENSE) © [Bymax One](https://github.com/bymaxone)

---

<p align="center">
  <sub>Built with ❤️ by <a href="https://github.com/bymaxone">Bymax One</a></sub>
</p>
