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
- ✅ **JWT Blacklisting** — Instant token revocation via Redis

### 🏢 Multi-Tenant & Platform

- ✅ **Tenant Isolation** — All operations scoped by `tenantId` with configurable resolver
- ✅ **Platform Admin Auth** — Separate token type and role hierarchy for super-admins
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
import { IUserRepository, AuthUser } from "@bymax-one/nest-auth";
import { PrismaService } from "./prisma.service";

export class PrismaUserRepository implements IUserRepository {
  constructor(private prisma: PrismaService) {}

  async findByEmail(email: string, tenantId: string): Promise<AuthUser | null> {
    return this.prisma.user.findUnique({
      where: { email_tenantId: { email, tenantId } },
    });
  }

  async create(data: Partial<AuthUser>): Promise<AuthUser> {
    return this.prisma.user.create({ data });
  }

  // ... implement all IUserRepository methods
}
```

### 3. Register the Module

```typescript
// app.module.ts
import { Module } from "@nestjs/common";
import { BymaxAuthModule } from "@bymax-one/nest-auth";

@Module({
  imports: [
    BymaxAuthModule.registerAsync({
      imports: [ConfigModule, DatabaseModule, RedisModule],
      useFactory: (config, userRepo, redis) => ({
        jwt: {
          secret: config.get("JWT_SECRET"), // min 32 chars, high entropy
          accessExpiresIn: "15m",
          refreshExpiresInDays: 7,
        },
        tokenDelivery: "cookie", // 'cookie' | 'bearer' | 'both'
        roles: {
          hierarchy: ["user", "manager", "admin"],
        },
        userRepository: userRepo,
        redisClient: redis,
        // All other options have sensible defaults
      }),
      inject: [ConfigService, UserRepository, RedisClient],
    }),
  ],
})
export class AppModule {}
```

### 4. Protect Routes

```typescript
// users.controller.ts
import { Controller, Get, UseGuards } from "@nestjs/common";
import {
  JwtAuthGuard,
  RolesGuard,
  Roles,
  CurrentUser,
  DashboardJwtPayload,
} from "@bymax-one/nest-auth";

@Controller("users")
@UseGuards(JwtAuthGuard, RolesGuard)
export class UsersController {
  @Get("me")
  getProfile(@CurrentUser() user: DashboardJwtPayload) {
    return { id: user.sub, role: user.role, tenantId: user.tenantId };
  }

  @Get()
  @Roles("admin")
  listUsers() {
    // Only accessible by admins (and above in hierarchy)
  }
}
```

### 5. Frontend Integration (React)

```tsx
// app.tsx
import { AuthProvider } from "@bymax-one/nest-auth/react";

export function App({ children }) {
  return (
    <AuthProvider apiUrl="https://api.example.com/auth">
      {children}
    </AuthProvider>
  );
}

// profile.tsx
import { useSession, useAuth } from "@bymax-one/nest-auth/react";

export function Profile() {
  const { user, status } = useSession();
  const { logout } = useAuth();

  if (status === "loading") return <div>Loading...</div>;
  if (status === "unauthenticated") return <div>Please log in</div>;

  return (
    <div>
      <p>Welcome, {user.name}!</p>
      <button onClick={logout}>Sign out</button>
    </div>
  );
}
```

### 6. Frontend Integration (Next.js 16)

```typescript
// proxy.ts (Next.js 16 — formerly middleware.ts)
import { createAuthProxy } from "@bymax-one/nest-auth/nextjs";

export const { proxy, config } = createAuthProxy({
  backendUrl: process.env.BACKEND_URL!,
  publicRoutes: ["/", "/login", "/register"],
});
```

```typescript
// app/api/auth/silent-refresh/route.ts
import { createSilentRefreshHandler } from "@bymax-one/nest-auth/nextjs";

export const GET = createSilentRefreshHandler({
  backendUrl: process.env.BACKEND_URL!,
});
```

---

## ⚙️ Configuration

All options are configurable via `registerAsync()`. Here are the key configuration groups:

| Group                 | Key Options                                                                 | Default                 |
| --------------------- | --------------------------------------------------------------------------- | ----------------------- |
| **jwt**               | `secret` (required), `accessExpiresIn`, `refreshExpiresInDays`, `algorithm` | `15m`, `7d`, `HS256`    |
| **password**          | `costFactor`, `blockSize`, `parallelization`                                | scrypt N=2¹⁵, r=8, p=1  |
| **tokenDelivery**     | `'cookie'` \| `'bearer'` \| `'both'`                                        | `'cookie'`              |
| **cookies**           | `secure`, `sameSite`, `httpOnly`, `refreshCookiePath`                       | `true`, `'lax'`, `true` |
| **mfa**               | `encryptionKey`, `issuer`, `totpWindow`, `recoveryCodeCount`                | —                       |
| **sessions**          | `enabled`, `maxSessions`, `newSessionAlert`                                 | `false`                 |
| **bruteForce**        | `maxAttempts`, `windowSeconds`                                              | `5`, `900`              |
| **passwordReset**     | `method` (`'token'` \| `'otp'`), `otpLength`, `otpTtlSeconds`               | `'token'`               |
| **emailVerification** | `required`, `otpTtlSeconds`                                                 | `false`                 |
| **platformAdmin**     | `enabled`, `platformHierarchy`                                              | `false`                 |
| **invitations**       | `enabled`, `tokenTtlDays`, `maxPendingPerTenant`                            | `false`                 |
| **roles**             | `hierarchy` (required), `blockedStatuses`                                   | —                       |
| **oauth**             | `google: { clientId, clientSecret, callbackUrl }`                           | —                       |
| **controllers**       | Toggle individual controllers on/off                                        | All enabled             |

> [!NOTE]
> When a feature is not configured (e.g., `mfa`, `sessions`, `platformAdmin`), its controllers and services are **not registered** in the NestJS container — zero overhead.

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

## 🔐 Security

| Layer             | Implementation                                    |
| ----------------- | ------------------------------------------------- |
| Password Hashing  | `node:crypto` scrypt (N=2¹⁵, r=8, p=1, keyLen=64) |
| MFA Encryption    | AES-256-GCM with 12-byte IV                       |
| TOTP              | HMAC-SHA1 per RFC 4226/6238                       |
| Token Generation  | `crypto.randomBytes`                              |
| Secret Comparison | `crypto.timingSafeEqual` (constant-time)          |
| JWT               | HS256 via `@nestjs/jwt`, blacklist via Redis      |
| Cookies           | HttpOnly, Secure, SameSite=Lax, path-scoped       |
| Brute-Force       | Redis-backed rate limiting per email + tenant     |

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

| Guard                | Decorator                      | Purpose                                                     |
| -------------------- | ------------------------------ | ----------------------------------------------------------- |
| `JwtAuthGuard`       | —                              | Validates JWT from cookie or `Authorization: Bearer` header |
| `RolesGuard`         | `@Roles('admin')`              | Hierarchical role check                                     |
| `UserStatusGuard`    | —                              | Blocks inactive/banned users (Redis-cached)                 |
| `MfaRequiredGuard`   | `@SkipMfa()`                   | Enforces MFA verification                                   |
| `JwtPlatformGuard`   | —                              | Platform admin JWT validation                               |
| `PlatformRolesGuard` | `@PlatformRoles('superadmin')` | Platform role hierarchy                                     |
| `SelfOrAdminGuard`   | —                              | User can only access own resources (or admin)               |
| `OptionalAuthGuard`  | —                              | Attaches user if authenticated, proceeds if not             |
| `WsJwtGuard`         | —                              | WebSocket JWT validation                                    |

### Server Decorators

| Decorator                  | Usage                                                                        |
| -------------------------- | ---------------------------------------------------------------------------- |
| `@CurrentUser()`           | Extract JWT payload from request: `@CurrentUser() user: DashboardJwtPayload` |
| `@Roles(...roles)`         | Set required roles: `@Roles('admin', 'manager')`                             |
| `@PlatformRoles(...roles)` | Set required platform roles                                                  |
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
