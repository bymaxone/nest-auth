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
  <a href="https://github.com/bymaxone/nest-auth/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/bymaxone/nest-auth/ci.yml?branch=main&style=flat-square&colorA=000000&label=CI" alt="CI status" /></a>
  <a href="https://github.com/bymaxone/nest-auth/actions/workflows/ci.yml"><img src="https://img.shields.io/badge/coverage-100%25-brightgreen?style=flat-square&colorA=000000" alt="coverage" /></a>
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
pnpm add @nestjs/common @nestjs/core @nestjs/jwt @nestjs/throttler @nestjs/websockets ioredis class-validator class-transformer reflect-metadata

# React subpath (optional)
pnpm add react

# Next.js subpath (optional)
pnpm add next react
```

> [!IMPORTANT]
> Requires `@nestjs/throttler >= 6.0.0` for `AUTH_THROTTLE_CONFIGS` decorators to be honored.

### 2. Implement the Repository Interface

The package defines **what** it needs — your app provides **how**. The consumer maps the abstract `AuthUser` fields onto its own database schema (column names, indexes, soft-delete columns are entirely up to you). The only invariant is that `passwordHash` MUST be persisted exactly as supplied by the library — it is the output of `node:crypto` scrypt and re-hashing or transforming it will break login.

```typescript
// user.repository.ts
import { Injectable } from '@nestjs/common'
import type {
  AuthUser,
  CreateUserData,
  CreateWithOAuthData,
  IUserRepository,
  UpdateMfaData
} from '@bymax-one/nest-auth'
import { PrismaService } from './prisma.service'

@Injectable()
export class PrismaUserRepository implements IUserRepository {
  constructor(private readonly prisma: PrismaService) {}

  async findById(id: string, tenantId?: string): Promise<AuthUser | null> {
    const where = tenantId ? { id, tenantId } : { id }
    return this.prisma.user.findFirst({ where })
  }

  async findByEmail(email: string, tenantId: string): Promise<AuthUser | null> {
    return this.prisma.user.findUnique({
      where: { email_tenantId: { email: email.toLowerCase(), tenantId } }
    })
  }

  async create(data: CreateUserData): Promise<AuthUser> {
    return this.prisma.user.create({
      data: {
        email: data.email.toLowerCase(),
        name: data.name,
        passwordHash: data.passwordHash,
        role: data.role ?? 'user',
        status: data.status ?? 'pending',
        tenantId: data.tenantId,
        emailVerified: data.emailVerified ?? false,
        mfaEnabled: false
      }
    })
  }

  async updatePassword(id: string, passwordHash: string): Promise<void> {
    await this.prisma.user.update({ where: { id }, data: { passwordHash } })
  }

  async updateMfa(id: string, data: UpdateMfaData): Promise<void> {
    await this.prisma.user.update({
      where: { id },
      data: {
        mfaEnabled: data.mfaEnabled,
        mfaSecret: data.mfaSecret,
        mfaRecoveryCodes: data.mfaRecoveryCodes ?? []
      }
    })
  }

  async updateLastLogin(id: string): Promise<void> {
    await this.prisma.user.update({ where: { id }, data: { lastLoginAt: new Date() } })
  }

  async updateStatus(id: string, status: string): Promise<void> {
    await this.prisma.user.update({ where: { id }, data: { status } })
  }

  async updateEmailVerified(id: string, verified: boolean): Promise<void> {
    await this.prisma.user.update({ where: { id }, data: { emailVerified: verified } })
  }

  async findByOAuthId(
    provider: string,
    providerId: string,
    tenantId: string
  ): Promise<AuthUser | null> {
    return this.prisma.user.findFirst({
      where: { oauthProvider: provider, oauthProviderId: providerId, tenantId }
    })
  }

  async linkOAuth(userId: string, provider: string, providerId: string): Promise<void> {
    await this.prisma.user.update({
      where: { id: userId },
      data: { oauthProvider: provider, oauthProviderId: providerId }
    })
  }

  async createWithOAuth(data: CreateWithOAuthData): Promise<AuthUser> {
    return this.prisma.user.create({
      data: {
        email: data.email.toLowerCase(),
        name: data.name,
        passwordHash: null,
        role: data.role ?? 'user',
        status: data.status ?? 'active',
        tenantId: data.tenantId,
        emailVerified: data.emailVerified ?? true,
        oauthProvider: data.oauthProvider,
        oauthProviderId: data.oauthProviderId,
        mfaEnabled: false
      }
    })
  }
}
```

### 3. Implement the Email Provider Interface

Email delivery is fully delegated to the consumer — the library never imports a mailer SDK. Implement `IEmailProvider` with your transport of choice (Resend, SendGrid, SES, Nodemailer) and bind it to the `BYMAX_AUTH_EMAIL_PROVIDER` token.

> [!WARNING]
> Any user-supplied value (display name, tenant name, inviter name) interpolated into HTML email bodies MUST be escaped to prevent stored XSS in notification content. Tokens and OTPs are library-generated and safe, but `inviterName`, `tenantName`, device strings, and any consumer-supplied placeholder are attacker-controllable.

```typescript
// email.provider.ts
import { Injectable } from '@nestjs/common'
import type { IEmailProvider, InviteData, SessionInfo } from '@bymax-one/nest-auth'
import { Resend } from 'resend'

const escapeHtml = (s: string): string =>
  s.replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')

@Injectable()
export class ResendEmailProvider implements IEmailProvider {
  private readonly client = new Resend(process.env.RESEND_API_KEY!)
  private readonly from = 'no-reply@example.com'
  private readonly appUrl = process.env.APP_URL!

  async sendPasswordResetToken(email: string, token: string, _locale?: string): Promise<void> {
    const url = `${this.appUrl}/reset-password?token=${encodeURIComponent(token)}`
    await this.client.emails.send({
      from: this.from,
      to: email,
      subject: 'Reset your password',
      html: `<p>Click <a href="${url}">here</a> to reset your password.</p>`
    })
  }

  async sendPasswordResetOtp(email: string, otp: string, _locale?: string): Promise<void> {
    await this.client.emails.send({
      from: this.from,
      to: email,
      subject: 'Your password reset code',
      html: `<p>Your code is <strong>${otp}</strong>. It expires in 10 minutes.</p>`
    })
  }

  async sendEmailVerificationOtp(email: string, otp: string, _locale?: string): Promise<void> {
    await this.client.emails.send({
      from: this.from,
      to: email,
      subject: 'Verify your email',
      html: `<p>Your verification code is <strong>${otp}</strong>.</p>`
    })
  }

  async sendMfaEnabledNotification(email: string, _locale?: string): Promise<void> {
    await this.client.emails.send({
      from: this.from,
      to: email,
      subject: 'MFA enabled on your account',
      html: '<p>Two-factor authentication has been enabled. If this was not you, contact support immediately.</p>'
    })
  }

  async sendMfaDisabledNotification(email: string, _locale?: string): Promise<void> {
    await this.client.emails.send({
      from: this.from,
      to: email,
      subject: 'MFA disabled on your account',
      html: '<p>Two-factor authentication has been disabled. If this was not you, contact support immediately.</p>'
    })
  }

  async sendNewSessionAlert(
    email: string,
    sessionInfo: SessionInfo,
    _locale?: string
  ): Promise<void> {
    await this.client.emails.send({
      from: this.from,
      to: email,
      subject: 'New sign-in to your account',
      html: `
        <p>New session detected:</p>
        <ul>
          <li>Device: ${escapeHtml(sessionInfo.device)}</li>
          <li>IP: ${escapeHtml(sessionInfo.ip)}</li>
          <li>Session: ${escapeHtml(sessionInfo.sessionHash)}</li>
        </ul>
      `
    })
  }

  async sendInvitation(
    email: string,
    inviteData: InviteData,
    _locale?: string
  ): Promise<void> {
    const url = `${this.appUrl}/accept-invite?token=${encodeURIComponent(inviteData.inviteToken)}`
    await this.client.emails.send({
      from: this.from,
      to: email,
      subject: `You have been invited to ${inviteData.tenantName}`,
      html: `
        <p><strong>${escapeHtml(inviteData.inviterName)}</strong> invited you to join
           <strong>${escapeHtml(inviteData.tenantName)}</strong>.</p>
        <p><a href="${url}">Accept invitation</a></p>
        <p>This link expires on ${inviteData.expiresAt.toUTCString()}.</p>
      `
    })
  }
}
```

Wire it via `extraProviders` alongside the user repository:

```typescript
import { BYMAX_AUTH_EMAIL_PROVIDER } from '@bymax-one/nest-auth'

extraProviders: [
  { provide: BYMAX_AUTH_EMAIL_PROVIDER, useClass: ResendEmailProvider }
]
```

### 4. Register the Module

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

### 5. Protect Routes

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

### 6. Frontend Integration (React)

Build an `AuthClient` once with `createAuthClient`, then hand it to
`AuthProvider`. Hooks (`useSession`, `useAuth`, `useAuthStatus`) read
the context populated by the provider.

```tsx
// app/providers.tsx
'use client'
import { AuthProvider } from '@bymax-one/nest-auth/react'
import { createAuthClient } from '@bymax-one/nest-auth/client'

const authClient = createAuthClient({
  // Same-origin calls go through the Next.js proxy routes under
  // `/api/auth/*`. Set `baseUrl` only when calling a cross-origin API.
})

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <AuthProvider client={authClient} onSessionExpired={() => (location.href = '/login')}>
      {children}
    </AuthProvider>
  )
}
```

```tsx
// app/(dashboard)/profile.tsx
'use client'
import { useAuth, useSession } from '@bymax-one/nest-auth/react'

export function Profile() {
  const { user, status } = useSession()
  const { logout } = useAuth()

  if (status === 'loading') return <div>Loading…</div>
  if (status === 'unauthenticated') return <div>Please log in</div>

  return (
    <div>
      <p>Welcome, {user.name}!</p>
      <button onClick={() => logout()}>Sign out</button>
    </div>
  )
}
```

### 7. Frontend Integration (Next.js 16)

Mount the Edge-Runtime auth proxy at the project root and expose the
three `/api/auth/*` route handlers. The proxy handles anti-redirect-
loop protection, RBAC, status blocking, and background-request
detection; the route handlers bridge the browser to your NestJS
backend.

```typescript
// proxy.ts — Next.js 16 Edge middleware
import { createAuthProxy } from '@bymax-one/nest-auth/nextjs'

export const { proxy } = createAuthProxy({
  publicRoutes: ['/', '/auth/login', '/auth/register'],
  publicRoutesRedirectIfAuthenticated: ['/auth/login', '/auth/register'],
  protectedRoutes: [
    { pattern: '/dashboard/:path*', allowedRoles: ['admin', 'member'] },
    { pattern: '/admin/:path*', allowedRoles: ['admin'] }
  ],
  loginPath: '/auth/login',
  getDefaultDashboard: (role) => (role === 'admin' ? '/dashboard/admin' : '/dashboard'),
  apiBase: process.env.API_BASE_URL!,
  jwtSecret: process.env.JWT_SECRET,
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
})

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)']
}
```

```typescript
// app/api/auth/silent-refresh/route.ts
import { createSilentRefreshHandler } from '@bymax-one/nest-auth/nextjs'

export const GET = createSilentRefreshHandler({
  apiBase: process.env.API_BASE_URL!,
  loginPath: '/auth/login',
  cookieNames: {
    access: 'access_token',
    refresh: 'refresh_token',
    hasSession: 'has_session'
  }
})
```

```typescript
// app/api/auth/client-refresh/route.ts
import { createClientRefreshHandler } from '@bymax-one/nest-auth/nextjs'

export const POST = createClientRefreshHandler({ apiBase: process.env.API_BASE_URL! })
```

```typescript
// app/api/auth/logout/route.ts
import { createLogoutHandler } from '@bymax-one/nest-auth/nextjs'

export const POST = createLogoutHandler({
  apiBase: process.env.API_BASE_URL!,
  mode: 'redirect',
  loginPath: '/auth/login',
  cookieNames: {
    access: 'access_token',
    refresh: 'refresh_token',
    hasSession: 'has_session'
  }
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
| **cookies**       | `accessTokenName`, `refreshTokenName`, `sessionSignalName`, `refreshCookiePath`, `resolveDomains` | — (see cookie section)   |
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

### Security Checklist

When integrating `@bymax-one/nest-auth` in production, verify each of the following:

- `cookies.resolveDomains` MUST validate against an allowlist of configured domains
- MFA recovery without TOTP requires admin intervention (no self-service)
- `@MaxLength(128)` on password DTOs prevents algorithmic-DoS via oversized scrypt inputs
- JWT algorithm pinning to HS256 prevents algorithm-confusion attacks
- Constant-time comparisons via `crypto.timingSafeEqual` for all secret comparisons
- HttpOnly cookies; `Secure` enforced in production; `SameSite=Strict` for refresh tokens

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
| Cookies           | HttpOnly, Secure, SameSite=Strict, path-scoped     |
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

### HTTP Endpoints

Conditionally registered controllers (mfa, sessions, platform, invitations, oauth, password-reset) only mount their endpoints when the corresponding feature is enabled in `BymaxAuthModule.registerAsync()`.

| Method | Path                          | Auth / Guard                                | Description                                                |
| ------ | ----------------------------- | ------------------------------------------- | ---------------------------------------------------------- |
| POST   | `/register`                   | Public                                      | Register a new dashboard user and issue tokens             |
| POST   | `/login`                      | Public                                      | Authenticate with email/password (may return MFA challenge) |
| POST   | `/logout`                     | `JwtAuthGuard`                              | Revoke tokens and clear session                            |
| POST   | `/refresh`                    | Public (refresh cookie)                     | Rotate refresh token, issue new access token               |
| GET    | `/me`                         | `JwtAuthGuard`                              | Current dashboard user payload                             |
| POST   | `/verify-email`               | Public                                      | Verify email with OTP                                      |
| POST   | `/resend-verification`        | Public                                      | Resend email-verification OTP                              |
| POST   | `/password/forgot-password`   | Public                                      | Request password reset (token or OTP)                      |
| POST   | `/password/reset-password`    | Public                                      | Submit new password with reset token                       |
| POST   | `/password/verify-otp`        | Public                                      | Verify password-reset OTP                                  |
| POST   | `/password/resend-otp`        | Public                                      | Resend password-reset OTP                                  |
| POST   | `/mfa/setup`                  | `JwtAuthGuard`                              | Generate TOTP secret and recovery codes                    |
| POST   | `/mfa/verify-enable`          | `JwtAuthGuard`                              | Confirm setup and enable MFA                               |
| POST   | `/mfa/challenge`              | Public + `@SkipMfa()`                       | Submit TOTP/recovery code after login                      |
| POST   | `/mfa/disable`                | `JwtAuthGuard`                              | Disable MFA for the current user                           |
| GET    | `/sessions`                   | `JwtAuthGuard`, `UserStatusGuard`           | List active sessions for the current user                  |
| DELETE | `/sessions/all`               | `JwtAuthGuard`, `UserStatusGuard`           | Revoke all sessions                                        |
| DELETE | `/sessions/:id`               | `JwtAuthGuard`, `UserStatusGuard`           | Revoke a specific session                                  |
| POST   | `/invitations`                | `JwtAuthGuard`                              | Create a tenant invitation                                 |
| POST   | `/invitations/accept`         | Public                                      | Accept an invitation and create the user                   |
| POST   | `/platform/login`             | Public                                      | Platform admin login (separate token context)              |
| POST   | `/platform/mfa/challenge`     | Public                                      | Platform admin MFA challenge                               |
| GET    | `/platform/me`                | `JwtPlatformGuard`                          | Current platform admin payload                             |
| POST   | `/platform/logout`            | `JwtPlatformGuard`                          | Revoke platform tokens                                     |
| POST   | `/platform/refresh`           | Public (platform refresh cookie)            | Rotate platform refresh token                              |
| DELETE | `/platform/sessions`          | `JwtPlatformGuard`                          | Revoke all platform sessions                               |
| GET    | `/oauth/:provider`            | Public + `@SkipMfa()`                       | Initiate OAuth authorization redirect                      |
| GET    | `/oauth/:provider/callback`   | Public + `@SkipMfa()`                       | Handle OAuth callback, exchange code, issue tokens         |

### Server Guards

| Guard                | Decorator                       | Purpose                                                     |
| -------------------- | ------------------------------- | ----------------------------------------------------------- |
| `JwtAuthGuard`       | —                               | Validates JWT from cookie or `Authorization: Bearer` header |
| `RolesGuard`         | `@Roles('admin')`               | Hierarchical role check                                     |
| `UserStatusGuard`    | —                               | Blocks inactive/banned users (Redis-cached status)          |
| `MfaRequiredGuard`   | `@SkipMfa()`                    | Enforces MFA verification on protected routes               |
| `JwtPlatformGuard`   | —                               | Platform admin JWT validation (Bearer only)                 |
| `PlatformRolesGuard` | `@PlatformRoles('super_admin')` | Platform role hierarchy enforcement                         |

> [!NOTE]
> Three additional guards — `SelfOrAdminGuard` (ownership checks), `OptionalAuthGuard` (routes that behave differently for anonymous vs authenticated users), and `WsJwtGuard` (JWT authentication on WebSocket gateways) — are exported from the public `@bymax-one/nest-auth` barrel. Use them exactly like the core guards above.

### Server Decorators

| Decorator                  | Usage                                                                        |
| -------------------------- | ---------------------------------------------------------------------------- |
| `@CurrentUser()`           | Extract JWT payload from request: `@CurrentUser() user: DashboardJwtPayload` |
| `@Roles(...roles)`         | Set required roles: `@Roles('admin', 'manager')`                             |
| `@PlatformRoles(...roles)` | Set required platform roles: `@PlatformRoles('super_admin')`                 |
| `@Public()`                | Mark route as public (skip JWT guard)                                        |
| `@SkipMfa()`               | Skip MFA verification for this route                                         |

### React Hooks

| Hook              | Returns                                                                                                  |
| ----------------- | -------------------------------------------------------------------------------------------------------- |
| `useSession()`    | `{ user, status, isLoading, refresh(), lastValidation }` — current session state and revalidation helper |
| `useAuth()`       | `{ login(), logout(), register(), forgotPassword(), resetPassword() }` — auth actions                    |
| `useAuthStatus()` | `{ isAuthenticated, isLoading }` — derived state                                                         |

### Next.js Factories

| Factory                        | Type         | Purpose                         |
| ------------------------------ | ------------ | ------------------------------- |
| `createAuthProxy()`            | Proxy config | Auth-aware proxy for `proxy.ts` |
| `createSilentRefreshHandler()` | GET handler  | iframe-based token refresh      |
| `createClientRefreshHandler()` | POST handler | Client-triggered token refresh  |
| `createLogoutHandler()`        | POST handler | Clear tokens and session        |

---

## 🗺️ Roadmap

The items below are on deck for future minor / major releases. None are shipping today — the list exists so contributors can see where the library is headed and where help is most useful. Open an issue if you'd like to discuss priorities or propose a design.

| Area                        | Item                                                                                                                    | Status    |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------- | --------- |
| OAuth providers             | First-class `oauth.plugins` array so consumers can drop in GitHub / Microsoft / Apple plugins without forking the core  | Planned   |
| Error-message i18n          | `BymaxAuthModule.forRoot({ messages })` override for `AUTH_ERROR_MESSAGES` (defaults stay Portuguese; English preset)   | Planned   |
| Refresh-token families      | Family-level revocation: detect grace-window reuse as a stolen-token signal and invalidate the entire session family    | Planned   |
| Passwordless / magic link   | `MagicLinkService` + email-delivered single-use link, reusing the existing `generateSecureToken` + `IEmailProvider` API | Exploring |
| Passkeys / WebAuthn         | Optional WebAuthn primitive as an MFA method (and eventually a first-factor), behind a peer-dep-gated module            | Exploring |
| Per-tenant configuration    | Per-tenant overrides for session limits, MFA enforcement, and password policy resolved at request time                  | Exploring |
| Absolute session lifetime   | Hard cap on refresh chains so a session rotated every 6 days does not live forever                                      | Planned   |
| Pluggable password policy   | `IPasswordPolicy` interface for disallow-lists, complexity classes, and per-tenant rules                                | Planned   |
| Custom token delivery modes | `ITokenDelivery` for non-cookie / non-bearer transports (custom headers, WebSocket handshakes, split client types)      | Exploring |

> Track progress and discuss proposals on the [issues board](https://github.com/bymaxone/nest-auth/issues).

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
