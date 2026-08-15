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
  <a href="https://github.com/bymaxone/nest-auth/blob/main/docs/mutation_testing_results.md"><img src="https://img.shields.io/badge/mutation-100%25-brightgreen?style=flat-square&colorA=000000" alt="mutation score" /></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/bymaxone/nest-auth"><img src="https://api.scorecard.dev/projects/github.com/bymaxone/nest-auth/badge?style=flat-square" alt="OpenSSF Scorecard" /></a>
  <a href="https://github.com/bymaxone/nest-auth/blob/main/LICENSE"><img src="https://img.shields.io/github/license/bymaxone/nest-auth?style=flat-square&colorA=000000&colorB=000000" alt="license" /></a>
  <a href="https://www.typescriptlang.org/"><img src="https://img.shields.io/badge/TypeScript-strict-3178C6?style=flat-square&logo=typescript&logoColor=white" alt="TypeScript" /></a>
  <a href="https://nodejs.org/"><img src="https://img.shields.io/badge/Node.js-24%2B-339933?style=flat-square&logo=node.js&logoColor=white" alt="Node.js" /></a>
</p>

<p align="center">
  <a href="https://github.com/bymaxone/nest-auth">GitHub</a> ·
  <a href="https://github.com/bymaxone/nest-auth/issues">Issues</a> ·
  <a href="#-quick-start">Quick Start</a> ·
  <a href="#-subpath-exports">API Reference</a> ·
  <a href="https://github.com/bymaxone/nest-auth-example">Example App</a>
</p>

---

## ✨ Overview

`@bymax-one/nest-auth` is a **complete authentication and authorization solution** shipped as a single npm package with **5 subpath exports** — covering everything from NestJS backend guards to React hooks and Next.js route handlers.

Instead of wiring together dozens of packages for JWT, MFA, OAuth, sessions, password reset, and brute-force protection, you install one library and get a production-ready auth system that works across your entire stack.

### Why nest-auth?

- **🎯 One package, full stack** — Backend module, shared types, fetch client, React hooks, and Next.js integration all in a single `pnpm add`. Types and constants are shared automatically between server and client — no manual synchronization.
- **🔌 Your database, your rules** — The library defines TypeScript interfaces (`IUserRepository`, `IEmailProvider`). You implement them with your ORM of choice (Prisma, TypeORM, Drizzle). No vendor lock-in, no hidden database dependencies.
- **🔒 Native crypto only** — All security-critical code (password hashing, MFA encryption, TOTP, token generation) runs on `node:crypto` — zero third-party crypto packages, so the most sensitive code paths carry no third-party supply-chain risk.
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
- ✅ **Session Management** — Track active sessions with FIFO eviction, and an `onNewSession` hook fired on every session created (alerting on it is yours to decide — see `sendNewSessionAlert`)
- ✅ **HttpOnly Cookies** — Secure, SameSite, path-scoped refresh tokens by default
- ✅ **Timing-Safe Comparisons** — All secret comparisons use `crypto.timingSafeEqual`
- ✅ **JWT Revocation** — Instant access token revocation via Redis JTI blacklist
- ✅ **Refresh-Token Reuse Detection** — Replaying a consumed token revokes that login's whole lineage, and only that lineage
- ✅ **Bulk Access-Token Revocation** — A password reset advances a per-user token epoch, invalidating every outstanding access token in one write
- ✅ **Absolute Session Lifetime** — Optional hard cap on how long one login can be extended by rotation
- ✅ **Cross-Site Request Refusal** — Cookie-authenticated writes from an untrusted origin are rejected (matters under `SameSite=None`)
- ✅ **Breached-Password Refusal** — Optional Have I Been Pwned check by k-anonymity range; the password never leaves the process
- ✅ **Per-IP Rate Limiting** — Enforced by the library over Redis, so the limit holds across instances with no host wiring

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

> [!TIP]
> Prefer to learn from a working app? See the [nest-auth-example](https://github.com/bymaxone/nest-auth-example) — a full NestJS + Next.js project wired with this library.

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
pnpm add next react server-only
```

> [!NOTE]
> `server-only` is what makes importing the Next.js JWT helper from a Client Component a
> **build error**. That module receives the HS256 secret, and a secret in a client chunk is a
> secret published to every visitor — with nothing downstream to notice. It is a marker package
> with no runtime behaviour, and Next.js's own documentation prescribes it for exactly this.

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

  async updateMfa(id: string, tenantId: string | undefined, data: UpdateMfaData): Promise<void> {
    // Scoped by tenant, like findById: `updateMany` with both id and tenantId so an id shared
    // across tenants cannot cross the write onto the wrong account.
    await this.prisma.user.updateMany({
      where: { id, tenantId },
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

  async updateEmail(id: string, email: string): Promise<void> {
    await this.prisma.user.update({ where: { id }, data: { email: email.toLowerCase() } })
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
  s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')

@Injectable()
export class ResendEmailProvider implements IEmailProvider {
  private readonly client = new Resend(process.env.RESEND_API_KEY!)
  private readonly from = 'no-reply@example.com'
  private readonly appUrl = process.env.APP_URL!

  async sendPasswordResetToken(
    _tenantId: string,
    email: string,
    token: string,
    _locale?: string
  ): Promise<void> {
    const url = `${this.appUrl}/reset-password?token=${encodeURIComponent(token)}`
    await this.client.emails.send({
      from: this.from,
      to: email,
      subject: 'Reset your password',
      html: `<p>Click <a href="${url}">here</a> to reset your password.</p>`
    })
  }

  async sendPasswordResetOtp(
    _tenantId: string,
    email: string,
    otp: string,
    _locale?: string
  ): Promise<void> {
    await this.client.emails.send({
      from: this.from,
      to: email,
      subject: 'Your password reset code',
      html: `<p>Your code is <strong>${otp}</strong>. It expires in 10 minutes.</p>`
    })
  }

  async sendEmailVerificationOtp(
    _tenantId: string,
    email: string,
    otp: string,
    _locale?: string
  ): Promise<void> {
    await this.client.emails.send({
      from: this.from,
      to: email,
      subject: 'Verify your email',
      html: `<p>Your verification code is <strong>${otp}</strong>.</p>`
    })
  }

  async sendMfaEnabledNotification(
    _tenantId: string,
    email: string,
    _locale?: string
  ): Promise<void> {
    await this.client.emails.send({
      from: this.from,
      to: email,
      subject: 'MFA enabled on your account',
      html: '<p>Two-factor authentication has been enabled. If this was not you, contact support immediately.</p>'
    })
  }

  async sendMfaDisabledNotification(
    _tenantId: string,
    email: string,
    _locale?: string
  ): Promise<void> {
    await this.client.emails.send({
      from: this.from,
      to: email,
      subject: 'MFA disabled on your account',
      html: '<p>Two-factor authentication has been disabled. If this was not you, contact support immediately.</p>'
    })
  }

  async sendNewSessionAlert(
    _tenantId: string,
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
    _tenantId: string,
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

extraProviders: [{ provide: BYMAX_AUTH_EMAIL_PROVIDER, useClass: ResendEmailProvider }]
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
        // Required while the limiter is on, and neither value can be a default:
        // 'peer' behind a proxy reads the proxy's address for every request, and
        // 'trusted-proxy' without one trusts a header the client can forge.
        rateLimit: { clientIpSource: 'trusted-proxy' }, // 'peer' | 'trusted-proxy'
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
import { JwtAuthGuard, RolesGuard, Roles, CurrentUser } from '@bymax-one/nest-auth'
// `import type` is required for a type used in a decorated signature: with
// `emitDecoratorMetadata` and `isolatedModules`, a value import would be emitted
// into the metadata and fail to erase (TS1272).
import type { DashboardJwtPayload } from '@bymax-one/nest-auth'

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
  // Same-origin: a relative base sends every call through the Next.js
  // proxy routes — `'/api'` plus the default `routePrefix` composes
  // `/api/auth/*`. Use an absolute origin for a cross-origin API.
  baseUrl: '/api'
})

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <AuthProvider client={authClient} onSessionExpired={() => (location.href = '/login')}>
      {children}
    </AuthProvider>
  )
}
```

> **Which 401 spends a refresh.** The client's `authFetch` retries through `/refresh` only when
> the 401 says the access token is the problem — `auth.token_invalid`, or a body carrying no
> readable code. A route can sit behind the JWT guard _and_ verify a second credential, so
> `auth.invalid_credentials` from a password change and an expired token arrive at the same URL
> with the same status; the code separates them, the path never could. Any other 401 is returned
> to the caller untouched, and `createAuthClient({ onSessionExpired })` fires only when a refresh
> was warranted and failed. `AuthProvider`'s own `onSessionExpired` prop is a different hook: it
> reacts to a 401 from the session read itself.

```tsx
// app/(dashboard)/profile.tsx
'use client'
import { useAuth, useSession } from '@bymax-one/nest-auth/react'

export function Profile() {
  const { user, status } = useSession()
  const { logout } = useAuth()

  if (status === 'loading') return <div>Loading…</div>
  // `status` and `user` are separate fields, so the status check alone does
  // not narrow `user` away from null — test the one you are about to read.
  if (!user) return <div>Please log in</div>

  return (
    <div>
      <p>Welcome, {user.name}!</p>
      <button onClick={() => logout()}>Sign out</button>
    </div>
  )
}
```

#### Plain SPAs — set `refreshEndpoint`

The example above is a Next.js app, where the default works. **A Vite/CRA SPA talking straight to
a Nest backend must set `refreshEndpoint`**, because it defaults to `/api/auth/client-refresh` —
a Next.js proxy route this library ships for that framework, and a path a plain SPA serves
nothing at.

```ts
const authClient = createAuthClient({
  baseUrl: 'https://api.example.com',
  // Without this, refresh POSTs to the Next proxy route and 404s.
  refreshEndpoint: 'https://api.example.com/auth/refresh'
})
```

**The symptom, because it does not look like a configuration problem:** _if every access-token
expiry logs the user out, check `refreshEndpoint` before looking at cookies._ The 404 is silent —
refresh fails, the session ends, and it presents as a session bug rather than as a missing route.

Also note `tenantId` is **optional** on every client input. Whether the server wants it is the
deployment's answer, not the type's: it is required when no `tenantIdResolver` is configured and
**refused** when one is, answering `auth.validation` with a `tenantId` field detail either way.
Send it, or do not, according to the deployment you talk to.

### 7. Frontend Integration (Next.js 16)

Mount the Edge-Runtime auth proxy at the project root and expose the
three `/api/auth/*` route handlers. The proxy handles anti-redirect-
loop protection, RBAC, status blocking, and background-request
detection; the route handlers bridge the browser to your NestJS
backend.

```typescript
// proxy.ts — Next.js 16 Edge middleware
import { createAuthProxy } from '@bymax-one/nest-auth/nextjs'

// Next 16 scans this file for a function exported as `proxy` (or as the default), and it
// does not recognise a destructuring pattern: `export const { proxy } = ...` fails the build
// with "The file ./proxy.ts must export a function". Bind first, then export.
const authProxy = createAuthProxy({
  publicRoutes: ['/', '/auth/login', '/auth/register'],
  publicRoutesRedirectIfAuthenticated: ['/auth/login', '/auth/register'],
  protectedRoutes: [
    { pattern: '/dashboard/:path*', allowedRoles: ['admin', 'member'] },
    { pattern: '/admin/:path*', allowedRoles: ['admin'] }
  ],
  loginPath: '/auth/login',
  getDefaultDashboard: (role) => (role === 'admin' ? '/dashboard/admin' : '/dashboard'),
  apiBase: process.env.API_BASE_URL!,
  jwtSecret: process.env.JWT_SECRET!,
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

export const proxy = authProxy.proxy

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

### WebSocket upgrades

The browser `WebSocket` API cannot set handshake headers, so a browser client cannot send
`Authorization: Bearer <token>` at the upgrade. The usual workaround puts the access token in the
query string, where it lands in access logs, browser history and proxy caches — a long-lived
credential in plaintext. `WsJwtGuard` refuses it.

The supported path is a single-use ticket:

```typescript
// 1. Mint from an authenticated session (POST, cookies or bearer as usual).
const { ticket, expiresIn } = await fetch('/auth/ws-ticket', {
  method: 'POST',
  credentials: 'include'
}).then((r) => r.json())

// 2. Open the socket with it. The ticket is consumed by the first redemption.
const socket = new WebSocket(`wss://api.example.com/socket?ticket=${ticket}`)
```

The ticket is opaque, 32 bytes of CSPRNG output, and lives 30 seconds. Only `sha256(ticket)` is
ever a Redis key, and the stored value is a verified-identity **snapshot** — no `jti`, no
signature, no expiry of its own — so a redeemed ticket authorizes a socket and cannot be turned
back into a session. Minting requires an authenticated session in good standing that has already
satisfied MFA, so a ticket never carries more authority than the request that asked for it.

Non-browser clients that can set headers keep using `Authorization: Bearer` at the handshake;
both channels are accepted, and a ticket wins when both are present.

Both channels live on the client's `handshake`, and only a **Socket.IO** client has one — with
`@nestjs/platform-ws` the gateway receives the raw `ws` socket, which carries no `handshake` and
does not retain the upgrade request. `WsJwtGuard` refuses such a connection with
`auth.token_invalid` instead of crashing on it, but it cannot authenticate anyone on that
adapter. And because `AuthException` extends `HttpException`, which Nest's WebSocket layer does
not recognise, a gateway that applies the guard also needs `WsAuthExceptionFilter` for the
refusal to reach the client as anything but `Internal server error` — see
[On a WebSocket, the envelope needs its own filter](#on-a-websocket-the-envelope-needs-its-own-filter).

---

## ⚙️ Configuration

All options are configurable via `registerAsync()`. Here are the key configuration groups:

| Group                 | Key Options                                                                                                                                         | Default                                   |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| **jwt**               | `secret` (required), `previousSecrets`, `accessExpiresIn`, `refreshExpiresInDays`, `absoluteSessionLifetimeDays`, `algorithm`, `issuer`, `audience` | `15m`, `7d`, `30d` cap, `HS256`, both off |
| **environment**       | `'production'` \| `'development'` \| `'test'` — the only input that answers "is this production"                                                    | `'production'`                            |
| **password**          | `minLength`, `costFactor`, `blockSize`, `parallelization`                                                                                           | `15`, scrypt N=2¹⁷, r=8, p=1              |
| **tokenDelivery**     | `'cookie'` \| `'bearer'` \| `'both'`                                                                                                                | `'cookie'`                                |
| **cookies**           | `accessTokenName`, `refreshTokenName`, `sessionSignalName`, `refreshCookiePath`, `sameSite`, `trustedOrigins`, `resolveDomains`                     | `'lax'`, `[]` (see cookie section)        |
| **mfa**               | `encryptionKey`, `previousEncryptionKeys`, `issuer`, `totpWindow`, `recoveryCodeCount`                                                              | —                                         |
| **sessions**          | `enabled`, `defaultMaxSessions`, `maxSessionsResolver`                                                                                              | `false`, `5`, —                           |
| **bruteForce**        | `maxAttempts`, `windowSeconds`                                                                                                                      | `5`, `900`                                |
| **rateLimit**         | `enabled`, `clientIpSource` (`'peer'` \| `'trusted-proxy'`) — per-IP limits over Redis                                                              | `true`, **required**                      |
| **passwordReset**     | `method` (`'token'` \| `'otp'`), `otpLength`, `otpTtlSeconds`                                                                                       | `'token'`                                 |
| **platform**          | `enabled`                                                                                                                                           | `false`                                   |
| **invitations**       | `enabled`, `tokenTtlSeconds`                                                                                                                        | `false`                                   |
| **roles**             | `hierarchy` (required), `platformHierarchy`                                                                                                         | —                                         |
| **oauth**             | `google: { clientId, clientSecret, callbackUrl }`                                                                                                   | —                                         |
| **emailVerification** | `required`, `otpTtlSeconds`                                                                                                                         | `true`, `600`                             |
| **password** (screen) | `blocklist` — extra words the default screen refuses, on top of the ones it ships                                                                   | `[]`                                      |
| **controllers**       | Toggle individual controllers on/off                                                                                                                | `auth`, `passwordReset` on; rest opt-in   |

> [!NOTE]
> When a feature is not configured (e.g., `mfa`, `sessions`, `platform`), its controllers and services are **not registered** in the NestJS container — zero overhead.

> [!IMPORTANT]
> **`environment` is how the module decides whether this is production, and it defaults to
> saying yes.** It drives cookie `Secure`, the HTTPS requirement on the OAuth `callbackUrl`, and
> three redirect validations. It used to be read from `NODE_ENV`, which failed **open** on every
> near miss — unset, `'staging'`, `'prod'`, or `'production '` with a trailing space each
> silently took the insecure branch, in all six places at once. Whether a deployment is
> production is something the deployer knows and the process environment only hints at, so it is
> passed in. The consequence to plan for: a local or test setup must now say
> `environment: 'development'` (or `'test'`) explicitly, or it will be held to production rules —
> an `http://` callback URL is refused, and cookies are marked `Secure` and never sent over
> plaintext. That failure is loud, which is the point; the old one was silent. Matches
> `Environment` in rust-auth.

> [!NOTE]
> **`password.minLength` defaults to 15, not 8.** The DTOs keep a structural floor of 8 — the
> lowest NIST SP 800-63B-4 §3.1.1.1 permits under any circumstance — and this is the
> deployment's policy on top of it. §3.1.1.1 allows 8 only for a password used as part of
> multi-factor authentication and requires 15 for one used as a single factor; MFA here is
> opt-in per user, so the default deployment **is** single-factor. Configurable to anything in
> `8..=128`, validated at startup: below 8 changes no outcome (the DTOs refuse the request
> first), and above 128 is longer than any password the validation layer accepts. It is checked
> in the service rather than a decorator because a decorator is evaluated when the class is
> defined, before any configuration exists — and it answers the same `auth.validation` code and
> the same `{ field, message }[]` details a length failure already produced, so a client
> handling short passwords sees no new shape.

> [!IMPORTANT]
> **`rateLimit.clientIpSource` is required** whenever rate limiting is enabled — there is no
> default. The option group is a discriminated union, so TypeScript refuses the omission at
> compile time; the module also refuses to start without it, because the type binds TypeScript
> and nothing else. Set `'peer'` when the application is
> directly exposed: the limit keys on the socket address, read from the connection and never
> from a forwarding header. Set `'trusted-proxy'` when it runs behind a proxy and `trust proxy`
> is configured for the real hop count: the limit keys on `req.ip`, the forwarded client
> address. Neither can be the default, because each is a working limiter in one deployment and
> no limiter at all in the other — `'peer'` behind a proxy puts every client in **one** bucket,
> so a single caller can rate-limit your whole user base with no credential, and
> `'trusted-proxy'` without a proxy lets the caller choose their own key. Both look like a
> working limiter at runtime. Pass `rateLimit.enabled: false` if the limits are enforced at the
> edge instead.

> [!TIP]
> **Binding tokens to an issuer and an audience.** `jwt.issuer` and `jwt.audience` are off by
> default. Set either and its value is stamped on every token this backend mints and **required**
> on every token it verifies — one carrying a different value, or none at all, is rejected.
> That matters with HS256, where the verifier can also sign: every service holding the secret to
> check a token can mint one, so audience binding is what stops a token minted for one service
> being replayed at another that trusts the same secret.
>
> Two things to know before switching it on. Both backends of a shared deployment must carry the
> same pair, or they stop accepting each other's tokens. And enabling it invalidates the access
> tokens already in flight, since those were minted without the claims — a window of one
> access-token lifetime, which clients close by refreshing. An empty string reads as unconfigured
> rather than as "require the empty issuer", so an unset environment variable cannot turn the
> check on by accident.

> **Rotating the signing secret.** `jwt.previousSecrets` lists secrets retired by a rotation,
> accepted for verification only. Without it, changing `jwt.secret` signs every user out the
> moment the new configuration rolls out **and** invalidates every stored recovery-code digest —
> those are keyed by an HMAC derived from the secret, so users lose the codes they printed and
> filed. With it, both keep working while tokens issued under the old secret drain, and a
> rotation becomes a rollout. Remove the entry once the longest-lived token signed under it has
> expired: every entry is a key that still opens the door. `mfa.encryptionKey` rotates the same
> way, through its own list — see below.

> [!TIP]
> **Rotating the MFA encryption key.** `mfa.previousEncryptionKeys` lists AES-256 keys retired by
> a rotation of `mfa.encryptionKey`. The stored ciphertext carries no key identifier, so without
> the list a change of key makes every enrolled user's TOTP secret undecryptable at once, with no
> way back — their authenticator simply stops matching. With it, a stored secret that opened
> under a retired key is **re-encrypted under the current one** on the next successful challenge,
> so the rotation drains on its own instead of requiring the retired key to stay configured
> forever. Each entry is validated at startup exactly like the current key (base64, exactly 32
> bytes, and never equal to the current key or to another entry), because a malformed one would
> otherwise surface at a user's first challenge rather than at boot. Drop the entry once your
> enrolled users have had time to authenticate at least once.

> [!IMPORTANT]
> **The parameters that carry a control's strength are bounded at startup.** `mfa.totpWindow`
> must be `0..=10`: the window counts 30-second steps on _either_ side of now, so `2n + 1`
> codes are valid at once — three at the default of 1, but 121 at 60, which makes a six-digit
> code a hundred times easier to guess while the configuration still reads as "MFA enabled".
> `mfa.recoveryCodeCount` must be `1..=50`, because zero enrols an account with no way back
> if the authenticator is lost. `password.blockSize` must be at least 8 and
> `password.parallelization` at least 1: scrypt's memory cost is `128 * N * r`, so a smaller
> block size divides the hardness that `password.costFactor`'s floor exists to guarantee —
> invisibly, since the bounded parameter is still intact. `rust-auth` enforces the identical
> ranges.

> [!IMPORTANT]
> `jwt.accessExpiresIn` must not exceed **30 days**, the window the store keeps a bumped token
> epoch readable. The epoch is what makes a stateless access token revocable: a password reset
> advances it and every token stamped below it stops verifying — but only while the bumped value
> is still there. A longer-lived access token would outlive it, the lookup would fall back to
> `0`, and a token the reset revoked would verify again. Startup refuses the configuration
> rather than letting it fail open, and rejects an unreadable time span or a non-positive
> lifetime on the same pass.

> [!WARNING]
> **Do not gate on the access token's `status` claim.** It is **point-in-time, never
> authoritative**, and which of its three states you get depends on things a client cannot see:
>
> | how the token was minted                                                   | `status`                                                                                  |
> | -------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
> | login, register, OAuth, MFA challenge                                      | the account's value **at that moment**                                                    |
> | an ordinary refresh rotation                                               | **empty string** — the session record carries no live status, so there is nothing to copy |
> | a refresh that re-signs because `role`, `tenantId` or `mfaEnabled` changed | the account's value **at that moment**, read during that request                          |
>
> `rust-auth` stamps the same empty string on its rotation path, deliberately and with a test
> pinning it, so the middle row is a shared contract rather than a defect in either library.
>
> Every populated value is stale the instant the account changes, because status can change under
> an unexpired token and nothing re-stamps it. So a route that reads the claim is wrong in **both**
> directions: `status !== 'active'` refuses everyone whose session has been refreshed ordinarily,
> and `status === 'suspended'` refuses nobody, ever. Both fail quietly and hours from the code
> that caused them — the first looks like a broken login, the second like nothing at all.
>
> The exceptional re-stamp is the worst of the three for a reader, not the best: it makes the
> claim _usually_ wrong instead of _reliably_ empty, which is the failure mode that survives
> testing.
>
> Status is resolved per request or not at all: mount `UserStatusGuard` on the route, and for
> anything richer read the account **tenant-scoped**, the way that guard does —
> `findById(request.user.sub, request.user.tenantId)`. The tenant argument is not optional in
> practice: ids may collide across tenants, and `findById` accepts an absent tenant only for
> flows that are deliberately cross-tenant, so dropping it here can resolve another tenant's
> account. That is what the library's own guards do, which
> is why the claim can be left as it is. `mfaVerified` behaves the same way and for the same
> reason — it is always `false` after a rotation, so step-up does not survive a refresh and a
> user re-acquires it through the MFA challenge.
>
> One consequence worth planning for: the guard reads a status cache with a
> `userStatusCacheTtlSeconds` window (default **60**), so a suspension takes up to that long to
> bite on a guarded route, and a reactivation the same to restore. Nothing exported invalidates
> that key for one user today — the only immediate lever is `bumpUserTokenEpoch`, which ends
> every session the user has rather than refreshing one cached string. Lower the TTL if a faster
> answer matters more than the repository reads it costs.

`jwt.absoluteSessionLifetimeDays` caps how long one login can be extended by rotation, and is
**on by default at 30 days** — NIST SP 800-63B-4 §3 makes a definite reauthentication timeout a
SHALL and puts it at no more than 30 days for AAL1. Without a cap, a client refreshing every
fifteen minutes keeps a session alive forever, and a refresh token stolen once becomes permanent
access. Raise it to a value the product can justify, or set `0` to accept unbounded sessions
deliberately.

Lowering the value ends sessions that are already older than the new one, at their next rotation;
raising it or setting `0` ends nothing. Sessions established before the cap existed carry no
recorded birth time and are never capped, whatever the value — they age out under
`refreshExpiresInDays` like any other.

`cookies.trustedOrigins` is deliberately off by default, because switching it on changes
behaviour for origins that already exist. It is required as soon as `cookies.sameSite: 'none'`
is set, and refused otherwise — that posture is the only one where the browser sends the session
cookie cross-site, and it is the only one where the origin check has anything to authorize.

The breach check is opt-in for a different reason: it is the only part of the credential path
that reaches the network, and a library should not start talking to a third party because it was
upgraded. Wire it explicitly:

```typescript
BymaxAuthModule.registerAsync({
  useFactory: () => ({ ... }),
  extraProviders: [{ provide: BYMAX_AUTH_BREACH_CHECKER, useClass: HibpBreachChecker }]
})
```

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

| Principle                  | Description                                                                                                                                  |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| **🔌 Interface-Driven**    | Define contracts, inject implementations — works with Prisma, TypeORM, Drizzle, or any SQL ORM                                               |
| **🔒 Secure by Default**   | scrypt hashing, HttpOnly cookies, JWT blacklisting, brute-force protection — all enabled out of the box                                      |
| **🪶 Zero Runtime Deps**   | `"dependencies": {}` — adds no runtime deps of its own; crypto is native `node:crypto`. Required peers (NestJS, ioredis…) come from your app |
| **🌳 Tree-Shakeable**      | `sideEffects: false`, subpath exports, ESM + CJS dual output                                                                                 |
| **⚡ Conditional Loading** | Unconfigured features don't register — no wasted memory or startup time                                                                      |

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
- HttpOnly cookies; `Secure` enforced in production; `SameSite=Lax` by default on every auth
  cookie, so the OAuth provider's cross-site redirect back to your app still carries them.
  Deployments that do not need that redirect can take the stricter posture with
  `cookies.sameSite: 'strict'`. CSRF does not rest on this setting — `TrustedOriginGuard` is
  applied to every controller and runs before authentication.

**The tokens are never readable from JavaScript, and verifying that end-to-end is yours.** Under
cookie delivery this library never writes a token to `localStorage`, `sessionStorage`, or a
JS-readable cookie: `access_token` and `refresh_token` are `HttpOnly`, and the only readable
cookie is `has_session=1`, a hint carrying no credential so a SPA can tell a session probably
exists without touching a token.

This library's suite asserts **its half** — that the `Set-Cookie` headers carry those flags — and
it structurally cannot assert the other half. A token leaking into JS-readable storage is
invisible from the server: the API answers identically, the wire looks correct, and every test
here passes. Only a browser observes it. **If you run a browser suite, assert there that
`localStorage` and `sessionStorage` are empty and that `document.cookie` carries neither token**;
it is the one guarantee cookie delivery exists for and the one no server-side test can reach.

---

## 🛡️ Security Table

| Layer              | Implementation                                                                                         |
| ------------------ | ------------------------------------------------------------------------------------------------------ |
| Password Hashing   | `node:crypto` scrypt (N=2¹⁷, r=8, p=1, keyLen=64) — OWASP's recommended minimum                        |
| MFA Encryption     | AES-256-GCM with 12-byte random IV per call                                                            |
| TOTP               | HMAC-SHA1 per RFC 4226/6238, ±1 step window                                                            |
| Token Generation   | `crypto.randomBytes(32)` — 256 bits of entropy                                                         |
| Secret Comparison  | `crypto.timingSafeEqual` (constant-time)                                                               |
| JWT                | HS256 via `@nestjs/jwt`, JTI blacklist via Redis                                                       |
| Cookies            | HttpOnly, Secure, SameSite=Lax (override to `strict`), path-scoped                                     |
| Brute-Force        | Redis atomic counters per HMAC(email, jwt.secret)                                                      |
| CSRF (OAuth)       | 64-char hex state nonce, single-use via `getdel()`                                                     |
| Refresh Rotation   | Single-use tokens with a grace window; a replay past it revokes that login's whole family lineage      |
| Cross-Site Writes  | `Origin` / `Sec-Fetch-Site` check on cookie-authenticated writes — the gap `SameSite=None` leaves open |
| Breached Passwords | Optional Have I Been Pwned range check by k-anonymity; only a 5-char SHA-1 prefix leaves the process   |
| Rate Limiting      | Per-IP fixed-window counters in Redis, keyed by `HMAC(ip)` — enforced by the library, not by the host  |
| Session Lifetime   | Optional absolute cap on how long one login can be extended by rotation                                |

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

## 🧪 Testing & Quality

Authentication is critical infrastructure, so the suite is held to a bar beyond "it runs" — every behavior is pinned so that a regression **fails a test**.

- ✅ **100% line coverage** — statements, branches, functions, and lines, enforced as a release gate across unit + e2e
- ✅ **100% mutation score** — verified with [Stryker](https://stryker-mutator.io/): 5,333 seeded faults detected (5,311 killed, 22 timed out), **no survivors and nothing left uncovered**, against a `break` threshold of 100 ([measured cold on 2026-08-15](./docs/mutation_testing_results.md#re-measured-cold--2026-08-15))
- ✅ **3,971 tests** — 3,721 unit and 250 end-to-end, spanning all five subpaths
- ✅ **Every equivalent mutant documented** — the 367 mutants that no test can kill (a redundant guard, a dependency array of stable references) each carry an inline `// Stryker disable` with the reason, so the score is an accounting rather than a number

```bash
pnpm test          # unit suite
pnpm test:cov:all  # unit + e2e, 100% coverage gate
pnpm mutation      # Stryker mutation testing
```

> [!NOTE]
> Line coverage proves a line _executed_ under test; mutation testing proves a test _would fail_ if that line were wrong. The full methodology and per-area breakdown are in [docs/mutation_testing_results.md](./docs/mutation_testing_results.md).

---

## 📖 API Reference

### HTTP Endpoints

Conditionally registered controllers (mfa, sessions, platform, invitations, oauth, password-reset) only mount their endpoints when the corresponding feature is enabled in `BymaxAuthModule.registerAsync()`.

| Method | Path                           | Auth / Guard                       | Description                                                 |
| ------ | ------------------------------ | ---------------------------------- | ----------------------------------------------------------- |
| POST   | `/register`                    | Public                             | Register a new dashboard user and issue tokens              |
| POST   | `/login`                       | Public                             | Authenticate with email/password (may return MFA challenge) |
| POST   | `/logout`                      | Public (reads both credentials)    | Revoke the session; blacklists the access token it is given |
| POST   | `/refresh`                     | Public (refresh cookie or body)    | Rotate refresh token, issue new access token                |
| GET    | `/me`                          | `JwtAuthGuard`                     | Current dashboard user payload                              |
| POST   | `/ws-ticket`                   | `JwtAuthGuard`                     | Mint a single-use ticket for a WebSocket upgrade            |
| POST   | `/verify-email`                | Public                             | Verify email with OTP                                       |
| POST   | `/resend-verification`         | Public                             | Resend email-verification OTP                               |
| POST   | `/password/forgot-password`    | Public                             | Request password reset (token or OTP)                       |
| POST   | `/password/reset-password`     | Public                             | Submit new password with reset token                        |
| POST   | `/password/verify-otp`         | Public                             | Verify password-reset OTP                                   |
| POST   | `/password/resend-otp`         | Public                             | Resend password-reset OTP                                   |
| POST   | `/mfa/setup`                   | `JwtAuthGuard`                     | Generate TOTP secret and recovery codes                     |
| POST   | `/mfa/verify-enable`           | `JwtAuthGuard`                     | Confirm setup and enable MFA                                |
| POST   | `/mfa/challenge`               | Public + `@SkipMfa()`              | Submit TOTP/recovery code after login                       |
| POST   | `/mfa/disable`                 | `JwtAuthGuard`                     | Disable MFA for the current user                            |
| POST   | `/mfa/recovery-codes`          | `JwtAuthGuard`                     | Replace the recovery codes, proving a fresh OTP             |
| GET    | `/sessions`                    | `JwtAuthGuard`, `UserStatusGuard`  | List active sessions for the current user                   |
| POST   | `/sessions/revoke-all`         | `JwtAuthGuard`, `UserStatusGuard`  | Revoke every session except the caller's                    |
| DELETE | `/sessions/:id`                | `JwtAuthGuard`, `UserStatusGuard`  | Revoke a specific session                                   |
| POST   | `/invitations`                 | `JwtAuthGuard`, `UserStatusGuard`  | Create a tenant invitation                                  |
| POST   | `/invitations/accept`          | Public                             | Accept an invitation and create the user                    |
| POST   | `/invitations/revoke`          | `JwtAuthGuard`, `UserStatusGuard`  | Withdraw a pending invitation                               |
| POST   | `/email/change`                | `JwtAuthGuard`, `UserStatusGuard`  | Request an address change (re-proves the current password)  |
| POST   | `/email/change/confirm`        | Public                             | Confirm it with the token mailed to the new address         |
| POST   | `/platform/login`              | Public                             | Platform admin login (separate token context)               |
| POST   | `/platform/mfa/challenge`      | Public                             | Platform admin MFA challenge                                |
| GET    | `/platform/me`                 | `JwtPlatformGuard`                 | Current platform admin payload                              |
| POST   | `/platform/logout`             | Public (refresh token in body)     | Revoke the session; blacklists the access token it is given |
| POST   | `/platform/refresh`            | Public (refresh token in body)     | Rotate the platform refresh token                           |
| DELETE | `/platform/sessions`           | `JwtPlatformGuard`                 | Revoke all platform sessions                                |
| POST   | `/platform/mfa/setup`          | `JwtPlatformGuard`                 | Generate the admin's TOTP secret and recovery codes         |
| POST   | `/platform/mfa/verify-enable`  | `JwtPlatformGuard`                 | Confirm setup and enable MFA for the admin                  |
| POST   | `/platform/mfa/disable`        | `JwtPlatformGuard`                 | Disable the admin's MFA, proving a fresh OTP                |
| POST   | `/platform/mfa/recovery-codes` | `JwtPlatformGuard`                 | Replace the admin's recovery codes                          |
| POST   | `/password/change`             | `JwtAuthGuard` + `UserStatusGuard` | Change the password, proving the current one                |
| GET    | `/oauth/:provider`             | Public + `@SkipMfa()`              | Initiate OAuth authorization redirect                       |
| GET    | `/oauth/:provider/callback`    | Public + `@SkipMfa()`              | Handle OAuth callback, exchange code, issue tokens          |

> **The platform plane never uses a refresh cookie.** `extractPlatformRefreshToken` reads
> `req.body.refreshToken` in every `tokenDelivery` mode, and the access token is always the
> `Authorization` header — so a consumer sending platform credentials as cookies is sending
> something the server does not read. `platform/logout` and `platform/refresh` are `@Public()`
> for the same reason their dashboard twins are: an operator whose fifteen-minute access token
> expired must still be able to end the session, or the seven-day refresh session of the
> highest-privilege identity in the system outlives the console they walked away from. Both
> still READ the access token when one is sent, and `logout` blacklists its `jti`.

> **The OAuth routes require `cookie-parser`.** `GET /oauth/:provider` plants an HttpOnly
> `oauth_state` cookie carrying the flow's `state`, and the callback refuses any request that
> does not send it back — the binding RFC 6749 §10.12 requires, without which an attacker can
> hand a victim a callback URL and have the victim's browser complete the attacker's login.
> Mount `app.use(cookieParser())` before the module's routes or every callback answers 401.

### Request bodies

Validated by `createAuthValidationPipe()` with `whitelist` and `forbidNonWhitelisted`, so an
unknown property is a `400 auth.validation` rather than a silently ignored field. `tenantId` is
optional on every **unauthenticated** body below (≤128 chars, no control characters) and scopes
the operation to one organization. `POST /password/change` is the exception: it is behind
`JwtAuthGuard`, takes its tenant from the JWT, and declares no `tenantId` — so sending one is an
unknown property, and `forbidNonWhitelisted` answers `400 auth.validation`. That same rule is why
it **declares** `refreshToken`: an undeclared field would be refused rather than read. Email
fields are trimmed and lowercased before they reach the service, so the stored identity matches
the case-insensitive lookup and every email-keyed control.

`refreshToken` is **optional, and both answers are valid requests.** Send it and the device making
the change stays signed in; omit it and every session ends — which is the right answer when you are
rotating a credential you believe was stolen. Where the server looks for it follows
`tokenDelivery`: the refresh cookie under `'cookie'`, this body field under `'bearer'`, and the
cookie first then this field under `'both'` — so a `'both'` caller with no refresh cookie must send
it here to keep its session.

| Endpoint                         | Body                                                                             |
| -------------------------------- | -------------------------------------------------------------------------------- |
| `POST /register`                 | `{ email, password, name }` — `name` 2–128                                       |
| `POST /login`                    | `{ email, password }`                                                            |
| `POST /verify-email`             | `{ email, otp }` — `otp` is **exactly 6 digits**                                 |
| `POST /resend-verification`      | `{ email }`                                                                      |
| `POST /password/forgot-password` | `{ email }`                                                                      |
| `POST /password/verify-otp`      | `{ email, otp }`                                                                 |
| `POST /password/resend-otp`      | `{ email }`                                                                      |
| `POST /password/reset-password`  | `{ email, newPassword }` **plus exactly one** of `token`, `otp`, `verifiedToken` |
| `POST /password/change`          | `{ currentPassword, newPassword }` — optional `refreshToken`, see below          |

Three constraints are worth stating because they are not visible from the field names:

- **`reset-password` carries exactly one proof.** `token` is the emailed URL parameter, `otp` the
  emailed 4–8 character code, and `verifiedToken` the 64-character handle `POST
/password/verify-otp` returns (5-minute TTL) so the OTP need not be re-submitted. All three are
  optional at the validation boundary and the mutual exclusivity is enforced in the service — a
  body carrying none or more than one is rejected there, not by the DTO.
- **The password length the DTO enforces is not your policy.** `@MinLength(8)` is structural: it
  is the floor NIST SP 800-63B-4 §3.1.1.1 permits under any circumstance, and it is what a
  decorator can express, since decorators evaluate before any configuration exists. The real
  floor is `password.minLength` — **default 15** — enforced by `PasswordService`, which answers
  the same `auth.validation` code and `details` shape. A client that validates against 8 will see
  a `400` from the service.
- **`login` deliberately floors `password` at 1 character.** Rejecting only the empty string
  stops a caller from spending a full scrypt derivation for free; enforcing the configured policy
  length here would leak it as a pre-KDF timing signal, because a request failing validation
  returns before the hash runs.

#### On `@bymax-one/nest-core`, the security posture writes itself

A deployment that builds its OpenAPI document with `@bymax-one/nest-core` **1.4.0 or later** gets
this library's operations described automatically — which schemes exist, which operation requires
which, and which are reachable unauthenticated. Nothing to enable and nothing to import: the
module registers a contributor, nest-core discovers it while building the document, and the
fragments are merged.

It has to be derived at your boot rather than shipped as a static file, because the answer
depends on your configuration:

| your options                   | what the document says                                                                                                                                                                                                                                                                                                           |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tokenDelivery: 'cookie'`      | `bymaxAuthAccessCookie` and `bymaxAuthRefreshCookie`, **carrying your cookie names**                                                                                                                                                                                                                                             |
| `tokenDelivery: 'bearer'`      | `bymaxAuthAccessBearer` only — no refresh scheme exists, and `logout`/`refresh` instead carry a documented `{ refreshToken }` body                                                                                                                                                                                               |
| `tokenDelivery: 'both'`        | both access schemes as **alternatives** (`security: [{cookie}, {bearer}]`, which OpenAPI reads as OR)                                                                                                                                                                                                                            |
| `controllers.platform: true`   | `bymaxPlatformAccessBearer` — always bearer, in every mode, because platform credentials are read from the header whatever `tokenDelivery` says. The **registration** switch decides, not `platform.enabled`: the module mounts the platform controllers on `controllers.platform` and validates the `platform` config only then |
| a controller you did not mount | nothing at all: no operation, and no scheme only it would have referenced                                                                                                                                                                                                                                                        |

A scheme the resolved options cannot satisfy is **absent**, never defined-and-unreferenced — a
document that defines a credential the server will not read tells a generated client to offer it.

The four names — `bymaxAuthAccessCookie`, `bymaxAuthAccessBearer`, `bymaxAuthRefreshCookie`,
`bymaxPlatformAccessBearer` — are stable identifiers. Renaming one is a break a generated client
feels, so they will not change; their **definitions** are config-derived.

> **This package does not depend on `@bymax-one/nest-core`** — not as a dependency, a peer, or a
> devDependency. The contract revision is inlined, the discovery marker is the documented string
> literal, and a gate fails the build if any file here imports another Bymax library. That keeps
> your install graph free of a package you may not use, and it moves one check to your side:
>
> ```typescript
> // in your suite, where both packages are installed at the versions you run
> import {
>   BYMAX_OPENAPI_CONTRACT_VERSION,
>   BYMAX_OPENAPI_CONTRIBUTOR_METADATA
> } from '@bymax-one/nest-core/openapi'
>
> expect(fragment.contractVersion).toBe(BYMAX_OPENAPI_CONTRACT_VERSION)
> expect(Reflect.getMetadata(BYMAX_OPENAPI_CONTRIBUTOR_METADATA, contributor.constructor)).toBe(
>   true
> )
> ```
>
> Worth writing once. A revision mismatch fails your document build loudly and names the
> contributor, but a **marker** mismatch is silent: the provider is simply never discovered and
> the document renders without the fragments — the same symptom as running nest-core < 1.4.0.

> **On nest-core older than 1.4.0 the fragments are silently ignored.** There is no contributor
> lane to discover them, so the document renders exactly as before — no error, no warning, no
> failed boot. If you add a document and the auth schemes do not appear, check in this order:
> whether this library is new enough to contribute them at all, and only then your nest-core
> version. The two states look identical from the document.

**If you already wrote these by hand, delete them** — not because they are wrong. They are what
makes your document correct today; the deletion is what hands the job to the library, and it is
needed precisely because they were doing it. Precedence, read from nest-core's
`augmentOperation` rather than summarised: the generated operation's own `security` outranks
everything, then your `openapi.operationSecurity` override, then this library's fragment, then
nest-core's policy. So a stale scheme name or an override for an auth route keeps winning and the
contributed one never lands — the document goes on describing whatever you wrote when you wrote
it, including cookie names you have since changed.

> **Delete the entries for THESE routes. Keep your document-level `security`.** They are usually
> written in the same options block, and taking the block out is the failure this warning exists
> for — reported by a consumer who ran the comparison below and found their document **more wrong
> after adopting than before**. The mechanism is in `augmentOperation`: an operation with no
> requirement of its own, no override and no fragment falls through to `ownRouteSecurity`, which
> answers `undefined` for anything that is not a health or metrics route — so **your** guarded
> routes carry no requirement and inherit the document default. Remove that default and every
> route this library does not describe reads as needing no credential. The health probes lose
> their explicit `[]` in the same move: `ownRouteSecurity` only returns it when
> `openapi.security.length > 0`.
>
> **On nest-core below 1.5.0, nothing reports this.** No error, no unmatched key, no failing
> build — the document simply stops asking for credentials on the routes the library never knew
> about, which are the ones your backend owns. **nest-core 1.5.0 warns**, on exactly this shape:
> a document with no top-level `security` where some other operation does state a requirement, so
> the bare ones are bare against a described posture rather than in a document that describes
> none. It names the operations and never throws. That makes the failure visible, not impossible —
> a warning in a build log is still something a person has to read.
>
> Keep the default, and **derive it from your `tokenDelivery` rather than writing a literal**. The
> derivation is not style. Take a default written as `[{ bymaxAuthAccessCookie: [] }]`, which is
> correct under `cookie`, and read what the other two modes do with it:
>
> | mode     | this contributor declares         | that literal default                                        |
> | -------- | --------------------------------- | ----------------------------------------------------------- |
> | `cookie` | the cookie scheme only            | correct                                                     |
> | `both`   | the cookie **and** bearer schemes | resolves, but describes only one of the two channels        |
> | `bearer` | no cookie scheme at all           | names an undeclared scheme — `assertSchemesDeclared` throws |
>
> **The two wrong outcomes are not the same failure, and the difference is the point.** Under
> `bearer` the scheme does not exist, so nest-core's `assertSchemesDeclared` **throws** and the
> document never builds — loud, immediate, impossible to ship. Under `both` the scheme does exist,
> so nothing throws; the default is merely **incomplete**, telling a reader that your own routes
> take a cookie when they equally accept a bearer token. That one is quiet, and it is the same
> class of quiet as the bug this whole note is about. A literal written against a bearer-only
> deployment inverts the table and fails under `cookie` for the same reasons.
>
> So the advice that fixes a silently wrong document can introduce a loud broken one **or a second
> quiet one**, depending on which mode you land in. Read the mode you configured and name the
> schemes that mode actually defines — deriving from the same input the contributor reads is right
> in all three, once, instead of correct in one and checked forever.
>
> The default is what covers your routes, and it cannot disturb this library's: a per-operation
> requirement outranks a document-level one, and every operation the contributor describes carries
> its own.
>
> **What an empty `{}` alternative says, and where this library uses it as an approximation.**
> In OpenAPI it means one thing: authentication is **optional** for that operation — a caller
> presenting none of the named schemes is valid. Tooling reads it as anonymous access and infers
> nothing about a request body from it.
>
> On `logout` that is exactly right, in **every** delivery mode including `cookie`: the operation
> really does answer a caller who presents nothing, which is why a user whose access token
> expired can still sign out. How many alternatives you see depends on the mode, since each one
> is a combination of the credentials that mode actually has:
>
> | operation         | `cookie` | `bearer` | `both` |
> | ----------------- | -------- | -------- | ------ |
> | `logout`          | 4        | 2        | 6      |
> | `password/change` | 2        | 1        | 4      |
>
> On `refresh` under `tokenDelivery: 'both'` it is an **approximation, and a permissive one**.
> That operation refuses a caller with no credential at all; the token may simply arrive in the
> request body, which `security` has no vocabulary for. The empty entry is what lets the document
> describe the body-only caller, and the cost is that it also tells tooling anonymous access is
> acceptable when it is not.
>
> The `requestBody` beside it **documents the body channel; it does not carry the requirement**.
> Under `'both'` it is `required: false` and its schema does not list `refreshToken` as required,
> because either channel satisfies the server and a body that omits the token is valid when the
> cookie carries it. So the document as a whole permits a request with neither, and the server
> refuses that request. **OpenAPI cannot express "one of these two channels" across a security
> requirement and a request body**, and this is the shape of that limitation rather than an
> oversight. Under `'bearer'`, where the cookie does not exist, the body becomes required at both
> levels and the document is exact.
>
> Written out because two earlier versions of this note were wrong in opposite directions: one
> called `{}` "a credential this member cannot model", which is the intent rather than the
> notation; the other claimed the `requestBody` carried the requirement, which it does not.
>
> **Verify with a diff, not by reasoning.** Render the document with the contributor active and
> again with your entries in place, and compare only the operations you mount. The consumer who
> did this found their own three differences were improvements — a configured cookie name over
> the exported default, `logout` gaining the access-only and refresh-only alternatives their map
> called unsatisfiable — and one regression that no status-code probe could have surfaced,
> because the routes it broke still answered correctly at runtime.
>
> **And there is one shape nothing can warn you about, so the diff is the only check that
> covers it.** If you remove _every_ requirement at once — no library describing anything, no
> decorator, no override, no document default — what remains is indistinguishable from the
> document of an API that is public on purpose. Both are a set of operations that ask for
> nothing. No tool can separate the two without also shouting at every genuinely public API,
> which is how a warning earns the right to be ignored. This is why nest-core's warning requires
> that _some_ operation still state a requirement: the gap is deliberate, not an omission, and no
> version closes it. Render the document twice and compare; it is the one step that does not
> depend on somebody having anticipated your case.

**That chain is about `security` alone, and the other members run the opposite rule** — worth
stating because generalising either one produces a wrong belief about the other. There is no
configuration channel for a `description`, a `summary` or a tag: `mergeFragment` merges the
scanned operation **over** the fragment, so a contributed member lands unless the handler itself
declared that member, and the handler is this library's. Concretely, the `description` on
`logout` cannot be shadowed by anything in your options — only by an `@ApiOperation` on a handler
you do not own. Nothing to delete for that half; the deletion above is entirely about `security`.

> **Your own document test will not catch this.** A consumer seat measured it on their own
> repository: ten `operationSecurity` entries, all for this library's routes, and a suite
> asserting the operation-to-posture map with `toEqual`. On adoption, every contributed fragment
> loses to those entries, the old scheme names survive — and the suite stays **green**, because
> it is asserting the old answer that is still being served. A test that pins your document
> confirms the staleness rather than finding it. The deletion is the step; nothing downstream
> will remind you.

Do it as one change: delete the literals, update whatever pins your document to the four-name
vocabulary, rebuild it, and regenerate any typed client — the operation ids do not move, but the
scheme names and the per-operation requirements do.

#### Machine-readable schemas

The same contracts are published as data in
[`conformance/openapi-request-schemas.json`](./conformance/openapi-request-schemas.json) —
OpenAPI 3.0 schemas for all 22 DTOs, generated from the decorators themselves and regenerated by
`pnpm gen:openapi-schemas`. Alongside it,
[`openapi-request-descriptions.json`](./conformance/openapi-request-descriptions.json) carries the
facts no keyword expresses: the twelve e-mail fields that are **trimmed and lowercased before
validation**, each entry shipping the probe that verifies its own sentence.

A third file,
[`openapi-declared-structures.json`](./conformance/openapi-declared-structures.json), carries the
contracts the generated header names and no decorator can express — as **structure**, not prose:

| Declared                                                                                                         | As                                                                  |
| ---------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `reset-password` takes exactly one of `token`, `otp`, `verifiedToken`                                            | `oneOf`                                                             |
| An OAuth callback with neither `code` nor `error` is the **handler's** refusal, not the pipe's                   | probes the pipe accepts and the handler answers `auth.oauth_failed` |
| The 8-character floor is structural, not your policy                                                             | probes showing the pipe accepting what the deployment refuses       |
| `forgot-password`, `resend-otp`, `resend-verification`, `verify-email` answer identically for an unknown address | probes asserting the two responses are **equal**                    |

Three rules keep it honest. Only `required`, `oneOf` and `anyOf` may appear — `allOf` and `not`
are valid OpenAPI 3.0 and are **refused at load**, because a keyword nothing evaluates publishes
a claim nothing checks. Every entry carries probes, and both suites run them: the unit suite
evaluates each body against its own structure and reads what the pipe answers, the e2e suite
answers the rest with a real application. An entry whose two layers disagree — the pipe accepting
what the handler or the service then refuses — is split across the two suites on purpose, because
neither can see the pair. And presence means _present and not `null`_ — this
server's rule rather than JSON Schema's, because `@IsOptional()` treats `null` as absent, so a
body sending `null` and one omitting the key are the same request.

A structure is a **necessary** condition, never a sufficient one, and `reset-password` shows why:
which of the three proofs is eligible depends on `passwordReset.method`, and an ineligible proof
is refused with the same code a structural violation gets. That narrowing is declared with its
own probes and is deliberately not something a client can generate against.

All three are development artifacts — they are not in the published tarball, and nothing reads
them at runtime yet. They exist so the schemas are a function of the decorators rather than a
second description maintained by hand, and so the same file can be asserted from `rust-auth`.

### Administrative operations — methods, deliberately not routes

Two support-desk operations ship as **methods with no HTTP route**. Every route above is scoped
to the caller's own account, and both of these act on somebody else's — so exposing them would
mean inventing an authorization model ("who is an admin?") that this library does not have and
your application already does. Call them from your own admin surface, where the caller is
already authorized.

| Method                                     | Answers                                             |
| ------------------------------------------ | --------------------------------------------------- |
| `AuthService.unlockAccount(email, tenant)` | "I am locked out and I need in now"                 |
| `MfaService.resetMfa(userId, context?)`    | "I lost my authenticator **and** my recovery codes" |

**`unlockAccount`** clears the brute-force lockout. It grants no access: the password, the
status gate, the verification gate and MFA all still apply — it restores the ability to _try_.
It exists because the counter is keyed by an HMAC under the library's own `hmacKey`, which no
consumer can derive, so until it existed a lockout could only be waited out. It is also the
lever an attacker pulls to deny service to one specific account, which makes undoing it part of
the defence. Idempotent.

**`resetMfa`** removes a second factor without one. Every self-service exit needs the factor
itself — `disable` wants a valid TOTP code, the recovery codes want the codes — so a user who
has lost both is locked out permanently by the control meant to protect them (ASVS v5 §6.1.1
asks for this path for exactly that reason). It invalidates every session and bumps the token
epoch, so access tokens carrying `mfaVerified: true` die with the factor; it **notifies the
account holder** through the same channel a self-service disable uses; and it logs at `warn`
under its own prefix. The notification is not optional: an administrative reset the owner
cannot see is an account-takeover path, and it is what makes the event detectable and
disputable. Idempotent; throws for an id that resolves to nobody, so a typo cannot read as
"done".

> `MfaService` is only registered when `controllers.mfa` or `controllers.platform` is on —
> otherwise add it to `extraProviders` to inject it.

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

### One error envelope

Every failure the module raises answers with the same body, so a client parses `error.code` and
nothing else:

```json
{ "error": { "code": "auth.invalid_credentials", "message": "…", "details": null } }
```

That includes malformed requests: the controllers mount `createAuthValidationPipe()`, which
answers `auth.validation` with the offending fields under `error.details` as
`[{ "field": "email", "message": "…" }]` rather than the framework's own shape.

Failures the module did **not** raise are the application's to answer, so nothing is imposed on
them by default. Register the optional filter to bring them into the same envelope:

```typescript
app.useGlobalFilters(new AuthExceptionFilter())
```

It passes an `AuthException` through untouched, keeps the status any other `HttpException`
chose, and answers an unhandled throw with `auth.internal` and a generic message — never the
thrown one.

> **Do not register it on a `@bymax-one/nest-core` application.** The two filters are mutually
> exclusive and this one wins: `useGlobalFilters` binds ahead of an `APP_FILTER` provider, and
> `@Catch()` with no argument catches everything, so nest-core's envelope filter never runs.
> Measured — the same request answers `{ error: { code, message, details } }` with this filter
> registered and the flat `{ statusCode, code, message, timestamp, path, details }` without it.
> Registering both therefore **loses** `statusCode`, `timestamp`, `path` and the correlation id,
> which is the opposite of what adding a filter looks like it should do.
>
> On nest-core, take theirs: it already recognises this library's envelope and passes the code,
> message and per-field details through unchanged. The symptom of getting it wrong is a body
> nested under `error` where the rest of your application answers flat.
>
> **This library does not test the composition** — it would have to depend on nest-core to do so,
> and it depends on nothing. Assert it in your own suite: the code, the per-field details, and the
> flat fields (`statusCode`, `timestamp`, `path`) surviving a real request.

#### On a WebSocket, the envelope needs its own filter

`WsJwtGuard` throws the same `AuthException` every HTTP guard throws — and `AuthException`
extends `HttpException`, which Nest's **WebSocket** exception layer does not recognise. It
understands `WsException` and nothing else, so without a filter a refused socket client receives:

```json
{ "status": "error", "message": "Internal server error" }
```

The refusal itself is correct: the handler never runs. What is lost is everything the client
could act on. A reconnect policy cannot tell a dead credential from a crashed handler, and the
sensible default for an unknown error is to retry — so an expired token becomes a reconnect loop
against an endpoint that will refuse it forever.

> **Socket.IO only, measured.** `WsJwtGuard` reads both credential channels from the client's
> `handshake`, and only a Socket.IO client has one: with `@nestjs/platform-ws` the gateway
> receives the raw `ws` socket, which carries no `handshake` — and `ws` does not retain the
> upgrade request either, so there is nothing to read. Such a connection is **refused** with
> `auth.token_invalid` rather than crashing the socket, and the filter below delivers that
> refusal, but the guard cannot authenticate anyone on that adapter. Supporting it needs the
> gateway to stash the upgrade request in `handleConnection`, which is a contract this library
> does not have today.

Register the filter on any gateway that applies the guard:

```typescript
@UseFilters(new WsAuthExceptionFilter())
@UseGuards(WsJwtGuard)
@WebSocketGateway()
export class FeedGateway {}
```

```json
{ "status": "error", "error": { "code": "auth.token_invalid", "message": "...", "details": null } }
```

`status: 'error'` is kept — it is the field Nest itself sets and the one socket.io clients
already branch on — and the envelope is added beside it, so a client handling both shapes needs
no second listener. The `AuthException` travels whole, so a `details` payload survives.

The filter is scoped to `AuthException` on purpose. An argument-less `@Catch()` would claim
every exception the gateway raises, so a `WsException` an unrelated handler throws — a domain
error with its own contract — would be rewritten as an `auth.*` code, and following this README
would silently break errors a consumer already ships. Everything that is not this library's
refusal keeps travelling through Nest's own exception layer, untouched.

Both transports are answered. A Socket.IO client is dispatched to with `emit`; a native `ws`
client is written to with `send`, in the `{event, data}` envelope `@nestjs/platform-ws` uses for
every other message — emitting on one of those succeeds, dispatches a local event and sends the
peer nothing, which is the failure this ordering exists to prevent. Both paths are driven over a
real handshake in `test/e2e/ws-guard.e2e-spec.ts`.

#### The HTTP status belongs to the code

Every code answers exactly one status, and the status is derived from the code rather than
chosen at the throw site — `AuthException` takes no status argument. A client can switch on
`error.code` and the status line together and get the same answer from either implementation:
`@bymax-one/nest-auth` and `rust-auth` read the same table, pinned in
[`conformance/wire-contract.json`](./conformance/wire-contract.json) under
`errorCatalog.statuses` and asserted by both suites against that file.

| Status | Codes                                                                                                                                                                                                                                                             |
| -----: | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
|  `400` | `auth.validation` · `auth.password_compromised` · `auth.password_reset_token_invalid` · `auth.email_change_token_invalid` · `auth.invalid_invitation_token` · `auth.mfa_not_enabled` · `auth.mfa_setup_required`                                                  |
|  `401` | `auth.invalid_credentials` · `auth.token_invalid` · `auth.refresh_token_invalid` · `auth.mfa_invalid_code` · `auth.mfa_temp_token_invalid` · `auth.otp_invalid` · `auth.oauth_failed` · `auth.platform_auth_required`                                             |
|  `403` | `auth.account_inactive` · `auth.account_suspended` · `auth.account_banned` · `auth.pending_approval` · `auth.email_not_verified` · `auth.mfa_required` · `auth.insufficient_role` · `auth.forbidden` · `auth.untrusted_origin` · `auth.reauthentication_required` |
|  `404` | `auth.session_not_found`                                                                                                                                                                                                                                          |
|  `409` | `auth.email_already_exists` · `auth.mfa_already_enabled` · `auth.mfa_state_conflict` · `auth.oauth_email_mismatch`                                                                                                                                                |
|  `429` | `auth.account_locked` · `auth.too_many_requests`                                                                                                                                                                                                                  |
|  `500` | `auth.internal`                                                                                                                                                                                                                                                   |

`AUTH_ERROR_STATUS` is exported if you need the mapping at runtime — for a typed client, an
API document, or a test that asserts against it.

> **Assert your fixtures against the catalogue, not against string literals.** `AUTH_ERROR_CODES`
> is exported from `@bymax-one/nest-auth/shared` so a suite can check that every code it branches
> on is one the server can actually produce. A frontend seat found three invented codes this way —
> `auth.unauthorized` among them, which does not exist — and a branch on a code the server never
> sends is silent forever: it simply never runs, and the handler it replaces is the one that
> matters. The check is one test over your own source, and it is worth having standing rather than
> as a one-off audit.
>
> **Five codes are internal-only and never reach a client**: `auth.token_expired`,
> `auth.token_revoked`, `auth.token_missing` (all collapsed onto `auth.token_invalid`) and
> `auth.otp_expired`, `auth.otp_max_attempts` (onto `auth.otp_invalid`). Each says so in its own
> JSDoc. They are in the catalogue because both implementations share it and both use them
> internally for logs and control flow — branching on them client-side is the same dead branch as
> an invented code, for a subtler reason.

> **Anti-enumeration reads through the status too.** `POST /forgot-password` answers `200` and
> `POST /verify-email` / the resend endpoints answer `204` **whether or not the address exists**.
> A `200` there does not mean an email was sent, and treating it as confirmation re-introduces
> the account enumeration the endpoints exist to prevent. For the same reason the OTP failures
> collapse: a wrong code, a record that expired, and an exhausted attempt ceiling are one code
> (`auth.otp_invalid`) at one status (`401`) — a `429` on the ceiling would say the address was
> registered, since only a record that exists can reach one.

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

If you discover a security vulnerability, please **do not** open a public issue. Instead, email us at **support@bymax.one** with details. We take security seriously and will respond promptly.

---

## 📄 License

[MIT](./LICENSE) © [Bymax One](https://github.com/bymaxone)

---

<p align="center">
  <sub>Built with ❤️ by <a href="https://github.com/bymaxone">Bymax One</a></sub>
</p>
