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
- ✅ **Session Management** — Track active sessions with FIFO eviction and new-session alerts
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

  async sendInvitation(email: string, inviteData: InviteData, _locale?: string): Promise<void> {
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

---

## ⚙️ Configuration

All options are configurable via `registerAsync()`. Here are the key configuration groups:

| Group                 | Key Options                                                                                                                                         | Default                                 |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| **jwt**               | `secret` (required), `previousSecrets`, `accessExpiresIn`, `refreshExpiresInDays`, `absoluteSessionLifetimeDays`, `algorithm`, `issuer`, `audience` | `15m`, `7d`, off, `HS256`, both off     |
| **password**          | `costFactor`, `blockSize`, `parallelization`                                                                                                        | scrypt N=2¹⁷, r=8, p=1                  |
| **tokenDelivery**     | `'cookie'` \| `'bearer'` \| `'both'`                                                                                                                | `'cookie'`                              |
| **cookies**           | `accessTokenName`, `refreshTokenName`, `sessionSignalName`, `refreshCookiePath`, `sameSite`, `trustedOrigins`, `resolveDomains`                     | `'lax'`, `[]` (see cookie section)      |
| **mfa**               | `encryptionKey`, `previousEncryptionKeys`, `issuer`, `totpWindow`, `recoveryCodeCount`                                                              | —                                       |
| **sessions**          | `enabled`, `defaultMaxSessions`, `maxSessionsResolver`, `evictionStrategy`                                                                          | `false`, `5`, —, `'fifo'`               |
| **bruteForce**        | `maxAttempts`, `windowSeconds`                                                                                                                      | `5`, `900`                              |
| **rateLimit**         | `enabled`, `clientIpSource` (`'peer'` \| `'trusted-proxy'`) — per-IP limits over Redis                                                              | `true`, `'peer'`                        |
| **passwordReset**     | `method` (`'token'` \| `'otp'`), `otpLength`, `otpTtlSeconds`                                                                                       | `'token'`                               |
| **platform**          | `enabled`                                                                                                                                           | `false`                                 |
| **invitations**       | `enabled`, `tokenTtlSeconds`                                                                                                                        | `false`                                 |
| **roles**             | `hierarchy` (required), `platformHierarchy`                                                                                                         | —                                       |
| **oauth**             | `google: { clientId, clientSecret, callbackUrl }`                                                                                                   | —                                       |
| **emailVerification** | `required`, `otpTtlSeconds`                                                                                                                         | `true`, `600`                           |
| **password** (screen) | `blocklist` — extra words the default screen refuses, on top of the ones it ships                                                                   | `[]`                                    |
| **controllers**       | Toggle individual controllers on/off                                                                                                                | `auth`, `passwordReset` on; rest opt-in |

> [!NOTE]
> When a feature is not configured (e.g., `mfa`, `sessions`, `platform`), its controllers and services are **not registered** in the NestJS container — zero overhead.

> [!IMPORTANT]
> **`rateLimit.clientIpSource` defaults to `'peer'`** — the socket address, read from the
> connection and never from a forwarding header. Behind a proxy with Express's `trust proxy`
> set, `req.ip` is whatever the client wrote in `X-Forwarded-For` unless the hop count is
> configured exactly right, and an attacker who can pick their own key is not rate-limited at
> all. Keying on the peer address instead over-counts — every request behind one proxy shares a
> bucket — which is visible and recoverable. Switch to `'trusted-proxy'` once `trust proxy` is
> configured for your real hop count.

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

Two options are deliberately off by default because switching them on changes behaviour for
sessions and origins that already exist:

- `jwt.absoluteSessionLifetimeDays` caps how long one login can be extended by rotation. Without
  it, a client refreshing every fifteen minutes keeps a session alive forever.
- `cookies.trustedOrigins` is required as soon as `cookies.sameSite: 'none'` is set, and refused
  otherwise — that posture is the only one where the browser sends the session cookie
  cross-site, and it is the only one where the origin check has anything to authorize.

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
- HttpOnly cookies; `Secure` enforced in production; `SameSite=Strict` for refresh tokens

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
| Cookies            | HttpOnly, Secure, SameSite=Strict, path-scoped                                                         |
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
- ✅ **100% mutation score** — verified with [Stryker](https://stryker-mutator.io/): 3,474 seeded faults killed, **no survivors and nothing left uncovered**, against a `break` threshold of 95
- ✅ **2,458 tests** — unit and end-to-end, spanning all five subpaths
- ✅ **Every equivalent mutant documented** — the handful that no test can kill (a redundant guard, a dependency array of stable references) carries an inline `// Stryker disable` with the reason it cannot be killed, so the score is an accounting rather than a number

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

| Method | Path                        | Auth / Guard                       | Description                                                 |
| ------ | --------------------------- | ---------------------------------- | ----------------------------------------------------------- |
| POST   | `/register`                 | Public                             | Register a new dashboard user and issue tokens              |
| POST   | `/login`                    | Public                             | Authenticate with email/password (may return MFA challenge) |
| POST   | `/logout`                   | `JwtAuthGuard`                     | Revoke tokens and clear session                             |
| POST   | `/refresh`                  | Public (refresh cookie)            | Rotate refresh token, issue new access token                |
| GET    | `/me`                       | `JwtAuthGuard`                     | Current dashboard user payload                              |
| POST   | `/verify-email`             | Public                             | Verify email with OTP                                       |
| POST   | `/resend-verification`      | Public                             | Resend email-verification OTP                               |
| POST   | `/password/forgot-password` | Public                             | Request password reset (token or OTP)                       |
| POST   | `/password/reset-password`  | Public                             | Submit new password with reset token                        |
| POST   | `/password/verify-otp`      | Public                             | Verify password-reset OTP                                   |
| POST   | `/password/resend-otp`      | Public                             | Resend password-reset OTP                                   |
| POST   | `/mfa/setup`                | `JwtAuthGuard`                     | Generate TOTP secret and recovery codes                     |
| POST   | `/mfa/verify-enable`        | `JwtAuthGuard`                     | Confirm setup and enable MFA                                |
| POST   | `/mfa/challenge`            | Public + `@SkipMfa()`              | Submit TOTP/recovery code after login                       |
| POST   | `/mfa/disable`              | `JwtAuthGuard`                     | Disable MFA for the current user                            |
| GET    | `/sessions`                 | `JwtAuthGuard`, `UserStatusGuard`  | List active sessions for the current user                   |
| DELETE | `/sessions/all`             | `JwtAuthGuard`, `UserStatusGuard`  | Revoke all sessions                                         |
| DELETE | `/sessions/:id`             | `JwtAuthGuard`, `UserStatusGuard`  | Revoke a specific session                                   |
| POST   | `/invitations`              | `JwtAuthGuard`, `UserStatusGuard`  | Create a tenant invitation                                  |
| POST   | `/invitations/accept`       | Public                             | Accept an invitation and create the user                    |
| POST   | `/invitations/revoke`       | `JwtAuthGuard`, `UserStatusGuard`  | Withdraw a pending invitation                               |
| POST   | `/email/change`             | `JwtAuthGuard`, `UserStatusGuard`  | Request an address change (re-proves the current password)  |
| POST   | `/email/change/confirm`     | Public                             | Confirm it with the token mailed to the new address         |
| POST   | `/platform/login`           | Public                             | Platform admin login (separate token context)               |
| POST   | `/platform/mfa/challenge`   | Public                             | Platform admin MFA challenge                                |
| GET    | `/platform/me`              | `JwtPlatformGuard`                 | Current platform admin payload                              |
| POST   | `/platform/logout`          | `JwtPlatformGuard`                 | Revoke platform tokens                                      |
| POST   | `/platform/refresh`         | Public (platform refresh cookie)   | Rotate platform refresh token                               |
| DELETE | `/platform/sessions`        | `JwtPlatformGuard`                 | Revoke all platform sessions                                |
| POST   | `/password/change`          | `JwtAuthGuard` + `UserStatusGuard` | Change the password, proving the current one                |
| GET    | `/oauth/:provider`          | Public + `@SkipMfa()`              | Initiate OAuth authorization redirect                       |
| GET    | `/oauth/:provider/callback` | Public + `@SkipMfa()`              | Handle OAuth callback, exchange code, issue tokens          |

> **The OAuth routes require `cookie-parser`.** `GET /oauth/:provider` plants an HttpOnly
> `oauth_state` cookie carrying the flow's `state`, and the callback refuses any request that
> does not send it back — the binding RFC 6749 §10.12 requires, without which an attacker can
> hand a victim a callback URL and have the victim's browser complete the attacker's login.
> Mount `app.use(cookieParser())` before the module's routes or every callback answers 401.

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

| Area                        | Item                                                                                                                                                                                                      | Status    |
| --------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- |
| OAuth providers             | First-class `oauth.plugins` array so consumers can drop in GitHub / Microsoft / Apple plugins without forking the core                                                                                    | Planned   |
| Error-message i18n          | `BymaxAuthModule.forRoot({ messages })` override for `AUTH_ERROR_MESSAGES` (defaults are English; ship locale presets)                                                                                    | Planned   |
| Passwordless / magic link   | `MagicLinkService` + email-delivered single-use link, reusing the existing `generateSecureToken` + `IEmailProvider` API                                                                                   | Exploring |
| Passkeys / WebAuthn         | Optional WebAuthn primitive as an MFA method (and eventually a first-factor), behind a peer-dep-gated module                                                                                              | Exploring |
| Per-tenant configuration    | Per-tenant overrides for session limits, MFA enforcement, and password policy resolved at request time                                                                                                    | Exploring |
| Pluggable password policy   | `IPasswordPolicy` for complexity classes and per-tenant rules (the breach check already ships as `IPasswordBreachChecker`)                                                                                | Planned   |
| Custom token delivery modes | `ITokenDelivery` for non-cookie / non-bearer transports (custom headers, WebSocket handshakes, split client types)                                                                                        | Exploring |
| Generated shared types      | Emit `./shared` from one source of truth with a CI drift gate, the way `rust-auth` generates its TypeScript from the Rust types — today the two sides are held in step by the conformance tier and review | Planned   |

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

If you discover a security vulnerability, please **do not** open a public issue. Instead, email us at **support@bymax.one** with details. We take security seriously and will respond promptly.

---

## 📄 License

[MIT](./LICENSE) © [Bymax One](https://github.com/bymaxone)

---

<p align="center">
  <sub>Built with ❤️ by <a href="https://github.com/bymaxone">Bymax One</a></sub>
</p>
