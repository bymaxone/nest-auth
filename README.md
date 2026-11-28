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
  <a href="#-api-reference">API Reference</a> ·
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
- ✅ **OAuth 2.0** — Google, the one supported provider
- ✅ **Password Reset** — Token-based or OTP, configurable per deployment
- ✅ **Email Verification** — OTP-based with configurable TTL

### 🛡️ Security

- ✅ **Zero External Crypto** — All cryptography via native `node:crypto` (scrypt, AES-256-GCM, HMAC-SHA1, TOTP)
- ✅ **Brute-Force Protection** — Configurable rate limiting per email + tenant
- ✅ **Session Management** — Track active sessions with FIFO eviction, and an `onNewSession` hook fired on every session created (alerting on it is yours to decide — see `sendNewSessionAlert`)
- ✅ **HttpOnly Cookies** — Secure, SameSite, path-scoped refresh tokens by default
- ✅ **Timing-Safe Comparisons** — All secret comparisons use `crypto.timingSafeEqual`
- ✅ **JWT Revocation** — Instant access token revocation via Redis, per token (`jti`) and per session (`sid`)
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
- ✅ **Workspaces** — One identity with a role in each of many workspaces, switched without a login (see _Workspaces_ below)

### 🧩 Developer Experience

- ✅ **Full-Stack TypeScript** — Strict types shared across server and client
- ✅ **5 Subpath Exports** — Import only what you need, tree-shakeable
- ✅ **Dynamic Module** — Configure everything via `registerAsync()`, sensible defaults included
- ✅ **Interface-Driven** — Bring your own database and email provider
- ✅ **No Passport Required** — Guards validate JWT natively via `@nestjs/jwt`

---

## 📦 Subpath Exports

One package, six entry points — import only what your app needs:

| Subpath           | Import                               | Purpose                                                |    Dependencies    |
| ----------------- | ------------------------------------ | ------------------------------------------------------ | :----------------: |
| **Server**        | `@bymax-one/nest-auth`               | NestJS module, guards, decorators, services            | NestJS 11, ioredis |
| **Shared**        | `@bymax-one/nest-auth/shared`        | Types, constants, error codes                          |        None        |
| **Client**        | `@bymax-one/nest-auth/client`        | Fetch-based auth client                                |        None        |
| **React**         | `@bymax-one/nest-auth/react`         | Hooks & AuthProvider                                   |      React 19      |
| **Next.js**       | `@bymax-one/nest-auth/nextjs`        | Proxy, route handlers, JWT helpers                     |     Next.js 16     |
| **Observability** | `@bymax-one/nest-auth/observability` | Metrics contributor and readiness indicator (optional) |   `prom-client`    |

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
pnpm add @nestjs/common @nestjs/core @nestjs/jwt @nestjs/throttler @nestjs/websockets express ioredis class-validator class-transformer reflect-metadata rxjs
pnpm add -D @types/express

# Also needed with `tokenDelivery: 'cookie'` or `'both'` (see step 4): the library reads `req.cookies`
pnpm add cookie-parser

# React subpath (optional)
pnpm add react
pnpm add -D @types/react # a TypeScript project: the subpath's declarations import React's types

# Next.js subpath (optional)
pnpm add next react server-only
```

> [!NOTE]
> The server subpath needs one Redis that every request reaches: a single node, a Sentinel setup or a replica set.
> Redis Cluster is not supported, because the scripts that write a session touch keys that hash to different slots.

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
  FindUserByEmailParams,
  FindUserByOAuthIdParams,
  IUserRepository,
  LinkOAuthParams,
  TenantScopedUserRef,
  UpdateEmailParams,
  UpdateEmailVerifiedParams,
  UpdateMfaParams,
  UpdatePasswordParams,
  UpdateStatusParams
} from '@bymax-one/nest-auth'
import { PrismaService } from './prisma.service'

@Injectable()
export class PrismaUserRepository implements IUserRepository {
  constructor(private readonly prisma: PrismaService) {}

  async findById({ id, tenantId }: TenantScopedUserRef): Promise<AuthUser | null> {
    // Both halves of the key, always. An id is unique only within a tenant, so `findUnique`
    // by id alone can answer with another tenant's row.
    return this.prisma.user.findFirst({ where: { id, tenantId } })
  }

  async findByEmail({ email, tenantId }: FindUserByEmailParams): Promise<AuthUser | null> {
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

  // Every mutator below uses `updateMany` rather than `update`, for one reason: `update` takes a
  // UNIQUE where-clause, so it cannot accept `{ id, tenantId }` unless your schema declares that
  // pair unique — and `update({ where: { id } })` is the tenant-blind write this port exists to
  // prevent. `updateMany` accepts the compound filter and touches nothing outside the tenant.
  async updatePassword({ id, tenantId, passwordHash }: UpdatePasswordParams): Promise<void> {
    await this.prisma.user.updateMany({ where: { id, tenantId }, data: { passwordHash } })
  }

  async updateMfa({ id, tenantId, data }: UpdateMfaParams): Promise<void> {
    await this.prisma.user.updateMany({
      where: { id, tenantId },
      data: {
        mfaEnabled: data.mfaEnabled,
        mfaSecret: data.mfaSecret,
        mfaRecoveryCodes: data.mfaRecoveryCodes ?? []
      }
    })
  }

  async updateLastLogin({ id, tenantId }: TenantScopedUserRef): Promise<void> {
    await this.prisma.user.updateMany({
      where: { id, tenantId },
      data: { lastLoginAt: new Date() }
    })
  }

  async updateStatus({ id, tenantId, status }: UpdateStatusParams): Promise<void> {
    await this.prisma.user.updateMany({ where: { id, tenantId }, data: { status } })
  }

  async updateEmailVerified({ id, tenantId, verified }: UpdateEmailVerifiedParams): Promise<void> {
    await this.prisma.user.updateMany({
      where: { id, tenantId },
      data: { emailVerified: verified }
    })
  }

  async updateEmail({ id, tenantId, email }: UpdateEmailParams): Promise<void> {
    await this.prisma.user.updateMany({
      where: { id, tenantId },
      data: { email: email.toLowerCase() }
    })
  }

  async findByOAuthId({
    provider,
    providerId,
    tenantId
  }: FindUserByOAuthIdParams): Promise<AuthUser | null> {
    return this.prisma.user.findFirst({
      where: { oauthProvider: provider, oauthProviderId: providerId, tenantId }
    })
  }

  async linkOAuth({ id, tenantId, provider, providerId }: LinkOAuthParams): Promise<void> {
    await this.prisma.user.updateMany({
      where: { id, tenantId },
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

When the provider (or the `BYMAX_AUTH_HOOKS` object) is registered as a ready-made `useValue` object, `registerAsync` checks it when it is called: each member the library calls by name that is present must be a function (any other member of the object is yours and is not looked at), and the provider must carry the methods the library calls without a guard: `sendPasswordResetToken`, `sendPasswordResetOtp`, `sendEmailVerificationOtp`, `sendMfaEnabledNotification`, `sendMfaDisabledNotification` and `sendInvitation`. A class, a factory or an alias is not inspected.

> [!WARNING]
> Any user-supplied value (display name, tenant name, inviter name) interpolated into HTML email bodies MUST be escaped to prevent stored XSS in notification content. Tokens and OTPs are library-generated and safe, but `inviterName`, `tenantName`, device strings, and any consumer-supplied placeholder are attacker-controllable.

> [!CAUTION]
> **Never log the error your transport rejects with.** A relay that answers `550` commonly quotes the
> message body, so the error `send()` throws can carry the OTP or token the library rendered into it,
> and logging it (or attaching it as a `cause`) puts a working credential in your logs. Log
> `describeChannelStatus(error)` instead: it is exported for exactly this and reads nothing the
> channel wrote. See [Keeping delivery errors out of your logs](./docs/email-delivery-errors.md).

> [!NOTE]
> The bundled `DefaultAuthEmailProvider` implements every method of `IEmailProvider`, the optional
> ones included (`sendWorkspaceInvitation` among them), so a host that takes it can enable every
> controller. It renders a **token**, not a link: the invitation messages say "use this token to
> accept: ..." and it has no base URL to build one from. To send a link, override the message,
> `new DefaultAuthEmailProvider(sink, { messages: { invitation, workspaceInvitation } })`, with a
> renderer that returns your own `html`; the escaping of caller-supplied text, the credential flag
> and the delivery-error policy still apply to it. A workspace invitation says whether it is for a
> workspace that exists (`kind: 'member'`) or a platform invitation to set one up and own it
> (`kind: 'bootstrap'`).

```typescript
// email.provider.ts
import { Injectable } from '@nestjs/common'
import type { IEmailProvider, InviteData, SessionAlertInfo } from '@bymax-one/nest-auth'
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

  // The library does NOT await the three MFA notices — by the time one is sent the factor is
  // already enabled or removed, so a bounced notice must not answer the caller with an error for
  // an operation that succeeded. The consequence is here: an inline send like this one can be
  // lost to a process shutdown or a serverless freeze arriving between the response and the send
  // completing. Where these alerts matter — the administrative reset most of all, since it is what
  // makes a support-desk takeover detectable — enqueue durably and resolve instead of sending
  // inline. Awaiting would not fix it either: a freeze mid-await loses the notice AND the response.
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
    sessionInfo: SessionAlertInfo,
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
  BYMAX_AUTH_REDIS_CLIENT,
  BYMAX_AUTH_EMAIL_PROVIDER
} from '@bymax-one/nest-auth'
import { PrismaUserRepository } from './user.repository'
import { ResendEmailProvider } from './email.provider'

// Yours, not this library's: `ConfigModule` and `ConfigService` come from `@nestjs/config`,
// `DatabaseModule` is your module exporting the database client the repository uses, and
// `RedisModule` is your module exporting `RedisService`, whose `client` is an `ioredis` instance.

@Module({
  imports: [
    BymaxAuthModule.registerAsync({
      imports: [ConfigModule, DatabaseModule, RedisModule],
      useFactory: (config: ConfigService) => ({
        jwt: {
          secret: config.getOrThrow('JWT_SECRET'), // min 32 chars, high entropy
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
          provide: BYMAX_AUTH_EMAIL_PROVIDER,
          useClass: ResendEmailProvider
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

With `tokenDelivery: 'cookie'` (or `'both'`) the library reads the credential from `req.cookies`, and it takes no dependency on a parser, so mount one yourself. Without it a correctly signed-in user is answered `401 auth.token_invalid` on every protected route.

```typescript
// main.ts
import { NestFactory } from '@nestjs/core'
import cookieParser from 'cookie-parser'
import { AppModule } from './app.module'

async function bootstrap() {
  const app = await NestFactory.create(AppModule)
  app.use(cookieParser())
  await app.listen(3000)
}
bootstrap()
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

> [!IMPORTANT]
> **The proxy is a routing hint, not an authorization check.** `jwtSecret` lets the proxy tell
> whether an access token was minted with your secret and has not expired, which is enough to choose
> between rendering a page and redirecting to sign-in. It cannot see what the backend sees: a logout,
> a password reset or a revoke-all, a blocked account, the MFA state, or a workspace membership. A
> token the proxy lets through may be one the backend refuses on the next call, so a role or a header
> the proxy sets must never be the access decision for data or an action: the backend verifies every
> request that reads or changes anything.
>
> Set `jwtIssuer`, `jwtAudience` and `jwtPreviousSecrets` to the same values as the backend's
> `jwt.issuer`, `jwt.audience` and `jwt.previousSecrets`. The backend requires a configured issuer
> and audience on every token and keeps accepting the retired secrets while a rotation drains, so a
> proxy without them signs out a session the backend still honours, or admits a token the backend
> refuses. `verifyJwtToken` takes the same three values as its `options` argument.

How the route lists match a path: an entry matches the path that equals it and anything under
it (`'/auth'` covers `/auth/login`), and takes no wildcards (`'/auth/*'` matches nothing). An
entry ending in `/` is a plain prefix, so `'/'` matches every path. In `publicRoutes` that is
harmless: `protectedRoutes` are tried first, and a path no list names is already let through. In
`publicRoutesRedirectIfAuthenticated` it sends a signed-in user to their dashboard from every page
that is not protected, so list the login and register pages there, never `'/'`.

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

> [!NOTE]
> Authenticating a WebSocket (single-use upgrade tickets, tenant binding on a socket, a proxy that rewrites `Host`) is covered in [WebSocket upgrades](./docs/websocket-upgrades.md).

---

## ⚙️ Configuration

All options are configurable via `registerAsync()`. Here are the key configuration groups:

| Group                      | Key Options                                                                                                                                                                    | Default                                                 |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------- |
| **jwt**                    | `secret` (required), `previousSecrets`, `accessExpiresIn`, `refreshExpiresInDays`, `absoluteSessionLifetimeDays`, `algorithm`, `issuer`, `audience`                            | `15m`, `7d`, `30d` cap, `HS256`, both off               |
| **identifierKey**          | Top-level secret the Redis account identifiers and MFA recovery-code digests derive from; pin it before rotating `jwt.secret`                                                  | `jwt.secret`                                            |
| **environment**            | `'production'` \| `'development'` \| `'test'` — the only input that answers "is this production"                                                                               | `'production'`                                          |
| **password**               | `minLength`, `costFactor`, `blockSize`, `parallelization`                                                                                                                      | `15`, scrypt N=2¹⁷, r=8, p=1                            |
| **tokenDelivery**          | `'cookie'` \| `'bearer'` \| `'both'`                                                                                                                                           | `'cookie'`                                              |
| **cookies**                | `accessTokenName`, `refreshTokenName`, `sessionSignalName`, `refreshCookiePath`, `sameSite`, `trustedOrigins`, `resolveDomains`                                                | `'lax'`, `[]` (see cookie section)                      |
| **mfa**                    | `encryptionKey`, `previousEncryptionKeys`, `issuer`, `totpWindow`, `recoveryCodeCount`                                                                                         | `totpWindow` `1`, `recoveryCodeCount` `8`               |
| **sessions**               | `enabled`, `defaultMaxSessions`, `maxSessionsResolver`                                                                                                                         | `false`, `5`, —                                         |
| **`bruteForce`**           | `maxAttempts`, `windowSeconds`                                                                                                                                                 | `5`, `900`                                              |
| **rateLimit**              | `enabled`, `clientIpSource` (`'peer'` \| `'trusted-proxy'`) — per-IP limits over Redis                                                                                         | `true`, **required**                                    |
| **passwordReset**          | `method` (`'token'` \| `'otp'`), `otpLength`, `otpTtlSeconds`                                                                                                                  | `'token'`                                               |
| **platform**               | `enabled`                                                                                                                                                                      | `false`                                                 |
| **invitations**            | `enabled`, `tokenTtlSeconds`                                                                                                                                                   | `false`                                                 |
| **apiKeys**                | `enabled`, `pepper` and `scopes` (required when enabled), `header`, `prefix`, `lastUsedFlushSeconds`, `auditMode` — see [Service API keys](#-service-api-keys-machine-callers) | `false`, `'x-api-key'`, `'bak'`, `60`, `'best-effort'`  |
| **roles**                  | `hierarchy` (required), `platformHierarchy`                                                                                                                                    | —                                                       |
| **oauth**                  | `google: { clientId, clientSecret, callbackUrl, scope }`                                                                                                                       | `scope`: `['openid', 'email', 'profile']`               |
| **`emailVerification`**    | `required`, `otpTtlSeconds`                                                                                                                                                    | `true`, `600`                                           |
| **password** (screen)      | `blocklist` — extra words the default screen refuses, on top of the ones it ships                                                                                              | `[]`                                                    |
| **jwt** (cookie, refresh)  | `accessCookieMaxAgeMs`, `refreshGraceWindowSeconds`                                                                                                                            | `900000`, `30`                                          |
| **`secureCookies`**        | Top-level `Secure` flag on the auth cookies; `false` is refused unless `environment` is `development` or `test`                                                                | `true`, unless `environment` is `development` or `test` |
| **cookies** (MFA)          | `mfaTempCookiePath` — set it to the real `/mfa` path when the app uses a Nest global prefix or a different `routePrefix`                                                       | `/auth/mfa` (it does not follow `routePrefix`)          |
| **emailChange**            | `tokenTtlSeconds`; the flow itself is switched on by `controllers.emailChange`                                                                                                 | `3600`                                                  |
| **oauth** (redirects)      | `successRedirectUrl`, `mfaRedirectUrl`, `errorRedirectUrl`                                                                                                                     | —                                                       |
| **`enforceTenantBinding`** | Top-level: the guards re-resolve the tenant and refuse a token whose `tenantId` differs; needs `tenantIdResolver`                                                              | `false`                                                 |
| **`isTrustedProxy`**       | Top-level predicate: whether the peer of a WebSocket upgrade is a proxy whose `X-Forwarded-Host` may be believed                                                               | unset                                                   |
| **controllers**            | Toggle individual controllers on/off — passed to `registerAsync()` itself, never returned from `useFactory` (which refuses it at startup)                                      | `auth`, `passwordReset` on; rest opt-in                 |

An option that is omitted, or that holds `undefined` or `null`, is unset and takes its default; it never means "no limit". To switch
a cap off, use the documented value (`0` for `jwt.absoluteSessionLifetimeDays`), not an absent one. A host-defined map or a required value (`oauth.<provider>`, the `oauth` redirect URLs, `roles.hierarchy.<role>`, `workspaces.permissions.<action>`) refuses `null` by name.
A flag must be exactly `true` or `false` (`workspaces.allowCreate` may also be a function), and an option with a documented set of values exactly one of them: anything else, an empty string and `'false'` included, is
refused at startup naming the option, never read as off or as a default.
A text option (`jwt.issuer`, `jwt.audience`, the cookie names and paths, `mfa.issuer`, `apiKeys.pepper`, `redisNamespace`,
`routePrefix`) must be a string, `blockedStatuses`, `cookies.trustedOrigins` and `password.blocklist` an array of strings, and each
settings group an object; any other type is refused at startup naming the option and the type received, and never printing the content of a value that is not a number. `controllers` is read once, by
`registerAsync()`, and a `controllers` key in what `useFactory` returns is refused whatever its value, `null` and `undefined` included.

> [!NOTE]
> When a feature is not enabled (e.g., `mfa`, `sessions`, `platform`), its controllers and services are **not registered** in the NestJS container — zero overhead. A feature is enabled by `controllers.<name>: true` on the `registerAsync()` call together with its configuration group (`mfa.encryptionKey` and `mfa.issuer`, `sessions.enabled`, `platform.enabled`); either half alone leaves it unregistered or fails at startup.

> [!IMPORTANT]
> **`environment` is how the module decides whether this is production, and it defaults to
> saying yes.** It drives cookie `Secure`, the HTTPS requirement on the OAuth `callbackUrl`, and
> redirect validations. A local or test setup must say `environment: 'development'` (or
> `'test'`) explicitly, or it is held to production rules: an `http://` callback URL is refused and
> cookies are marked `Secure`. It is an explicit option rather than `NODE_ENV` because a near miss
> (unset, `'staging'`, `'prod'`) would otherwise silently take the insecure branch.

> [!NOTE]
> **`password.minLength` defaults to 15, not 8.** The DTOs keep a structural floor of 8, the lowest
> NIST SP 800-63B-4 §3.1.1.1 permits under any circumstance, and 15 is the minimum it requires for a
> password used as a single factor. MFA is opt-in per user, so the default deployment is
> single-factor. Configurable to anything in `8..=128`, validated at startup. A shorter password
> answers the same `auth.validation` code and `{ field, message }[]` details as any length failure.

> [!IMPORTANT]
> **`rateLimit.clientIpSource` is required** whenever rate limiting is enabled; there is no default,
> and the module refuses to start without it. Set `'peer'` when the application is directly
> exposed: the limit keys on the socket address, never on a forwarding header. Set
> `'trusted-proxy'` when it runs behind a proxy and `trust proxy` is configured for the real hop
> count: the limit keys on `req.ip`. Neither can be the default, because each is a working limiter
> in one deployment and none in the other: `'peer'` behind a proxy puts every client in **one**
> bucket, and `'trusted-proxy'` without a proxy lets the caller choose their own key. Pass
> `rateLimit.enabled: false` if the limits are enforced at the edge instead.
>
> `'trusted-proxy'` is only as honest as the hops in front of the app: the client is the rightmost
> `X-Forwarded-For` entry that is not itself a trusted proxy. A hop that forwards the client's own
> header unchanged lets the client choose its address; behind such a hop use `'peer'`, or make the
> hop append or overwrite the header. An entry that is not an address is never a key; the limit is
> charged to the nearest trusted hop instead.

> [!TIP]
> **Binding tokens to an issuer and an audience.** `jwt.issuer` and `jwt.audience` are off by
> default. Set either and its value is stamped on every token this backend mints and **required**
> on every token it verifies. With HS256 every service holding the secret can mint a token, so
> audience binding is what stops a token minted for one service being replayed at another that
> trusts the same secret. Both backends of a shared deployment must carry the same pair, and
> enabling it invalidates access tokens already in flight (one access-token lifetime, closed by a
> refresh). An empty string reads as unconfigured, so an unset environment variable cannot turn the
> check on.

> **Rotating the signing secret.** `jwt.previousSecrets` lists secrets retired by a rotation,
> accepted for verification only. Without it, changing `jwt.secret` signs every user out and
> invalidates every stored recovery-code digest, since those are keyed by an HMAC derived from the
> secret. With it both keep working while old tokens drain. Remove an entry once the longest-lived
> token signed under it has expired: every entry is a key that still opens the door.
> `mfa.encryptionKey` rotates the same way, through its own list, below.
>
> **Pin `identifierKey` before you rotate.** Every Redis name that identifies an account (the
> session index, the token epoch, the MFA keys, the recent-authentication marker, the OTP and
> rate-limit identifiers) and every stored MFA recovery-code digest is an HMAC under a key derived
> from `jwt.secret`, unless you set `identifierKey`. Rotate `jwt.secret` alone and all of them are
> renamed: live sessions lose their index, every token epoch reads zero (so a token that a password
> reset had refused is accepted again until it expires), and recovery codes stop verifying.
> `identifierKey` is a secret of its own for those names and digests, validated like `jwt.secret`;
> it never signs or verifies a token. Its value is simply the secret you want them to keep deriving
> from.
>
> |                 | Routine rotation — keep sessions, epochs and recovery codes                                                                                                | Rotation after a compromise — cut the link                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
> | --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
> | Before rotating | Once, set `identifierKey` to the value `jwt.secret` has **now** and deploy. Nothing moves: the derivation is unchanged. Later rotations leave it as it is. | Revoke what has to be revoked while the session index can still find it; afterwards nothing can be revoked through it, and refresh tokens, which are looked up by their own hash, keep working. Do not list the compromised secret in `jwt.previousSecrets`.                                                                                                                                                                                                                                                                                                                                                                                  |
> | Rotating        | Put the new secret in `jwt.secret` and the old one in `jwt.previousSecrets`; keep `identifierKey` as it is.                                                | Put the new secret in `jwt.secret` **and** choose a new `identifierKey`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
> | Names           | Unchanged.                                                                                                                                                 | Moved: sessions lose their index until they next refresh (meanwhile they are missing from the session list and cannot be revoked through it, and their refresh tokens still work until they expire), every epoch reads zero, MFA set-up state and lockout counters start empty, and stored recovery-code digests stop verifying.                                                                                                                                                                                                                                                                                                              |
> | Revoked tokens  | Stay revoked.                                                                                                                                              | Tokens signed under the old secret no longer verify. A token signed under a secret that stays in `previousSecrets` and had been refused by an epoch is accepted again, because the epoch is renamed with the rest and revoking first does not carry it across: remove retired secrets from `previousSecrets` or wait out `jwt.accessExpiresIn`.                                                                                                                                                                                                                                                                                               |
> | Afterwards      | Drop the old secret from `previousSecrets` once its last token has expired.                                                                                | Users with MFA need new recovery codes: an old code is refused like any wrong code, and sign-in with the authenticator app is unaffected. A signed-in user replaces them with `POST /mfa/recovery-codes` (`POST /platform/mfa/recovery-codes` for an admin), proving a fresh OTP; the library does not regenerate them at the next sign-in or notify anyone, so your application prompts for it. Listing the secret the digests were keyed from (the old `identifierKey` value) in `previousSecrets` would keep the old codes working, and would keep tokens signed with it verifying if it was also a signing secret: that is the trade-off. |
>
> Pinning to the old secret leaves the derived Redis names computable by anyone who knows that
> secret. They are names, not signing material, and using one still needs access to your Redis; if
> cutting that link matters more than keeping sessions, take the second column.

> [!TIP]
> **Rotating the MFA encryption key.** `mfa.previousEncryptionKeys` lists AES-256 keys retired by a
> rotation of `mfa.encryptionKey`. The stored ciphertext carries no key identifier, so without the
> list a change of key makes every enrolled TOTP secret undecryptable at once. With it, a secret
> that opened under a retired key is **re-encrypted under the current one** on the next successful
> challenge, so the rotation drains on its own. Each entry is validated at startup like the current
> key (base64, exactly 32 bytes, never equal to the current key or another entry). Drop an entry
> once your enrolled users have authenticated at least once.

> [!WARNING]
> **Keep your `updateMfa` fast.** The library serializes MFA writes per account with a lock that
> expires on its own (`MFA_TRANSITION_LOCK_TTL_SECONDS`, 10 seconds), so a process that dies
> mid-write cannot strand the account. The lock cannot outlast a write that is still running: if
> your `updateMfa` stalls past that time, a second change takes the lock and writes, and the stalled
> write then lands _after_ it and overwrites it. The repository interface has no compare-and-set, so
> the library cannot detect this. Keep `updateMfa` well under the lock's lifetime (a plain
> single-row update is). The lock also covers the read the transition makes inside it, so a slow
> `findById` counts against the same lifetime.

> [!IMPORTANT]
> **The parameters that carry a control's strength are bounded at startup.** `mfa.totpWindow` must
> be `0..=2`: the window counts 30-second steps on _either_ side of now, so `2n + 1` codes are
> valid at once (three at the default of 1). `mfa.recoveryCodeCount` must be `1..=50`,
> because zero enrols an account with no way back if the authenticator is lost.
> `password.blockSize` must be at least 8 and `password.parallelization` between 1 and 16: scrypt's memory
> cost is `128 * N * r`, so a smaller block size divides the hardness `password.costFactor`'s floor
> exists to guarantee.

> [!IMPORTANT]
> `jwt.accessExpiresIn` must not exceed **30 days**, the window the store keeps a bumped token epoch
> readable. A longer-lived access token would outlive the epoch, the lookup would fall back to `0`,
> and a token a password reset had revoked would verify again. Startup refuses the configuration
> rather than failing open, and rejects an unreadable time span or a non-positive lifetime on the
> same pass.

> [!WARNING]
> **Do not gate on the access token's `status` claim.** It is **point-in-time, never
> authoritative**:
>
> | how the token was minted                                                   | `status`                                                                                 |
> | -------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
> | login, register, OAuth, MFA challenge                                      | the account's value **at that moment**                                                   |
> | an ordinary refresh rotation                                               | **empty string**: the session record carries no live status, so there is nothing to copy |
> | a refresh that re-signs because `role`, `tenantId` or `mfaEnabled` changed | the account's value **at that moment**, read during that request                         |
>
> Every populated value is stale the instant the account changes, so a route that reads the claim
> is wrong in **both** directions: `status !== 'active'` refuses everyone whose session was
> refreshed ordinarily, and `status === 'suspended'` refuses nobody. Resolve status per request:
> mount `UserStatusGuard` on the route (on a WebSocket, SSE stream or message consumer, call
> `AuthTokenVerifierService.verifyAccessToken`, which resolves status through the same cache before
> it applies the MFA policy), and for anything richer read the account **tenant-scoped**:
> `findById({ id: request.user.sub, tenantId: request.user.tenantId })`. The tenant argument is
> required by the port because ids may collide across tenants.
>
> The guard reads a status cache with a `userStatusCacheTtlSeconds` window (default **60**), so a
> suspension takes up to that long to bite on a guarded route, and a reactivation the same to
> restore. Call `AccountStatusService.invalidate({ userId, tenantId })` after persisting a status
> change to drop that account's cached status at once (a request already resolving can still write
> the old value back; see
> [Invalidating the account cache](./docs/server-services.md#invalidating-the-account-cache--accountstatusserviceinvalidate)).
> `bumpUserTokenEpoch` is the heavier lever: it ends every session the user has. Lower
> `userStatusCacheTtlSeconds` if a faster answer matters more than the repository reads it costs.
>
> `userStatusCacheTtlSeconds` is a whole number of seconds from **1 to 3600**. It is the window in which a
> suspended account keeps passing the guard, so the module refuses a longer one (and a fraction, `NaN`
> or a string) at boot.

`jwt.absoluteSessionLifetimeDays` caps how long one login can be extended by rotation, and is
**on by default at 30 days** — NIST SP 800-63B-4 §3 makes a definite reauthentication timeout a
SHALL and puts it at no more than 30 days for AAL1. Without a cap, a client refreshing every
fifteen minutes keeps a session alive forever, and a refresh token stolen once becomes permanent
access. Raise it to a value the product can justify, or set `0` to accept unbounded sessions
deliberately.
Any other value is from one hour (`0.0417` days) to `3650` days.

Lowering the value ends sessions that are already older than the new one, at their next rotation;
raising it or setting `0` ends nothing. Sessions established before the cap existed carry no
recorded birth time and are never capped, whatever the value — they age out under
`refreshExpiresInDays` like any other.

`cookies.trustedOrigins` is deliberately off by default, because switching it on changes
behaviour for origins that already exist. It is required as soon as `cookies.sameSite: 'none'`
is set, and refused otherwise — that posture is the only one where the browser sends the session
cookie cross-site, and it is the only one where the origin check has anything to authorize.

> [!IMPORTANT]
> **Bound your Redis client.** Every authentication and authorization decision here reads Redis and
> **fails closed**: when Redis is unreachable the request is refused with `503
auth.service_unavailable`, never admitted. What the library cannot do is bound how long the client waits before it gives
> up, because the client is yours (`BYMAX_AUTH_REDIS_CLIENT`). With ioredis defaults the offline
> queue is on and a command retries up to 20 times, so a Redis outage reads as requests that hang
> before they fail, and `maxRetriesPerRequest: null` waits forever. Build the client with a
> deadline on every command and a bounded reconnect:
>
> ```typescript
> new Redis(url, {
>   commandTimeout: 500, // ms; every command rejects after this, which the library answers as a 503
>   maxRetriesPerRequest: 1, // do not queue a command through repeated reconnects
>   enableOfflineQueue: false, // refuse a command while disconnected instead of holding it
>   retryStrategy: (attempt) => Math.min(attempt * 200, 2000) // bounded, never `null` in a server
> })
> ```
>
> This is the **auth** client: give a BullMQ queue its own connection. BullMQ workers require `maxRetriesPerRequest: null`, which is the opposite of the setting
> above, so one shared client forces a choice between the two.
>
> The module warns at startup when the client carries no `commandTimeout`, and it sends `PING`
> at bootstrap every quarter second for up to 5 seconds, so a Redis that is still starting does not
> fail the boot on its first refusal, while a mis-pointed address or a wrong password stops the
> process from starting, with a message that names only the host and port, instead of surfacing as the first
> request's error. While Redis is down, login, refresh, logout, rate-limited routes and every
> guarded route answer `503` with `error.code` `auth.service_unavailable` and the envelope
> `{ error: { code, message, details: null } }`; nothing of the store reaches the body, and no
> `Retry-After` is sent, because nothing here knows when Redis returns. It is the fail-closed
> behaviour, and a client may retry. A Redis outage is a timeout, a closed or refused connection,
> or a server that answers it cannot serve; one function classifies them, and any other failure of a Redis call (a script that
> is not loaded, a key of the wrong type, an aborted command) is a defect: it becomes an
> `AuthException` carrying `auth.internal` (HTTP 500), with or without `AuthExceptionFilter`, with no
> `cause`. The library logs it as `AUTH_STORE_FAILED` with `operation` `redis:<family>` (or `redis`)
> and `detail` the class of the error, and nothing else of the key or the command. In the OAuth callback, past its
> rate limit, it redirects to a set `errorRedirectUrl` with `error=internal`.
>
> The 503 is an `AuthException` whose `cause` is a new `Error` named after the class of the client's
> error and the kind of the outage (`Error (timeout)`), with `redis:<family>` (or `redis`) as its message. The client's error is not kept, because it
> can carry the command it failed and Nest's logger prints a `cause`. A host filter that logs 5xx
> answers can record that class, kind and family; `isServiceUnavailable(error)`, exported from
> the package, tells that 503 apart from every other `AuthException` and narrows it, so a host filter
> or interceptor can handle it without comparing codes. The library's own `AuthExceptionFilter`
> writes no log line for it: your readiness probe, not the request log, is the signal that Redis is
> down, so put a Redis health check next to it. Two answers keep their meaning: a password-reset
> request refused because the cooldown store cannot answer is the same `503` for every address, and the
> OAuth callback, past its rate limit, redirects to your `errorRedirectUrl` with `error=service_unavailable` when you
> configured one. A failure to cache an answer the library can recompute (the workspace membership
> cache, the denied-access counter, the session limit) is still absorbed, not refused.
> The paths, the outcome of each and the test that pins it are in
> [`docs/redis-outage.md`](./docs/redis-outage.md).

> [!NOTE]
> **`keyPrefix` on the auth client.** A string prefix is supported: keys are stored under
> `keyPrefix`, then `redisNamespace`, then `:`, so a backend that shares the keyspace sets its own
> namespace to the first two. A prefix given as a `Buffer` is refused at startup, and a cluster was
> not measured. An application that ran 1.5.16 or earlier with a prefix should read the
> `keyPrefix` entry of the 1.5.18 CHANGELOG.

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

## 🪝 Auth hooks

`IAuthHooks` is where a host reacts to, or refuses, what the library does. Provide it under the `BYMAX_AUTH_HOOKS` token:

```typescript
extraProviders: [{ provide: BYMAX_AUTH_HOOKS, useClass: MyAuthHooks }]
```

Without one the library registers `NoOpAuthHooks`, which allows every registration and whose `onOAuthLogin` creates an account for an unlinked identity and keeps a link only when the address matches and the provider verified it. Yours replaces it entirely, and every OAuth sign-in fails without `onOAuthLogin`, so extend `NoOpAuthHooks` to keep it. Its methods are typed to return a value or a promise, so an override can be `async`.

Where the table says **logged**, the call is not awaited: a throw or a rejection is written as `AUTH_HOOK_FAILED` and the operation is unaffected. "Dashboard" and "platform" are the two identity planes.

| Hook                               | When it is called                                                                                                                                                                                                                                                                                                                                                                                        | If it throws                                                                                                                                                |
| ---------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `beforeRegister`                   | `register`, before the duplicate-address check and the password policy. `allowed: false` answers `403 auth.forbidden`, without the `reason`; `modifiedData` can set `role`, `status` and `emailVerified` (ignored when verification is required).                                                                                                                                                        | The registration fails with what was thrown.                                                                                                                |
| `afterRegister`                    | `register`, after the account and its tokens exist. Not for OAuth or invitations.                                                                                                                                                                                                                                                                                                                        | Logged.                                                                                                                                                     |
| `beforeLogin`                      | Dashboard password login, after the lockout check and before the account is looked up. Not platform login.                                                                                                                                                                                                                                                                                               | The login fails with what was thrown; no failed attempt is counted and `onLoginFailed` is not called.                                                       |
| `afterLogin`                       | A dashboard password or OAuth sign-in that needs no MFA, a platform password login that needs no MFA, a completed MFA challenge on either plane, and `issueTokensForUserId`. Not `register`, not the invitation acceptance routes.                                                                                                                                                                       | Logged.                                                                                                                                                     |
| `onLoginFailed`                    | A refused dashboard password login: `locked_out`, `invalid_credentials`, `account_blocked` or `email_not_verified`.                                                                                                                                                                                                                                                                                      | Logged.                                                                                                                                                     |
| `onLockout`                        | A dashboard login that fails on its credentials and leaves the identifier locked.                                                                                                                                                                                                                                                                                                                        | Logged.                                                                                                                                                     |
| `afterLogout`                      | A dashboard logout that completes and can name its owner, the retry of a failed attempt included (once for sequential retries; concurrent attempts can repeat it).                                                                                                                                                                                                                                       | Logged.                                                                                                                                                     |
| `afterPlatformLogout`              | The same, for a platform logout. A platform logout does not call `afterLogout`.                                                                                                                                                                                                                                                                                                                          | Logged.                                                                                                                                                     |
| `onRefreshTokenReuseDetected`      | A consumed refresh token is replayed after its grace window and its family has been revoked, on either plane, when the owner is known.                                                                                                                                                                                                                                                                   | Logged.                                                                                                                                                     |
| `afterMfaEnabled`                  | MFA enrolment is committed, on either plane.                                                                                                                                                                                                                                                                                                                                                             | Logged.                                                                                                                                                     |
| `afterMfaDisabled`                 | MFA is removed by the user or by `resetMfa`, on either plane. `resetMfa` passes an empty `ip` and `userAgent`.                                                                                                                                                                                                                                                                                           | Logged.                                                                                                                                                     |
| `afterMfaRecoveryCodesRegenerated` | Recovery codes are regenerated, on either plane.                                                                                                                                                                                                                                                                                                                                                         | Logged.                                                                                                                                                     |
| `onNewSession`                     | Every dashboard session recorded under `sessions.enabled`, new device or not; not on token rotation.                                                                                                                                                                                                                                                                                                     | Logged.                                                                                                                                                     |
| `onSessionEvicted`                 | The session limit evicted a session, with the evicted session's full hash.                                                                                                                                                                                                                                                                                                                               | Logged.                                                                                                                                                     |
| `onSessionsRevoked`                | Refresh sessions were revoked, on either plane, for any reason (see below).                                                                                                                                                                                                                                                                                                                              | Logged.                                                                                                                                                     |
| `afterEmailVerified`               | `verifyEmail` confirms an address. The user passed is the record read before the change, with `emailVerified` set to `true`.                                                                                                                                                                                                                                                                             | Logged.                                                                                                                                                     |
| `afterPasswordReset`               | A password reset, by any method, has stored the new password and revoked the sessions. Skipped if the account cannot be read back.                                                                                                                                                                                                                                                                       | Logged.                                                                                                                                                     |
| `onOAuthLogin`                     | The OAuth callback, once the provider profile is fetched. It returns `create`, `link` or `reject`.                                                                                                                                                                                                                                                                                                       | The callback fails (an `AuthException` follows `errorRedirectUrl` when one is set). Returning nothing, or not implementing it, answers `auth.oauth_failed`. |
| `afterInvitationAccepted`          | An invitation creates the account: invitation acceptance, workspace invitation signup, or a workspace invitation completed by an OAuth sign-in that created the account. It runs once the account's session is issued: a failure to issue it answers the request with an error and runs no hook, with the account created and the token spent. Not when a signed-in user accepts a workspace invitation. | Logged.                                                                                                                                                     |
| `beforeWorkspaceCreate`            | Before a workspace is written: workspace creation, and acceptance of an invitation that creates the workspace. On an invitation signup the account does not exist yet: `context.accountPending` is `true` and the user is provisional, with an empty `id`. `allowed: false` answers `403 auth.forbidden` with the `reason`.                                                                              | The creation is refused with what was thrown.                                                                                                               |
| `onWorkspaceEvent`                 | A workspace or membership change has committed, or an invitation was sent, resent, revoked or accepted; also `access.denied` (rate-limited) and `workspace.switched`. A bootstrap acceptance that creates the workspace reports `workspace.created`, and `invitation.accepted` as every acceptance does.                                                                                                 | Logged.                                                                                                                                                     |
| `onApiKeyRequest`                  | Every request to a route guarded by `ApiKeyGuard`, refusals included.                                                                                                                                                                                                                                                                                                                                    | Logged. Under `apiKeys.auditMode: 'required'` the call is awaited, and a throw, or no such hook, denies the request.                                        |

### Following every revocation

`onSessionsRevoked` is the one hook to implement when the host keeps state per session, such as open sockets or a cache. The more specific hooks in the table still fire beside it.

It receives `{ userId, tenantId?, plane, reason, sessionIds? }`. `tenantId` is absent on the platform plane and for a session record that names none. `sessionIds` holds the SHA-256 hashes of the revoked refresh sessions when the operation names them; when it is absent, the event does not say which sessions ended, so treat any session of that account as possibly revoked.

| `reason`                 | What revoked                                                                                                      | `sessionIds` |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------- | ------------ |
| `logout`                 | A logout, on either plane.                                                                                        | Yes          |
| `session_revoked`        | `DELETE /sessions/:id`, or `SessionService.revokeSession` and `revokeOtherSession`.                               | Yes          |
| `other_sessions_revoked` | `POST /sessions/revoke-all`, or `SessionService.revokeAllExceptCurrent` without a `reason`.                       | Yes          |
| `all_sessions_revoked`   | `AuthService.revokeAllSessions`, `PlatformAuthService.revokeAllPlatformSessions` and `DELETE /platform/sessions`. | No           |
| `account_unavailable`    | A refresh that found the account missing or blocked, on either plane.                                             | No           |
| `password_changed`       | A password change. With the current session kept, the ids of the others; with none kept, every one.               | If one kept  |
| `password_reset`         | A password reset, by any method.                                                                                  | No           |
| `mfa_enabled`            | MFA enrolment.                                                                                                    | No           |
| `mfa_disabled`           | MFA removal, by the user or by `resetMfa`.                                                                        | No           |
| `session_evicted`        | The session limit.                                                                                                | Yes          |
| `refresh_reuse`          | A replayed refresh token whose family was revoked, when the owner is known.                                       | If any       |

It runs after the store has deleted the sessions and is not awaited. It also runs when the sessions were deleted but a later write was refused, so the operation can fail after the event. A retried or repeated operation can report the same account again: handle it idempotently. A revocation that can name no account is not reported.

---

## 🔑 Service API keys (machine callers)

For a caller that is a program, not a person: an automation service, a build agent, a partner
integration. A key is stored only as a peppered HMAC digest, carries a set of scopes, is checked
by a guard that has no dependency on user sessions, and every guarded request — refused ones
included — reaches an audit hook. Nothing is registered until you opt in.

### Enable it

```typescript
// app.module.ts
import { BYMAX_AUTH_API_KEY_REPOSITORY, BymaxAuthModule } from '@bymax-one/nest-auth'

BymaxAuthModule.registerAsync({
  useFactory: () => ({
    jwt: { secret: process.env.JWT_SECRET ?? '' },
    roles: { hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] } },
    rateLimit: { clientIpSource: 'peer' },
    apiKeys: {
      enabled: true,
      // A secret of its own, held apart from the database that stores the digests.
      pepper: process.env.API_KEY_PEPPER ?? '',
      // The closed vocabulary: issue() refuses anything else, and so does the startup scan.
      scopes: ['read', 'operate', 'publish-claim', 'admin']
    }
  }),
  extraProviders: [
    // …BYMAX_AUTH_USER_REPOSITORY and BYMAX_AUTH_REDIS_CLIENT as usual
    { provide: BYMAX_AUTH_API_KEY_REPOSITORY, useClass: PrismaApiKeyRepository }
  ]
})
```

The feature is registered by the repository provider **and** `apiKeys.enabled`. Either one alone
fails at startup and says which is missing.

| Option                 | Default         | Meaning                                                                                                                                                                                                                                         |
| ---------------------- | --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pepper`               | — (required)    | The HMAC key every digest is computed under. As strong as `jwt.secret`, and refused if it equals `jwt.secret` (current or retired), `identifierKey` or an MFA key.                                                                              |
| `scopes`               | — (required)    | The closed vocabulary: letters, digits and `: . _ -`, up to 64 characters each.                                                                                                                                                                 |
| `header`               | `'x-api-key'`   | Where the key is read from. Never the query string. Lowercased. Never a header the library reads, such as `authorization`, `cookie`, `user-agent`, `origin` or the forwarded-address headers; also avoid one your own `tenantIdResolver` reads. |
| `prefix`               | `'bak'`         | Literal start of every issued key, for secret scanners. Lowercase letters and digits, 2 to 16, no underscore.                                                                                                                                   |
| `lastUsedFlushSeconds` | `60`            | How often coalesced `lastUsedAt` values are written, in one batch. 1 to 3600.                                                                                                                                                                   |
| `auditMode`            | `'best-effort'` | `'required'` awaits the audit hook and **denies** the request if it throws, and startup refuses it when the registered hooks plainly lack `onApiKeyRequest`. See [Audit](./docs/service-api-keys.md#audit).                                     |

### Protect a route

```typescript
// videos.controller.ts
import { Controller, Get, Post } from '@nestjs/common'
import { CurrentApiKey, ServiceKey } from '@bymax-one/nest-auth'
import type { ApiKeyPrincipal } from '@bymax-one/nest-auth'

@Controller('videos')
export class VideosController {
  @ServiceKey('read')
  @Get()
  list(@CurrentApiKey() key: ApiKeyPrincipal) {
    // key.id, key.label and key.scopes — and nothing secret.
    return { caller: key.label }
  }

  @ServiceKey('operate', 'publish-claim')
  @Post()
  publish() {
    // The key must hold BOTH scopes.
  }
}
```

`@ServiceKey(...scopes)` does three things in one decorator so they cannot be separated by
mistake: it declares the scopes, it lets the route past `JwtAuthGuard` and `JwtPlatformGuard`
(which skip a route carrying the public marker), and it binds `ApiKeyGuard`. **"Public" here
means "not a user route", never "unauthenticated"**: the key guard refuses a missing or invalid
key on every request, even with a global `JwtAuthGuard` registered.

- A key must hold **all** the scopes a route declares. There is no wildcard and no hierarchy:
  `admin` does not imply `read`, so grant both.
- The most specific declaration wins: a method's `@ApiKeyScopes` replaces its class's.
- **A route with no scope declaration is refused** (`403 auth.forbidden`) before any credential
  is read, so a forgotten declaration cannot become an open route. If you bind `ApiKeyGuard`
  globally, every route without a declaration is refused: that is the strict mode.
- A scope outside `apiKeys.scopes` stops the application at startup, not at the first request.
- Verification attaches `request.apiKey` and never `request.user`, so no user-session guard can
  mistake a machine for a person.

### Issue, revoke and rotate

The library mounts no controller: the admin surface is yours, and `ApiKeyService` is the
mechanism behind it.

```typescript
// keys-admin.controller.ts
import { Body, Controller, Delete, Param, Post } from '@nestjs/common'
import { ApiKeyService, JwtAuthGuard, Roles, RolesGuard } from '@bymax-one/nest-auth'
import { UseGuards } from '@nestjs/common'

@Controller('admin/keys')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles('admin')
export class KeysAdminController {
  constructor(private readonly keys: ApiKeyService) {}

  @Post()
  async issue(@Body() body: { label: string; scopes: string[] }) {
    const { key, record } = await this.keys.issue(body)
    // `key` is the plaintext. It is returned this once and cannot be retrieved again.
    return { key, record }
  }

  @Post(':id/rotate')
  rotate(@Param('id') id: string) {
    // The old key keeps working for an hour so the caller can switch without downtime.
    return this.keys.rotate(id, { overlapSeconds: 3600 })
  }

  @Delete(':id')
  revoke(@Param('id') id: string) {
    return this.keys.revoke(id)
  }
}
```

- `issue({ label, scopes, expiresAt? })`: the label is 1 to 128 characters with no control
  characters, `expiresAt` must be in the future, and every scope must come from the vocabulary.
  Failures answer `auth.validation`.
- Several active keys may share one label. **Rotation is that rule, not a special case**:
  `rotate(id, { overlapSeconds })` issues a second key with the same label and scopes, then
  retires the first after the overlap (`0` retires it at once; the maximum is
  `API_KEY_MAX_OVERLAP_SECONDS`). The new key is issued before the old one is retired,
  so a failure in between leaves both valid rather than neither. A revoked or expired key is
  not rotated (`auth.api_key_not_found`): that would re-issue access nobody holds.
- `revoke(id)` takes effect on the very next request: the row is read on every request, and
  there is no verification cache.

Everything else is in [Service API keys: reference](./docs/service-api-keys.md):

- **The repository** you implement (`IApiKeyRepository`): what each method must guarantee.
- **How a key is stored and checked**: `bak_<keyId>_<secret>`, only `HMAC-SHA-256(pepper, secret)`
  is stored, every key takes the same steps and every refusal answers `401 auth.api_key_invalid`.
  Changing the pepper makes every issued key unverifiable.
- **Audit**: implement `onApiKeyRequest` on your `IAuthHooks`; it fires for every guarded request,
  refused ones included. With `apiKeys.auditMode: 'required'` a throwing hook denies the request.
- **Logs and rate limiting**: the library never logs the key, but your HTTP logger sits outside it,
  so redact the key header there. Rate limiting is deliberately not built in; use
  `@nestjs/throttler` per address before the guard and per key after it.

## 🗂️ Workspaces (one identity, many workspaces)

For a product where one person belongs to several teams, each with its own role. The identity, its
sessions and its tokens do not change: a workspace role is resolved on each request, for the
workspace that request names, so switching workspace never needs a login and two workspaces can be
open in two tabs at once. Workspaces live inside a tenant. Nothing is registered until you opt in.

### Enable it

```typescript
import {
  BYMAX_AUTH_MEMBERSHIP_REPOSITORY,
  BYMAX_AUTH_WORKSPACE_REPOSITORY,
  BymaxAuthModule
} from '@bymax-one/nest-auth'

BymaxAuthModule.registerAsync({
  useFactory: () => ({
    jwt: { secret: process.env.JWT_SECRET ?? '' },
    roles: { hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] } },
    rateLimit: { clientIpSource: 'peer' },
    workspaces: {
      enabled: true,
      roles: {
        // Denormalized, like `roles.hierarchy`: each role lists every role it includes.
        hierarchy: { owner: ['admin', 'member'], admin: ['member'], member: [] },
        ownerRole: 'owner'
      }
    },
    controllers: { workspaces: true, workspaceInvitations: true }
  }),
  extraProviders: [
    // …BYMAX_AUTH_USER_REPOSITORY and BYMAX_AUTH_REDIS_CLIENT as usual
    { provide: BYMAX_AUTH_WORKSPACE_REPOSITORY, useClass: PrismaWorkspaceRepository },
    { provide: BYMAX_AUTH_MEMBERSHIP_REPOSITORY, useClass: PrismaMembershipRepository }
  ]
})
```

`controllers.workspaces` mounts the routes and needs `workspaces.enabled` and both repositories.
`controllers.workspaceInvitations` also needs an email provider that implements
`sendWorkspaceInvitation`, which the bundled `DefaultAuthEmailProvider` does. The module refuses to
boot when a piece is missing. With
`workspaces.enabled: false`, the default, nothing in this section exists in your application.

You implement two ports: `IWorkspaceRepository` (`createWithOwner`, `findById`, `rename`,
`updateStatus`) and `IMembershipRepository` (`find`, `listForUser`, `listForWorkspace`, `create`,
`changeRole`, `remove`, `removeAllForUser`, `transferOwnership`, `countOwned`, `listSoleOwned`). Every call carries the
tenant and the workspace. The writes that must not race (a role change, a removal, an ownership
transfer) are guarded writes the repository answers atomically, so two requests cannot both remove
the last owner.

### Options

| Option                               | Default                          | Meaning                                                                                                                                                                  |
| ------------------------------------ | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `roles.hierarchy`, `roles.ownerRole` | — (required)                     | The workspace role hierarchy, separate from `roles.hierarchy`. It must name the owner role, and the owner must include every other role.                                 |
| `permissions`                        | owner only                       | Which roles may `manageWorkspace` (rename), `deleteWorkspace` and `manageMembers`; `viewMembers` defaults to every active member.                                        |
| `allowCreate`                        | `true`                           | Whether an identity may create a workspace: a flag, or a function of the user.                                                                                           |
| `maxWorkspacesPerUser`               | `0`                              | Most workspaces one identity may own; `0` is unlimited. The check is advisory under concurrency; the repository's create call receives the value for an exact cap.       |
| `invitationTtlSeconds`               | `604800`                         | How long an invitation stays valid. Up to `2592000`.                                                                                                                     |
| `maxPendingInvitationsPerWorkspace`  | `100`                            | Most pending invitations one workspace may hold.                                                                                                                         |
| `membershipCacheTtlSeconds`          | `60`                             | How long a resolved membership is cached; `0` always reads the repository. Up to `3600`. A host that changes memberships outside the library must invalidate or set `0`. |
| `deletionGraceDays`                  | `14`                             | Days a deleted workspace can be restored; `0` deletes at once.                                                                                                           |
| `accessDeniedEvents`                 | `{ max: 10, windowSeconds: 60 }` | Bounds the `access.denied` events one account can cause. The access decision is never affected.                                                                          |
| `resolveRequestWorkspace`            | the route                        | Reads the workspace from a request when the host does not carry it in the route. Never from the body.                                                                    |
| `resolveWsWorkspace`                 | `data.workspaceId`               | Reads the workspace a socket message names, from the message body and nothing else.                                                                                      |

`registration: 'invitation-only'` closes sign-up except through an invitation for that exact address
(password registration and the OAuth `create` action answer `403 auth.registration_closed`; the
invitation accept routes stay open; existing accounts keep signing in). Startup refuses the mode unless an
invitation controller is mounted (`controllers.workspaceInvitations` with `workspaces.enabled`, or
`controllers.invitations` with `invitations.enabled`), and names what is missing.

### Protect a route

```typescript
@UseGuards(JwtAuthGuard, UserStatusGuard, WorkspaceGuard)
@Controller('workspaces/:workspaceId/projects')
export class ProjectsController {
  @Get()
  @WorkspaceRoles(ANY_WORKSPACE_MEMBER)
  list(@CurrentWorkspace() workspace: CurrentWorkspaceContext) {
    // workspace.tenantId, workspace.workspaceId, workspace.userId, workspace.role
  }

  @Delete(':id')
  @WorkspaceRoles('admin')
  remove(@CurrentWorkspace() workspace: CurrentWorkspaceContext) {}
}
```

`WorkspaceGuard` is default-deny. In order it: refuses a route that declares neither
`@WorkspaceRoles(...)` nor `@WorkspacePermission(...)` (`403 auth.forbidden`, so a forgotten
decorator closes the route); accepts only a dashboard token, never a platform one; takes the
workspace from the route or `resolveRequestWorkspace`, never the body and never a remembered
default; resolves the caller's membership with the tenant from the token; and checks the role through
the hierarchy. A workspace that does not exist, one that is not active and one the caller does not
belong to all answer `404 auth.workspace_not_found`, so the answer reveals nothing about which
workspaces exist. An insufficient role answers `403 auth.insufficient_workspace_role`. The owner of a
workspace pending deletion gets `409 auth.workspace_pending_deletion`, except on a route marked
`@AllowPendingWorkspace()`. A service takes its workspace from `@CurrentWorkspace()` and never from a
DTO or a query.

A transport with no guard in front of it uses the same decision: `WsWorkspaceGuard` and
`@CurrentWsWorkspace()` for a gateway, `AuthTokenVerifierService.verifyAccessToken(token, { plane:
'dashboard', workspace })` for a stream, and `stampJobContext` with
`WorkspaceAccessService.assertStillAuthorized` for a job that must re-check the caller before it
writes. `workspaceScopedName` builds cache keys and room names that two workspaces cannot share.

### Routes

With `controllers.workspaces: true`; every `:workspaceId` is a path segment, never a body field or a
header.

| Route                                        | Method         | Meaning                                                            |
| -------------------------------------------- | -------------- | ------------------------------------------------------------------ |
| `workspaces`                                 | GET / POST     | The caller's workspaces and the last one they switched to / create |
| `workspaces/:workspaceId/access`             | GET            | The workspace and the caller's role in it                          |
| `workspaces/:workspaceId/switch`             | POST           | Record it as the last active one; no token changes                 |
| `workspaces/:workspaceId`                    | PATCH          | Rename                                                             |
| `workspaces/:workspaceId/schedule-deletion`  | POST           | Schedule deletion, re-proving the caller with the password         |
| `workspaces/:workspaceId/restore`            | POST           | Undo it within the grace period                                    |
| `workspaces/:workspaceId/members`            | GET            | List members                                                       |
| `workspaces/:workspaceId/members/:userId`    | PATCH / DELETE | Change a role / remove a member                                    |
| `workspaces/:workspaceId/leave`              | POST           | Leave                                                              |
| `workspaces/:workspaceId/transfer-ownership` | POST           | Hand ownership over, re-proving the caller                         |

With `controllers.workspaceInvitations: true`: `POST` and `GET workspaces/:workspaceId/invitations`
(invite, list pending), `POST .../invitations/resend` and `.../invitations/revoke`, and the
token-based `POST workspaces/invitations/preview` (public), `.../accept` (the signed-in account the
invitation was addressed to) and `.../accept-signup` (public, creates the account). On these routes
the token travels in a POST body, never in a query string. The one exception is the OAuth sign-in
start, `GET /oauth/:provider?workspaceInvitation=<token>`: it stores only the token's sha256 in the
state record and answers with `Referrer-Policy: no-referrer`. On your accept page, put the token in
the URL fragment and set `Referrer-Policy: no-referrer` there.

A revoke, here and on the tenant's `POST /invitations/revoke`, whose invitation is replaced by a
newer one while it is read or before it is removed reads the address again and applies the role
ceiling to the record it finds.
A tenant invite stores the record and the invitee index in one step, and a tenant revoke removes
them in one step, so a failed command never leaves one without the other.
When the invitation changes during each attempt to remove it, the revoke answers `429`
`auth.too_many_requests`; the caller can try again.

### Frontend

```typescript
// client — a separate factory, so a frontend that does not use workspaces does not ship it
import { createWorkspaceClient } from '@bymax-one/nest-auth/client'
const workspaces = createWorkspaceClient({ baseUrl: '/api' })
```

```tsx
// react — inside <AuthProvider>
<WorkspaceProvider client={workspaces} activeWorkspaceId={params.workspaceId} hierarchy={...}>
  <App />
</WorkspaceProvider>
// const { memberships, activeWorkspace, switchWorkspace, hasWorkspaceRole, status } = useWorkspaces()
```

The active workspace is the URL's, else the one chosen with `switchWorkspace`, else the server's
`lastActiveWorkspaceId`; never `localStorage`. The provider stores what it loads with the account it
was read for, so a different account never reads another's list. `hasWorkspaceRole` is a hint for
what to render and carries no authority; the server decides. `onWorkspaceChanged` and
`onWorkspaceAccessLost` are options; call `handleWorkspaceError(workspaceId, error)` from your own
catch to feed the latter. Other tabs reload their lists through a `BroadcastChannel`, and a tab that
is signed out makes no request.

```typescript
// nextjs — a server-only reader for a /w/[workspaceId] layout, cached per request
import { createWorkspaceAccessReader } from '@bymax-one/nest-auth/nextjs'
export const getWorkspaceAccess = createWorkspaceAccessReader({ apiBase })
// { workspace, role } for a 200; null for 403, 404 and 409, so call notFound()
```

`createAuthProxy` accepts `lastWorkspaceCookie`: set a cookie yourself after `listWorkspaces()`
(`HttpOnly; Secure; SameSite=Lax`) and `getDefaultDashboard(role, hint)` receives
`{ lastActiveWorkspaceId }` only when the cookie holds a UUID, `{}` otherwise. The library never
writes the cookie and the value carries no authority; the layout's reader decides. The proxy strips
an inbound `x-workspace-id` and never sets one. Path values go through `fillRoute` and `pathSegment`
(`./shared`), which refuse an empty value, `.` and `..` and percent-encode the rest.

### Hooks, account deletion and the threat model

`beforeWorkspaceCreate` can refuse a creation and `onWorkspaceEvent` reports what happens, best-effort.
A host that deletes a user must call `MembershipService.removeAllForUser(tenantId, userId,
actorUserId, context)` first; it refuses with `409 auth.last_owner` while the account is the only
owner of an active or suspended workspace. A workspace id is never trusted from the body, a header
or a stored default, and non-members and nonexistent workspaces are indistinguishable. All of it is in
[Workspaces: reference](./docs/workspaces.md).

---

## 📊 Observability

The flows count what they do whether or not anything publishes it: the module registers `AuthMetricsTally`, a few integer counts keyed by closed sets, and the optional `@bymax-one/nest-auth/observability` subpath reads them. It needs `prom-client` and a metrics registry that discovers contributors by the `bymax-one:metrics-contributor` metadata key (`@bymax-one/nest-core` >= 1.6.15 does); the package itself imports no other Bymax library.

```ts
import { AuthMetrics, AuthRedisHealthIndicator } from '@bymax-one/nest-auth/observability'

@Module({
  imports: [BymaxAuthModule.registerAsync({/* ... */})],
  providers: [AuthMetrics, AuthRedisHealthIndicator] // discovered by the metrics and health modules
})
export class ObservabilityModule {}
```

### Metrics

Every label is a member of a closed set, a sample exists for each plane and outcome from the first scrape, and no id, tenant, user, address or message is ever a label. `plane` is `dashboard` or `platform`.

| Name                                   | Type    | Labels             | Meaning                                                                                                   |
| -------------------------------------- | ------- | ------------------ | --------------------------------------------------------------------------------------------------------- |
| `bymax_auth_logins_total`              | counter | `plane`, `outcome` | Login attempts. `outcome`: `success`, `invalid_credentials`, `locked`, `mfa_required`, `blocked`          |
| `bymax_auth_refresh_total`             | counter | `plane`, `outcome` | Refresh attempts. `outcome`: `rotated`, `reuse_detected`, `expired`, `invalid`                            |
| `bymax_auth_mfa_verifications_total`   | counter | `plane`, `outcome` | MFA challenges. `outcome`: `success`, `invalid` (a wrong code, or a token that does not verify), `locked` |
| `bymax_auth_bruteforce_lockouts_total` | counter | none               | Identifiers locked out after too many failures, counted once at the failure that reaches the threshold    |

A login that ends any other way (an unverified address, a server error) is not counted. `POST /mfa/challenge` serves both planes, so its `plane` is the plane of the session it ends with and, for a refused challenge, the plane of the token it verified; a token that does not verify (counted as `invalid`) has no plane and counts as `dashboard`. `reuse_detected` is a refresh that presented an already-consumed token; `expired` is a session past `jwt.absoluteSessionLifetimeDays`. The caller receives the same `auth.refresh_token_invalid` for every refused refresh.

### Spans

With `@opentelemetry/api` installed and an SDK registered, each of these routes runs inside a span carrying `bymax.auth.plane`, except `POST /mfa/challenge`, which serves both planes and whose span names none because the token decides it; without them nothing is created. A failed span carries the library error code (`auth.invalid_credentials`) and never the message.

| Span                  | Routes                                                            |
| --------------------- | ----------------------------------------------------------------- |
| `auth.login`          | `POST /login`, `POST /platform/login`                             |
| `auth.refresh`        | `POST /refresh`, `POST /platform/refresh`                         |
| `auth.mfa.verify`     | `POST /mfa/challenge`, `POST /platform/mfa/challenge`             |
| `auth.password_reset` | `POST /password/forgot-password`, `POST /password/reset-password` |

### Readiness

`AuthRedisHealthIndicator` (name `auth-redis`) asks the Redis client the module was given for a `PING`: one round trip, nothing written, no detail reported. It gives up after 4 seconds, under the 5 seconds the readiness aggregator of `@bymax-one/nest-core` waits by default, or as soon as the aggregator's signal aborts, and probes that arrive while a `PING` is still pending share it, so a store that never answers is asked at most once per 4-second window rather than once per probe; a `PING` that has outlived the timeout is dropped and the next probe sends a fresh one, so readiness recovers when the store does. `AuthHealthProbe` is the same question for a host that wires its own check. A `PING` the client fails is rejected with the library's own `Error`, `The authentication store failed the PING.`, naming in parentheses the code of the error reply (`WRONGPASS`, `LOADING`) or the kind of outage (`closed`, `unreachable`) when the client's error names one. The client's error, message, command and `cause` are not forwarded.

### Log events

The flows write each event as one object through the plain Nest `Logger`: `{ ...fields, event, message }`, so a field can never replace the code or the message. The `event` is a code from the table, the `message` is the library's own text for it (the Message column), and every field is a closed value, a library-made id or `detail`, a description the library composed of a failure.

Who an event may name is split by what it records. A **success or audit event** (level `log`) may carry `userId` and `tenantId` as declared fields, because an audit trail without "who" is useless; these are the ids of your own database, and `actorUserId` is the user who performed an invitation. A **refusal or failure** names no user and no tenant, because a log that says which account was refused lets whoever reads it enumerate accounts; the refresh reuse events carry `familyId`, the lineage of a refresh token, which is library-made. No event of any level carries an email address, a provider name, an IP address, a token or a code, and no text a host or a store wrote. `detail` is never the `Error` the host or the store threw, because a relay can quote the code it was sent; it is the library's description of the failure (`describeChannelStatus`), which drops the channel's text. A spec pins both halves of this: the catalog lists only the field names above, only `log` events name a user or a tenant, and no logger call in the library writes an identity as text.

A Nest `Logger` calls the host logger and discards what it returns, so a host logger that throws synchronously cannot change what the flow does (the throw is swallowed), while a host logger that is asynchronous and rejects is the host's own unhandled rejection. Measured: behind a Nest `Logger` that rejection is not caught anywhere, and it ends the process with exit code 1 unless your application handles `unhandledRejection`. Make a host logger synchronous, or handle `unhandledRejection` at the process level.

| Code                                  | Level | Message                                                                                 | When                                                                                                                                                               | Fields                               |
| ------------------------------------- | ----- | --------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------ |
| `AUTH_LOGIN_LOCKED`                   | warn  | login: account locked                                                                   | A login is refused because the account is at its failure ceiling                                                                                                   | `plane`                              |
| `AUTH_LOGIN_INVALID_CREDENTIALS`      | warn  | login: invalid credentials                                                              | A login is refused for a wrong password (the platform plane also writes it for an unknown account)                                                                 | `plane`                              |
| `AUTH_MFA_CODE_INVALID`               | warn  | MFA: invalid code                                                                       | An MFA code is refused (flow: challenge, enable, disable, recovery_codes)                                                                                          | `plane`, `flow`                      |
| `AUTH_MFA_LOCKED`                     | warn  | MFA: account locked                                                                     | An MFA step is refused because the account is at its failure ceiling (flow: challenge, disable, recovery_codes)                                                    | `plane`, `flow`                      |
| `AUTH_MFA_RESET`                      | warn  | MFA: removed administratively                                                           | An administrator removes the MFA factor of an account                                                                                                              | `plane`                              |
| `AUTH_PASSWORD_REJECTED`              | warn  | the current password was rejected                                                       | A password re-proof is refused (flow: change_password, email_change)                                                                                               | `flow`                               |
| `AUTH_ACCOUNT_LOCKED`                 | warn  | account locked                                                                          | A password re-proof is refused because the account is at its failure ceiling (flow: change_password, email_change, reauthentication)                               | `flow`                               |
| `AUTH_REAUTHENTICATION_REFUSED`       | warn  | reauthentication refused                                                                | A sensitive action is refused for lack of a recent authentication (reason: no_recent_authentication)                                                               | `plane`, `reason`                    |
| `AUTH_REFRESH_REUSE_DETECTED`         | warn  | refresh: reuse of a consumed token detected, revoking its family                        | A refresh token that was already exchanged is presented again                                                                                                      | `plane`, `familyId`                  |
| `AUTH_REFRESH_FAMILY_REVOKED`         | warn  | refresh: token family revoked after reuse detection                                     | The family of a reused refresh token has been revoked                                                                                                              | `plane`, `familyId`                  |
| `AUTH_REFRESH_REFUSED`                | warn  | refresh: no valid session or grace window found                                         | A refresh token matches no live session and no grace window                                                                                                        | `plane`                              |
| `AUTH_SESSION_LIFETIME_EXCEEDED`      | warn  | refresh: the session has outlived the absolute lifetime cap                             | A rotation is refused because the login it descends from is older than jwt.absoluteSessionLifetimeDays                                                             | none                                 |
| `AUTH_TOKEN_REVOCATION_REFUSED`       | warn  | a dashboard token carrying no tenant is refused without a store read                    | A revocation check cannot name the epoch key of a token (reason: missing_tenant)                                                                                   | `reason`                             |
| `AUTH_WS_TICKET_REFUSED`              | warn  | ws-ticket: refused                                                                      | A WebSocket ticket is refused (reason: mfa_not_satisfied, no_life_left, unknown_or_used, session_revoked, expired, tenant_mismatch, account_gone, account_blocked) | `reason`                             |
| `AUTH_OAUTH_STATE_REFUSED`            | warn  | oauth: callback state refused                                                           | An OAuth callback is refused (reason: not_bound, provider_mismatch, invalid_or_expired, unparseable)                                                               | `reason`                             |
| `AUTH_OTP_STORE_FAILED`               | error | email verification: the code could not be stored                                        | The store refuses the write of an email-verification code                                                                                                          | `detail`                             |
| `AUTH_IDENTIFIER_REFUSED`             | error | brute-force: an identifier was refused                                                  | An identifier passed to the lockout counter is not usable (reason: forbidden_characters, too_long)                                                                 | `reason`                             |
| `AUTH_LOGIN_SUCCEEDED`                | log   | login: succeeded                                                                        | A login completes and its tokens are issued (via: password, oauth)                                                                                                 | `plane`, `userId`, `tenantId`, `via` |
| `AUTH_LOGIN_MFA_CHALLENGED`           | log   | login: MFA challenge issued                                                             | A login is answered with an MFA challenge instead of tokens (via: password, oauth)                                                                                 | `plane`, `userId`, `tenantId`, `via` |
| `AUTH_LOGOUT`                         | log   | logout                                                                                  | A session is logged out; the user id is left out when no live session was found                                                                                    | `plane`, `userId`                    |
| `AUTH_USER_REGISTERED`                | log   | register: user registered                                                               | A registration, or an OAuth login that creates one, makes an account (via: password, oauth)                                                                        | `userId`, `tenantId`, `via`          |
| `AUTH_TOKENS_ISSUED`                  | log   | tokens issued for an existing user                                                      | The host asks the library to issue tokens for a user id it has already authenticated                                                                               | `userId`, `tenantId`                 |
| `AUTH_EMAIL_VERIFIED`                 | log   | email verified                                                                          | The email address of an account is verified                                                                                                                        | `userId`, `tenantId`                 |
| `AUTH_ACCOUNT_UNLOCKED`               | log   | lockout cleared by an administrator                                                     | An administrator clears the lockout of an account                                                                                                                  | `tenantId`                           |
| `AUTH_EMAIL_CHANGE_REQUESTED`         | log   | email change: verification sent                                                         | A verification is sent for a requested email change                                                                                                                | `userId`                             |
| `AUTH_EMAIL_CHANGED`                  | log   | email change: address changed                                                           | An email change is confirmed                                                                                                                                       | `userId`                             |
| `AUTH_INVITATION_CREATED`             | log   | invitation created                                                                      | An invitation is created (actorUserId: the inviter)                                                                                                                | `tenantId`, `actorUserId`            |
| `AUTH_INVITATION_REVOKED`             | log   | invitation withdrawn                                                                    | An invitation is withdrawn (actorUserId: who withdrew it)                                                                                                          | `tenantId`, `actorUserId`            |
| `AUTH_INVITATION_ACCEPTED`            | log   | invitation accepted                                                                     | An invitation is accepted and the account joins the tenant                                                                                                         | `userId`, `tenantId`                 |
| `AUTH_MFA_CHALLENGE_PASSED`           | log   | MFA: challenge passed                                                                   | An MFA challenge is answered correctly                                                                                                                             | `plane`, `userId`                    |
| `AUTH_MFA_SETUP_STARTED`              | log   | MFA: setup initiated                                                                    | An MFA setup is started                                                                                                                                            | `plane`, `userId`                    |
| `AUTH_MFA_ENABLED`                    | log   | MFA: enabled                                                                            | An MFA factor is confirmed and enabled                                                                                                                             | `plane`, `userId`                    |
| `AUTH_MFA_DISABLED`                   | log   | MFA: disabled                                                                           | An MFA factor is disabled by its owner                                                                                                                             | `plane`, `userId`                    |
| `AUTH_MFA_RECOVERY_CODES_REGENERATED` | log   | MFA: recovery codes regenerated                                                         | The recovery codes of an account are replaced                                                                                                                      | `plane`, `userId`                    |
| `AUTH_MFA_NOTHING_TO_RESET`           | log   | MFA: no second factor to remove                                                         | An administrator resets the MFA of an account that has no factor                                                                                                   | `plane`, `userId`                    |
| `AUTH_WS_TICKET_ISSUED`               | log   | ws-ticket: issued                                                                       | A WebSocket ticket is issued                                                                                                                                       | `userId`, `tenantId`                 |
| `AUTH_REHASH_SKIPPED`                 | log   | rehash on verify skipped: the stored hash changed                                       | A password rehash after a successful login is skipped because the stored hash changed in the meantime                                                              | none                                 |
| `AUTH_LOCKOUT_STATE_UNREADABLE`       | warn  | login: lockout state unreadable for the onLockout hook                                  | The lockout state cannot be read when the onLockout hook is about to run                                                                                           | `detail`                             |
| `AUTH_EMAIL_CHANGE_TOKEN_STALE`       | warn  | email change: the token is no longer bound to the account password                      | A confirmation is refused because the password changed after the token was issued                                                                                  | none                                 |
| `AUTH_PASSWORD_RESET_TOKEN_STALE`     | warn  | password reset: the token was issued against a password that has since changed          | A reset is refused because the password changed after the token was issued                                                                                         | none                                 |
| `AUTH_MFA_SETUP_KEY_CONSUMED`         | warn  | MFA: the setup key was consumed by a concurrent request                                 | Two requests race to confirm the same MFA setup and one loses                                                                                                      | none                                 |
| `AUTH_INVITATION_REFUSED`             | warn  | invitation: refused                                                                     | An invitation is refused (reason: outranked, changed_under_rank_check, revoke_outranked, inviter_cannot_grant)                                                     | `reason`                             |
| `AUTH_OAUTH_CREATE_REFUSED`           | warn  | oauth: create refused, the account already exists                                       | An OAuth profile would create an account that already exists in the tenant                                                                                         | none                                 |
| `AUTH_OAUTH_PROVIDER_ERROR`           | warn  | oauth: the provider returned an error on the callback                                   | The provider redirects back with an error instead of a code (error: an RFC 6749 code, or other)                                                                    | `error`                              |
| `AUTH_OAUTH_EXCHANGE_FAILED`          | error | oauth: the code exchange or profile fetch failed                                        | The plugin fails during the code exchange or the profile fetch                                                                                                     | `detail`                             |
| `AUTH_DELIVERY_FAILED`                | error | delivery failed                                                                         | A notification cannot be delivered (kind: the notification that failed)                                                                                            | `kind`, `detail`                     |
| `AUTH_PASSWORD_RESET_ROLLBACK_FAILED` | error | password reset: the rollback delete failed                                              | The stored reset token cannot be deleted after its delivery failed                                                                                                 | `detail`                             |
| `AUTH_SESSION_EVICTION_SKIPPED`       | error | session limit: eviction skipped                                                         | A session record cannot be read while the session limit is enforced                                                                                                | `detail`                             |
| `AUTH_SESSION_EVICTION_FAILED`        | error | session limit: eviction failed                                                          | An evicted session cannot be removed while the session limit is enforced                                                                                           | `detail`                             |
| `AUTH_SESSION_LIMIT_RESOLVER_INVALID` | error | session limit: maxSessionsResolver returned a value that is not a positive whole number | The answer of the resolver is unusable and defaultMaxSessions applies                                                                                              | none                                 |
| `AUTH_EMAIL_NOT_SENT`                 | log   | no-op email provider: nothing was sent                                                  | The no-op provider receives a message to deliver (kind: the method called)                                                                                         | `kind`                               |
| `AUTH_MFA_SETUP_PAYLOAD_INVALID`      | warn  | MFA: a stored payload is not valid JSON                                                 | A stored MFA payload cannot be parsed (kind: setup, recovery_codes)                                                                                                | `kind`                               |
| `AUTH_HOOK_FAILED`                    | error | a hook or a fire-and-forget step failed                                                 | A hook, or a step that runs beside a flow such as the last-login write, fails (how: threw, rejected)                                                               | `hook`, `how`                        |
| `AUTH_STORE_FAILED`                   | error | a store or repository operation failed                                                  | A store or repository operation fails and the flow reports it (operation: the named step)                                                                          | `operation`, `detail`                |
| `AUTH_STORE_DEGRADED`                 | warn  | a store or repository operation failed and the flow went on                             | A store or repository operation fails and the flow goes on without it (operation: the named step)                                                                  | `operation`, `detail`                |
| `AUTH_RECORD_INVALID`                 | warn  | a stored record is not valid                                                            | A stored record cannot be parsed (record: stored_invitation, reset_context, session_json)                                                                          | `record`                             |
| `AUTH_PROVIDER_MISSING`               | warn  | no email provider is configured                                                         | A flow needs the email provider and none is configured (flow: email_verification_otp, password_reset_token, password_reset_otp)                                    | `flow`                               |
| `AUTH_BREACH_CHECK_UNAVAILABLE`       | warn  | the breach check did not answer and the password was admitted                           | The breach checker does not answer (reason: unavailable, unreachable, threw)                                                                                       | `reason`                             |
| `AUTH_API_KEY_REFUSED`                | error | api key: refused                                                                        | An API-key route is refused for a configuration the host must fix (reason: unscoped_route, audit_hook_missing)                                                     | `reason`                             |
| `AUTH_TENANT_SCOPE_VIOLATED`          | warn  | login: the repository returned an account outside the requested tenant                  | The user repository returns an account of another tenant, so findByEmail does not scope by its tenant argument                                                     | none                                 |
| `AUTH_UNHANDLED_EXCEPTION`            | error | unhandled exception                                                                     | An exception reaches the library's filter (surface: http, ws)                                                                                                      | `surface`, `detail`                  |

#### Discriminators

The fields that name a step come from sets the library owns, typed in the code and listed here; none is ever text a host or a store wrote.

- **`hook`** of `AUTH_HOOK_FAILED`: `beforeRegister`, `afterRegister`, `beforeLogin`, `afterLogin`, `afterLogout`, `afterPlatformLogout`, `onLoginFailed`, `onLockout`, `onRefreshTokenReuseDetected`, `afterMfaEnabled`, `afterMfaDisabled`, `afterMfaRecoveryCodesRegenerated`, `onNewSession`, `afterEmailVerified`, `afterPasswordReset`, `onOAuthLogin`, `afterInvitationAccepted`, `onSessionEvicted`, `onSessionsRevoked`, `onApiKeyRequest`, `beforeWorkspaceCreate`, `onWorkspaceEvent`, `updateLastLogin`, `accessDenied`, `maxSessionsResolver`.
- **`operation`** of `AUTH_STORE_FAILED` and `AUTH_STORE_DEGRADED`: `account_status_cache_write`, `api_key_last_used_flush`, `api_key_lookup`, `cache_invalidation`, `dead_member_prune`, `grace_pointer_prune`, `logout_marker_clear`, `logout_owner_keep`, `mfa_lock_release`, `mfa_reencryption`, `new_session_user_lookup`, `redis` (a failed call of the Redis store that is not an outage; written `redis:<family>`, such as `redis:rl`, `redis:lf` or `redis:ep`, when the first key the command names has a family), `rehash_on_verify`, `resend_cooldown_release`, `reset_account_lookup`, `reset_cooldown_release`, `reset_cooldown_store`, `reset_issue`, `session_cleanup`, `session_detail_read`, `session_detail_rotation`, `session_record_read`, `workspace_cache_read`, `workspace_cache_write`.
- **`kind`** of `AUTH_DELIVERY_FAILED`: `passwordResetToken`, `passwordResetOtp`, `emailVerificationOtp`, `passwordChanged`, `emailChangeVerification`, `emailChanged`, `mfaEnabled`, `mfaDisabled`, `newSessionAlert`, `invitation`, `workspaceInvitation`, `email_verification_otp`, `password_changed_notice`, `password_reset_token`, `password_reset_otp`, `mfa_enabled_notice`, `mfa_disabled_notice`, `mfa_reset_notice`, `email_change_notice`.

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

Access tokens are short-lived (default 15 minutes) and immediately revocable: a Redis JTI blacklist refuses one token, and an entry keyed by the token's `sid` refuses every access token of a session that ended and leaves the account's other sessions alone. Refresh tokens rotate on every use with a configurable grace window to handle concurrent requests. This is the industry-standard hybrid approach used by Auth0, Okta, and SuperTokens — combining short lifetimes for low-latency revocation with rotating refresh tokens for session continuity.

### A Process That Changes Its Own Built-ins

Code running in your process can plant a key on `Object.prototype` or replace a built-in after the library loaded (`Array.prototype.some`, `Map.prototype.get`, `crypto.timingSafeEqual`, `Reflect.getMetadata`). A role check, a revocation lookup, a token signature check and an `@Public()` route are all decided with such built-ins, so the library does not decide with a runtime it cannot vouch for.

- The primitives the library calls itself (the comparisons of secrets, the digests, the random bytes, `JSON.parse` and `JSON.stringify`) are taken once, when the module loads.
- What it cannot copy (the functions the JWT libraries read at each call: `node:crypto` and the `Hash`, `Hmac`, `Sign` and `Verify` objects it hands back, `JSON.parse` and `JSON.stringify`, `Buffer`; `Reflector`; the methods of arrays, strings, maps and sets that the guards and services decide with) is recorded when the module loads and compared whenever a decision is made: at the entry of a verification, a signature, a hash and a cookie, at the start of each guard that decides, and again after each lookup a guard or a service waits for.
- A call made while one of them differs, or while a key is planted on `Object.prototype`, is refused with `auth.internal` (HTTP 500) and a count, never a name. A refusal is not turned into another answer, so a polluted process answers 500 and does not look like every token being invalid.

The trade-off: a monitoring agent, polyfill or test double that **replaces** one of the recorded functions after the library loaded makes the library refuse until it is put back. Only the functions the library's sources call or read are recorded, so a function nothing calls can be patched freely, and `Promise`, `Date`, `Intl` and the timers (which test doubles replace) are never compared. Load such a patch before the library, or have it wrap without replacing the recorded functions.

The set is the union of what the library's sources call and what the JWT chain (`@nestjs/jwt`, `jsonwebtoken`, `jws`, `jwa` and their dependencies) reads, found by a test that reads the installed packages, so it is exact for the versions the library is tested with; a newer version of those packages that reads another built-in is covered once the list is updated.

The boundary: the library checks the runtime's own built-ins (JavaScript globals and their prototypes, and the `node:*` modules). A host that replaces exports of `jsonwebtoken`, `jws` or `jwa` after load is outside what the library checks: that is code targeting a dependency, the same class as replacing the library itself.

### Security Checklist

When integrating `@bymax-one/nest-auth` in production, verify each of the following:

- `cookies.resolveDomains` MUST validate against an allowlist of configured domains
- MFA recovery without TOTP requires admin intervention (no self-service)
- `@MaxLength(128)` on password DTOs prevents algorithmic-DoS via oversized scrypt inputs
- JWT algorithm pinning to HS256 prevents algorithm-confusion attacks
- Constant-time comparisons via `crypto.timingSafeEqual` for all secret comparisons
- HttpOnly cookies; `Secure` enforced in production; `SameSite=Lax` by default on the access and
  session-signal cookies, so the OAuth provider's cross-site redirect back to your app still
  carries them. The refresh cookie is `Strict` under `lax` and `strict`, and `None` only when
  you configure `cookies.sameSite: 'none'`.
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
| Cookies            | HttpOnly, Secure, SameSite=Lax (override to `strict`), refresh cookie Strict, path-scoped              |
| Brute-Force        | Redis atomic counters per HMAC(email, identifier key)                                                  |
| CSRF (OAuth)       | 64-char hex state nonce, single-use via `getdel()`                                                     |
| Refresh Rotation   | Single-use tokens with a grace window; a replay past it revokes that login's whole family lineage      |
| Cross-Site Writes  | `Origin` / `Sec-Fetch-Site` check on cookie-authenticated writes — the gap `SameSite=None` leaves open |
| Breached Passwords | Optional Have I Been Pwned range check by k-anonymity; only a 5-char SHA-1 prefix leaves the process   |
| Rate Limiting      | Per-IP fixed-window counters in Redis, keyed by `HMAC(ip)` — enforced by the library, not by the host  |
| Session Lifetime   | Optional absolute cap on how long one login can be extended by rotation                                |

---

## 🧱 Tech Stack

<p>
  <img src="https://img.shields.io/badge/NestJS-11-E0234E?style=flat-square&logo=nestjs&logoColor=white" alt="NestJS" />
  <img src="https://img.shields.io/badge/TypeScript-strict-3178C6?style=flat-square&logo=typescript&logoColor=white" alt="TypeScript" />
  <img src="https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react&logoColor=black" alt="React" />
  <img src="https://img.shields.io/badge/Next.js-16-000000?style=flat-square&logo=next.js&logoColor=white" alt="Next.js" />
  <img src="https://img.shields.io/badge/Node.js-24%2B-339933?style=flat-square&logo=node.js&logoColor=white" alt="Node.js" />
  <img src="https://img.shields.io/badge/Redis-7%2B-DC382D?style=flat-square&logo=redis&logoColor=white" alt="Redis" />
  <img src="https://img.shields.io/badge/Jest-30-C21325?style=flat-square&logo=jest&logoColor=white" alt="Jest" />
</p>

---

## 🧪 Testing & Quality

Authentication is critical infrastructure, so the suite is held to a bar beyond "it runs" — every behavior is pinned so that a regression **fails a test**.

- ✅ **100% line coverage** — statements, branches, functions, and lines, enforced as a release gate across unit + e2e
- ✅ **100% mutation score** — verified with [Stryker](https://stryker-mutator.io/) against a `break` threshold of 100, **no survivors and nothing left uncovered** (the latest cold measurement is in [docs/mutation_testing_results.md](./docs/mutation_testing_results.md))
- ✅ **Thousands of tests** — unit and end-to-end, spanning all five subpaths
- ✅ **Every equivalent mutant documented** — each mutant that no test can kill (a redundant guard, a dependency array of stable references) carries an inline `// Stryker disable` with the reason, so the score is an accounting rather than a number

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
| POST   | `/logout`                      | Public (reads both credentials)    | Revoke the session and its access tokens                    |
| POST   | `/refresh`                     | Public (refresh cookie or body)    | Rotate refresh token, issue new access token                |
| GET    | `/me`                          | `JwtAuthGuard`                     | Current dashboard user payload                              |
| POST   | `/ws-ticket`                   | `JwtAuthGuard`, `UserStatusGuard`  | Mint a single-use ticket for a WebSocket upgrade            |
| POST   | `/verify-email`                | Public                             | Verify email with OTP                                       |
| POST   | `/resend-verification`         | Public                             | Resend email-verification OTP                               |
| POST   | `/password/forgot-password`    | Public                             | Request password reset (token or OTP)                       |
| POST   | `/password/reset-password`     | Public                             | Submit new password with reset token                        |
| POST   | `/password/verify-otp`         | Public                             | Verify password-reset OTP                                   |
| POST   | `/password/resend-otp`         | Public                             | Resend password-reset OTP                                   |
| POST   | `/mfa/setup`                   | `JwtAuthGuard`, `UserStatusGuard`  | Generate TOTP secret and recovery codes                     |
| POST   | `/mfa/verify-enable`           | `JwtAuthGuard`, `UserStatusGuard`  | Confirm setup and enable MFA                                |
| POST   | `/mfa/challenge`               | Public + `@SkipMfa()`              | Submit TOTP/recovery code after login                       |
| POST   | `/mfa/disable`                 | `JwtAuthGuard`, `UserStatusGuard`  | Disable MFA for the current user                            |
| POST   | `/mfa/recovery-codes`          | `JwtAuthGuard`, `UserStatusGuard`  | Replace the recovery codes, proving a fresh OTP             |
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
| POST   | `/platform/logout`             | Public (refresh token in body)     | Revoke the session and its access tokens                    |
| POST   | `/platform/refresh`            | Public (refresh token in body)     | Rotate the platform refresh token                           |
| DELETE | `/platform/sessions`           | `JwtPlatformGuard`                 | Revoke all platform sessions                                |
| POST   | `/platform/mfa/setup`          | `JwtPlatformGuard`                 | Generate the admin's TOTP secret and recovery codes         |
| POST   | `/platform/mfa/verify-enable`  | `JwtPlatformGuard`                 | Confirm setup and enable MFA for the admin                  |
| POST   | `/platform/mfa/disable`        | `JwtPlatformGuard`                 | Disable the admin's MFA, proving a fresh OTP                |
| POST   | `/platform/mfa/recovery-codes` | `JwtPlatformGuard`                 | Replace the admin's recovery codes                          |
| POST   | `/password/change`             | `JwtAuthGuard` + `UserStatusGuard` | Change the password, proving the current one                |
| GET    | `/oauth/:provider`             | Public + `@SkipMfa()`              | Initiate OAuth authorization redirect                       |
| GET    | `/oauth/:provider/callback`    | Public + `@SkipMfa()`              | Handle OAuth callback, exchange code, issue tokens          |

> `GET /sessions` marks `isCurrent` by the refresh token the request carries. When none reaches it (a
> bearer client that sends none, or a refresh cookie whose path does not cover the route), it marks the
> sessions of the login the access token's `sid` names.

> **`DELETE /sessions/:id` ends the named session and its access tokens only.** The other
> sessions keep working. When the stored session names no family, it
> advances the account's token epoch instead, so every access token of the account answers `401`
> until its client refreshes. `POST /sessions/revoke-all` always advances the epoch.

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

#### OpenAPI: the security posture writes itself

A deployment that builds its OpenAPI document with `@bymax-one/nest-core` **1.4.0 or later** gets
this library's operations described automatically: which schemes exist, which operation requires
which, and which are reachable unauthenticated. Nothing to enable and nothing to import; the module
registers a contributor and nest-core merges its fragments. The answer depends on your
configuration, so it is derived at your boot:

| your options                   | what the document says                                                                                                                                                                                                                                                                                                           |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tokenDelivery: 'cookie'`      | `bymaxAuthAccessCookie` and `bymaxAuthRefreshCookie`, **carrying your cookie names**                                                                                                                                                                                                                                             |
| `tokenDelivery: 'bearer'`      | `bymaxAuthAccessBearer` only — no refresh scheme exists, and `logout`/`refresh` instead carry a documented `{ refreshToken }` body                                                                                                                                                                                               |
| `tokenDelivery: 'both'`        | both access schemes as **alternatives** (`security: [{cookie}, {bearer}]`, which OpenAPI reads as OR)                                                                                                                                                                                                                            |
| `controllers.platform: true`   | `bymaxPlatformAccessBearer` — always bearer, in every mode, because platform credentials are read from the header whatever `tokenDelivery` says. The **registration** switch decides, not `platform.enabled`: the module mounts the platform controllers on `controllers.platform` and validates the `platform` config only then |
| a controller you did not mount | nothing at all: no operation, and no scheme only it would have referenced                                                                                                                                                                                                                                                        |

A scheme the resolved options cannot satisfy is **absent**, never defined-and-unreferenced.

The four names — `bymaxAuthAccessCookie`, `bymaxAuthAccessBearer`, `bymaxAuthRefreshCookie`,
`bymaxPlatformAccessBearer` — are stable identifiers. Renaming one is a break a generated client
feels, so they will not change; their **definitions** are config-derived.

Import them rather than spelling them: a hand-written literal drifts from your configuration. A
platform-only deployment guarding its own routes with `JwtAuthGuard` has to declare the dashboard
access scheme itself, because the fragment only declares what you mounted.

```typescript
import { AUTH_SECURITY_SCHEMES } from '@bymax-one/nest-auth'

// [{ bymaxAuthAccessCookie: [] }], spelled by the package that owns the name
const security = [{ [AUTH_SECURITY_SCHEMES.accessCookie]: [] }]
```

This package does not depend on `@bymax-one/nest-core`. From nest-core 1.6.1 the request-body
schemas of every mounted DTO are described too. Which nest-core version contributes what, how to
remove hand-written `operationSecurity` entries and derive the document-level default with
`authDocumentSecurity`, and the machine-readable schemas under `conformance/` are in
[OpenAPI documents and `@bymax-one/nest-core`](./docs/openapi-interop.md).

### Server services for operations that are not routes

Services cover what a guard or a route cannot, each documented in
[Server services](./docs/server-services.md):

- **Administrative operations** — support-desk operations that ship as methods with no HTTP route.
- **`AuthRevocationService`** — check revocation outside a guard.
- **`AuthTokenVerifierService`** — authorise a long-lived transport (a WebSocket, an SSE stream, a
  message consumer): signature, token type, the revocation channels, account status and the MFA
  policy, with the same refusals the guards give.
- **`AccountStatusService.invalidate`** — drop an account's cached status after you persist a
  status change.

### Server Guards

| Guard                | Decorator                       | Purpose                                                          |
| -------------------- | ------------------------------- | ---------------------------------------------------------------- |
| `JwtAuthGuard`       | —                               | Validates JWT from cookie or `Authorization: Bearer` header      |
| `RolesGuard`         | `@Roles('admin')`               | Hierarchical role check                                          |
| `UserStatusGuard`    | —                               | Blocks inactive/banned users (Redis-cached status)               |
| `MfaRequiredGuard`   | `@SkipMfa()`                    | Enforces MFA verification on protected routes                    |
| `JwtPlatformGuard`   | —                               | Platform admin JWT validation (Bearer only)                      |
| `PlatformRolesGuard` | `@PlatformRoles('super_admin')` | Platform role hierarchy enforcement                              |
| `ApiKeyGuard`        | `@ServiceKey('read')`           | Service API key for machine callers; fails closed without scopes |

> [!NOTE]
> Three additional guards — `SelfOrAdminGuard` (ownership checks), `OptionalAuthGuard` (routes that behave differently for anonymous vs authenticated users), and `WsJwtGuard` (JWT authentication on WebSocket gateways) — are exported from the public `@bymax-one/nest-auth` barrel. Use them exactly like the core guards above. `SelfOrAdminGuard` also holds a route that captures the tenant (`:tenantId`, `:tenant_id` or `:tenant`) to the token's tenant: a capture that differs from `req.user.tenantId`, disagrees with another capture, or is empty is refused with `403` before the self-or-admin decision, so neither a matching id nor the `admin` role reaches into another tenant. A wildcard capture arrives as an array and is refused, and the id (`:userId` or `:id`) must be one non-empty path segment, so an empty value or a decoded `%2F` is refused too. Only those three capture names are read: a route that names the tenant `{org}` or captures none is decided by identity and role alone, and your handler must bind the tenant itself. If a capture name is used at two nesting levels Express keeps the inner value, and a parent router mounted without `mergeParams` does not expose its captures to the inner route, so the guard does not see them.

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
> The same request answers `{ error: { code, message, details } }` with this filter
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

`AuthException` extends `HttpException`, which Nest's WebSocket layer does not recognise, so a
gateway that applies `WsJwtGuard` also needs `WsAuthExceptionFilter`; without it the refusal reaches
the client as `Internal server error`. See
[On a WebSocket, the envelope needs its own filter](./docs/websocket-upgrades.md#on-a-websocket-the-envelope-needs-its-own-filter).

#### The HTTP status belongs to the code

Every code answers exactly one status, and the status is derived from the code rather than
chosen at the throw site — `AuthException` takes no status argument. A client can switch on
`error.code` and the status line together. The table is pinned in
[`conformance/wire-contract.json`](./conformance/wire-contract.json) under
`errorCatalog.statuses` and asserted against that file.

| Status | Codes                                                                                                                                                                                                                                                                                                 |
| -----: | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
|  `400` | `auth.validation` · `auth.password_compromised` · `auth.password_reset_token_invalid` · `auth.email_change_token_invalid` · `auth.invalid_invitation_token` · `auth.mfa_not_enabled` · `auth.mfa_setup_required`                                                                                      |
|  `401` | `auth.invalid_credentials` · `auth.token_invalid` · `auth.refresh_token_invalid` · `auth.mfa_invalid_code` · `auth.mfa_temp_token_invalid` · `auth.otp_invalid` · `auth.oauth_failed` · `auth.platform_auth_required` · `auth.api_key_invalid`                                                        |
|  `403` | `auth.account_inactive` · `auth.account_suspended` · `auth.account_banned` · `auth.pending_approval` · `auth.email_not_verified` · `auth.mfa_required` · `auth.insufficient_role` · `auth.forbidden` · `auth.untrusted_origin` · `auth.reauthentication_required` · `auth.api_key_scope_insufficient` |
|  `404` | `auth.session_not_found` · `auth.api_key_not_found`                                                                                                                                                                                                                                                   |
|  `409` | `auth.email_already_exists` · `auth.mfa_already_enabled` · `auth.mfa_state_conflict` · `auth.oauth_email_mismatch`                                                                                                                                                                                    |
|  `429` | `auth.account_locked` · `auth.too_many_requests`                                                                                                                                                                                                                                                      |
|  `500` | `auth.internal`                                                                                                                                                                                                                                                                                       |
|  `503` | `auth.service_unavailable`                                                                                                                                                                                                                                                                            |

`AUTH_ERROR_STATUS` ships from `@bymax-one/nest-auth/shared`, beside `AUTH_ERROR_CODES`, if you
need the mapping at runtime — for a typed client, an API document, or a test that asserts against
it:

```ts
import { AUTH_ERROR_CODES, AUTH_ERROR_STATUS } from '@bymax-one/nest-auth/shared'
```

> **Assert your fixtures against the catalogue, not against string literals.** `AUTH_ERROR_CODES`
> is exported from `@bymax-one/nest-auth/shared` so a suite can check that every code it branches
> on is one the server can actually produce. A branch on a code the server never sends (for example
> `auth.unauthorized`, which does not exist) is silent forever: it simply never runs, and the
> handler it replaces is the one that matters. The check is one test over your own source.
>
> **Five codes are internal-only and never reach a client**: `auth.token_expired`,
> `auth.token_revoked`, `auth.token_missing` (all collapsed onto `auth.token_invalid`) and
> `auth.otp_expired`, `auth.otp_max_attempts` (onto `auth.otp_invalid`). Each says so in its own
> JSDoc. They are in the catalogue because both implementations share it and both use them
> internally for logs and control flow — branching on them client-side is the same dead branch as
> an invented code, for a subtler reason.

> **Anti-enumeration reads through the status too.** `POST /password/forgot-password` and
> `POST /password/resend-otp` answer `200`, and `POST /verify-email` and
> `POST /resend-verification` answer `204`, **whether or not the address exists**.
> A `200` there does not mean an email was sent, and treating it as confirmation re-introduces
> the account enumeration the endpoints exist to prevent. `POST /password/verify-otp` answers `200`
> only for a correct code; for the same reason the OTP failures
> collapse: a wrong code, a record that expired, and an exhausted attempt ceiling are one code
> (`auth.otp_invalid`) at one status (`401`) — a `429` on the ceiling would say the address was
> registered, since only a record that exists can reach one.

> **A verification code that cannot be stored.** `POST /register` stores the code after the account is created, and
> `POST /resend-verification` stores it before it sends. When the store refuses the write, both answer exactly as
> they do when it succeeds, no email is sent (it would carry a code nothing holds), and one error line records
> `[AUTH_OTP_STORE_FAILED] email_verification` and only the shape of the failure, never the address, the user id or text the store wrote. The user
> asks for a new code through `POST /resend-verification`.

> **When a password-reset request fails.** A failure that is the same for every address answers
> after the same timing floor as every other exit: `503` (`auth.service_unavailable`) when the
> resend-cooldown store cannot answer, `500` (`auth.internal`) for any other failure of it and for
> your repository's `findByEmail` throwing. The answer is the same for every address because the
> cooldown is the first thing every request consults, and a later failure releases the cooldown so
> the retry is not refused. A failure after the account is known (storing the
> code, or the mail provider failing after the response has left) is logged and the `200` stands,
> because it happens only for a registered address. Two limits are left as they are. A `findByEmail`
> that takes longer than the cooldown (60 seconds) and then fails releases the cooldown by key, and
> by then that key may belong to a later request, whose cooldown is removed early: keep
> `findByEmail` well under the cooldown. A mail provider that fails late never touches the
> cooldown, so the address stays throttled for the rest of its window.

### Server Decorators

| Decorator                  | Usage                                                                        |
| -------------------------- | ---------------------------------------------------------------------------- |
| `@CurrentUser()`           | Extract JWT payload from request: `@CurrentUser() user: DashboardJwtPayload` |
| `@Roles(...roles)`         | Set required roles: `@Roles('admin', 'manager')`                             |
| `@PlatformRoles(...roles)` | Set required platform roles: `@PlatformRoles('super_admin')`                 |
| `@Public()`                | Mark route as public (skip JWT guard)                                        |
| `@ServiceKey(...scopes)`   | Machine-caller route: scopes + JWT bypass + `ApiKeyGuard`, in one            |
| `@ApiKeyScopes(...scopes)` | Declare required scopes only (when binding `ApiKeyGuard` yourself)           |
| `@CurrentApiKey()`         | Inject the verified key: `@CurrentApiKey() key: ApiKeyPrincipal`             |
| `@SkipMfa()`               | Skip MFA verification for this route                                         |

### Every other server export

Everything the server entry exports that the sections above do not describe. The row groups what the names are; the types and the contracts are in the code that exports them, and a spec keeps this list in step with `src/server/index.ts` both ways.

| Group                                 | Exports                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | What they are                                                                                                                                                                     |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Injection tokens                      | `BYMAX_AUTH_API_KEY_CLOCK`, `BYMAX_AUTH_API_KEY_REPOSITORY`, `BYMAX_AUTH_BREACH_CHECKER`, `BYMAX_AUTH_MEMBERSHIP_REPOSITORY`, `BYMAX_AUTH_OPTIONS`, `BYMAX_AUTH_PLATFORM_USER_REPOSITORY`, `BYMAX_AUTH_USER_REPOSITORY`, `BYMAX_AUTH_WORKSPACE_REPOSITORY`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Symbols you provide the options, the repositories, the breach checker and the API-key clock under.                                                                                |
| Option types                          | `AUTH_SECRET_MIN_LENGTH`, `AuthModuleAsyncOptions`, `BymaxAuthModuleOptions`, `BymaxAuthRateLimitOptions`, `ClientIpSource`, `RegistrationMode`, `ResolvedOptions`, `TenantResolverRequest`, `WorkspaceOptions`, `WorkspacePermissionOptions`, `WorkspaceRoleList`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | The types of the module options, of the async registration and of the resolved options, and the minimum secret length.                                                            |
| Crypto helpers                        | `decrypt`, `encrypt`, `generateSecureToken`, `hmacSha256`, `sha256`, `timingSafeCompare`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | The `node:crypto` helpers the library itself uses, exported for hosts that must match them.                                                                                       |
| Error catalogue                       | `AUTH_ERROR_MESSAGES`, `AuthErrorCode`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | The default end-user message of each error code and the type of a code.                                                                                                           |
| OpenAPI                               | `AUTH_SECURITY_SCHEMES`, `AuthDocumentSecurityParams`, `AuthGuardFamily`, `OpenApiSecurityRequirement`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | The security schemes and the helpers that describe which guard family protects a route.                                                                                           |
| Hooks                                 | `ApiKeyAccessEvent`, `ApiKeyDenyReason`, `BeforeRegisterResult`, `BeforeWorkspaceCreateResult`, `HookContext`, `NoOpAuthHooks`, `OAuthLoginResult`, `SessionRevocationReason`, `SessionsRevokedEvent`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | The no-op implementation of the hooks and the types their arguments and results use.                                                                                              |
| Request types                         | `AuthenticatedRequest`, `PlatformAuthenticatedRequest`, `WorkspaceRequest`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | The request as the guards leave it, for the dashboard plane, the platform plane and the workspace.                                                                                |
| Results                               | `AuthResult`, `MfaChallengeResult`, `MfaSetupResult`, `OAuthMfaChallengeResult`, `PlatformAuthResult`, `RotatedTokenResult`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | What the flows answer with: tokens, an MFA challenge, the platform result, a rotated token, the MFA setup.                                                                        |
| Email provider                        | `AUTH_EMAIL_KINDS`, `AuthEmailCatalogue`, `AuthEmailContext`, `AuthEmailKind`, `AuthEmailMessage`, `AuthEmailSink`, `DefaultAuthEmailProviderOptions`, `DeliveryErrorPolicy`, `DeliveryErrorPolicyMap`, `InviteData`, `NoOpEmailProvider`, `SessionAlertInfo`, `WorkspaceInviteData`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | The bundled providers and the types of the messages, the catalogue, the sink and the delivery policy.                                                                             |
| Token payloads                        | `AuthPlane`, `MfaTempPayload`, `PlatformJwtPayload`, `RevocableTokenPayload`, `VerifiedAccessToken`, `VerifiedWorkspaceAccessToken`, `VerifyAccessTokenOptions`, `WorkspaceCheck`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | The payloads of the tokens the library signs, the verified access token, the claims a revocation check reads, and the plane, the options and the workspace check of the verifier. |
| OAuth                                 | `OAuthProfile`, `OAuthProviderPlugin`, `OAuthService`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | The plugin contract, the profile a plugin returns and the service that runs the flow.                                                                                             |
| Platform repository                   | `AuthPlatformUser`, `IPlatformUserRepository`, `SafeAuthPlatformUser`, `UpdatePlatformMfaData`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | The contract you implement for platform administrators and the types it exchanges.                                                                                                |
| User repository types                 | `CreateUserData`, `CreateWithOAuthData`, `FindUserByEmailParams`, `FindUserByOAuthIdParams`, `LinkOAuthParams`, `SafeAuthUser`, `TenantScopedUserRef`, `UpdateEmailParams`, `UpdateEmailVerifiedParams`, `UpdateMfaData`, `UpdateMfaParams`, `UpdatePasswordParams`, `UpdateStatusParams`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | The parameter and data types of the user repository you implement.                                                                                                                |
| Membership and workspace repositories | `ANY_WORKSPACE_MEMBER`, `AccountRemovalAudit`, `ActingMember`, `AuthMembership`, `AuthWorkspace`, `ChangeMembershipRoleParams`, `CountOwnedParams`, `CreateMembershipParams`, `CreateMembershipResult`, `CreateWorkspaceResult`, `CreateWorkspaceWithOwnerParams`, `GuardedWriteResult`, `LastActiveWorkspaceRef`, `ListMembershipsForUserParams`, `ListMembershipsForWorkspaceParams`, `ListSoleOwnedParams`, `MemberChangeResult`, `MembershipPage`, `MembershipRef`, `MembershipStatus`, `MembershipWithWorkspace`, `RemoveAllMembershipsParams`, `RemoveAllMembershipsResult`, `RemoveMembershipParams`, `RemovedMembership`, `RenameWorkspaceParams`, `RenameWorkspaceResult`, `SetLastActiveWorkspaceParams`, `TransferOwnershipParams`, `TransferOwnershipResult`, `UpdateWorkspaceStatusParams`, `UpdateWorkspaceStatusResult`, `WorkspaceActor`, `WorkspaceAuditEvent`, `WorkspaceRef`, `WorkspaceStatus` | The parameter, result and record types of the membership and workspace repositories, the acting member, and the any-member role marker.                                           |
| Password checkers                     | `AllowAllBreachChecker`, `CommonPasswordChecker`, `HibpBreachChecker`, `IPasswordBreachChecker`, `reduceToBaseWord`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | The common-password screen, the breach checkers and the contract a breach checker implements.                                                                                     |
| Guards and pipe                       | `AuthFieldError`, `AuthRateLimitGuard`, `RequestEncodingGuard`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | The rate-limit and request-encoding guards and the shape of a field error the validation pipe returns.                                                                            |
| Decorator keys and types              | `ALLOW_PENDING_WORKSPACE_KEY`, `AuthRateLimit`, `AuthRateLimitWindow`, `Authenticated`, `CurrentWorkspaceContext`, `IS_PUBLIC_KEY`, `PLATFORM_ROLES_KEY`, `ROLES_KEY`, `RequestEncoding`, `RequestEncodingPolicy`, `SKIP_MFA_KEY`, `WORKSPACE_PERMISSION_KEY`, `WORKSPACE_ROLES_KEY`, `WorkspaceAction`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Decorators not described above, the metadata keys behind the decorators and the types of their arguments.                                                                         |
| Request DTOs                          | `AcceptInvitationDto`, `ChangePasswordDto`, `CreateInvitationDto`, `ForgotPasswordDto`, `LoginDto`, `MfaChallengeDto`, `MfaDisableDto`, `MfaRegenerateRecoveryCodesDto`, `MfaVerifyDto`, `PlatformLoginDto`, `RegisterDto`, `ResendOtpDto`, `ResendVerificationDto`, `ResetPasswordDto`, `VerifyEmailDto`, `VerifyOtpDto`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | The validated request bodies of the routes.                                                                                                                                       |
| Services                              | `AuthService`, `BruteForceService`, `EmailChangeService`, `InvitationService`, `MembershipService`, `MfaService`, `OtpService`, `PasswordResetService`, `PlatformAuthService`, `ReauthenticationService`, `SessionService`, `TokenDeliveryService`, `WorkspaceActionsService`, `WorkspaceCallerService`, `WorkspaceInvitationService`, `WorkspaceService`, `WsTicketService`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | The services a host can inject to run a flow from its own code.                                                                                                                   |
| Service parameter and response types  | `BearerAuthResponse`, `BothAuthResponse`, `CookieAuthResponse`, `CreateSessionParams`, `ListSessionsParams`, `LiveSessionParams`, `PlatformBearerAuthResponse`, `RevokeAllExceptCurrentParams`, `RevokeAllSessionsParams`, `RevokeSessionParams`, `SessionInfo`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | The parameters of the session service and the token-delivery responses.                                                                                                           |
| Metrics outcomes                      | `AUTH_PLANES`, `LOGIN_OUTCOMES`, `LoginOutcome`, `MFA_OUTCOMES`, `MfaOutcome`, `REFRESH_OUTCOMES`, `RefreshOutcome`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | The closed sets of outcomes the login, MFA and refresh counters count, and the planes.                                                                                            |
| WebSocket tickets                     | `WS_TICKET_TTL_SECONDS`, `WsTicketSnapshot`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | The lifetime of a ticket and the snapshot a ticket stands for.                                                                                                                    |
| Utilities                             | `describeError`, `hasRole`, `redactSecrets`, `sanitizeHeaders`, `sleep`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Small helpers the library uses and exports: error description with redaction, role check, header sanitising, sleep.                                                               |
| API keys                              | `API_KEY_MAX_LABEL_LENGTH`, `ApiKeyClock`, `AuthApiKey`, `AuthApiKeySummary`, `IssueApiKeyInput`, `IssuedApiKey`, `RotateApiKeyInput`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | The key records, the inputs to issue and rotate a key, the label limit and the clock.                                                                                             |
| Workspace helpers and records         | `AcceptedInvitation`, `AcceptedSignup`, `BootstrapInvitationRecord`, `FinalizeResult`, `MemberInvitationRecord`, `MembershipBumpFailedError`, `MyWorkspaces`, `ResolvedWorkspaceMember`, `ScheduledDeletion`, `SignupRequest`, `StoredWorkspaceInvitation`, `WORKSPACE_CURSOR_MAX_LENGTH`, `WORKSPACE_CURSOR_PART_MAX_LENGTH`, `WORKSPACE_ID_MAX_LENGTH`, `WORKSPACE_OWNER_ROLE_MAX_LENGTH`, `WorkspaceAccess`, `WorkspaceAccessView`, `WorkspaceInvitationPreview`, `WorkspaceInvitationView`, `WorkspaceJobContext`, `assertWorkspaceId`, `decodeWorkspaceCursor`, `decodeWorkspaceScopedName`, `encodeWorkspaceCursor`, `isWorkspaceOwnerRole`, `readWorkspacePosition`, `workspacePositionOf`, `workspaceQueryKey`                                                                                                                                                                                             | Helpers, limits, views, records and one error class of the workspace feature.                                                                                                     |

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

## 🚫 What This Library Does NOT Do

- **It does not store your users.** You implement `IUserRepository` (and the workspace, membership and API-key repositories if you enable those); the library never imports an ORM or a database driver.
- **It does not send email.** You implement `IEmailProvider`; the bundled `DefaultAuthEmailProvider` renders messages and hands them to a transport you supply.
- **It does not take a custom OAuth provider.** Google, through `oauth.google`, is the only one; `OAuthProviderPlugin` is exported as a type and there is no way to register an implementation.
- **It does not delete users.** `IUserRepository` has no delete; a host that deletes one removes its workspace memberships first.
- **It does not mount an admin API for service keys or platform operations.** `ApiKeyService` and the support-desk operations are methods; the routes and who may call them are yours.
- **It does not rate-limit per service key.** Per-address limits on the auth routes are built in; limits on your own routes and on a verified key are yours (`@nestjs/throttler`).
- **It does not authenticate a WebSocket on `@nestjs/platform-ws`.** `WsJwtGuard` reads a Socket.IO `handshake`, which the raw `ws` adapter does not provide.
- **It does not depend on Passport, a crypto package, or `@bymax-one/nest-core`.** Cryptography is `node:crypto`; guards verify the JWT through `@nestjs/jwt`.

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
