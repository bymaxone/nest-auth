# @bymax-one/nest-auth — Agent Specification

> **Prerequisite:** Read [CLAUDE.md](./CLAUDE.md) first for critical rules. This file extends it with architecture and patterns — load on demand, not every session.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture](#2-architecture)
3. [Backend Patterns](#3-backend-patterns)
4. [Frontend Patterns](#4-frontend-patterns)
5. [Security Specification](#5-security-specification)
6. [Testing Strategy](#6-testing-strategy)
7. [Build and Publish](#7-build-and-publish)
8. [Common Pitfalls](#8-common-pitfalls)
9. [Pre-Task Checklist](#9-pre-task-checklist)
10. [Guidelines Reference](#10-guidelines-reference)

---

## 1. Project Overview

`@bymax-one/nest-auth` is a **public npm library** — not an application. It provides full-stack authentication for the Bymax SaaS ecosystem.

**Features:** Registration, login/logout, JWT access+refresh tokens, MFA (TOTP), sessions (FIFO eviction), password reset (token/OTP), email verification, OAuth (Google, plugin-extensible), platform admin auth, invitations, RBAC with hierarchy, brute-force protection, rate limiting, multi-tenant isolation.

**What it does NOT do:** No database connections (defines `IUserRepository`), no email sending (defines `IEmailProvider`), no Redis connections (accepts injected client), no UI components, no Passport.

---

## 2. Architecture

### Dynamic Module — runs inside the host app

```
Host App (SaaS)
├── BymaxAuthModule.registerAsync({ ... })
│   ├── Controllers ←→ Services ←→ Redis
│   ├── Guards ←→ Crypto (node:crypto)
│   └── Decorators ←→ Token Manager (@nestjs/jwt)
│
├── Injected by host:
│   ├── IUserRepository (e.g., Prisma)
│   ├── IEmailProvider (e.g., Resend)
│   ├── Redis client (ioredis)
│   └── IAuthHooks (custom lifecycle)
```

### Initialization

1. `BymaxAuthModule.registerAsync()` → resolve options (shallow merge with defaults)
2. Validate injected providers → register controllers conditionally → ready

### Request Flow

```
Request → JwtAuthGuard → UserStatusGuard → RolesGuard → MfaRequiredGuard → Controller → Service
```

---

## 3. Backend Patterns

### Injection Tokens (6 Symbols)

| Token | Type | Required |
|-------|------|----------|
| `BYMAX_AUTH_OPTIONS` | `ResolvedOptions` | Always |
| `BYMAX_AUTH_USER_REPOSITORY` | `IUserRepository` | Always |
| `BYMAX_AUTH_PLATFORM_USER_REPOSITORY` | `IPlatformUserRepository` | If `platformAdmin.enabled` |
| `BYMAX_AUTH_EMAIL_PROVIDER` | `IEmailProvider` | Always (NoOp default) |
| `BYMAX_AUTH_HOOKS` | `IAuthHooks` | Always (NoOp default) |
| `BYMAX_AUTH_REDIS_CLIENT` | `Redis` | Always |

### Service Method Structure

```typescript
async login(dto: LoginDto, req: Request, res: Response): Promise<AuthResult | MfaChallengeResult> {
  // 1. Validate — find user, check status, check brute-force
  // 2. Execute — verify password, check MFA requirement
  // 3. Generate — tokens, session
  // 4. Deliver — set cookies or return in body
  // 5. Hook — call afterLogin
  // 6. Return
}
```

### Controller Pattern — Thin, delegate everything

```typescript
@Post('login')
@Throttle(AUTH_THROTTLE_CONFIGS.login)
@HttpCode(HttpStatus.OK)
async login(
  @Body() dto: LoginDto,
  @Req() req: Request,
  @Res({ passthrough: true }) res: Response,
): Promise<AuthResult | MfaChallengeResult> {
  return this.authService.login(dto, req, res);
}
```

### Error Response Format

```json
{ "error": { "code": "INVALID_CREDENTIALS", "message": "...", "details": {} } }
```

All codes from `AUTH_ERROR_CODES` (33 codes). Throw `AuthException(code, statusCode?, details?)`.

### Redis Key Patterns

Format: `{namespace}:{prefix}:{identifier}`

| Prefix | Purpose | TTL |
|--------|---------|-----|
| `rt` | Refresh token hash | `refreshExpiresInDays` |
| `rv` | Revoked JWT (blacklist) | Remaining token lifetime |
| `lf` | Login failures | `bruteForce.windowSeconds` |
| `otp` | OTP codes | `otpTtlSeconds` |
| `sess` | Session set per user | Session lifetime |
| `sd` | Session detail | Session lifetime |

---

## 4. Frontend Patterns

### React (`./react`) — Hooks + AuthProvider

| Export | Returns |
|--------|---------|
| `AuthProvider` | Context provider — wraps app, manages session, auto-refresh |
| `useSession()` | `{ user, status, refresh() }` |
| `useAuth()` | `{ login(), logout(), register() }` |
| `useAuthStatus()` | `{ isAuthenticated, isLoading }` |

Rules: Hooks only. Memoize context value. AbortController on unmount. Handle loading/error/success states.

### Next.js (`./nextjs`) — Proxy + Route Handlers

| Export | Purpose |
|--------|---------|
| `createAuthProxy()` | Proxy config for `proxy.ts` (Next.js 16 renamed middleware) |
| `createSilentRefreshHandler()` | GET — iframe-based token refresh |
| `createClientRefreshHandler()` | POST — client-side refresh |
| `createLogoutHandler()` | POST — clear tokens and session |
| `decodeJwtToken()` / `verifyJwtToken()` | JWT helpers without `@nestjs/jwt` |

Rules: `cookies()` is async in Next.js 16. `params`/`searchParams` are Promises. Proxy uses Node.js runtime (not Edge).

### Shared (`./shared`) — Types + constants synced between server and client

Cookie names, error codes, route paths, TypeScript types. Zero dependencies.

### Client (`./client`) — Fetch-based, zero dependencies

`createAuthClient(config)` → typed methods for all endpoints. `createAuthFetch(config)` → auto-refresh wrapper.

---

## 5. Security Specification

### Cryptographic Operations

| Operation | Algorithm | File |
|-----------|----------|------|
| Password hashing | scrypt (N=2^15, r=8, p=1, keyLen=64) | `crypto/scrypt.ts` |
| MFA encryption | AES-256-GCM (12-byte IV) | `crypto/aes-gcm.ts` |
| TOTP | HMAC-SHA1 (RFC 4226/6238) | `crypto/totp.ts` |
| Token generation | `crypto.randomBytes` → hex | `crypto/secure-token.ts` |
| Token storage | SHA-256 hash | `crypto/secure-token.ts` |
| OTP codes | `crypto.randomInt` (max length 8) | `crypto/secure-token.ts` |

### JWT Token Types

| Type | Lifetime | Transport | Key Claims |
|------|----------|-----------|------------|
| Dashboard access | 15min | Cookie/Bearer | jti, sub, tenantId, role, status, mfaVerified |
| Platform access | 15min | Cookie/Bearer | jti, sub, role, mfaVerified |
| Refresh | 7d | HttpOnly cookie | Opaque UUID → SHA-256 in Redis |
| MFA temp | 5min | Cookie/Bearer | sub, context (dashboard\|platform) |

### Key Validations at Startup

- JWT secret: >= 32 chars, Shannon entropy >= 3.5 bits/char, reject repetitive patterns
- MFA encryption key: must decode from base64 to exactly 32 bytes
- Roles hierarchy: must not be empty
- OTP length: must be <= 8 (randomInt MAX_SAFE_INTEGER limit)

---

## 6. Testing Strategy

### Coverage Targets

| Module | Target |
|--------|--------|
| `crypto/`, `guards/` | 95% |
| `services/` (core) | 90% |
| `controllers/`, `config/`, `react/`, `nextjs/` | 80% |
| **Overall minimum** | **80%** |

### Mocking Strategy

| Dependency | Approach |
|-----------|----------|
| Redis | `jest.fn()` for GET/SET/DEL/PIPELINE |
| Repositories | `jest.fn()` per method |
| Email provider | `jest.fn()` — verify calls only |
| JwtService | `jest.fn()` for sign/verify |
| `node:crypto` | Spy on specific functions, never mock entire module |
| `fetch` | `jest.fn()` replacing `global.fetch` |

### Mutation Testing (Stryker)

Line coverage proves code *executes*; mutation testing proves the tests would *fail* if the code regressed — the stronger gate for a security library. Run `pnpm mutation` (Node 24) before tagging a release. Survivors are either real gaps (add a test) or equivalent mutants (mark `// Stryker disable next-line <Mutator>: <reason>`). The full methodology, config rationale, ESM/pnpm setup corrections, and the per-file iteration workflow are documented in [docs/mutation_testing_plan.md](./docs/mutation_testing_plan.md). Mutation testing is a manual/release gate — not wired into per-PR CI or `prepublishOnly`.

---

## 7. Build and Publish

tsup builds 5 entry points → `dist/{subpath}/index.{mjs,cjs,d.ts}`

```bash
pnpm clean        # rm -rf dist coverage
pnpm typecheck    # tsc --noEmit
pnpm test         # jest
pnpm build        # tsup
pnpm release      # npm publish --access public
```

Post-build checks: all 5 exports resolve, CJS + ESM work, .d.ts present, no bundled peer deps.

---

## 8. Common Pitfalls

### Security

| Pitfall | Fix |
|---------|-----|
| `===` for token comparison | `crypto.timingSafeEqual` |
| Logging tokens/secrets | Log event type + user ID only |
| JWT secret < 32 chars | Validate at startup, reject weak |
| External crypto packages | `node:crypto` only |
| Raw refresh token storage | Store SHA-256 hash |

### Architecture

| Pitfall | Fix |
|---------|-----|
| Importing Prisma/ORM directly | Use `IUserRepository` interface |
| String injection tokens | `Symbol()` |
| Registering disabled features | Conditional registration |
| `Scope.REQUEST` | Singleton (default) |
| Cross-subpath imports (react → server) | Only import from `shared` |

### TypeScript

| Pitfall | Fix |
|---------|-----|
| Using `any` | `unknown`, generics, explicit types |
| Missing `export type` | Separate `export type` for interfaces |
| Barrel re-exporting internals | Export only public API |
| Default exports | Named exports only |

### Testing

| Pitfall | Fix |
|---------|-----|
| Testing implementation details | Test behavior, not internals |
| Real Redis in unit tests | Mock ioredis |
| Shared mutable state | Fresh mocks in `beforeEach` |

---

## 9. Pre-Task Checklist

**Before starting:**
- [ ] Read CLAUDE.md critical rules
- [ ] Identify 1-2 relevant guidelines → load only those
- [ ] Check `docs/development_tasks.md` for dependencies and status

**Before finishing:**
- [ ] `pnpm typecheck && pnpm lint && pnpm test && pnpm build` — all pass
- [ ] Barrel export updated if new public API added
- [ ] JSDoc on new public exports
- [ ] All text in English

---

## 10. Guidelines Reference

> Load **only** the 1-2 files relevant to your task. Never preload all.

| Domain | File | Load when... |
|--------|------|-------------|
| NestJS | `docs/guidelines/NESTJS-GUIDELINES.md` | Modifying `src/server/` |
| TypeScript | `docs/guidelines/TYPESCRIPT-GUIDELINES.md` | Type design, barrel exports |
| Testing | `docs/guidelines/JEST-TESTING-GUIDELINES.md` | Writing or fixing tests |
| Redis | `docs/guidelines/REDIS-IOREDIS-GUIDELINES.md` | Redis ops, sessions, brute-force |
| JWT | `docs/guidelines/JWT-AUTH-GUIDELINES.md` | Token management, auth guards |
| React | `docs/guidelines/REACT-GUIDELINES.md` | Working on `src/react/` |
| Next.js | `docs/guidelines/NEXTJS-GUIDELINES.md` | Working on `src/nextjs/` |
| Build | `docs/guidelines/TSUP-BUILD-GUIDELINES.md` | Build config, exports map |
| DTOs | `docs/guidelines/CLASS-VALIDATOR-GUIDELINES.md` | Creating/modifying DTOs |
| Crypto | `docs/guidelines/NODE-CRYPTO-GUIDELINES.md` | Crypto operations |
