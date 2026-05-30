# nest-auth — Repository Instructions

`@bymax-one/nest-auth` is a public npm library providing full-stack authentication and authorization for NestJS 11+, React 19, and Next.js 16 — JWT, MFA (TOTP), OAuth 2.0, sessions, brute-force protection, and multi-tenant SaaS isolation. Runtime: Node 24+. Package manager: pnpm. **Security-critical code uses `node:crypto` only — zero third-party crypto.**

## Commands

```bash
pnpm install          # install dev dependencies
pnpm typecheck        # tsc --noEmit (tsconfig.json + tsconfig.server.json)
pnpm lint             # ESLint on src/
pnpm test             # Jest unit tests
pnpm test:e2e         # Jest E2E tests (real NestJS bootstrap)
pnpm test:cov:all     # all tests with coverage — 100% gate (pre-publish enforced)
pnpm mutation         # Stryker mutation tests — break: 95, aspirational high: 99
pnpm build            # clean + tsup → dist/ (ESM + CJS + .d.ts for all 5 subpaths)
pnpm size             # zero-dep brotli bundle-size gate
```

## Source layout

```
src/
  server/   →  exported as "."          (NestJS: module, guards, services, controllers, decorators, crypto, redis, oauth)
  shared/   →  exported as "./shared"   (framework-agnostic types, DTOs, constants, error codes — imported by every other subpath)
  client/   →  exported as "./client"   (framework-agnostic fetch client for the auth API)
  react/    →  exported as "./react"    (hooks + AuthProvider: useAuth, <AuthProvider>)
  nextjs/   →  exported as "./nextjs"   (proxy, route handlers, JWT helpers — App Router)
```

## Non-negotiable rules

1. **`package.json → "dependencies"` must remain empty** — every runtime requirement lives in `peerDependencies` (most are optional, gated per subpath). Adding a real dependency is a breaking change to the supply-chain contract.
2. **Native crypto only (`node:crypto`)** — password hashing (scrypt), MFA secret encryption (AES-256-GCM), TOTP, and token generation. `bcrypt`, `argon2`, `jose`, `uuid`, `nanoid`, `crypto-js`, and bare `crypto` are ESLint-banned (`no-restricted-imports`). Use the `node:` prefix.
3. **Timing-safe comparisons** — every secret / hash / token comparison uses `crypto.timingSafeEqual`, never `===` or `==`. ESLint `security/detect-possible-timing-attacks` is an error.
4. **Multi-tenant isolation** — every user-facing operation is scoped by `tenantId`. A missing or mismatched tenant is a **security bug**, not a 404. A repository query without `tenantId` is a cross-tenant data leak.
5. **Opt-in features** — MFA, sessions, OAuth, platform admin are configured explicitly; when off, their controllers and providers are **never registered** in the NestJS container.
6. **DI tokens are `Symbol()`** — declared in `bymax-auth.constants.ts` as `BYMAX_AUTH_*` (e.g. `BYMAX_AUTH_USER_REPOSITORY`). Never string literals (silent collisions across modules).
7. **JSDoc on every export** — every exported `class`, `function`, `interface`, `type`, and `const` requires JSDoc, with an `@example` where non-trivial.
8. **Conventional Commits** — `feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`. PR titles and commit messages must comply.

## Architecture context

- **Repository pattern** — the consumer supplies persistence via `BYMAX_AUTH_USER_REPOSITORY` / `BYMAX_AUTH_PLATFORM_USER_REPOSITORY`; the library is storage-agnostic (Prisma, TypeORM, raw SQL all work). Key methods (`findById`, `findByEmail`, `create`, `update`, `findByOAuthProvider`) take an optional `tenantId`.
- **Redis for shared state** — sessions, JTI blacklist (token revocation), and brute-force counters live in Redis via `BYMAX_AUTH_REDIS_CLIENT` (ioredis). Tenant-prefix every shared key.
- **DTO validation** — every controller input is a `class-validator` DTO; never trust a raw request body.
- **Rate limiting** — auth endpoints are protected via `@nestjs/throttler` + `AUTH_THROTTLE_CONFIGS`.
- **Randomness** — `crypto.randomBytes` / `crypto.randomUUID` only; never `Math.random()` for anything security-sensitive.
