---
applyTo: 'src/**/*.ts'
---

# TypeScript source code standards

## TypeScript compiler flags — practical implications

`tsconfig.json` enables `strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `noImplicitOverride`, `noImplicitReturns`, `noFallthroughCasesInSwitch`. Review impact:

- **`noUncheckedIndexedAccess`**: `array[0]` is `T | undefined`. Every index access must be guarded. Flag unguarded accesses.
- **`exactOptionalPropertyTypes`**: `{ prop?: string }` ≠ `{ prop: string | undefined }`. Flag conflation.
- **`noImplicitOverride`**: NestJS lifecycle hooks that override a parent must have `override`. Flag missing keyword.
- **`noImplicitReturns`**: every code path must return. Flag conditional fall-through.

## ESLint rules enforced as errors

- `no-explicit-any: error` — no `any` in source.
- `no-non-null-assertion: error` — never `!`. Narrow the type instead.
- `consistent-type-imports: error` — type-only imports must use `import type { ... }`.
- `explicit-function-return-type: error` — explicit return type on all functions.
- `explicit-module-boundary-types: error` — explicit types on all exported parameters.
- `import/no-cycle: error` — circular imports are forbidden.
- `no-restricted-imports: error` — bare `crypto`, `bcrypt`, `argon2`, `uuid`, `nanoid`, `crypto-js` are banned (see crypto section).
- `security/detect-possible-timing-attacks: error` — flags non-constant-time secret comparison.

## Crypto — `node:crypto` only (security-critical)

- **Always `import ... from 'node:crypto'`** with the `node:` prefix. Bare `crypto` is banned.
- **No third-party crypto packages** — `bcrypt`, `argon2`, `jose`, `uuid`, `nanoid`, `crypto-js` are ESLint-banned. Password hashing = `scrypt`; IDs = `crypto.randomUUID()`; random = `crypto.randomBytes()`.
- **Timing-safe**: every secret / hash / token / OTP / signature comparison uses `crypto.timingSafeEqual` on equal-length buffers — never `===`, `==`, or `.equals()` on the raw string.
- **MFA secrets encrypted at rest** with AES-256-GCM — never stored or logged plaintext.
- **Randomness**: `crypto.randomBytes` / `crypto.randomUUID` only. Flag any `Math.random()` on a security path.

## Multi-tenant isolation

- Every repository call and every Redis key is scoped by `tenantId`. Flag any `findBy*` / `update` / Redis operation that omits the tenant scope where the entity is tenant-owned.
- A missing/mismatched `tenantId` is a security bug (cross-tenant leak), not a not-found. Flag code that returns 404 where it should reject on tenant mismatch.

## NestJS patterns

- DI only — no `new ServiceClass()` outside tests.
- **Injection tokens must use `Symbol()`** declared in `bymax-auth.constants.ts` as `BYMAX_AUTH_*` — never string literals.
- Dynamic module supports `forRoot(options)` and `forRootAsync({ useFactory, useClass, useExisting })`.
- **Opt-in features** (MFA, sessions, OAuth, platform admin) must NOT register their controllers/providers when disabled. Flag a controller registered unconditionally for an opt-in feature.
- **Repository pattern** — core logic depends on the `UserRepository` / `PlatformUserRepository` interface, never a concrete persistence class.
- Controller inputs are `class-validator` DTOs — flag a handler reading a raw `@Body()` without a validated DTO.
- `OnModuleDestroy` where a Redis client or other resource needs teardown.

## Import ordering

`node:*` → external → internal → parent/sibling → index. Alphabetical within each group (enforced by `import/order`).

## Security and secrets in logs

- Never log raw tokens, secrets, passwords, password hashes, MFA secrets, or OAuth tokens — in any path, including error/diagnostic logs.
- OAuth `state` parameter must be validated (CSRF). Flag an OAuth callback that trusts `state` without comparison.
- Sessions and JTI blacklist live in Redis; access tokens must be revocable. Flag a session/JTI write without a tenant-prefixed key.
