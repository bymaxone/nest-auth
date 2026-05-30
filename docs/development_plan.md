# Development Plan — @bymax-one/nest-auth

> **Version:** 1.2.0
> **Created on:** 2026-04-10
> **Last revision:** 2026-04-13 (addition of Phases 7-9 frontend, native NestJS guards, cryptography via node:crypto)
> **Based on:** [Technical Specification v1.0.0](./technical_specification.md)
> **Total estimate:** ~8-9 weeks (1 developer + AI agent)

---

## Table of Contents

1. [Plan Overview](#1-plan-overview)
2. [Phase 1 — Foundation and Infrastructure](#2-phase-1--foundation-and-infrastructure)
3. [Phase 2 — Core Authentication](#3-phase-2--core-authentication)
4. [Phase 3 — Multi-Factor Authentication (MFA)](#4-phase-3--multi-factor-authentication-mfa)
5. [Phase 4 — Sessions and Password Reset](#5-phase-4--sessions-and-password-reset)
6. [Phase 5 — Platform, OAuth and Invitations](#6-phase-5--platform-oauth-and-invitations)
7. [Phase 6 — Integration, Polishing and Publishing](#7-phase-6--integration-polishing-and-publishing)
8. [Phase 7 — Shared + Client Subpath](#8-phase-7--shared--client-subpath)
9. [Phase 8 — React Subpath](#9-phase-8--react-subpath)
10. [Phase 9 — Next.js Subpath](#10-phase-9--nextjs-subpath)
11. [Quality Criteria per Phase](#11-quality-criteria-per-phase)
12. [Risks and Mitigations](#12-risks-and-mitigations)
13. [Dependencies between Phases](#13-dependencies-between-phases)
14. [Audit Log](#14-audit-log)

---

## 1. Plan Overview

### 1.1 Development strategy

Development follows an **incremental, layered approach**, where each phase produces testable and functional artifacts that serve as the basis for the next. The order of the phases respects the chain of dependencies: infrastructure → basic authentication → security extensions → platform extensions → polishing.

### 1.2 Guiding principles

- **TDD in each phase:** Unit tests are written alongside the code, not accumulated at the end. Minimum coverage of 100% per phase.
- **Clean compilation:** Each phase must compile (`tsc`) without errors before being considered complete.
- **Incremental barrel export:** The `index.ts` is updated in each phase with the new public exports. Distinguish `export type` (interfaces, type aliases) from `export` (classes, constants, decorators, guards).
- **Security validation:** Each phase includes an explicit review of the security points listed in Appendix B of the specification.
- **Disciplined zero `any`:** Zero use of `any` in production code. `Record<string, unknown>` should be avoided where the type is statically known. For boundaries with untyped external data (OAuth profiles), use explicit types or `Record<string, unknown>` with narrowing documented via JSDoc.
- **Shallow merge for configuration:** `resolveOptions()` must use shallow merge per group (not `JSON.parse/stringify`) to preserve properties that are functions (`maxSessionsResolver`, `tenantIdResolver`, `resolveDomains`).

### 1.3 Schedule summary

| Phase | Week     | Focus                              | Dependency |
| ----- | -------- | ---------------------------------- | ---------- |
| 1     | Week 1   | Foundation and infrastructure      | —          |
| 2     | Week 2   | Core authentication                | Phase 1    |
| 3     | Week 3   | MFA (TOTP)                         | Phase 2    |
| 4     | Week 3-4 | Sessions + password reset          | Phase 2    |
| 5     | Week 4-5 | Platform + OAuth + invitations     | Phases 2-4 |
| 6     | Week 5-6 | Integration, polishing, publishing | Phases 1-5 |
| 7     | Week 6-7 | Shared + Client subpath            | Phase 6    |
| 8     | Week 7   | React subpath                      | Phase 7    |
| 9     | Week 7-8 | Next.js subpath                    | Phase 7    |

---

## 2. Phase 1 — Foundation and Infrastructure

**Duration:** 1 week
**Objective:** Create the entire base structure of the package — scaffold, interfaces, configuration, Redis, foundational services and cryptography utilities. At the end of this phase, the package compiles and has all the infrastructure needed to build the authentication flows.

### 2.1 Project scaffold

**Files to create:**

| File                  | Description                                                                                                                                                                                                                                                     |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `package.json`        | Name `@bymax-one/nest-auth`, version `1.0.0`, peer dependencies as per section 18 of the spec, `"dependencies": {}` (zero direct dependencies), scripts `"build": "tsup"`, `lint`, `test`, `test:cov`, `prepublishOnly`. devDependencies includes `tsup ^8.0.0` |
| `tsconfig.json`       | Target ES2022, module CommonJS, strict mode enabled, experimental decorators, emitDecoratorMetadata                                                                                                                                                             |
| `tsconfig.build.json` | Extends `tsconfig.json`, excludes `**/*.spec.ts` and `test/`, outDir `dist`                                                                                                                                                                                     |
| `.eslintrc.js`        | ESLint configuration with `@typescript-eslint`, NestJS rules                                                                                                                                                                                                    |
| `jest.config.ts`      | Preset `ts-jest`, root `src/`, coverage threshold 100%                                                                                                                                                                                                          |
| `.gitignore`          | `node_modules/`, `dist/`, `coverage/`, `.env`                                                                                                                                                                                                                   |
| `.npmignore`          | Everything except `dist/`, `package.json`, `README.md`, `LICENSE`                                                                                                                                                                                               |
| `LICENSE`             | MIT license as per section 1.4 of the spec                                                                                                                                                                                                                      |
| `CHANGELOG.md`        | Initial empty file — will be populated with the v1.0.0 entry in Phase 6                                                                                                                                                                                         |
| `src/server/index.ts` | Initial barrel export (empty, will be populated incrementally)                                                                                                                                                                                                  |

**Detailed tasks:**

1. Run `pnpm init` with scope `@bymax-one`
2. Install peer dependencies as devDependencies for local development
3. Confirm that `"dependencies": {}` — the package has no direct dependencies (all cryptography uses native `node:crypto`)
4. Install devDependencies: `@nestjs/testing`, `jest`, `ts-jest`, `typescript`, `tsup ^8.0.0`
5. Configure `package.json` with `"files": ["dist"]` (preferred over `.npmignore` for precise control of the published content)
6. Configure `tsconfig.json` with:
   - `"target": "ES2022"`
   - `"module": "commonjs"`
   - `"strict": true`
   - `"experimentalDecorators": true`
   - `"emitDecoratorMetadata": true`
   - `"declaration": true`
   - `"declarationMap": true`
   - `"sourceMap": true`
   - `"outDir": "./dist"`
   - `"rootDir": "./src"`
7. Configure `tsconfig.build.json` excluding tests
8. Configure Jest with preset `ts-jest`, minimum coverage of 100% (branches, functions, lines, statements)
9. Create the directory structure: `src/server/` (main backend directory), `src/shared/`, `src/client/`, `src/react/`, `src/nextjs/`, and inside `src/server/`: `interfaces/`, `config/`, `services/`, `controllers/`, `guards/`, `decorators/`, `redis/`, `dto/`, `crypto/`, `errors/`, `oauth/`, `constants/`, `providers/`, `hooks/`
10. Verify that `pnpm build` compiles without errors (even with an empty barrel export)

### 2.2 Interfaces and contracts

**Files to create:**

| File                                                          | Content                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/server/interfaces/auth-module-options.interface.ts`      | Complete `BymaxAuthModuleOptions` interface as per section 4.1 of the spec — all 15 option groups (jwt, password, tokenDelivery, cookies, mfa, sessions, bruteForce, passwordReset, emailVerification, platform, invitations, roles, blockedStatuses, oauth, controllers)                                                                                                                                                                                            |
| `src/server/interfaces/user-repository.interface.ts`          | Interface `AuthUser` (15 fields) and `IUserRepository` (11 methods: findById, findByEmail, create, updatePassword, updateMfa, updateLastLogin, updateStatus, updateEmailVerified, findByOAuthId, linkOAuth, createWithOAuth)                                                                                                                                                                                                                                         |
| `src/server/interfaces/platform-user-repository.interface.ts` | Interface `AuthPlatformUser` (13 fields) and `IPlatformUserRepository` (6 methods: findById, findByEmail, updateLastLogin, updateMfa, updatePassword, updateStatus)                                                                                                                                                                                                                                                                                                  |
| `src/server/interfaces/email-provider.interface.ts`           | Interface `IEmailProvider` with 7 methods: sendPasswordResetToken, sendPasswordResetOtp, sendEmailVerificationOtp, sendMfaEnabledNotification, sendMfaDisabledNotification, sendNewSessionAlert, sendInvitation — all with a `locale?` parameter                                                                                                                                                                                                                     |
| `src/server/interfaces/auth-hooks.interface.ts`               | Interface `IAuthHooks` (12 optional hooks), `HookContext`, `BeforeRegisterResult`, `OAuthLoginResult`, `OAuthProfile`                                                                                                                                                                                                                                                                                                                                                |
| `src/server/interfaces/jwt-payload.interface.ts`              | Interfaces `DashboardJwtPayload` (with jti, sub, tenantId, role, type, status, mfaVerified, iat, exp), `PlatformJwtPayload` (with jti, sub, role, type, mfaVerified, iat, exp), `MfaTempPayload` (with sub, type, context, iat, exp). **Note:** `emailVerified` is NOT a JWT claim (despite being mentioned in spec section 6.1 as available in the JWT). The host app must verify via `AuthUser.emailVerified` from the `/me` endpoint or the `afterRegister` hook. |
| `src/server/interfaces/auth-result.interface.ts`              | Interfaces `AuthResult` (user, accessToken, rawRefreshToken, sessionHash?), `PlatformAuthResult` (admin, accessToken, rawRefreshToken), `MfaChallengeResult` (mfaRequired, mfaToken). **Note:** Defined in Phase 1 so that Phase 3 can compile `MfaService.challenge()` which returns `AuthResult \| PlatformAuthResult`.                                                                                                                                            |
| `src/server/interfaces/authenticated-request.interface.ts`    | Interfaces `AuthenticatedRequest` (Request + user: DashboardJwtPayload) and `PlatformAuthenticatedRequest` (Request + user: PlatformJwtPayload)                                                                                                                                                                                                                                                                                                                      |
| `src/server/interfaces/oauth-provider.interface.ts`           | Interface `OAuthProviderPlugin` (name, strategy, guard, extractProfile). OAuth flow based on native `fetch` — no external dependencies. `extractProfile(rawProfile: Record<string, unknown>)` converts the provider's raw profile into `OAuthProfile`.                                                                                                                                                                                                               |

**Detailed tasks:**

1. Implement each interface according to the technical specification, respecting exact types
2. Ensure that `AuthUser.mfaEnabled`, `mfaSecret` and `mfaRecoveryCodes` are optional (`?`)
3. Ensure that `IUserRepository.create()` accepts `passwordHash: string | null` (for OAuth)
4. Ensure that all `IEmailProvider` methods accept `locale?: string`
5. Ensure that all `IAuthHooks` hooks are optional (`?` on the method name)
6. In `NoOpAuthHooks`, use explicit types from `IAuthHooks` — never `any` for `sessionInfo` (use `{ device: string; ip: string; sessionHash: string }`). **Deviation from the spec:** spec section 9.3 uses `_sessionInfo: any` — implement it with the correct type from the `IAuthHooks` interface
7. Implement utility function `sanitizeHeaders(headers)` for the `HookContext`: explicit blocklist of `['authorization', 'cookie', 'x-api-key', 'x-auth-token', 'x-csrf-token', 'x-session-id']` + pattern match `/^x-.*-token$/i`. Include unit tests
8. Type `tenantIdResolver` as `(req: import('express').Request) => string | Promise<string>` instead of `(req: any)` for type safety in the public API
9. Define `AuthResult`, `PlatformAuthResult` and `MfaChallengeResult` as interfaces in `auth-result.interface.ts` — needed from Phase 1 onward for compilation of subsequent phases. Use `rawRefreshToken` (never `refreshToken`) as the field name throughout the documentation and code
   - **Deviation from the spec:** the spec exports these types from `./services/auth.service` and `./services/platform-auth.service`. Since the services do not exist in Phase 1, the barrel export must use `export type { AuthResult, MfaChallengeResult } from './interfaces/auth-result.interface'` and `export type { PlatformAuthResult } from './interfaces/auth-result.interface'`. The services in later phases must import from `./interfaces/`, never re-define these types
10. Add JSDoc on each interface explaining purpose and contract
11. Export all interfaces in `index.ts` — use `export type` for interfaces/type aliases and `export` for classes/constants
12. Verify clean compilation

### 2.3 Constants and configuration

**Files to create:**

| File                                       | Content                                                                                                                                                                                                                                                                                                                 |
| ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/server/bymax-auth.constants.ts`       | 6 Symbols: `BYMAX_AUTH_OPTIONS`, `BYMAX_AUTH_USER_REPOSITORY`, `BYMAX_AUTH_PLATFORM_USER_REPOSITORY`, `BYMAX_AUTH_EMAIL_PROVIDER`, `BYMAX_AUTH_HOOKS`, `BYMAX_AUTH_REDIS_CLIENT`                                                                                                                                        |
| `src/server/config/default-options.ts`     | Object with all default values as per table 4.2 of the spec                                                                                                                                                                                                                                                             |
| `src/server/config/resolved-options.ts`    | Type `ResolvedOptions` (options with defaults applied) + function `resolveOptions(userOptions)` that does a deep merge with defaults + validation of `jwt.secret` (min 32 chars, Shannon entropy >= 3.5 bits/char, rejects repetitive patterns) + validation of `mfa.encryptionKey` (32 bytes when decoded from base64) |
| `src/server/constants/index.ts`            | Re-export of public constants                                                                                                                                                                                                                                                                                           |
| `src/server/constants/throttle-configs.ts` | Object `AUTH_THROTTLE_CONFIGS` with 14 rate limiting configurations as per section 16.2                                                                                                                                                                                                                                 |
| `src/server/constants/error-codes.ts`      | Re-export of `AUTH_ERROR_CODES`                                                                                                                                                                                                                                                                                         |

**Detailed tasks:**

1. Create the 6 Symbols with descriptive names (e.g.: `Symbol('BYMAX_AUTH_OPTIONS')`)
2. Implement `default-options.ts` covering all defaults from table 4.2
3. Implement `resolveOptions()` with:
   - **Shallow merge per group** (not `JSON.parse/stringify`) to preserve properties that are functions (`maxSessionsResolver`, `tenantIdResolver`, `resolveDomains`). Use the spread operator per level: `{ ...defaults.jwt, ...userOptions.jwt }`
   - Mandatory validation of `jwt.secret`: length >= 32, entropy >= 3.5, rejection of repetitive strings
   - Validation of `jwt.algorithm`: if provided, must be exactly `'HS256'` — throw an error if any other value
   - Conditional validation of `mfa.encryptionKey`: if `mfa` is provided, `encryptionKey` is mandatory, verify that it decodes to exactly 32 bytes
   - Validation of `roles.hierarchy`: cannot be empty
   - Validation of `platformHierarchy`: mandatory if `platform.enabled`
   - Validation of `passwordReset.otpLength`: if provided, must be <= 8 (above 8, `crypto.randomInt(0, 10**length)` exceeds `Number.MAX_SAFE_INTEGER` and throws `RangeError`)
   - Warning (log warning, not error) if `routePrefix` differs from `'auth'` and `cookies.refreshCookiePath` is not explicitly configured — the refresh cookie may not be sent to the correct endpoint
   - Throw a descriptive exception for each failed validation
4. Implement `AUTH_THROTTLE_CONFIGS` with the 14 endpoints as per section 16.2. **Note:** requires `@nestjs/throttler` >= 6.0.0 (named throttlers API with `{ default: { limit, ttl } }`)
5. Write unit tests for `resolveOptions()`: success scenarios, weak secret, short secret, invalid encryptionKey, empty hierarchy, invalid algorithm, function preserved after merge
6. Export constants in `index.ts`

### 2.4 Error system

**Files to create:**

| File                                    | Content                                                                                                                                                                            |
| --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/server/errors/auth-error-codes.ts` | Constant `AUTH_ERROR_CODES` (33 codes) + `AUTH_ERROR_MESSAGES` (mapping code → message in Portuguese) as per section 15                                                            |
| `src/server/errors/auth-exception.ts`   | Class `AuthException extends HttpException` with constructor `(code, statusCode?, details?)` that formats the response in the pattern `{ error: { code, message, details } }`      |
| `src/server/utils/sleep.ts`             | Function `sleep(ms: number): Promise<void>` — wrapper of `setTimeout` in a Promise. Used for timing normalization in anti-enumeration endpoints                                    |
| `src/server/utils/roles.util.ts`        | Function `hasRole(userRole, requiredRole, hierarchy): boolean` — hierarchical verification logic extracted for reuse by `RolesGuard`, `PlatformRolesGuard` and `InvitationService` |

**Detailed tasks:**

1. Implement all **33 error codes** from table 15.3 of the spec (including `ACCOUNT_BANNED`, `FORBIDDEN`, `PENDING_APPROVAL`, `SESSION_LIMIT_REACHED`, `SESSION_NOT_FOUND`, `OAUTH_FAILED`, `OAUTH_EMAIL_MISMATCH`, `PLATFORM_AUTH_REQUIRED`)
2. Implement `AuthException` as per section 15.1, with automatic lookup of the message in `AUTH_ERROR_MESSAGES`
3. Ensure that `AUTH_ERROR_CODES` is typed as `as const` for literal type inference
4. Write unit tests: verify response format, message lookup, default status code (401)
5. Export both in `index.ts` with `export` (value, not `export type`)

### 2.5 Cryptography utilities

**Files to create:**

| File                                | Content                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ----------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/server/crypto/aes-gcm.ts`      | Functions `encrypt(plaintext, key)` and `decrypt(ciphertext, key)` using AES-256-GCM. 12-byte IV generated with `crypto.randomBytes(12)`. Output format: `base64(iv):base64(authTag):base64(ciphertext)`. Uses Node.js `crypto.createCipheriv('aes-256-gcm', ...)`                                                                                                                                                               |
| `src/server/crypto/secure-token.ts` | Functions `generateSecureToken(bytes?)` (returns hex from `crypto.randomBytes`) and `sha256(input)` (returns hex from `crypto.createHash('sha256')`)                                                                                                                                                                                                                                                                             |
| `src/server/crypto/scrypt.ts`       | Functions `scryptHash(plain)` and `scryptCompare(plain, hash)` using `node:crypto` scrypt. Parameters: N=2^15, r=8, p=1, keyLen=64, salt=16 bytes via `crypto.randomBytes`. Output format: `scrypt:{salt_hex}:{derived_hex}`. Comparison via `crypto.timingSafeEqual`                                                                                                                                                            |
| `src/server/crypto/totp.ts`         | Native TOTP implementation using `node:crypto`. Includes: `base32Decode(encoded)` (Base32 decoding helper), `hotp(secret, counter)` (HMAC-SHA1 as per RFC 4226), `totp(secret, period?)` (RFC 6238 with counter = `Math.floor(Date.now() / 1000 / period)`), `verifyTotp(secret, code, window?)` (verification with configurable window), `buildTotpUri(secret, email, issuer)` (generates `otpauth://totp/...` URI for QR code) |

**Detailed tasks:**

1. Implement `encrypt()`:
   - Generate IV with `crypto.randomBytes(12)` — NEVER reuse
   - Decode key from base64 to Buffer
   - Create cipher with `crypto.createCipheriv('aes-256-gcm', keyBuffer, iv)`
   - Return `base64(iv):base64(authTag):base64(ciphertext)`
2. Implement `decrypt()`:
   - Parse the format `iv:authTag:ciphertext`
   - Create decipher with `crypto.createDecipheriv('aes-256-gcm', keyBuffer, iv)`
   - Set authTag with `decipher.setAuthTag(authTagBuffer)`
   - Return plaintext
3. Implement `generateSecureToken(bytes = 32)` using `crypto.randomBytes`
4. Implement `sha256(input)` using `crypto.createHash('sha256')`
5. Write unit tests:
   - Round-trip of encrypt/decrypt with varied data
   - Verify that IVs are different between calls (no reuse)
   - Verify that decrypt fails with a tampered authTag (integrity)
   - Verify that decrypt fails with a different key
   - Verify the output format of `generateSecureToken` and `sha256`
6. Implement `scryptHash(plain)`:
   - Generate a 16-byte salt with `crypto.randomBytes(16)`
   - Derive the key with `crypto.scrypt(plain, salt, 64, { N: 2**15, r: 8, p: 1 })` (promisified)
   - Return `scrypt:{salt_hex}:{derived_hex}`
7. Implement `scryptCompare(plain, hash)`:
   - Parse the format `scrypt:{salt_hex}:{derived_hex}`
   - Derive the key with the same parameters using the extracted salt
   - Compare with `crypto.timingSafeEqual(derivedBuffer, storedBuffer)` to prevent timing attacks
8. Implement `base32Decode(encoded)`: convert a Base32 string (RFC 4648) to Buffer
9. Implement `hotp(secret, counter)`: HMAC-SHA1 as per RFC 4226 — `crypto.createHmac('sha1', secret)`, dynamic truncation, returns a 6-digit zero-padded string
10. Implement `totp(secret, period = 30)`: computes counter as `Math.floor(Date.now() / 1000 / period)`, delegates to `hotp()`
11. Implement `verifyTotp(secret, code, window = 1)`: verifies code against `totp()` with configurable window (counter ± window)
12. Implement `buildTotpUri(secret, email, issuer)`: returns `otpauth://totp/${issuer}:${email}?secret=${base32Secret}&issuer=${issuer}`
13. Write unit tests for scrypt and TOTP:
    - scrypt: round-trip hash/compare, correct output format, rejection of tampered hash, timing-safe comparison
    - TOTP: code generation with RFC 6238 test vector, verification with window, base32 decode, URI format

### 2.6 Redis Module

**Files to create:**

| File                                     | Content                                                                                                                                                                                                                                                                                                                                                                                                |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `src/server/redis/auth-redis.service.ts` | Service `AuthRedisService` that wraps the `ioredis` instance injected via `BYMAX_AUTH_REDIS_CLIENT`. Methods: `get(key)`, `set(key, value, ttl?)`, `del(key)`, `incr(key)`, `expire(key, ttl)`, `ttl(key)`, `sadd(setKey, member)`, `srem(setKey, member)`, `smembers(setKey)`, `sismember(setKey, member)`, `eval(script, keys, args)`. All methods automatically prefix the key with `{namespace}:`. |
| `src/server/redis/auth-redis.module.ts`  | Internal NestJS module that registers `AuthRedisService` as a provider                                                                                                                                                                                                                                                                                                                                 |

**Detailed tasks:**

1. Inject `BYMAX_AUTH_REDIS_CLIENT` (ioredis instance) and `BYMAX_AUTH_OPTIONS` (for namespace)
2. Implement automatic prefixing: all keys receive `{namespace}:` as a prefix
3. Implement each method by delegating to the ioredis instance
4. The `eval()` method must support execution of Lua scripts (used in refresh token rotation)
5. Write unit tests with an ioredis mock:
   - Verify namespace prefixing on each operation
   - Verify that `set` with TTL calls `SET key value EX ttl`
   - Verify SET operations (sadd, srem, smembers, sismember)
6. Export `AuthRedisService` internally (not in the public barrel export)

> **Additional Redis keys (not present in the spec, added by the plan):**
>
> | Prefix      | Key Pattern                                          | Value                                             | TTL               | Purpose                                     |
> | ----------- | ---------------------------------------------------- | ------------------------------------------------- | ----------------- | ------------------------------------------- |
> | `mfa_setup` | `auth:mfa_setup:{sha256(userId)}`                    | JSON: `{ encryptedSecret, hashedCodes }`          | 600s              | Temporary MFA setup data (Phase 3)          |
> | `psess`     | `auth:psess:{userId}`                                | SET of platform session hashes                    | = max refresh TTL | Tracking of active admin sessions (Phase 5) |
> | `psd`       | `auth:psd:{sessionHash}`                             | JSON: `{ device, ip, createdAt, lastActivityAt }` | = max refresh TTL | Platform session details (Phase 5)          |
> | `resend`    | `auth:resend:{purpose}:{sha256(tenantId+':'+email)}` | `'1'`                                             | 60s               | Cooldown between OTP resends (Phase 4)      |
>
> **Note:** `mfa_setup` uses `sha256(userId)` as the key (not userId in plaintext) to follow the spec's principle that all sensitive identifiers are hashed with SHA-256.

### 2.7 Foundational services

**Files to create:**

| File                                            | Content                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/server/services/password.service.ts`       | `PasswordService` with `hash(plain)` and `compare(plain, hash)` using `node:crypto` scrypt. Delegates to `scryptHash()` and `scryptCompare()` from `src/server/crypto/scrypt.ts`. Parameters: N=2^15, r=8, p=1, keyLen=64, salt=16 bytes. Format: `scrypt:{salt_hex}:{derived_hex}`.                                                                                                                                               |
| `src/server/services/token-manager.service.ts`  | `TokenManagerService` with `issueAccess()`, `issueTokens()`, `issuePlatformTokens()`, `reissueTokens()`, `decodeToken()`, `issueMfaTempToken()`, `verifyMfaTempToken()`. Uses `@nestjs/jwt` for JWT operations. Refresh tokens are opaque UUID v4 stored in Redis. `issuePlatformTokens()` issues a JWT with `type: 'platform'` and a refresh with prefix `prt:` — needed for `MfaService.challenge()` with `context: 'platform'`. |
| `src/server/services/token-delivery.service.ts` | `TokenDeliveryService` with `deliverAuthResponse()`, `deliverRefreshResponse()`, `extractAccessToken()`, `extractRefreshToken()`, `clearAuthSession()`, `resolveCookieDomains()`, `extractDomain()`. Behavior changes according to `tokenDelivery` (cookie/bearer/both).                                                                                                                                                           |
| `src/server/services/brute-force.service.ts`    | `BruteForceService` with `isLockedOut(identifier)`, `recordFailure(identifier)`, `resetFailures(identifier)`, `getRemainingLockoutSeconds(identifier)`. Uses Redis keys `lf:{identifier}`.                                                                                                                                                                                                                                         |

**Detailed tasks for PasswordService:**

1. Inject `BYMAX_AUTH_OPTIONS`
2. Implement `hash(plain)` delegating to `scryptHash(plain)` from `src/server/crypto/scrypt.ts` — uses `node:crypto` scrypt with N=2^15, r=8, p=1, keyLen=64, 16-byte salt. Output format: `scrypt:{salt_hex}:{derived_hex}`
3. Implement `compare(plain, hash)` delegating to `scryptCompare(plain, hash)` — uses `crypto.timingSafeEqual` for constant-time comparison
4. Write tests: hash generates a string in the format `scrypt:...`, compare returns true/false correctly, comparison is timing-safe

**Detailed tasks for TokenManagerService:**

1. Inject `JwtService` from `@nestjs/jwt`, `BYMAX_AUTH_OPTIONS`, `AuthRedisService`
2. Implement `issueAccess(payload: Omit<DashboardJwtPayload, 'jti' | 'iat' | 'exp'>)`:
   - Generate `jti` internally with `crypto.randomUUID()` — the caller must NOT provide `jti`, `iat` or `exp`
   - Sign the JWT with the payload claims + the generated `jti`
   - Use the HS256 algorithm and expiration of `accessExpiresIn`
3. Implement `issueTokens()`:
   - Generate access JWT via `issueAccess()`
   - Generate refresh token with `crypto.randomUUID()` (opaque token)
   - Store in Redis: `rt:{sha256(refreshToken)}` → JSON with `{ userId, tenantId, role, device, ip, createdAt }`
   - TTL = `refreshExpiresInDays * 86400` seconds
   - Return `AuthResult`
4. Implement `reissueTokens()` with an atomic Lua script (section 12.4):
   - Fetch the old session in Redis
   - Generate a new refresh token
   - Create a rotation pointer: `rp:{sha256(old)}` → new token (TTL = `refreshGraceWindowSeconds`)
   - Create a new session: `rt:{sha256(new)}` → updated data
   - Delete the old session
   - If the old token does not exist, check the grace window
   - If none found, throw `REFRESH_TOKEN_INVALID`
5. Implement `decodeToken()`: decode the JWT without validating expiration (for blacklist)
6. Implement `issueMfaTempToken()`:
   - JWT with `type: 'mfa_challenge'`, `context` ('dashboard' or 'platform'), expiration 5 minutes
   - Store in Redis: `mfa:{sha256(token)}` → userId, TTL 300s
7. Implement `verifyMfaTempToken()`:
   - Verify the JWT and look it up in Redis
   - If not found, throw `MFA_TEMP_TOKEN_INVALID`
   - Consume (delete from Redis) after verification
   - **Return `{ userId: string; context: 'dashboard' | 'platform' }`** (not just `string`) — the `context` is needed so that `MfaService.challenge()` knows which repository and result type to use
   - **Note:** spec section 6.3 was updated to return `{ userId, context }` — both (spec and plan) are now synchronized. The correct signature is `verifyMfaTempToken(token: string): Promise<{ userId: string; context: 'dashboard' | 'platform' }>`.
8. Implement `decodeToken()`: decode the JWT without validating expiration. **SECURITY:** Add JSDoc `@internal — NEVER use for authorization decisions, only for jti/exp extraction during logout/blacklist`. Validate that the payload contains `jti` — if absent, throw `TOKEN_INVALID`
9. Write unit tests with mocks of JwtService and Redis:
   - Valid token, expired token, blacklisted token
   - Token without `jti` → `TOKEN_INVALID`
   - `verifyMfaTempToken` returns userId + context correctly

**Detailed tasks for TokenDeliveryService:**

1. Inject `BYMAX_AUTH_OPTIONS` to access `tokenDelivery` and `cookies`
2. Implement `deliverAuthResponse()`:
   - `cookie` mode: set cookies (access, refresh, session signal) + return `{ user }`
   - `bearer` mode: do not set cookies + return `{ user, accessToken, refreshToken }`
   - `both` mode: set cookies + return `{ user, accessToken, refreshToken }`
3. Implement `deliverRefreshResponse()` with the same logic adapted for refresh
4. Implement `extractAccessToken()`:
   - `cookie` mode: read from `req.cookies[accessTokenName]`
   - `bearer` mode: read from `Authorization: Bearer <token>`
   - `both` mode: try cookie first, then header
5. Implement `extractRefreshToken()`:
   - `cookie` mode: read from `req.cookies[refreshTokenName]`
   - `bearer` mode: read from `req.body.refreshToken`
   - `both` mode: try cookie first, then body
6. Implement `clearAuthSession()`:
   - Clear all auth cookies on the resolved domains
   - `bearer` mode: no-op
7. Implement `resolveCookieDomains()` and `extractDomain()` as per section 14.2:
   - **SECURITY:** `extractDomain()` must validate that the hostname extracted from `req.hostname` matches a safe domain pattern (`/^[a-z0-9.-]+$/i`). Reject hostnames with invalid characters — use the configured default domain as a fallback
   - **SECURITY:** Before passing `req.hostname` to `resolveDomains`, strip ports and validate the format
   - Document in the README (Phase 6) that `resolveDomains` MUST validate against the allowlist of configured domains
8. Configure cookies as per table 14.1: HttpOnly, Secure (in prod), SameSite, paths
9. **Return typing:** Define discriminated types for the returns of `deliverAuthResponse` and `deliverRefreshResponse` instead of `Record<string, unknown>`:
   - `cookie` mode: `{ user: AuthUser }`
   - `bearer`/`both` mode: `{ user: AuthUser; accessToken: string; refreshToken: string }`
10. Write unit tests with mocks of Request/Response for each mode:
    - Test of each mode (cookie, bearer, both) for each operation (auth, refresh, extract, clear)
    - Test of `extractDomain` with a malformed hostname → safe fallback
    - Test of `extractAccessToken` and `extractRefreshToken` with cookie and header

**Detailed tasks for BruteForceService:**

1. Inject `AuthRedisService` and `BYMAX_AUTH_OPTIONS`
2. Implement `isLockedOut()`: read `lf:{identifier}`, compare with `maxAttempts`
3. Implement `recordFailure()`: `INCR lf:{identifier}`, `EXPIRE lf:{identifier} windowSeconds`
4. Implement `resetFailures()`: `DEL lf:{identifier}`
5. Implement `getRemainingLockoutSeconds()`: `TTL lf:{identifier}`, return 0 if not locked out
6. Write unit tests: lockout after N attempts, reset, correct TTL

### 2.8 Default providers

**Files to create:**

| File                                           | Content                                                                                                                                                                                                                                    |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `src/server/providers/no-op-email.provider.ts` | `NoOpEmailProvider implements IEmailProvider` — all methods log to the console via the NestJS `Logger`, do not send real email. Useful for development.                                                                                    |
| `src/server/hooks/no-op-auth.hooks.ts`         | `NoOpAuthHooks implements IAuthHooks` — `beforeRegister` returns `{ allowed: true }`, the remaining hooks are no-ops. `onOAuthLogin` implements safe default logic (link if email matches, create if new, reject if email does not match). |

**Detailed tasks:**

1. Implement `NoOpEmailProvider` with logs for each method as per section 10.3
2. Implement `NoOpAuthHooks` as per section 9.3, with email verification in `onOAuthLogin`
3. Export both in `index.ts`
4. Write basic unit tests

### 2.9 Barrel export update

Update `src/server/index.ts` with all the exports from Phase 1:

- Injection constants (6 Symbols)
- All interfaces (8 files)
- `AuthException` and `AUTH_ERROR_CODES`
- `AUTH_THROTTLE_CONFIGS`
- `NoOpEmailProvider` and `NoOpAuthHooks`

### 2.10 Phase 1 validation

- [ ] `pnpm build` compiles without errors
- [ ] `pnpm test` passes with coverage >= 100%
- [ ] All interfaces are exported and typed correctly (`export type` for interfaces, `export` for values)
- [ ] `AuthResult`, `PlatformAuthResult` and `MfaChallengeResult` defined and exported
- [ ] `resolveOptions()` validates jwt.secret, mfa.encryptionKey, jwt.algorithm and preserves functions after merge
- [ ] Encrypt/decrypt AES-256-GCM works in round-trip; IVs are unique; tampered authTag fails
- [ ] Redis namespace prefixing works correctly
- [ ] `PasswordService` hash/compare round-trip works correctly (scrypt with format `scrypt:{salt}:{derived}`)
- [ ] `scrypt.ts` hash/compare with timing-safe comparison works correctly
- [ ] `totp.ts` generates valid codes, verifies with window, base32 decode works, URI builder correct
- [ ] `BruteForceService` locks out after N attempts and resets successfully
- [ ] `TokenManagerService` issues and verifies tokens; rejects tokens without `jti`
- [ ] `TokenDeliveryService` works in the 3 modes (cookie, bearer, both)
- [ ] 33 error codes implemented in `AUTH_ERROR_CODES`
- [ ] `extractDomain()` validates the hostname and rejects malicious formats

---

## 3. Phase 2 — Core Authentication

**Duration:** 1 week
**Dependency:** Phase 1 complete
**Objective:** Implement the complete authentication flow — register, login, logout, refresh, /me — including guards, decorators, DTOs and the dynamic module. At the end of this phase, a user can register, log in, renew tokens and log out.

### 3.1 Guards

**Files to create:**

| File                                     | Content                                                                                                                                                                                                                                                                                                                                                                                     |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/server/guards/jwt-auth.guard.ts`    | `JwtAuthGuard implements CanActivate` — native NestJS guard (no external authentication dependencies). Extracts the token via `TokenDeliveryService.extractAccessToken()`, verifies with `jwtService.verify(token, { algorithms: ['HS256'] })`, validates claims (`type`, `jti`), checks the Redis blacklist, populates `request.user`. Respects the `@Public()` decorator via `Reflector`. |
| `src/server/guards/roles.guard.ts`       | `RolesGuard implements CanActivate` — reads the required roles from the `roles` metadata (via `Reflector`), compares with `request.user.role` using the hierarchy configured in `roles.hierarchy`. Implement `hasRole(userRole, requiredRole)` that checks hierarchical inheritance.                                                                                                        |
| `src/server/guards/user-status.guard.ts` | `UserStatusGuard implements CanActivate` — fetches the user status from the Redis cache (`us:{userId}`), if not found fetches from the database via `IUserRepository.findById()` and caches it with TTL. Compares against `blockedStatuses`. Throws a status-specific error (BANNED, INACTIVE, SUSPENDED).                                                                                  |

**Detailed tasks:**

1. **JwtAuthGuard:**
   - Inject `Reflector`, `JwtService` from `@nestjs/jwt`, `TokenDeliveryService`, `AuthRedisService`, `BYMAX_AUTH_OPTIONS`
   - Implement `canActivate(context)`:
     - Check `IS_PUBLIC_KEY` in the metadata via `Reflector` — if `@Public()`, return `true` without validating the JWT
     - Extract the token via `TokenDeliveryService.extractAccessToken(request)` — supports cookie and/or header as per `tokenDelivery`
     - If the token is absent, throw `TOKEN_MISSING`
     - Verify with `jwtService.verify(token, { algorithms: ['HS256'] })` — **MANDATORY** to pin the algorithm to prevent algorithm confusion (CVE-2015-9235)
     - Verify that `payload.jti` exists and is a string — if absent, throw `TOKEN_INVALID`
     - Verify `payload.type === 'dashboard'` — reject `platform` and `mfa_challenge` tokens
     - Check the Redis blacklist via `authRedis.isBlacklisted(jti)` (`rv:{jti}`) — if blacklisted, throw `TOKEN_REVOKED`
     - Populate `request.user` with the decoded payload
     - Return `true`
   - Handle JWT errors (expired, malformed, invalid signature) with `AuthException` and specific codes

2. **RolesGuard:**
   - Inject `Reflector` and `BYMAX_AUTH_OPTIONS`
   - Read the required roles from the `ROLES_KEY` metadata
   - If no role is required, allow access
   - Implement `hasRole()` as per section 8.2: check direct equality + inheritance in the hierarchy (single-level lookup, not recursive)
   - **IMPORTANT:** The hierarchy must be fully denormalized — each role must list ALL transitive descendants, not just direct children. E.g.: `OWNER: ['ADMIN', 'MEMBER', 'VIEWER']`, not just `OWNER: ['ADMIN']`. Document in the README with a prominent warning
   - Throw `INSUFFICIENT_ROLE` if the role does not satisfy

3. **UserStatusGuard:**
   - Inject `AuthRedisService`, `BYMAX_AUTH_USER_REPOSITORY`, `BYMAX_AUTH_OPTIONS`
   - Implement the flow as per section 8.3:
     1. Extract `user.sub` from the request
     2. Fetch `us:{userId}` in Redis
     3. If cache miss, fetch from the database and cache with `userStatusCacheTtlSeconds`
     4. Check against `blockedStatuses`
     5. Map status to a specific error (BANNED → `ACCOUNT_BANNED`, etc.)
   - If a public route (no user), return true

4. Write unit tests for each guard:
   - JwtAuthGuard: public route, valid token, absent token, expired token, wrong-type token, blacklisted token, token without jti
   - RolesGuard: exact role, inherited role, insufficient role
   - UserStatusGuard: status ACTIVE, BANNED, INACTIVE, cache hit, cache miss

### 3.2 Decorators

**Files to create:**

| File                                              | Content                                                                                                     |
| ------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `src/server/decorators/current-user.decorator.ts` | `@CurrentUser(property?)` — `createParamDecorator` that extracts `request.user` or `request.user[property]` |
| `src/server/decorators/roles.decorator.ts`        | `@Roles(...roles)` — `SetMetadata(ROLES_KEY, roles)` for use with `RolesGuard`                              |
| `src/server/decorators/public.decorator.ts`       | `@Public()` — `SetMetadata(IS_PUBLIC_KEY, true)` to skip `JwtAuthGuard`                                     |

**Detailed tasks:**

1. Implement `@CurrentUser()` with support for extracting a specific property (e.g.: `@CurrentUser('sub')`). **Note on typing:** NestJS's `createParamDecorator` returns `any` by design — narrowing at the call site requires separately exported type overloads or an instruction for the consumer to use a type assertion (e.g.: `@CurrentUser('sub') userId: string`). Document in the JSDoc that the parameter must be explicitly typed by the consumer
2. Implement `@Roles()` with the `ROLES_KEY` key consistent with the `RolesGuard`
3. Implement `@Public()` with the `IS_PUBLIC_KEY` key consistent with the `JwtAuthGuard`
4. Write unit tests for each decorator
5. Export all in `index.ts`

### 3.3 DTOs

**Files to create:**

| File                             | Content                                                                                                                                                                                                                                                                               |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/server/dto/register.dto.ts` | `RegisterDto` with validators: `@IsEmail() email`, `@IsString() @MinLength(8) @MaxLength(128) password`, `@IsString() @MinLength(2) name`, `@IsString() @IsNotEmpty() tenantId`                                                                                                       |
| `src/server/dto/login.dto.ts`    | `LoginDto` with validators: `@IsEmail() email`, `@IsString() @MaxLength(128) password`, `@IsString() @IsNotEmpty() tenantId`. **No `@MinLength` on the password** — deliberate so as not to reveal whether the password is too short before the scrypt comparison (anti-enumeration). |

**Detailed tasks:**

1. Implement DTOs with `class-validator` validators
2. `@MaxLength(128)` on the password as a reasonable input limit — prevent DoS via excessively large payloads in scrypt
3. `@IsNotEmpty()` on `tenantId` in all DTOs that use it (Register, Login, ForgotPassword, ResetPassword) to prevent an empty string from passing through `@IsString()`
4. Add JSDoc on `LoginDto.password`: "Deliberately without `@MinLength` — every password passes to the scrypt comparison so as not to reveal whether it is too short"
5. Write validation tests: invalid email, short password, long password, short name, empty tenantId
6. Export DTOs in `index.ts`

### 3.4 AuthService

**File:** `src/server/services/auth.service.ts`

**Detailed tasks:**

1. Inject: `BYMAX_AUTH_OPTIONS`, `BYMAX_AUTH_USER_REPOSITORY`, `BYMAX_AUTH_EMAIL_PROVIDER`, `BYMAX_AUTH_HOOKS`, `PasswordService`, `TokenManagerService`, `BruteForceService`, `AuthRedisService`, `OtpService`, `@Optional() SessionService`

> **Dependency note:** `OtpService` is moved to Phase 2 (originally planned in Phase 4) because `AuthService.register()` and `verifyEmail()` use it when `emailVerification.required = true`. The implementation is small and self-contained (generate, store, verify). **Implement as detailed in section 5.1** (the full documentation is there for historical reasons). `SessionService` is injected with `@Optional()` — the actual integration happens in Phase 4 (section 5.8), but the stub allows clean compilation.

2. **Implement `register()`** as per Appendix A.1:
   - Resolve `tenantId` via `tenantIdResolver` if provided, otherwise use it from the DTO
   - Execute `hooks.beforeRegister()` — if `allowed: false`, throw an exception with `reason`
   - Apply `modifiedData` from the hook (role, status, emailVerified)
   - Check for an existing email via `userRepo.findByEmail(email, tenantId)`
   - If it exists, throw `EMAIL_ALREADY_EXISTS`
   - Hash the password via `passwordService.hash()`
   - Create the user via `userRepo.create()` with the default status from the hook or `'ACTIVE'`
   - If `emailVerification.required`: generate OTP, store it, send via the email provider
   - Issue tokens via `tokenManager.issueTokens()`
   - Execute `hooks.afterRegister()` (errors logged, not propagated)
   - Return `AuthResult`

3. **Implement `login()`** as per Appendix A.2:
   - Resolve `tenantId`
   - Compute the brute-force identifier: `sha256(tenantId + ':' + email)`
   - Check lockout via `bruteForce.isLockedOut()`
   - If locked, get the remaining TTL and throw `ACCOUNT_LOCKED` with a `Retry-After` header
   - Execute `hooks.beforeLogin()` (errors propagated)
   - Fetch the user via `userRepo.findByEmail()`
   - If not found, record a brute-force failure and throw `INVALID_CREDENTIALS`
   - Check status against `blockedStatuses` — throw a specific error
   - If `emailVerification.required` and `!emailVerified`, throw `EMAIL_NOT_VERIFIED`
   - Compare the password via `passwordService.compare()`
   - If it fails, record a failure and throw `INVALID_CREDENTIALS`
   - If `user.mfaEnabled`:
     - Issue `mfaTempToken` via `tokenManager.issueMfaTempToken(userId, 'dashboard')`
     - Return `MfaChallengeResult`
   - If not MFA:
     - Reset brute-force
     - Issue tokens
     - Update `lastLoginAt`
     - Execute `hooks.afterLogin()`
     - Return `AuthResult`

4. **Implement `logout()`** as per Appendix A.5:
   - Decode the access token to extract `jti` and remaining time
   - Add `jti` to the blacklist: `rv:{jti}` with TTL = remaining time of the JWT
   - Delete the refresh token: `rt:{sha256(refreshToken)}`
   - If sessions enabled, remove from the SET
   - Execute `hooks.afterLogout()`

5. **Implement `refresh()`:**
   - Delegate to `tokenManager.reissueTokens()`
   - Return `AuthResult`

6. **Implement `getMe()`:**
   - Fetch the user via `userRepo.findById(userId)`
   - If not found, throw `TOKEN_INVALID`
   - Return `AuthUser`

7. **Implement `verifyEmail()`:**
   - Compute the identifier: `sha256(tenantId + ':' + email)`
   - Verify the OTP via `otpService.verify('email_verification', identifier, otp)`
   - Update `emailVerified` via `userRepo.updateEmailVerified(userId, true)`
   - Execute `hooks.afterEmailVerified()`

8. **Implement `resendVerificationEmail()`:**
   - **Atomic resend cooldown:** Use `SET resend:email_verification:{sha256(tenantId+':'+email)} 1 NX EX 60` via `AuthRedisService` (the `auth:` prefix is added automatically). `NX` ensures that only the first concurrent request proceeds. If it returns `nil`, the cooldown is active → return success without generating a new OTP
   - Fetch the user, generate a new OTP, store it, send via email
   - **Timing normalization:** wait a constant time regardless of whether the user exists (prevents an enumeration side-channel)

9. Write comprehensive unit tests:
   - Register: success, duplicate email, hook rejects, email verification
   - Login: success, invalid credentials, brute-force lockout, MFA redirect, blocked account
   - Logout: JWT blacklist, refresh removal
   - Refresh: successful rotation, invalid token, grace window
   - GetMe: user found, not found

### 3.5 AuthController

**File:** `src/server/controllers/auth.controller.ts`

**Detailed tasks:**

1. Apply decorators: `@Controller(routePrefix)` with a dynamic prefix
2. Implement 7 endpoints as per table 7.1:

   | Method | Route                  | Decorators                                   | Implementation                                                                                           |
   | ------ | ---------------------- | -------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
   | POST   | `/register`            | `@Public()`, `@Throttle(register)`           | Call `authService.register()`, deliver via `tokenDeliveryService`                                        |
   | POST   | `/login`               | `@Public()`, `@Throttle(login)`              | Call `authService.login()`, deliver via `tokenDeliveryService` (or return `MfaChallengeResult` directly) |
   | POST   | `/logout`              | `@UseGuards(JwtAuthGuard)`                   | Extract tokens via `tokenDeliveryService`, call `authService.logout()`, clear the session                |
   | POST   | `/refresh`             | `@Public()`, `@Throttle(refresh)`            | Extract refresh via `tokenDeliveryService`, call `authService.refresh()`, deliver new tokens             |
   | GET    | `/me`                  | `@UseGuards(JwtAuthGuard)`                   | Call `authService.getMe(user.sub)`                                                                       |
   | POST   | `/verify-email`        | `@Public()`, `@Throttle(verifyEmail)`        | Call `authService.verifyEmail()`                                                                         |
   | POST   | `/resend-verification` | `@Public()`, `@Throttle(resendVerification)` | Call `authService.resendVerificationEmail()`                                                             |

3. Use `@Res({ passthrough: true })` to preserve NestJS interceptors when manipulating cookies
4. Extract `req.ip` and `req.headers['user-agent']` to pass to the services
5. Write unit tests for the controller (mock the services)

### 3.6 Dynamic module

**File:** `src/server/bymax-auth.module.ts`

**Detailed tasks:**

1. Implement `BymaxAuthModule` as `@Module({})` with a static method `registerAsync()`:
   - Accept `imports`, `inject`, `useFactory`, `providers`
   - Use `DynamicModule` with `module: BymaxAuthModule`
   - Follow the pattern of `@nestjs/jwt` `registerAsync`: (1) `useFactory` resolves only configuration, (2) the user's providers (repositories, email, hooks, Redis) are registered directly via the `providers` array, (3) the module merges them internally with its own providers

2. In `useFactory`:
   - Resolve options via `resolveOptions(userOptions)` — applies defaults and validates
   - Register the resolved options as a provider with the token `BYMAX_AUTH_OPTIONS`

3. Register mandatory providers:
   - `AuthRedisService`
   - `PasswordService`
   - `TokenManagerService`
   - `TokenDeliveryService`
   - `BruteForceService`
   - `OtpService` (moved from Phase 4 — needed for email verification in `AuthService`)
   - `AuthService`
   - `JwtStrategy`
   - `JwtAuthGuard`, `RolesGuard`, `UserStatusGuard`

4. Register conditional providers:
   - If `BYMAX_AUTH_HOOKS` is not provided → use `@Optional() @Inject(BYMAX_AUTH_HOOKS)` in the services and register `NoOpAuthHooks` as a fallback
   - If `BYMAX_AUTH_EMAIL_PROVIDER` is not provided → register `NoOpEmailProvider`

5. **Register conditional controllers** — technical mechanism:
   - Build the `controllers` array dynamically inside the `registerAsync` method based on the resolved options
   - NestJS supports `controllers` in the return of `DynamicModule` — build the array before returning the module
   - `AuthController` if `controllers.auth !== false`
   - Other controllers added in later phases
   - **Alternative if needed:** use `RouterModule.register()` in the imports of the `DynamicModule` for dynamic route prefixing

6. **Guards strategy:** Do NOT register guards as a global `APP_GUARD` (side effect on the host app). Each package controller applies guards explicitly via `@UseGuards()`. Document in the README that the host app can register guards globally if it wishes.

7. **Dynamic route prefix:** Use `RouterModule.register([{ path: routePrefix, module: BymaxAuthModule }])` inside the imports of the `DynamicModule` to apply the configurable prefix. This is more reliable than `@Controller(dynamicPrefix)`, which requires a static string.

8. Import `JwtModule.registerAsync()` with `secret` and `signOptions` from the resolved options

9. Write integration tests for the module:
   - The module compiles and initializes with minimal configuration
   - Secret validation fails with a weak secret
   - Controllers are registered conditionally (auth: false → AuthController absent)
   - The route prefix works correctly

### 3.7 Barrel export update

Add to `index.ts`:

- `export { BymaxAuthModule }`
- `export { AuthService }` and `export type { AuthResult, MfaChallengeResult }` (already defined in Phase 1)
- Guards: `export { JwtAuthGuard, RolesGuard, UserStatusGuard }`
- Decorators: `export { CurrentUser, Roles, Public }`
- DTOs: `export { RegisterDto, LoginDto }`

### 3.8 Phase 2 validation

- [ ] Complete register → login → refresh → logout flow functional
- [ ] Guards work correctly (public, authenticated, roles)
- [ ] `RolesGuard` respects the hierarchy (OWNER accesses endpoints restricted to ADMIN)
- [ ] TokenDelivery works in the 3 modes (cookie, bearer, both)
- [ ] Brute-force locks out after N attempts, with a `Retry-After` header
- [ ] The dynamic module compiles and initializes
- [ ] Controllers are registered conditionally (auth: false → no AuthController)
- [ ] Dynamic route prefix works via RouterModule
- [ ] `tenantIdResolver` is called when provided, and `tenantId` from the body is ignored
- [ ] `pnpm build` without errors
- [ ] `pnpm test` with coverage >= 100%

---

## 4. Phase 3 — Multi-Factor Authentication (MFA)

**Duration:** 1 week
**Dependency:** Phase 2 complete
**Objective:** Implement complete TOTP-based MFA — setup, verification, challenge during login, deactivation, recovery codes. At the end, a user can enable MFA in the authenticator app, log in with a TOTP code and recover access via recovery codes.

### 4.1 MfaService

**File:** `src/server/services/mfa.service.ts`

**Detailed tasks:**

1. Inject: `BYMAX_AUTH_OPTIONS`, `BYMAX_AUTH_USER_REPOSITORY`, `@Optional() BYMAX_AUTH_PLATFORM_USER_REPOSITORY`, `AuthRedisService`, `TokenManagerService`, `@Optional() SessionService`, `BruteForceService`, `BYMAX_AUTH_EMAIL_PROVIDER`, `BYMAX_AUTH_HOOKS`, `PasswordService`
   - `BYMAX_AUTH_PLATFORM_USER_REPOSITORY` is `@Optional()` since it only exists when `platform.enabled`. If `context === 'platform'` and the repository is not available, throw a descriptive error
   - `SessionService` is `@Optional()` since it only exists when `sessions.enabled`

2. **Implement `setup(userId)`:**
   - Check whether MFA is already enabled → throw `MFA_ALREADY_ENABLED`
   - **Idempotency:** Check whether a setup is already in progress (`mfa_setup:{sha256(userId)}`) — if it exists and TTL > 0, return the existing result instead of generating a new one (prevents CPU waste with hashing recovery codes on concurrent calls)
   - Generate TOTP secret: 20 random bytes via `crypto.randomBytes(20)`, encoded in Base32
   - Encrypt the secret with `aes-gcm.encrypt(secret, encryptionKey)`
   - Generate recovery codes: 8 random codes (format: `xxxx-xxxx-xxxx` with alphanumeric characters)
   - Make a scrypt hash of each recovery code via `PasswordService.hash()`
   - Store in Redis temporarily: `mfa_setup:{sha256(userId)}` → `{ encryptedSecret, hashedCodes }`, TTL 10 min. **Note:** uses `sha256(userId)` as the key as per the spec's identifier-hashing principle
   - Generate the QR code URI via `buildTotpUri(secret, email, issuer)` from `src/server/crypto/totp.ts` — default format `otpauth://totp/${issuer}:${email}?secret=${secret}&issuer=${issuer}`
   - Return `MfaSetupResult { secret, qrCodeUri, recoveryCodes }`
   - **Note on `aes-gcm.ts`:** Already implemented in Phase 1 (section 2.5) — here it is consumed, not created. Intentional deviation from the spec, which lists it in Phase 3.

3. **Implement `verifyAndEnable(userId, code)`:**
   - Fetch the temporary setup in Redis `mfa_setup:{sha256(userId)}`
   - If not found, throw `MFA_SETUP_REQUIRED`
   - Decrypt the secret
   - Validate the TOTP code with `verifyTotp(secret, code, totpWindow)` from `src/server/crypto/totp.ts`
   - If invalid, throw `MFA_INVALID_CODE`
   - Persist to the database via `userRepo.updateMfa({ mfaEnabled: true, mfaSecret: encrypted, mfaRecoveryCodes: hashed })`
   - Delete the temporary setup from Redis
   - **SECURITY:** Invalidate all the user's active sessions via the `sess:{userId}` SET — revoke refresh tokens (DEL `rt:{sessionHash}` for each member of the SET). **Limitation:** active access tokens CANNOT be blacklisted because `jti` is not stored in the `rt:` record. Existing tokens (without `mfaVerified: true`) remain valid for up to `accessExpiresIn` (default 15min). Sensitive endpoints MUST use `MfaRequiredGuard` to mitigate this window
   - Send a notification via `emailProvider.sendMfaEnabledNotification()`
   - Execute `hooks.afterMfaEnabled()`

4. **Implement `challenge(mfaTempToken, code, ip, userAgent)`:**
   - Verify `mfaTempToken` via `tokenManager.verifyMfaTempToken()` — returns `{ userId, context }` (not just `string`)
   - Use `context` to determine the repository and result type:
   - Compute the brute-force identifier: `sha256(userId)`
   - Check lockout via `bruteForce.isLockedOut()`
   - Fetch the user in the correct repository as per `context`:
     - `dashboard` → `userRepo.findById(userId)`
     - `platform` → `platformUserRepo.findById(userId)`
   - Decrypt `mfaSecret`
   - Try to validate as a TOTP code (6 digits)
   - If a TOTP code: verify with `verifyTotp()` from `src/server/crypto/totp.ts`, check anti-replay (`tu:{userId}:{code}`)
   - If not TOTP (recovery code): verify against `mfaRecoveryCodes` via `verifyRecoveryCode()`
   - If invalid: record a failure, if 5+ failures → revoke `mfaTempToken` (force re-authentication), throw `MFA_INVALID_CODE`
   - If valid:
     - If TOTP: mark the code as used in Redis (`tu:{userId}:{code}`, TTL 90s)
     - If a recovery code: remove it from the list via `userRepo.updateMfa()`
     - Reset brute-force
     - Issue tokens with `mfaVerified: true` as per context:
       - `dashboard` → `tokenManager.issueTokens(user, ip, userAgent, { mfaVerified: true })` → return `AuthResult`
       - `platform` → issue platform tokens → return `PlatformAuthResult`
     - Create a session (if enabled and dashboard context)
     - Execute `hooks.afterLogin()`
   - Return the result as per context

5. **Implement `disable(userId, code)`:**
   - Fetch the user, check MFA is enabled → if not, throw `MFA_NOT_ENABLED`
   - Check brute-force lockout via `bruteForce.isLockedOut(sha256(userId))` (same identifier as `challenge`)
   - Decrypt the secret, validate the TOTP code
   - If invalid, record a failure via `bruteForce.recordFailure(sha256(userId))`, throw `MFA_INVALID_CODE`
   - If valid, reset brute-force
   - Disable via `userRepo.updateMfa({ mfaEnabled: false, mfaSecret: null, mfaRecoveryCodes: null })`
   - Notify via `emailProvider.sendMfaDisabledNotification()`
   - Execute `hooks.afterMfaDisabled()`

6. **Implement `encryptSecret()` and `decryptSecret()`:** delegate to `aes-gcm.ts`

7. **Implement `hashRecoveryCodes(count)`:**
   - Generate `count` random codes with `crypto.randomBytes`
   - Format as `xxxx-xxxx-xxxx`
   - Hash each code with `PasswordService.hash()` (scrypt via `node:crypto`)
   - Return `{ plainCodes, hashedCodes }`

8. **Implement `verifyRecoveryCode(code, hashedCodes)`:**
   - Iterate over `hashedCodes`, compare with `PasswordService.compare()` (scrypt + `crypto.timingSafeEqual`)
   - Return the index if found, -1 if not

9. Write comprehensive unit tests:
   - Setup: generates secret, QR code URI, recovery codes
   - VerifyAndEnable: correct code enables, incorrect code rejects
   - Challenge: correct TOTP, correct recovery code, brute-force lockout, anti-replay
   - Challenge with platform context: returns PlatformAuthResult
   - Disable: correct code disables, MFA not enabled rejects

### 4.2 MfaController

**File:** `src/server/controllers/mfa.controller.ts`

**Detailed tasks:**

1. Prefix: `{routePrefix}/mfa`
2. Implement 4 endpoints as per table 7.2:

   | Method | Route        | Guards         | Throttle       | Implementation                                                    |
   | ------ | ------------ | -------------- | -------------- | ----------------------------------------------------------------- |
   | POST   | `/setup`     | `JwtAuthGuard` | `mfaSetup`     | Call `mfaService.setup(user.sub)`                                 |
   | POST   | `/verify`    | `JwtAuthGuard` | —              | Call `mfaService.verifyAndEnable()`                               |
   | POST   | `/challenge` | Public         | `mfaChallenge` | Call `mfaService.challenge()`, deliver via `tokenDeliveryService` |
   | POST   | `/disable`   | `JwtAuthGuard` | `mfaDisable`   | Call `mfaService.disable()`                                       |

3. The `/challenge` endpoint is public because the user does not yet have a session JWT — it uses `mfaTempToken` in the body
4. Write unit tests for the controller

### 4.3 MFA DTOs

**Files to create:**

| File                                  | Fields                                                                                                                                                                                                                                                |
| ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/server/dto/mfa-verify.dto.ts`    | `@IsString() @IsNotEmpty() @Length(6, 6) code`                                                                                                                                                                                                        |
| `src/server/dto/mfa-challenge.dto.ts` | `@IsString() @IsNotEmpty() mfaTempToken`, `@IsString() @IsNotEmpty() @MaxLength(128) code`                                                                                                                                                            |
| `src/server/dto/mfa-disable.dto.ts`   | `@IsString() @IsNotEmpty() @Length(6, 6) code`. **Note:** Accepts only TOTP — recovery codes are not accepted to disable MFA (design decision from the spec). Document in the README that recovery without TOTP requires administrative intervention. |

### 4.4 MFA Guard and Decorator

**Files to create:**

| File                                          | Content                                                                                                                    |
| --------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `src/server/guards/mfa-required.guard.ts`     | Checks `request.user.mfaVerified === true`. If MFA enabled and not verified, throws `MFA_REQUIRED`. Respects `@SkipMfa()`. |
| `src/server/decorators/skip-mfa.decorator.ts` | `@SkipMfa()` — `SetMetadata(SKIP_MFA_KEY, true)`                                                                           |

### 4.5 Integration in the dynamic module

- Register `MfaService` conditionally (when `mfa` is configured)
- Register `MfaController` conditionally (when `mfa` is configured and `controllers.mfa !== false`)
- Register `MfaRequiredGuard`

### 4.6 Barrel export update

Add to `index.ts`:

- `export { MfaRequiredGuard }`
- `export { SkipMfa }`
- `export type { MfaSetupResult }`
- DTOs: `export { MfaVerifyDto, MfaChallengeDto, MfaDisableDto }`

### 4.7 Phase 3 validation

- [ ] setup → verify → challenge flow functional
- [ ] Setup is idempotent (concurrent call returns the same result)
- [ ] Recovery codes work for alternative access
- [ ] All recovery codes consumed → user locked out without TOTP (document the scenario)
- [ ] TOTP code anti-replay prevents reuse
- [ ] Brute-force on MFA challenge works (lockout + temp token revocation after 5 failures)
- [ ] Brute-force identifier is `sha256(userId)` (independent of login brute-force by email)
- [ ] Challenge with `context: 'platform'` returns `PlatformAuthResult` (compiles ok with the Phase 1 interface)
- [ ] Challenge with a `dashboard` token on the platform endpoint → rejected
- [ ] After enabling MFA, all existing sessions are invalidated
- [ ] Disable requires the correct TOTP code (recovery codes not accepted)
- [ ] `@SkipMfa()` bypasses `MfaRequiredGuard`
- [ ] Coverage >= 100%

---

## 5. Phase 4 — Sessions and Password Reset

**Duration:** 1 week
**Dependency:** Phase 2 complete
**Objective:** Implement session management (listing, revocation, FIFO eviction) and the complete password reset flow (token and OTP), including email verification.

### 5.1 OtpService

**File:** `src/server/services/otp.service.ts`

> **Phase note:** `OtpService` is created in **Phase 2** (moved from the original Phase 4) because `AuthService.verifyEmail()` uses it. In this section, the complete implementation is documented for reference, but the code already exists when Phase 4 begins.

**Detailed tasks:**

1. **Implement `generate(length = 6)`:**
   - Use `crypto.randomInt(0, 10 ** length)` — NEVER `Math.random()`
   - Pad with leading zeros: `String(num).padStart(length, '0')`

2. **Implement `store(purpose, identifier, code, ttlSeconds)`:**
   - Redis key: `otp:{purpose}:{identifier}`
   - Value: JSON `{ code, attempts: 0 }`
   - TTL: `ttlSeconds`

3. **Implement `verify(purpose, identifier, code)`:**
   - Look up in Redis by `otp:{purpose}:{identifier}`
   - If not found → throw `OTP_EXPIRED`
   - Check `attempts >= 5` → throw `OTP_MAX_ATTEMPTS`
   - **Constant-time comparison:** Convert both values to `Buffer.from(code, 'utf8')` before calling `crypto.timingSafeEqual()`. If the buffers have different lengths → return `OTP_INVALID` without calling `timingSafeEqual` (the length difference is already enough to reject; `timingSafeEqual` throws `RangeError` with buffers of different sizes)
   - If invalid → increment attempts, throw `OTP_INVALID`
   - If valid → delete from Redis
   - **Internal timing normalization:** All branches (expired, max attempts, invalid, valid) must have a similar response time. Use `const start = Date.now()` + `sleep(Math.max(0, 100 - elapsed))` before returning/throwing
   - **Returns `void`** — the caller already knows the identifier/purpose (unlike `verifyMfaTempToken`, which returns userId because the caller does not know whom the token belongs to)

4. **Implement `incrementAttempts()`:** increment the `attempts` field in Redis

5. Write tests: generation of correct length, storage, verification, expiration, max attempts, comparison with a different length

### 5.2 SessionService

**File:** `src/server/services/session.service.ts`

**Detailed tasks:**

1. **Implement `createSession(userId, refreshToken, ip, userAgent)`:**
   - Compute `sessionHash = sha256(refreshToken)`
   - Store details: `sd:{sessionHash}` → JSON `{ device: parseUserAgent(userAgent), ip, createdAt, lastActivityAt }`
   - Add to the SET: `SADD sess:{userId} sessionHash`
   - TTL of `sd:` and the SET = `refreshExpiresInDays * 86400`
   - Call `enforceSessionLimit(userId, user)`
   - Execute `hooks.onNewSession()`
   - If configured, send a new-login alert via `emailProvider.sendNewSessionAlert()`

2. **Implement `listSessions(userId, currentSessionHash?)`:**
   - Fetch the SET: `SMEMBERS sess:{userId}`
   - For each hash, fetch the details: `GET sd:{hash}`
   - Mark `isCurrent: hash === currentSessionHash`
   - Sort by `createdAt` descending
   - Return `SessionInfo[]`

3. **Implement `revokeSession(userId, sessionHash)`:**
   - **Ownership validation:** `SISMEMBER sess:{userId} sessionHash`
   - If it does not belong to the user → throw `SESSION_NOT_FOUND` (prevents BOLA/IDOR)
   - Remove the refresh token: `DEL rt:{sessionHash}` (note: sessionHash = sha256 of the refresh token)
   - Remove from the SET: `SREM sess:{userId} sessionHash`
   - Delete the details: `DEL sd:{sessionHash}`

4. **Implement `revokeAllExceptCurrent(userId, currentSessionHash)`:**
   - Fetch all sessions from the SET
   - Filter out `currentSessionHash`
   - Revoke each one individually

5. **Implement `enforceSessionLimit(userId, user)`:**
   - Resolve the limit: `maxSessionsResolver(user)` → `defaultMaxSessions` → 5
   - Count active sessions: `SCARD sess:{userId}`
   - If exceeded: apply FIFO — sort by `createdAt`, revoke the oldest

6. Implement `parseUserAgent(ua)`: extract device/browser from the user-agent string

7. **Implement `rotateSession(userId, oldRefreshToken, newRefreshToken)`:**
   - Called during refresh token rotation to keep `sess:{userId}` and `sd:` in sync
   - Remove `sha256(oldRefreshToken)` from the SET `sess:{userId}`
   - Add `sha256(newRefreshToken)` to the SET
   - Update `sd:{sha256(newRefreshToken)}` with the updated `lastActivityAt`
   - Delete `sd:{sha256(oldRefreshToken)}`
   - Renew the TTL of the SET `sess:{userId}` with `EXPIRE`
   - **Atomicity:** Extend the refresh rotation Lua script (spec section 12.4) to accept `sess:` and `sd:` keys as additional KEYS and execute SREM/SADD/SET/DEL atomically. The script must be parameterizable with prefixes (`rt/rp/sess/sd` for dashboard, `prt/prp/psess/psd` for platform) instead of hardcoding prefixes. This prevents inconsistencies if the process crashes between the token rotation and the session update
   - **Deviation from the spec:** `rotateSession()` does not exist in the `SessionService` API of spec section 6.4. It is a necessary addition to maintain consistency of the session SET during refresh

8. Write tests: create session, list, revoke (own and another user's), FIFO eviction, isCurrent, session rotation on refresh

### 5.3 SessionController

**File:** `src/server/controllers/session.controller.ts`

**Detailed tasks:**

1. Prefix: `{routePrefix}/sessions`
2. Implement 3 endpoints as per table 7.4:

   | Method | Route  | Guards         | Implementation                                       |
   | ------ | ------ | -------------- | ---------------------------------------------------- |
   | GET    | `/`    | `JwtAuthGuard` | List sessions with `currentSessionHash` from the JWT |
   | DELETE | `/:id` | `JwtAuthGuard` | Revoke session by `sessionHash`                      |
   | DELETE | `/all` | `JwtAuthGuard` | Revoke all except the current one                    |

3. Extract `currentSessionHash` from the JWT or compute it from the refresh token in the cookie
4. Write tests for the controller

### 5.4 PasswordResetService

**File:** `src/server/services/password-reset.service.ts`

**Injected dependencies:** `BYMAX_AUTH_OPTIONS`, `BYMAX_AUTH_USER_REPOSITORY`, `BYMAX_AUTH_EMAIL_PROVIDER`, `BYMAX_AUTH_HOOKS`, `OtpService`, `PasswordService`, `AuthRedisService`, `@Optional() SessionService` (to revoke all sessions after a password reset)

**Detailed tasks:**

1. **Implement `initiateReset(email, tenantId)`:**
   - Fetch the user by email — do NOT reveal whether it exists (always return success)
   - If method = `token`:
     - Generate a secure token via `generateSecureToken(32)`
     - Store in Redis: `pr:{sha256(token)}` → userId, TTL = `tokenTtlSeconds`
     - Send via `emailProvider.sendPasswordResetToken()`
   - If method = `otp`:
     - Generate OTP via `otpService.generate()`
     - Store via `otpService.store('password_reset', sha256(tenantId + ':' + email), otp, otpTtlSeconds)`
     - Send via `emailProvider.sendPasswordResetOtp()`
   - **Timing normalization:** wait a constant time to prevent a side-channel

2. **Implement `resetPassword(dto)`:**
   - If `verifiedToken` is present: validate via Redis (`prv:{sha256(verifiedToken)}` → `{ email, tenantId }`)
     - Verify that the request's `tenantId` matches the stored one (prevents cross-tenant)
   - If `token` is present: validate via Redis (`pr:{sha256(token)}` → userId)
   - If `otp` is present: validate via `otpService.verify()`
   - Hash the new password
   - Update via `userRepo.updatePassword()`
   - Consume the token/OTP from Redis
   - Invalidate all the user's sessions
   - Invalidate the status cache: `DEL us:{userId}`
   - Execute `hooks.afterPasswordReset()`

3. **Implement `verifyOtp(email, otp, tenantId)`:**
   - Compute the identifier: `sha256(tenantId + ':' + email)`
   - Validate the OTP via `otpService.verify('password_reset', identifier, otp)` — CONSUMES the OTP
   - Generate a temporary verification token (UUID)
   - Store: `prv:{sha256(token)}` → `{ email, tenantId }`, TTL 5 minutes
   - Return `{ verifiedToken }`

4. **Implement `resendOtp(email, tenantId)`:**
   - **Atomic resend cooldown:** Use `SET resend:password_reset:{sha256(tenantId+':'+email)} 1 NX EX 60` — `NX` ensures that only the first concurrent request proceeds (prevents a TOCTOU race). If it returns `nil`, the cooldown is already active → return success without generating a new OTP
   - Fetch the user — always return success (anti-enumeration)
   - If it exists: generate a new OTP, store it, send it
   - Timing normalization

5. Write tests: reset by token, reset by OTP, reset by verifiedToken, cross-tenant rejected, nonexistent user (no leak), resend cooldown respected

### 5.5 PasswordResetController

**File:** `src/server/controllers/password-reset.controller.ts`

**Detailed tasks:**

1. Prefix: `{routePrefix}/password`
2. Implement 4 endpoints as per table 7.3:

   | Method | Route              | Throttle            | Implementation         |
   | ------ | ------------------ | ------------------- | ---------------------- |
   | POST   | `/forgot-password` | `forgotPassword`    | Call `initiateReset()` |
   | POST   | `/reset-password`  | `resetPassword`     | Call `resetPassword()` |
   | POST   | `/verify-otp`      | `verifyOtp`         | Call `verifyOtp()`     |
   | POST   | `/resend-otp`      | `resendPasswordOtp` | Call `resendOtp()`     |

3. All endpoints are public
4. Write tests for the controller

### 5.6 Password Reset and Verification DTOs

**Files to create:**

| File                                        | Fields as per section 7.3                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/server/dto/forgot-password.dto.ts`     | `@IsEmail() email`, `@IsString() @IsNotEmpty() tenantId`                                                                                                                                                                                                                                                                                                                                                                                        |
| `src/server/dto/reset-password.dto.ts`      | `@IsEmail() email`, `@IsString() @MinLength(8) @MaxLength(128) newPassword`, `@IsOptional() @IsString() @IsNotEmpty() token?`, `@IsOptional() @IsString() @IsNotEmpty() otp?`, `@IsOptional() @IsString() @IsNotEmpty() verifiedToken?`, `@IsString() @IsNotEmpty() tenantId`. **Note:** `@IsNotEmpty()` on the optional fields ensures that if present, they are not an empty string (which would generate a valid but incorrect `sha256("")`) |
| `src/server/dto/verify-otp.dto.ts`          | `@IsEmail() email`, `@IsString() @IsNotEmpty() @Length(6, 8) otp` (min 6 = default, max 8 = maximum otpLength), `@IsString() @IsNotEmpty() tenantId`                                                                                                                                                                                                                                                                                            |
| `src/server/dto/resend-otp.dto.ts`          | `@IsEmail() email`, `@IsString() @IsNotEmpty() tenantId`                                                                                                                                                                                                                                                                                                                                                                                        |
| `src/server/dto/verify-email.dto.ts`        | `@IsEmail() email`, `@IsString() @IsNotEmpty() otp`, `@IsString() @IsNotEmpty() tenantId`                                                                                                                                                                                                                                                                                                                                                       |
| `src/server/dto/resend-verification.dto.ts` | `@IsEmail() email`, `@IsString() @IsNotEmpty() tenantId`                                                                                                                                                                                                                                                                                                                                                                                        |

### 5.7 Integration in the dynamic module

- `OtpService` already registered in Phase 2 — no additional registration needed
- Register `SessionService` conditionally (when `sessions.enabled`)
- Register `PasswordResetService` always
- Register controllers conditionally
- Add to the barrel export:
  - `export { ForgotPasswordDto, ResetPasswordDto, VerifyOtpDto, ResendOtpDto, VerifyEmailDto, ResendVerificationDto }`
  - `export type { SessionInfo }` from `./services/session.service`

### 5.8 Integration with AuthService (retroactive modification of Phase 2)

**Modified files:** `src/server/services/auth.service.ts`, `src/server/services/token-manager.service.ts`

- Integrate `SessionService` into the login/logout flow of `AuthService`:
  - `login()`: after issuing tokens, call `sessionService.createSession()` if `sessions.enabled`
  - `logout()`: call `sessionService.revokeSession()` to remove the session from the SET
  - `refresh()`: call `sessionService.rotateSession()` to update `sess:` and `sd:` during rotation
  - Include `sessionHash` in the returned `AuthResult`
- Integrate `SessionService` into `MfaService.challenge()`:
  - After issuing tokens with `mfaVerified: true`, create a session if `sessions.enabled` and `context === 'dashboard'`

> **Note:** This integration modifies Phase 2 code. The integration points must be marked with `// Phase 4: SessionService integration` comments during Phase 2 to make them easier to locate.

### 5.9 Phase 4 validation

- [ ] Password reset by token functional (email → token → reset)
- [ ] Password reset by OTP functional (email → OTP → verify → verifiedToken → reset)
- [ ] OTP resend works
- [ ] Cross-tenant reset rejected
- [ ] Sessions: create, list, revoke, revoke all
- [ ] FIFO eviction respects the configured limit
- [ ] Email verification functional
- [ ] Timing normalization in anti-enumeration endpoints (4 endpoints)
- [ ] DTOs `VerifyOtpDto`, `ResendOtpDto`, `VerifyEmailDto`, `ResendVerificationDto` validate correctly
- [ ] `logout()` derives `sessionHash` via `sha256(rawRefreshToken)` to call `revokeSession()`
- [ ] OTP resend cooldown (60s) works via a Redis key
- [ ] Coverage >= 100%

---

## 6. Phase 5 — Platform, OAuth and Invitations

**Duration:** 1 week
**Dependency:** Phases 2, 3 and 4 complete
**Objective:** Implement platform administrator authentication, an extensible OAuth system with a Google plugin, and an invitation system.

### 6.1 Platform Auth

**Files to create:**

| File                                                 | Content                                                                                                                                                                                                                                                               |
| ---------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/server/guards/jwt-platform.guard.ts`            | Native NestJS guard (same pattern as the `JwtAuthGuard` from Phase 2) that validates `payload.type === 'platform'`. Rejects `dashboard` with `PLATFORM_AUTH_REQUIRED`. Validates `jti` present. **MANDATORY:** pin `algorithms: ['HS256']` via `JwtService.verify()`. |
| `src/server/guards/platform-roles.guard.ts`          | Roles guard using `platformHierarchy`.                                                                                                                                                                                                                                |
| `src/server/decorators/platform-roles.decorator.ts`  | `@PlatformRoles()` for platform endpoints.                                                                                                                                                                                                                            |
| `src/server/services/platform-auth.service.ts`       | Login, logout, refresh, getMe, revokeAllPlatformSessions for admins.                                                                                                                                                                                                  |
| `src/server/controllers/platform-auth.controller.ts` | 6 endpoints as per table 7.5.                                                                                                                                                                                                                                         |
| `src/server/dto/platform-login.dto.ts`               | `email`, `password` (max 72).                                                                                                                                                                                                                                         |

**Detailed tasks for PlatformAuthService:**

1. Implement `login()`: brute-force → fetch admin → compare password → MFA redirect or tokens
   - **Brute-force identifier:** Use `sha256('platform:' + email)` — the `platform:` prefix avoids collision with the dashboard identifier `sha256(tenantId + ':' + email)` for the same email
   - Use `issueMfaTempToken(userId, 'platform')` if MFA enabled
   - Issue a JWT with `type: 'platform'` via `tokenManager.issuePlatformTokens()`
   - Refresh tokens with the `prt:` prefix in Redis
   - Maintain the SET `psess:{userId}` with the platform session hashes (analogous to the dashboard's `sess:{userId}`)
   - Maintain details in `psd:{sessionHash}` (analogous to `sd:{sessionHash}`)
2. Implement `logout()`: blacklist access JWT via `rv:{jti}` + delete `prt:{sha256(refreshToken)}` + remove from the SET `psess:{userId}` + delete `psd:{sessionHash}`
3. Implement `refresh()` via `tokenManager.reissuePlatformTokens()`: rotation with `prt:` and a `prp:` pointer. Update `psess:` and `psd:` during rotation. **Renew the TTL of the SET `psess:{userId}` with `EXPIRE`** on each rotation (prevents the SET from expiring while individual tokens are renewed)
4. Implement `getMe()`: fetch via `platformUserRepo.findById()`
5. Implement `revokeAllPlatformSessions(userId)`:
   - Use `SMEMBERS psess:{userId}` to enumerate all active session hashes
   - For each hash: delete `prt:{hash}`, delete `psd:{hash}`
   - Delete the SET `psess:{userId}`
   - **Note:** Do NOT use `SCAN prt:*` (O(N) over all Redis keys). The SET `psess:` guarantees O(M) where M = the admin's sessions
   - **Deviation from the spec:** spec section 6.9 incorrectly references `auth:prp:{userId}` as the session SET. `prp:` is the rotation pointer prefix (analogous to the dashboard's `rp:`). The correct SET is `psess:{userId}` as defined in this plan
6. Use `TokenDeliveryService` in all `PlatformAuthController` endpoints for token delivery (same pattern as the `AuthController`)
7. Write complete unit tests:
   - Login with and without MFA
   - `revokeAllPlatformSessions` invalidates all refresh tokens
   - `dashboard` token rejected by the `JwtPlatformGuard`

**Tasks for PlatformAuthController:**

1. Implement 6 endpoints as per table 7.5:
   - POST `/login` (public, `@Throttle(AUTH_THROTTLE_CONFIGS.platformLogin)`)
   - POST `/mfa/challenge` (public + mfaToken, `@Throttle(AUTH_THROTTLE_CONFIGS.mfaChallenge)`)
   - GET `/me` (JwtPlatformGuard)
   - POST `/logout` (JwtPlatformGuard)
   - POST `/refresh` (public, `@Throttle(AUTH_THROTTLE_CONFIGS.refresh)`)
   - DELETE `/sessions` (JwtPlatformGuard)
2. The `/mfa/challenge` endpoint reuses `MfaService.challenge()` — the `context: 'platform'` in the temp token directs the flow
3. All endpoints use `TokenDeliveryService` for token delivery and extraction (same pattern as the `AuthController`)
4. **Known limitation — post-login status check:** There is no `PlatformUserStatusGuard` equivalent to the dashboard's `UserStatusGuard`. If an admin is banned after login, the existing JWT remains valid until it expires (`accessExpiresIn`, default 15min). **Mitigation:** the host app MUST call `revokeAllPlatformSessions()` when changing an admin's status. Document in the README

### 6.2 OAuth Module

**Files to create:**

| File                                             | Content                                                                                                                                                                                                                                                                       |
| ------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/server/oauth/oauth.module.ts`               | Dynamic module that registers OAuth providers based on the configuration. Imported conditionally by `BymaxAuthModule`.                                                                                                                                                        |
| `src/server/oauth/oauth.service.ts`              | Central service: `handleCallback(provider, code, state, ip, ua)` — exchanges the code via the plugin, executes `onOAuthLogin`, creates/links the user, issues tokens. Manages CSRF state via Redis.                                                                           |
| `src/server/oauth/oauth-provider.plugin.ts`      | Interface `OAuthProviderPlugin` with 3 methods: `authorizeUrl(state, redirectUri): string`, `exchangeCode(code, redirectUri): Promise<OAuthTokens>`, `fetchProfile(accessToken): Promise<OAuthProfile>`. All implementations use native `fetch` — zero external dependencies. |
| `src/server/oauth/google/google-oauth.plugin.ts` | Google plugin implementing `OAuthProviderPlugin`. Builds Google OAuth2 URLs, exchanges the code via POST `https://oauth2.googleapis.com/token`, fetches the profile via GET `https://www.googleapis.com/oauth2/v3/userinfo`. All via native `fetch`.                          |

**Detailed tasks for OAuthService:**

1. **Implement `initiateOAuth(provider, tenantId)`:**
   - Generate a random state with `crypto.randomBytes(32).toString('hex')` (64 hex characters)
   - Store in Redis: `os:{sha256(state)}` → `{ tenantId }`, TTL 10 min (600s)
   - **`tenantId` validation:** The package does NOT validate that the `tenantId` exists (it is database-agnostic). The `onOAuthLogin` hook is the validation point — if `createData.tenantId` is invalid, `userRepo.createWithOAuth()` will fail in the database. Document that without the `onOAuthLogin` hook, tenant spoofing is possible in the OAuth flow
   - Build the redirect URL for the provider with query params: `client_id`, `redirect_uri`, `scope`, `state`
   - Register routes automatically for each configured provider:
     - `GET /{routePrefix}/{provider}?tenantId=xxx` → starts the flow (extracts `tenantId` from the query param)
     - `GET /{routePrefix}/{provider}/callback` → processes the callback
   - Return an HTTP 302 redirect to the provider's URL

2. **Implement `handleCallback(provider, code, state, ip, userAgent)`:**
   - Validate the state in Redis — if not found, throw `OAUTH_FAILED`
   - Extract `tenantId` from the stored state
   - Consume the state (delete from Redis)
   - Exchange the code via `plugin.exchangeCode(code, redirectUri)` — returns `accessToken`
   - Fetch the profile via `plugin.fetchProfile(accessToken)` — returns `OAuthProfile`
   - Fetch the existing user: `userRepo.findByOAuthId(provider, profile.providerId, tenantId)`
   - Execute `hooks.onOAuthLogin(profile, existingUser, context)`
   - As per the result:
     - `create`: create the user via `userRepo.createWithOAuth()` with the hook's data
     - `link`: link via `userRepo.linkOAuth()`
     - `reject`: throw an exception with `rejectReason`
   - Issue tokens
   - Create a session (if enabled)
   - Return `AuthResult`

3. **OAuth routes** (registered by the module):
   - `GET /{routePrefix}/{provider}?tenantId=xxx` → start the flow
   - `GET /{routePrefix}/{provider}/callback` → process the callback

4. Write tests: complete flow (create, link, reject), CSRF state, tenantId resolution

### 6.3 Invitations

**Files to create:**

| File                                              | Content                                                                                                                                                                                                                                                |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `src/server/services/invitation.service.ts`       | `invite()` and `acceptInvitation()`.                                                                                                                                                                                                                   |
| `src/server/controllers/invitation.controller.ts` | POST `/` (create invitation) and POST `/accept`.                                                                                                                                                                                                       |
| `src/server/dto/create-invitation.dto.ts`         | `@IsEmail() email`, `@IsString() @IsNotEmpty() role`, `@IsOptional() @IsString() tenantName?`. **Note:** `tenantId` is NOT in the DTO — it is extracted from the inviter's JWT. Validation of `role` against `roles.hierarchy` is done in the service. |
| `src/server/dto/accept-invitation.dto.ts`         | `@IsString() @IsNotEmpty() token`, `@IsString() @MinLength(2) name`, `@IsString() @MinLength(8) @MaxLength(128) password`                                                                                                                              |

**Detailed tasks for InvitationService:**

1. **Implement `invite(inviterId, email, role, tenantId)`:**
   - **Validate that the `role` exists in the configured `roles.hierarchy`** — if it does not exist, throw `INSUFFICIENT_ROLE` (prevents the creation of invitations with nonexistent roles)
   - **Authorization validation:** verify that the inviter's role is >= the requested role in the hierarchy (uses `hasRole` from the `RolesGuard`). The validation of the role against the hierarchy is done in the service (not in the DTO), because `class-validator` does not have access to the DI context
   - If not, throw `INSUFFICIENT_ROLE`
   - Generate a secure token via `generateSecureToken(32)`
   - Store: `inv:{sha256(token)}` → `{ email, role, tenantId, inviterId }`, TTL = `tokenTtlSeconds`
   - Fetch the inviter's name via `userRepo.findById(inviterId)` to include in the email
   - **`tenantName` resolution:** `IEmailProvider.sendInvitation()` requires `tenantName`. Since `IUserRepository` has no method to fetch the tenant's name, `tenantName` must be passed as an additional parameter by the controller (extracted from the `beforeRegister` hook or configured by the host app). **Design decision:** add `tenantName?: string` to the `invite()` parameter — if not provided, use `tenantId` as a fallback
   - Send via `emailProvider.sendInvitation()`
   - The raw token is NEVER logged by the service (only by the `NoOpEmailProvider`, truncated)

2. **Implement `acceptInvitation(dto, ip, userAgent)`:**
   - Fetch the invitation: `inv:{sha256(token)}`
   - If not found → throw `INVALID_INVITATION_TOKEN`
   - Check whether the email already exists in the tenant
   - Create the user with the invitation's role and tenant, with `emailVerified: true` (the invitation sent to the email implies verification of the address)
   - Consume the invitation (delete from Redis)
   - Issue tokens
   - Execute `hooks.afterInvitationAccepted()`
   - Return `AuthResult`

3. In the `InvitationController`:
   - POST `/` requires `JwtAuthGuard` + `RolesGuard` — `tenantId` extracted from the JWT, NOT from the body. `tenantName` comes from the body (`CreateInvitationDto.tenantName?`) or uses `tenantId` as a fallback. **Deviation from the spec:** the spec's DTO does not include `tenantName`, but `IEmailProvider.sendInvitation()` requires it. This is an optional field added by the plan
   - POST `/accept` is public, with `@Throttle(AUTH_THROTTLE_CONFIGS.invitationAccept)`

4. Write tests: create invitation, accept, invalid token, duplicate email, insufficient role

### 6.4 Integration in the dynamic module

- Register `PlatformAuthService` and controllers if `platform.enabled`
- Register `OAuthModule` if `oauth` is configured
- Register `InvitationService` and controller if `invitations.enabled`
- Update the barrel export

### 6.5 Barrel export update

Add to `index.ts`:

- `export { JwtPlatformGuard, PlatformRolesGuard }`
- `export { PlatformRoles }` decorator
- `export type { PlatformAuthResult }` (already defined in Phase 1, confirm export)
- DTOs: `export { PlatformLoginDto, AcceptInvitationDto, CreateInvitationDto }`

### 6.6 Phase 5 validation

- [ ] Platform admin login functional (with and without MFA)
- [ ] Platform JWT isolated from dashboard JWT (type claim)
- [ ] `JwtPlatformGuard` uses `algorithms: ['HS256']` via `JwtService.verify()` (algorithm pinning)
- [ ] `dashboard` token rejected by `JwtPlatformGuard` with `PLATFORM_AUTH_REQUIRED`
- [ ] `revokeAllPlatformSessions` invalidates all refresh tokens via the `psess:{userId}` SET
- [ ] OAuth Google: complete flow functional
- [ ] CSRF state validated and consumed (single-use)
- [ ] Invitations: create, accept, expire
- [ ] Role validation on the invitation: nonexistent role → `INSUFFICIENT_ROLE`
- [ ] Role validation on the invitation: inviter without authorization → `INSUFFICIENT_ROLE`
- [ ] TenantId on the invitation comes from the JWT, not the body
- [ ] All platform endpoints use `TokenDeliveryService`
- [ ] Coverage >= 100%

---

## 7. Phase 6 — Integration, Polishing and Publishing

**Duration:** 1 week
**Dependency:** Phases 1-5 complete
**Objective:** Finalize additional guards, E2E integration tests, JSDoc documentation, README and publishing on npm.

### 7.1 Additional guards

**Files to create:**

| File                                       | Content                                                                                                                                                   |
| ------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/server/guards/ws-jwt.guard.ts`        | Guard for WebSocket — extracts the JWT from the handshake via the `Authorization` header (NOT a query param). Validates and populates `client.data.user`. |
| `src/server/guards/self-or-admin.guard.ts` | Allows access if `:userId === JWT.sub` or if the role is admin in the hierarchy. Primary protection against IDOR.                                         |
| `src/server/guards/optional-auth.guard.ts` | Tries to authenticate via JWT, but does not fail if absent. Populates `request.user` or null.                                                             |

**Tasks for each guard:**

1. **WsJwtGuard:** extract the token from `client.handshake.headers.authorization`, validate the JWT, verify `payload.type === 'dashboard'` (reject `platform` and `mfa_challenge` tokens), populate `client.data.user`. **Optional peer dependency:** if `@nestjs/websockets` is not installed, `WsJwtGuard.canActivate()` must throw a descriptive error ("WsJwtGuard requires @nestjs/websockets") instead of crashing silently. The check must be in `canActivate()` (runtime), not just in the import (compile-time)
2. **SelfOrAdminGuard:** compare `req.params.userId` with `req.user.sub`, check the admin role in the hierarchy. For session hashes in `DELETE /sessions/:id`, validate the SHA-256 hex format (64 characters, `[a-f0-9]{64}`). **IMPORTANT — cross-tenant:** This guard does NOT validate that the target resource belongs to the JWT's `tenantId`. In multi-tenant contexts, the controller or service must additionally verify ownership. Document in the README
3. **OptionalAuthGuard:** extends `JwtAuthGuard`, override `handleRequest()` to not throw an exception if the token is absent — populate `request.user` as `null`
4. Write unit tests for each guard:
   - WsJwtGuard: `platform` token rejected, `dashboard` token accepted
   - SelfOrAdminGuard: own access allowed, admin allowed, another user rejected
   - OptionalAuthGuard: no token → `user` is `null`, with token → `user` populated

### 7.2 E2E integration tests

**Test scenarios:**

1. **Complete authentication flow:**
   - Register → login → refresh → /me → logout
   - Verify cookies set (cookie mode)
   - Verify body response (bearer mode)

2. **MFA flow:**
   - Register → login → setup MFA → verify → logout → login (MFA challenge) → challenge (TOTP) → access
   - Challenge with a recovery code

3. **Sessions flow:**
   - Login on 3 devices → list sessions → revoke one → revoke all except the current one

4. **Password reset flow:**
   - Token method: forgot → email with token → reset
   - OTP method: forgot → email with OTP → verify OTP → reset with verifiedToken

5. **Invitations flow:**
   - Admin creates invitation → email with token → accept → login

6. **OAuth flow (mock):**
   - Initiate → callback with profile → create user → tokens issued

7. **Sessions with FIFO eviction:**
   - Login from 6 devices (limit = 5) → verify that the oldest session was removed
   - Listing sessions returns 5, with the correct `isCurrent`

8. **Refresh concurrency:**
   - Two simultaneous refresh requests with the same token → the first succeeds, the second uses the grace window and returns the same new token

9. **Security:**
   - Brute-force: 10 failed attempts → lockout → verify `Retry-After`
   - Blacklisted token: logout → reuse token → 401
   - Cross-tenant: login in tenant A → access a resource of tenant B → 403
   - Insufficient role: MEMBER tries to access an ADMIN endpoint → 403
   - Token without `jti` → 401 `TOKEN_INVALID`
   - MFA temp token `dashboard` on the platform endpoint → rejected
   - OTP resend cooldown respected (< 60s → success without a new OTP)

### 7.3 Security review

Verify each item from Appendix B of the specification:

- [ ] Passwords hashed with scrypt (N=2^15, r=8, p=1)
- [ ] Constant-time comparison via `crypto.timingSafeEqual()` on passwords, OTPs, recovery codes
- [ ] TOTP secrets encrypted with AES-256-GCM
- [ ] Recovery codes hashed with scrypt (same parameters as passwords)
- [ ] Opaque refresh tokens (UUID v4, not JWT)
- [ ] Refresh rotation with grace window
- [ ] Access token blacklist via `jti`
- [ ] HttpOnly cookies in cookie/both mode
- [ ] SameSite Strict on the refresh cookie
- [ ] Restricted path `/auth` on the refresh cookie
- [ ] Brute-force by email (scoped by tenant)
- [ ] Rate limiting by IP on all sensitive endpoints
- [ ] No revelation of user existence
- [ ] PII masked in logs
- [ ] SHA-256 on all Redis keys
- [ ] TOTP code anti-replay
- [ ] OTP with a limit of 5 attempts
- [ ] Algorithm pinning in the JWT Strategy (HS256)
- [ ] Header sanitization in the HookContext

### 7.4 Documentation

1. **JSDoc:** Add documentation to all public methods of services, guards and decorators
2. **README.md:** Quick start guide with:
   - Installation
   - Minimal configuration
   - Example of `registerAsync()`
   - Example of an `IUserRepository` implementation
   - Example of an `IEmailProvider` implementation with a security note: all user values interpolated into HTML must be escaped (`escapeHtml(name)`) to prevent XSS in notifications
   - Endpoints table
   - Guards and decorators table
   - Security section: domain allowlist in `resolveDomains`, recovery without TOTP requires admin intervention, `@MaxLength(128)` on passwords
   - Note about `@nestjs/throttler` >= 6.0.0 as a requirement for `AUTH_THROTTLE_CONFIGS`
3. **CHANGELOG.md:** v1.0.0 entry (file created in Phase 1, populated here)

### 7.5 Barrel export update (Phase 6)

Add to `index.ts`:

- `export { WsJwtGuard, SelfOrAdminGuard, OptionalAuthGuard }`

### 7.6 Final polishing

1. Review the barrel export (`index.ts`) — verify that everything public is exported
2. Validation of options at module initialization — clear error messages
3. Structured logs with the NestJS `Logger` in all services
4. Ensure that the build produces a clean `dist/` with types and sourcemaps
5. Verify `files` in `package.json` — only `dist/` published
6. Test local installation in a test NestJS project

### 7.7 Publishing

1. Run `pnpm build`
2. Run `pnpm test:cov` — verify coverage >= 100%
3. Run `pnpm pack` to verify the package content
4. Publish with `pnpm publish --access public`

### 7.8 Phase 6 validation

- [ ] All E2E tests passing (including refresh concurrency and FIFO eviction)
- [ ] Total coverage >= 100%
- [ ] Build without errors or warnings
- [ ] README complete and functional with security sections
- [ ] JSDoc on all public exports
- [ ] All 14 endpoints have `@Throttle()` with configs from `AUTH_THROTTLE_CONFIGS`
- [ ] Security checklist 100% verified (Appendix B of the spec)
- [ ] `WsJwtGuard` verifies `payload.type === 'dashboard'`
- [ ] Barrel export distinguishes `export type` from `export` correctly
- [ ] Package published on npm

---

## 8. Phase 7 — Shared + Client Subpath

**Duration:** 1-2 weeks (Week 6-7)
**Dependency:** Phase 6 complete (server tested and published)
**Objective:** Extract shared types and constants to the `shared` subpath, and implement the framework-agnostic authentication client in the `client` subpath.

### 8.1 Shared Subpath (`src/shared/`)

**Files to create:**

| File                                      | Content                                                                                                           |
| ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `src/shared/types/auth-user.types.ts`     | `AuthUserClient` — representation of the authenticated user on the client-side                                    |
| `src/shared/types/auth-result.types.ts`   | `AuthClientResponse`, `MfaChallengeResult`, `AuthErrorResponse` — API result types                                |
| `src/shared/types/jwt-payload.types.ts`   | `DashboardJwtPayload`, `PlatformJwtPayload`, `MfaTempPayload` — JWT payload types                                 |
| `src/shared/constants/cookie-defaults.ts` | `AUTH_ACCESS_COOKIE_NAME`, `AUTH_REFRESH_COOKIE_NAME`, `AUTH_HAS_SESSION_COOKIE_NAME`, `AUTH_REFRESH_COOKIE_PATH` |
| `src/shared/constants/error-codes.ts`     | `AUTH_ERROR_CODES` — error codes used by the client to handle responses                                           |
| `src/shared/constants/routes.ts`          | `AUTH_ROUTES` — map of default auth API routes                                                                    |
| `src/shared/index.ts`                     | Barrel export of all the types and constants of the shared subpath                                                |

**Detailed tasks:**

1. **Extract types from the server to shared (structure by `types/` subdirectory):**
   - `types/jwt-payload.types.ts`: Move JWT payload interfaces (`DashboardJwtPayload`, `PlatformJwtPayload`, `MfaTempPayload`) that are used by both the server and the client
   - `types/auth-result.types.ts`: Move result types (`AuthClientResponse`, `MfaChallengeResult`, `AuthErrorResponse`) — the client needs to type the responses
   - `types/auth-user.types.ts`: Move `AuthUserClient` — representation of the authenticated user on the client-side
   - Update imports in the server to reference `../shared/types/` instead of the local definitions

2. **Extract constants (structure by `constants/` subdirectory):**
   - `constants/error-codes.ts`: `AUTH_ERROR_CODES` — error codes used by the client to handle responses
   - `constants/cookie-defaults.ts`: Cookie names (`AUTH_ACCESS_COOKIE_NAME`, `AUTH_REFRESH_COOKIE_NAME`, `AUTH_HAS_SESSION_COOKIE_NAME`) + `AUTH_REFRESH_COOKIE_PATH` — used by the Next.js proxy
   - `constants/routes.ts`: `AUTH_ROUTES` — map of default auth API routes

3. **Barrel export** in `src/shared/index.ts`

4. **Tests:**
   - Verify that all types compile without errors
   - Verify that the shared constants match the values used by the server (synchronization test)

### 8.2 Client Subpath (`src/client/`)

**Files to create:**

| File                             | Content                                                                                        |
| -------------------------------- | ---------------------------------------------------------------------------------------------- |
| `src/client/createAuthClient.ts` | Factory `createAuthClient(config: AuthClientConfig)` that returns typed authentication methods |
| `src/client/createAuthFetch.ts`  | `fetch` wrapper with 401 interception, automatic refresh and refresh dedup                     |
| `src/client/types.ts`            | `AuthClientConfig`, `AuthFetchConfig` and internal client types                                |
| `src/client/index.ts`            | Barrel export of the client subpath                                                            |

**Detailed tasks:**

1. **Implement `createAuthClient(config: AuthClientConfig)`:**
   - Factory that returns an object with typed methods: `login`, `register`, `logout`, `refresh`, `getMe`, `mfaChallenge`, `forgotPassword`, `resetPassword`
   - Each method encapsulates the corresponding HTTP call with correct input and output types
   - Uses `createAuthFetch` internally for automatic 401 interception
   - Config accepts: `baseUrl`, `fetchOptions`, `onSessionExpired`

2. **Implement `createAuthFetch(config: AuthFetchConfig)`:**
   - Native `fetch` wrapper — zero external dependencies
   - **Single-flight refresh dedup:** upon receiving a 401, it starts a refresh. If multiple requests fail simultaneously with 401, only ONE refresh call is made (`refreshPromise` pattern)
   - **`shouldSkipRefreshOnUrl(url)`:** complete list of URLs that must NOT trigger automatic refresh (e.g.: `/auth/login`, `/auth/register`, `/auth/refresh`, `/auth/forgot-password`, `/auth/reset-password`)
   - **401 interception → refresh → retry:** upon receiving a 401, it tries a refresh, and if it succeeds, re-executes the original request with new cookies/headers
   - **`onSessionExpired` callback:** called when refresh fails (genuinely expired session) — allows the host app to redirect to login
   - All operations via native `fetch`

3. **Barrel export** in `src/client/index.ts`

4. **Tests:**
   - Mock of the global `fetch`
   - Test refresh dedup (2 simultaneous 401 requests → 1 refresh)
   - Test the skip list (a login call with 401 does NOT try a refresh)
   - Test `onSessionExpired` called when refresh fails
   - Test retry of the original request after a successful refresh

### 8.3 Phase 7 validation

- [ ] All shared types compile without errors
- [ ] Shared constants match the values used by the server
- [ ] `createAuthClient` returns all typed methods
- [ ] `createAuthFetch` does refresh dedup (single-flight)
- [ ] Skip list prevents automatic refresh on auth URLs
- [ ] `onSessionExpired` is called when refresh fails
- [ ] Zero external dependencies — only native `fetch`
- [ ] Server still compiles after extracting the types to shared
- [ ] Coverage >= 100%

---

## 9. Phase 8 — React Subpath

**Duration:** ~0.5 week (Week 7)
**Dependency:** Phase 7 complete (client subpath functional)
**Objective:** Implement React hooks and context for authentication session management.

### 9.1 Files to create

| File                         | Content                                                                                                          |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `src/react/AuthProvider.tsx` | Context component that manages session state, periodic auto-revalidation and integration with `createAuthClient` |
| `src/react/useSession.ts`    | Hook that returns `{ user, status, isLoading, refresh, lastValidation }`                                         |
| `src/react/useAuth.ts`       | Hook that returns `{ login, register, logout, forgotPassword, resetPassword }`                                   |
| `src/react/useAuthStatus.ts` | Convenience hook that returns `{ isAuthenticated, isLoading }`                                                   |
| `src/react/types.ts`         | Internal types of the React subpath: `AuthProviderProps`, `SessionState`, `AuthContextValue`                     |
| `src/react/index.ts`         | Barrel export of the react subpath                                                                               |

### 9.2 Detailed tasks

1. **`AuthProvider` context component:**
   - Accepts `config` (same config as `createAuthClient`) and `children`
   - Manages session state: `user`, `status` (`loading` | `authenticated` | `unauthenticated`), `lastValidation` (timestamp)
   - Auto-revalidation: calls `getMe()` on mount and at a configurable interval
   - Exposes auth methods via context (login, register, logout, etc.)
   - Handles `onSessionExpired` to update the state automatically

2. **`useSession()` hook:**
   - Consumes the `AuthProvider` context
   - Returns `{ user: AuthUserClient | null, status, isLoading, refresh, lastValidation }`
   - `refresh()` forces immediate revalidation of the session
   - Throws an error if used outside the `AuthProvider`

3. **`useAuth()` hook:**
   - Consumes the `AuthProvider` context
   - Returns `{ login, register, logout, forgotPassword, resetPassword }`
   - Each method returns a `Promise` with appropriate types
   - `login` and `register` update the session state automatically on success

4. **`useAuthStatus()` hook:**
   - Convenience hook for simple checks
   - Returns `{ isAuthenticated: boolean, isLoading: boolean }`
   - Derived from `useSession()` internally

5. **Barrel export** in `src/react/index.ts`

6. **Tests:**
   - React Testing Library to test components and hooks
   - Mock the `AuthProvider` with different initial states
   - Verify state transitions: `loading` → `authenticated` → `unauthenticated` (after logout)
   - Verify that hooks throw an error outside the `AuthProvider`
   - Verify auto-revalidation (timer mock)

7. **Peer dependency:** `react ^19`

### 9.3 Phase 8 validation

- [ ] `AuthProvider` manages session state correctly
- [ ] `useSession()` returns updated user data
- [ ] `useAuth()` methods update the session state after login/logout
- [ ] `useAuthStatus()` derives the state correctly
- [ ] Hooks throw a descriptive error outside the `AuthProvider`
- [ ] Auto-revalidation works with a configurable interval
- [ ] Tests with React Testing Library passing
- [ ] Peer dependency `react ^19` declared
- [ ] Coverage >= 100%

---

## 10. Phase 9 — Next.js Subpath

**Duration:** 1-2 weeks (Week 7-8)
**Dependency:** Phase 7 complete (shared + client subpaths)
**Objective:** Implement Next.js utilities for authentication in the proxy (`proxy.ts`), refresh route handlers, and JWT/cookie helpers. This is the most critical frontend phase — all the patterns come from the bymax-fitness-ai project, where a redirect loop bug was found and fixed. Document ALL edge cases.

### 10.1 Files to create

| File                                           | Content                                                                                                        |
| ---------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `src/nextjs/createAuthProxy.ts`                | Factory `createAuthProxy(config)` that returns `{ proxy, config }` for use in Next.js 16's `proxy.ts`          |
| `src/nextjs/createSilentRefreshHandler.ts`     | Factory that returns a GET handler for `/api/auth/silent-refresh`                                              |
| `src/nextjs/createClientRefreshHandler.ts`     | Factory that returns a POST handler for `/api/auth/client-refresh`                                             |
| `src/nextjs/createLogoutHandler.ts`            | Factory that returns a POST handler for `/api/auth/logout` — forward to the backend + cookie cleanup           |
| `src/nextjs/helpers/buildSilentRefreshUrl.ts`  | Builds the URL for `/api/auth/silent-refresh?dest=<dest>&_r=<currentR+1>` with propagation of the `_r` counter |
| `src/nextjs/helpers/isBackgroundRequest.ts`    | Detects RSC/prefetch requests via headers (`RSC: 1`, `Next-Router-Prefetch: 1`, `Next-Router-State-Tree`)      |
| `src/nextjs/helpers/dedupeSetCookieHeaders.ts` | `dedupeSetCookieHeaders()`, `parseSetCookieHeader()` — cookie deduplication utilities                          |
| `src/nextjs/helpers/jwt.ts`                    | `decodeJwtToken()` (decode-only) and `verifyJwtToken()` (HS256 via Web Crypto API with algorithm pinning)      |
| `src/nextjs/types.ts`                          | `AuthProxyConfig`, `SilentRefreshConfig`, `ClientRefreshConfig`, `LogoutHandlerConfig` and internal types      |
| `src/nextjs/index.ts`                          | Barrel export of the nextjs subpath                                                                            |

### 10.2 Detailed tasks

1. **`createAuthProxy(config: AuthProxyConfig)`** — Factory that returns `{ proxy, config }` for `proxy.ts`:
   - **`isBackgroundRequest(request)`:** Detects RSC/prefetch requests via headers (`RSC: 1`, `Next-Router-Prefetch: 1`, `Next-Router-State-Tree`). Background requests return 401 instead of a redirect — without this, the Next.js prefetcher would receive redirect HTML instead of an RSC payload, causing hydration errors

   - **`_r` counter:** Limits silent-refresh attempts to `maxRefreshAttempts` (default 2). Prevents a redirect loop when the browser does not process the Set-Cookie between consecutive redirects. On each refresh attempt, the proxy increments `_r` in the query string. If `_r >= maxRefreshAttempts`, it redirects to login with `reason=expired` instead of trying again

   - **`reason=expired` guard:** On public routes (e.g.: `/login`), if `reason=expired` is already present in the query string, the proxy does NOT attempt a silent-refresh — the user has already been redirected after a failure, avoiding an infinite loop

   - **`has_session` signal cookie check:** The `has_session` cookie (non-HttpOnly) indicates whether an active session exists. If absent, the proxy does NOT attempt a silent-refresh on protected routes — it redirects directly to login. This avoids an unnecessary round-trip to the backend

   - **User status blocking:** Decodes the access token JWT and checks `status`. BANNED, INACTIVE or EXPIRED users are redirected to a blocking page (configurable), even with a valid token

   - **RBAC in the proxy:** Checks the JWT's `role` against the roles allowed for the route. Redirects to an access denied page if the role is insufficient. Supports redirects by role (e.g.: admin → `/admin/dashboard`, user → `/dashboard`)

   - **Header propagation:** Injects `x-user-id`, `x-user-role`, `x-tenant-id`, `x-tenant-domain` into the request headers for consumption by the server components and API routes

   - **`buildSilentRefreshUrl(destination, currentR)`:** Builds the URL for `/api/auth/silent-refresh?dest=<destination>&_r=<currentR+1>` with propagation of the `_r` counter

2. **`createSilentRefreshHandler(config?)`** — GET handler for `/api/auth/silent-refresh`:
   - Receives `dest` (post-refresh destination) and `_r` (counter) from the query string
   - Forward the request's cookies to the backend POST `/auth/refresh`
   - **Success:** 302 redirect to `dest` with propagation of Set-Cookie (new tokens)
   - **Failure:** 302 redirect to login with `reason=expired`, clear all auth cookies (access, refresh, has_session)
   - **Defense against open redirect:** Validate that `dest` is a relative path (starts with `/`), check the request's origin. Reject absolute URLs or paths that point to external domains. **Explicitly reject the `//` prefix** (protocol-relative URL attack — e.g.: `//evil.com` would be interpreted as `https://evil.com`)
   - **`dedupeSetCookieHeaders()`:** When propagating Set-Cookie from the backend, deduplicate by (name + domain) — last writer wins. Necessary because the backend may send multiple Set-Cookie for the same cookie in rotation scenarios
   - **`getSetCookie()` fallback:** For pre-Node 18.14 runtimes that do not support `Headers.getSetCookie()`, implement a fallback by parsing the `set-cookie` header manually

3. **`createClientRefreshHandler(config?)`** — POST handler for `/api/auth/client-refresh`:
   - Same-origin bridge to avoid CORS/credential cookie problems
   - The client-side `createAuthFetch` calls this endpoint instead of going directly to the backend
   - Forward the request's cookies to the backend POST `/auth/refresh`
   - Returns 200 with propagated Set-Cookie (success) or 401 (failure)
   - No redirect — it is a pure JSON API

4. **JWT helpers:**
   - **`decodeJwtToken(token)`:** Decode-only (without signature verification) — used by the proxy to read claims without needing the secret. Base64url parsing of the payload
   - **`verifyJwtToken(token, secret)`:** Complete verification with HS256 via Web Crypto API. **Mandatory algorithm pinning** — reject tokens with `alg !== 'HS256'` in the header BEFORE verifying the signature (prevents the `alg: 'none'` attack)

5. **Cookie utilities:**
   - **`dedupeSetCookieHeaders(headers)`:** Receives an array of Set-Cookie strings, groups by name+domain, keeps the last one (last writer wins)
   - **`parseSetCookieHeader(header)`:** Parses an individual Set-Cookie string into an object with `name`, `value`, `domain`, `path`, `expires`, `httpOnly`, `secure`, `sameSite`

6. **Barrel export** in `src/nextjs/index.ts`

7. **Tests:**
   - **Proxy:** test `isBackgroundRequest` with RSC/prefetch headers, test the `_r` counter (increment, limit, redirect to login), test the `reason=expired` guard, test the `has_session` cookie check
   - **Silent refresh handler:** mock fetch to the backend, test success with Set-Cookie propagation, test failure with cookie cleanup, test open redirect defense
   - **Client refresh handler:** test the same-origin bridge, test 200 vs 401
   - **JWT:** test decode of a valid payload, test HS256 verification, test rejection of `alg: 'none'`
   - **Cookies:** test dedup with multiple Set-Cookie, test parsing of a complex header

8. **Peer dependencies:** `next ^16`, `react ^19`

### 10.3 Phase 9 validation

- [ ] `createAuthProxy` integrates with Next.js 16's `proxy.ts`
- [ ] `isBackgroundRequest` detects RSC and prefetch correctly
- [ ] `_r` counter prevents a redirect loop (tested with 3+ attempts)
- [ ] `reason=expired` guard avoids retrying on public routes
- [ ] `has_session` cookie check avoids unnecessary refresh
- [ ] User status blocking functional (BANNED, INACTIVE, EXPIRED)
- [ ] RBAC in the proxy with redirects by role
- [ ] Headers `x-user-id`, `x-user-role`, `x-tenant-id`, `x-tenant-domain` propagated
- [ ] Silent refresh handler with Set-Cookie propagation functional
- [ ] Defense against open redirect tested (includes rejection of the `//` prefix — protocol-relative URL attack)
- [ ] `dedupeSetCookieHeaders` deduplication by name+domain
- [ ] Client refresh handler returns 200/401 correctly
- [ ] `verifyJwtToken` rejects `alg: 'none'` (algorithm pinning)
- [ ] Peer dependencies `next ^16` and `react ^19` declared
- [ ] Proxy coverage >= 100% (critical path)
- [ ] Overall coverage >= 100%

---

## 11. Quality Criteria per Phase

| Criterion                | Requirement                                                                                                                                                                                      |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Compilation**          | `pnpm build` without errors in each phase                                                                                                                                                        |
| **Test coverage**        | >= 100% (branches, functions, lines) per phase                                                                                                                                                   |
| **Linting**              | Zero ESLint errors                                                                                                                                                                               |
| **Typing**               | Zero use of `any` in production code. Prefer discriminated types over `Record<string, unknown>`. For untyped external data, use narrowing documented via JSDoc                                   |
| **Security**             | Review of the Appendix B items applicable to the phase                                                                                                                                           |
| **Redis performance**    | All operations O(1) except session listing                                                                                                                                                       |
| **DI without cycles**    | `TokenManagerService` NEVER injects `SessionService`. Session rotation is called by `AuthService`. `InvitationService` uses `hasRole()` from `utils/roles.util.ts`, does not inject `RolesGuard` |
| **Barrel export**        | Updated in each phase with new exports. DTOs always `export` (never `export type`) to preserve `class-validator` metadata at runtime                                                             |
| **Inline documentation** | JSDoc on all public methods (minimal in the phase, complete in 6)                                                                                                                                |
| **Phase 7**              | 100% coverage, zero external dependencies verified, types compatible with the server's exports                                                                                                   |
| **Phase 8**              | Component tests with React Testing Library, hooks tested in isolation                                                                                                                            |
| **Phase 9**              | Proxy logic with 100%+ coverage (critical path), redirect loop scenarios tested                                                                                                                  |

---

## 12. Risks and Mitigations

| Risk                                                             | Probability | Impact | Mitigation                                                                                                                                                                                                                                                                                                                 |
| ---------------------------------------------------------------- | ----------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Complexity of the NestJS dynamic module                          | High        | High   | Implement a basic scaffold in Phase 1, iterate in Phase 2. Use `DynamicModule` with a dynamic `controllers` array + `RouterModule` for the prefix                                                                                                                                                                          |
| Conditional controller registration                              | High        | High   | Build the `controllers` array dynamically in `registerAsync`. Test with each controller enabled/disabled                                                                                                                                                                                                                   |
| Refresh token Lua script with a race condition                   | Medium      | High   | Tests with simulated concurrency, review of the Lua script                                                                                                                                                                                                                                                                 |
| Incompatibility of peer dep versions                             | Medium      | Medium | Use flexible ranges (`^11.0.0`), test with minimum and maximum versions                                                                                                                                                                                                                                                    |
| AES-256-GCM cryptography with subtle errors                      | Medium      | High   | Extensive round-trip tests, use native Node.js crypto (not a polyfill)                                                                                                                                                                                                                                                     |
| `resolveOptions` stripping functions in a deep merge             | Medium      | High   | Use shallow merge per group (spread), never `JSON.parse/stringify`. Test that functions survive the merge                                                                                                                                                                                                                  |
| Optional peer dependencies (`@nestjs/websockets`)                | Medium      | Medium | Use `require.resolve()` with try/catch. Descriptive error if absent and the functionality is configured                                                                                                                                                                                                                    |
| OAuth state CSRF with multiple instances                         | Low         | High   | Test with Redis shared across instances                                                                                                                                                                                                                                                                                    |
| DoS via long recovery codes in scrypt                            | Low         | Medium | `@MaxLength(128)` in the MFA challenge DTO                                                                                                                                                                                                                                                                                 |
| Timing side-channel in OTP verification                          | Low         | Medium | Use `timingSafeEqual` with buffers of the same length; reject beforehand if the length differs                                                                                                                                                                                                                             |
| Cookie domain injection via Host header                          | Low         | High   | Validate the hostname in `extractDomain()`, document the allowlist in `resolveDomains`                                                                                                                                                                                                                                     |
| Timing normalization in anti-enumeration endpoints               | Medium      | Medium | Concrete pattern: `const start = Date.now()` at the beginning, `await sleep(Math.max(0, MIN_RESPONSE_MS - (Date.now() - start)))` before returning (MIN_RESPONSE_MS = 300ms). Apply on the 4 endpoints: `initiateReset`, `resendOtp`, `resendVerificationEmail`, `verifyEmail`. Best-effort, not a cryptographic guarantee |
| Recovery codes exhausted without TOTP                            | Low         | High   | Document that recovery requires admin intervention. No regeneration endpoint in v1                                                                                                                                                                                                                                         |
| Set-Cookie not processed between redirects (browser behavior)    | Medium      | High   | Mitigated by the `_r` counter that limits silent-refresh attempts and by the `reason=expired` guard that interrupts the loop                                                                                                                                                                                               |
| Race condition between the proxy and the client-side interceptor | Medium      | Medium | Mitigated by the 500ms delay in the client-side interceptor's redirect, allowing the proxy to process first                                                                                                                                                                                                                |

---

## 13. Dependencies between Phases

```
Phase 1 (Foundation)
  │
  ├──→ Phase 2 (Auth Core)
  │      │
  │      ├──→ Phase 3 (MFA) ──────────┐
  │      │                            │
  │      └──→ Phase 4 (Sessions) ────┤
  │                                   │
  │                                   └──→ Phase 5 (Platform + OAuth + Invitations)
  │                                          │
  └──────────────────────────────────────────┴──→ Phase 6 (Integration + Polishing)
                                                    │
                                                    ├──→ Phase 7 (Shared + Client)
                                                    │      │
                                                    │      ├──→ Phase 8 (React)
                                                    │      │
                                                    │      └──→ Phase 9 (Next.js)
```

**Phases 3 and 4 can be started in parallel** (both depend only on Phase 2), with caveats:

- `MfaService.challenge()` (Phase 3) injects `@Optional() SessionService` — it compiles without it, but the session integration in the MFA challenge requires Phase 4 complete
- Both phases modify `AuthService` from Phase 2 (Phase 3 for MFA redirect, Phase 4 for sessions) — watch out for merge conflicts
- `OtpService` was moved to Phase 2, eliminating the original circular dependency

**Phase 5 depends on Phases 3 and 4** because:

- `PlatformAuthService` reuses `MfaService.challenge()` with `context: 'platform'` (Phase 3)
- `OAuthService` can create sessions (Phase 4)
- `InvitationService` can integrate with sessions (Phase 4)

**Phases 7-9 depend on Phase 6** (server complete and tested). Phases 8 and 9 can be partially parallelized, since both depend on Phase 7 (shared + client) but do not depend on each other.

---

## 14. Audit Log

| Version | Date       | Description                                                                                                                                                                                                              |
| ------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| v1.0.0  | 2026-04-10 | Initial version of the plan — Phases 1-6 (complete server)                                                                                                                                                               |
| v1.1.0  | 2026-04-10 | Initial version after an audit by 4 specialist agents. Security, typing and consistency fixes                                                                                                                            |
| v1.2.0  | 2026-04-13 | Addition of Phases 7-9 (frontend subpaths: shared, client, react, nextjs). Removal of Passport/bcrypt/otpauth — native JWT guards via `@nestjs/jwt`, cryptography via `node:crypto`. Build tool changed to `tsup ^8.0.0` |

---

_End of the development plan._
