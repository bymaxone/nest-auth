# Changelog

All notable changes to `@bymax-one/nest-auth` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Phase 1 — Foundation and Infrastructure (NEST-001 to NEST-042)

**Scaffold and tooling**
- `package.json` with scope `@bymax-one`, peer dependencies (NestJS 11, ioredis, class-validator), zero direct runtime dependencies
- `tsconfig.json` and `tsconfig.build.json` with `strict: true`, ES2022 target, decorator support
- `tsconfig.jest.json` for ts-jest compilation
- ESLint flat config (`eslint.config.mjs`) with `@typescript-eslint`, `eslint-plugin-import`, `eslint-plugin-security`, `eslint-plugin-prettier`
- Prettier configuration (`.prettierrc`)
- Jest configuration (`jest.config.ts`) with ts-jest, 80% global coverage threshold, 95% for `crypto/` and `guards/`
- tsup build configuration (`tsup.config.ts`) for 5 subpaths with dual ESM+CJS output and `.d.ts` declarations
- Source directory structure: `server/{interfaces,config,services,controllers,guards,decorators,redis,dto,crypto,errors,oauth,constants,providers,hooks,utils}`, `shared`, `client`, `react`, `nextjs`
- MIT License, `.gitignore`, `AGENTS.md`, `CLAUDE.md`

**Interfaces**
- `BymaxAuthModuleOptions` — full module configuration interface with 15 optional groups (jwt, password, tokenDelivery, cookies, mfa, sessions, bruteForce, passwordReset, emailVerification, platformAdmin, invitations, roles, blockedStatuses, oauth, controllers)
- `AuthUser` and `SafeAuthUser` — user entity interfaces (15 fields) with credential-free safe variant
- `IUserRepository` — data access interface with 11 methods (findById, findByEmail, create, updatePassword, updateMfa, updateLastLogin, updateStatus, updateEmailVerified, findByOAuthId, linkOAuth, createWithOAuth)
- `AuthPlatformUser` and `IPlatformUserRepository` — platform admin entity and repository interfaces
- `IEmailProvider` — email delivery interface with 7 methods (OTP, reset, MFA notifications, session alert, invitation), each with optional `locale` parameter
- `IAuthHooks` — lifecycle hook interface with 12 optional hooks (beforeRegister, afterRegister, beforeLogin, afterLogin, afterLogout, afterMfaEnabled, afterMfaDisabled, onNewSession, afterEmailVerified, afterPasswordReset, onOAuthLogin, afterInvitationAccepted)
- `HookContext` — sanitized request context passed to all hooks (ip, userAgent, sanitizedHeaders, optional userId/email/tenantId)
- `BeforeRegisterResult` — hook result type with `allowed`, `reason`, and `modifiedData` fields
- `DashboardJwtPayload`, `PlatformJwtPayload`, `MfaTempPayload` — JWT payload interfaces
- `AuthResult`, `PlatformAuthResult`, `MfaChallengeResult`, `RotatedTokenResult` — service result types
- `AuthenticatedRequest` and `PlatformAuthenticatedRequest` — Express Request extensions with typed `user` payload
- `OAuthProviderPlugin` — native OAuth2 plugin interface (no Passport)
- `OAuthProfile` and `OAuthLoginResult` — OAuth profile and hook result types

**Constants and configuration**
- 6 Symbol-based DI injection tokens: `BYMAX_AUTH_OPTIONS`, `BYMAX_AUTH_USER_REPOSITORY`, `BYMAX_AUTH_PLATFORM_USER_REPOSITORY`, `BYMAX_AUTH_EMAIL_PROVIDER`, `BYMAX_AUTH_HOOKS`, `BYMAX_AUTH_REDIS_CLIENT`
- `DEFAULT_OPTIONS` — all default values (jwt.accessExpiresIn `'15m'`, refreshExpiresInDays `7`, tokenDelivery `'cookie'`, bruteForce 5 attempts / 900s window, etc.)
- `resolveOptions()` — startup function that merges consumer options with defaults, validates all security invariants, and produces `ResolvedOptions` with no optional fields
- Throttle configurations (`THROTTLE_CONFIGS`) per endpoint category

**Crypto utilities** (`src/server/crypto/`)
- `sha256(input)` — deterministic SHA-256 hex digest via `node:crypto`
- `hmacSha256(input, secret)` — keyed HMAC-SHA256 hex digest for low-entropy inputs (composite keys with email addresses)
- `encrypt(plaintext, keyBase64)` / `decrypt(ciphertext, keyBase64)` — AES-256-GCM authenticated encryption using random 12-byte IV per call; wire format `base64(iv):base64(authTag):base64(ciphertext)`
- `generateSecureToken()` — cryptographically random opaque token via `node:crypto.randomBytes`

**Error handling** (`src/server/errors/`)
- `AUTH_ERROR_CODES` — typed string union of all 30+ error codes with Portuguese end-user messages
- `AuthException` — NestJS `HttpException` subclass carrying structured `{ code, message, details? }` response body

**Redis layer** (`src/server/redis/`)
- `AuthRedisService` — typed wrapper around ioredis with automatic namespace prefixing; exposes `get`, `set`, `del`, `setnx`, `incr`, `expire`, `ttl`, `sadd`, `srem`, `smembers`, `sismember`, `eval`, `getdel`, `incrWithFixedTtl`
- `AuthRedisModule` — internal NestJS module registering `AuthRedisService`

**Services** (`src/server/services/`)
- `PasswordService` — scrypt-based password hashing and constant-time comparison; configurable cost factor, block size, and parallelization
- `BruteForceService` — fixed-window rate limiting via atomic `incrWithFixedTtl` Lua script; lockout with `getRemainingLockoutSeconds`
- `TokenManagerService` — JWT issuance (`issueTokens`, `issueMfaTempToken`), token rotation (`reissueTokens`), revocation blacklist via Redis `rv:{jti}` keys, raw refresh token storage via `rt:{sha256(token)}`
- `TokenDeliveryService` — cookie/bearer/both delivery modes; multi-domain support via `resolveDomains` callback; `extractAccessToken`, `extractRefreshToken`, `clearAuthSession`

**Utilities** (`src/server/utils/`)
- `sanitizeHeaders()` — removes sensitive headers (authorization, cookie, x-api-key, x-auth-token, x-csrf-token, x-session-id, pattern `/^x-.*-token$/i`) before passing to hook context
- `sleep(ms)` — Promise-based delay for timing normalization in anti-enumeration flows
- `hasRole(userRole, requiredRole, hierarchy)` — recursive role hierarchy checker supporting denormalized role trees

**NoOp fallback providers**
- `NoOpEmailProvider` — silent no-op implementation of `IEmailProvider` (registered when consumer does not supply one)
- `NoOpAuthHooks` — silent no-op implementation of `IAuthHooks` (registered when consumer does not supply one)

**Phase 1 barrel export** (`src/server/index.ts`) — all interfaces, types, constants, error codes, and injectable tokens

---

#### Phase 2 — Core Authentication (NEST-043 to NEST-064)

**Guards** (`src/server/guards/`)
- `JwtAuthGuard` — native NestJS guard (no Passport); verifies JWT via `@nestjs/jwt` `JwtService.verify()` with algorithm pinning from `ResolvedOptions.jwt.algorithm`; checks `rv:{jti}` revocation blacklist; skips public routes decorated with `@Public()`; asserts token type is `'dashboard'` via `assertTokenType` utility
- `RolesGuard` — hierarchical role guard using denormalized `roles.hierarchy`; reads `@Roles()` metadata via `Reflector`; throws `INSUFFICIENT_ROLE` (403) on failure
- `UserStatusGuard` — status-based access guard with Redis caching (`us:{userId}`, TTL from `userStatusCacheTtlSeconds`); maps blocked statuses to specific error codes (ACCOUNT_BANNED, ACCOUNT_INACTIVE, ACCOUNT_SUSPENDED, PENDING_APPROVAL) with ACCOUNT_INACTIVE as fallback
- `assertTokenType` utility — reusable guard helper that throws `TOKEN_INVALID` when the JWT `type` claim does not match the expected value

**Decorators** (`src/server/decorators/`)
- `@CurrentUser(property?)` — param decorator extracting `request.user` or a specific property from it
- `@Roles(...roles)` — metadata decorator setting `ROLES_KEY` for `RolesGuard`
- `@Public()` — metadata decorator setting `IS_PUBLIC_KEY` to skip `JwtAuthGuard`

**DTOs** (`src/server/dto/`)
- `RegisterDto` — `email`, `password` (8–128 chars), `name` (2+ chars), `tenantId`; all with class-validator decorators
- `LoginDto` — `email`, `password` (no `@MinLength` — deliberate anti-enumeration), `tenantId`

**Services** (`src/server/services/`)
- `OtpService` — `generate(length)` via `crypto.randomInt` with leading-zero padding; `store(purpose, identifier, code, ttl)` to Redis; `verify(purpose, identifier, code)` with constant-time comparison via `crypto.timingSafeEqual` (safe for different-length inputs), max-attempt enforcement (5), key deletion on exhaustion, and timing normalization (100ms floor); atomic attempt increment via Lua eval (single round-trip preserving TTL)
- `AuthService` — full authentication lifecycle: `register`, `login`, `logout`, `refresh`, `getMe`, `verifyEmail`, `resendVerificationEmail`; `@Optional()` hooks with fire-and-forget error isolation; tenant resolution via `tenantIdResolver`; brute-force integration; MFA challenge path

**Controllers** (`src/server/controllers/`)
- `AuthController` — 7 endpoints: `POST /register`, `POST /login`, `POST /logout`, `POST /refresh`, `GET /me`, `POST /verify-email`, `POST /resend-verification`; `@UsePipes(new ValidationPipe({ whitelist: true }))` at class level; conditional registration via `controllers.auth` option

**Module**
- `BymaxAuthModule.registerAsync(options)` — dynamic NestJS module; wraps consumer factory with `resolveOptions()`; conditionally registers `AuthController`; registers NoOp fallback providers when consumer omits email/hooks tokens; class-shorthand provider detection in `hasProviderToken`; `JwtModule.registerAsync` reads `jwt.secret` directly (no double `resolveOptions` call)

**Phase 2 barrel export** — adds `BymaxAuthModule`, `AuthService`, `JwtAuthGuard`, `RolesGuard`, `UserStatusGuard`, `CurrentUser`, `Roles`, `ROLES_KEY`, `Public`, `IS_PUBLIC_KEY`, `RegisterDto`, `LoginDto`

---

#### Phase 3 — Multi-Factor Authentication (TOTP)

**Crypto utilities** (`src/server/crypto/totp.ts`)
- `generateTotpSecret()` — generates a cryptographically random 20-byte TOTP secret via `node:crypto.randomBytes`; returns both raw `Buffer` and `base32`-encoded string
- `buildTotpUri(secret, account, issuer)` — constructs a standard `otpauth://totp/` URI for QR code generation
- `verifyTotp(secret, code, window)` — validates a 6-digit TOTP code within a configurable step window (±1 by default) using HMAC-SHA1 per RFC 6238
- `generateHotp(secret, counter)` — low-level HOTP generation (RFC 4226) used internally by `verifyTotp` and exposed for testing
- `fromBase32(input)` / `toBase32(buf)` — pure Base32 encode/decode without external dependencies; `fromBase32` strips whitespace, hyphens, and padding before decoding

**Services** (`src/server/services/mfa.service.ts`)
- `MfaService.setup(userId)` — generates TOTP secret and recovery codes; uses atomic `setIfAbsent` to guarantee idempotency under concurrent requests; encrypts secret with AES-256-GCM; returns plain recovery codes once (then discarded)
- `MfaService.verifyAndEnable(userId, code, ip, userAgent)` — validates the first TOTP code against the pending setup key; atomically consumes the setup key to prevent double-enable races; persists encrypted secret and hashed recovery codes to the user repository; invalidates all existing refresh sessions
- `MfaService.challenge(tempToken, code, ip, userAgent)` — exchanges a short-lived MFA temp token for full auth tokens; accepts both TOTP codes and recovery codes; enforces anti-replay via 90-second `setnx` key; brute-force lockout with `challenge:`-namespaced counter; supports both `dashboard` and `platform` contexts
- `MfaService.disable(userId, code, ip, userAgent, context)` — disables MFA after TOTP verification; only accepts TOTP (recovery codes cannot disable by design); invalidates all sessions; supports both dashboard and platform repositories via `context` parameter

**Guards** (`src/server/guards/mfa-required.guard.ts`)
- `MfaRequiredGuard` — enforces MFA verification on routes where the authenticated JWT has `mfaEnabled: true`; gates on `mfaVerified: true` claim; respects `@SkipMfa()` decorator to exclude specific endpoints (e.g. the challenge endpoint itself)

**Decorators** (`src/server/decorators/skip-mfa.decorator.ts`)
- `@SkipMfa()` — metadata decorator that marks an endpoint as exempt from `MfaRequiredGuard`; used on `POST /mfa/challenge` and any other pre-MFA routes

**DTOs** (`src/server/dto/`)
- `MfaChallengeDto` — `mfaTempToken` (string) + `code` (string); `@MaxLength(14)` as defence-in-depth before regex
- `MfaVerifyDto` — 6-digit TOTP code; `@MaxLength(6)` + `@Matches(/^\d{6}$/)`
- `MfaDisableDto` — 6-digit TOTP code; `@MaxLength(6)` + `@Matches(/^\d{6}$/)`; JSDoc explains why recovery codes are not accepted

**Controllers** (`src/server/controllers/mfa.controller.ts`)
- `POST /mfa/setup` — initiates TOTP setup; returns secret, QR URI, and plain recovery codes (shown once); idempotent within 10-minute window; dashboard users only
- `POST /mfa/verify-enable` — submits the first TOTP code to permanently activate MFA; returns 204 No Content
- `POST /mfa/challenge` — public endpoint (protected only by temp token); exchanges temp token + TOTP or recovery code for full auth tokens; returns cookie or bearer response for dashboard, plain JSON for platform
- `POST /mfa/disable` — disables MFA for dashboard or platform users; derived `context` from `user.type` JWT claim; returns 204 No Content

**Redis additions** (`src/server/redis/auth-redis.service.ts`)
- `setIfAbsent(key, value, ttl)` — atomic `SET NX EX`; returns `true` if the key was newly created, `false` if it already existed; used for idempotent setup key reservation
- `invalidateUserSessions(userId)` — Lua script that reads all members of `sess:{userId}`, deletes each session key (including grace pointers tracked in the SET), and removes the SET itself in a single round-trip

**Module integration** (`src/server/bymax-one-nest-auth.module.ts`)
- `controllers.mfa: true` option conditionally registers `MfaController`; startup validation throws if `controllers.mfa: true` is set without the `mfa` configuration group

---

### Security

- **Grace pointer survivorship fix** — `rotateFromPrimary` and `rotateFromGrace` now add grace pointer keys (`rp:{hash}`) to the `sess:{userId}` Redis SET so that `invalidateUserSessions` (called on MFA enable/disable) deletes them atomically, preventing stale refresh tokens from surviving MFA state changes
- **Brute-force counter namespacing** — MFA challenge and disable endpoints use HMAC identifiers prefixed with `challenge:` and `disable:` respectively, preventing a pre-auth attacker from exhausting the disable counter via the public challenge endpoint
- **`verifyAndEnable` re-entry guard** — added `MFA_ALREADY_ENABLED` check at entry so that a stale Redis setup key from a previous attempt cannot overwrite an active MFA secret and recovery codes
- **`disable()` context-awareness** — the disable flow now accepts a `context` parameter (`'dashboard'` | `'platform'`) and dispatches to the correct repository, preventing platform admins from receiving `TOKEN_INVALID` when attempting to disable MFA
- **HMAC keying for composite Redis keys**  — all `sha256(tenantId + email)` call sites replaced with `hmacSha256(..., jwt.secret)` to prevent rainbow-table reversal of email addresses stored as Redis key segments
- **Atomic resend cooldown** — GET+SET TOCTOU race in `resendVerificationEmail` replaced with atomic `SET NX EX` (`setnx`) preventing duplicate OTP sends under concurrent requests
- **Immutable DTO merging** — `Object.assign(dto, hookResult.modifiedData)` replaced with `dto = { ...dto, ...modifiedData }` preventing mutation of the class-validator–validated DTO and bypassing decorator constraints
- **`secureCookies` resolved at startup** — `process.env.NODE_ENV === 'production'` check moved from per-request code inside `TokenDeliveryService` to `resolveOptions()`, eliminating an environment-variable read inside library service methods
- **Algorithm pinning from options** — `JwtAuthGuard` now reads `algorithms: [this.options.jwt.algorithm]` instead of hardcoding `['HS256']`, ensuring the algorithm is validated once at startup and consistent across the full JWT lifecycle
- **Atomic OTP attempt increment** — `incrementAttempts` now uses a single Lua `EVAL` (GET+SET with preserved TTL) instead of separate `TTL` + `SET EX` calls, eliminating a race window between reads and writes
- **OTP key deleted on max-attempt exhaustion** — `verify()` now calls `redis.del(key)` when `attempts >= MAX_ATTEMPTS` before throwing `OTP_MAX_ATTEMPTS`, preventing further probing after lockout
- **`refreshCookiePath` validation is now a hard error** — mismatched `routePrefix` without explicit `refreshCookiePath` previously logged a warning; now throws at startup to prevent misconfigured cookie paths reaching production
- **`validateRefreshGraceWindowSeconds`** — startup validation added: throws if `refreshGraceWindowSeconds >= refreshExpiresInDays * 86400` to prevent a grace window larger than the token's lifetime

---

### Tests

- 561 tests across 34 co-located spec files (`*.spec.ts`), including `mfa-integration.spec.ts` with 11 Phase 3 end-to-end scenarios
- **100% coverage** on all metrics (Statements, Branches, Functions, Lines) across every source file
- Per-directory coverage thresholds enforced: 95% for `crypto/` and `guards/`, 80% global
- Every `it()` block has an English comment explaining the branch under test
- All spec files have a file-level JSDoc docblock describing strategy, mocks, and special setup
- Phase 3 integration smoke test validates: full setup→enable→challenge flow, idempotency, recovery codes, anti-replay, brute-force lockout, counter namespacing, platform context, session invalidation, disable TOTP-only enforcement, and `@SkipMfa()` guard bypass
