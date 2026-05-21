# Development Tasks — @bymax-one/nest-auth

> Generated on: 2026-04-11
> Based on: [development_plan.md](./development_plan.md) and [technical_specification.md](./technical_specification.md)
> Total tasks: 185

---

## Status Control

| Status      | Emoji | Description               |
| ----------- | ----- | ------------------------- |
| TODO        | ⬜    | Not started               |
| IN_PROGRESS | 🔄    | In progress               |
| DONE        | ✅    | Completed and verified    |
| BLOCKED     | 🚫    | Blocked by dependency     |
| REVIEW      | 👀    | Under review              |

## Specialist Agents

| Agent                 | When to use                                                                  |
| --------------------- | ---------------------------------------------------------------------------- |
| `architect`           | Interface design, dynamic module, project structure, barrel exports          |
| `planner`             | Planning complex sub-systems                                                 |
| `typescript-reviewer` | Type review, interfaces, generics, DTOs                                      |
| `security-reviewer`   | Crypto (AES-GCM, scrypt, native TOTP), JWT, brute-force, constant-time, CSRF |
| `code-reviewer`       | Overall quality, NestJS patterns, services, controllers, guards              |
| `database-reviewer`   | Redis operations, Lua scripts, key design                                    |
| `general-purpose`     | Scaffold, configuration, initial setup, tests                                |

## Progress Dashboard

| Phase                                       | Total   | TODO    | DONE   | Progress  |
| ------------------------------------------- | ------- | ------- | ------ | --------- |
| Phase 1 — Foundation and Infrastructure     | 42      | 0       | 42     | 100%      |
| Phase 2 — Core Authentication               | 22      | 0       | 22     | 100%      |
| Phase 3 — Multi-Factor Authentication (MFA) | 15      | 0       | 15     | 100%      |
| Phase 4 — Sessions and Password Reset       | 17      | 0       | 17     | 100%      |
| Phase 5 — Platform, OAuth and Invitations   | 25      | 0       | 25     | 100%      |
| Phase 6 — Integration, Polish and Publishing| 30      | 0       | 30     | 100%      |
| Phase 7 — Shared + Client Subpath           | 9       | 0       | 9      | 100%      |
| Phase 8 — React Subpath                     | 8       | 0       | 8      | 100%      |
| Phase 9 — Next.js Subpath                   | 17      | 0       | 17     | 100%      |
| **TOTAL**                                   | **185** | **0**   | **185**| **100%**  |

---

## Phase 1 — Foundation and Infrastructure

### NEST-001: Project scaffold - package.json and pnpm init

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** None
- **Agent:** architect
- **Estimate:** ~20min
- **Description:** Initialize the pnpm package with scope @bymax-one, configure package.json with name, version, peer dependencies, scripts (build, lint, test, test:cov, prepublishOnly), and "files": ["dist"].

**Prompt for the agent:**

> Create the package.json for @bymax-one/nest-auth v1.0.0. Run `pnpm init` with scope @bymax-one. Configure scripts: "build": "tsup", "lint": "eslint src/\*_/_.ts", "test": "jest", "test:cov": "jest --coverage", "prepublishOnly": "pnpm build". Set "files": ["dist"] for precise publish control. Add peer dependencies as specified in section 18 of /Users/maximiliano/Documents/My Apps/nest-auth/docs/technical_specification.md: @nestjs/common, @nestjs/core, @nestjs/jwt, @nestjs/throttler, ioredis, class-validator, class-transformer, reflect-metadata ^0.2.0. No direct dependencies (`"dependencies": {}`). Install devDependencies: @nestjs/testing, jest, ts-jest, typescript, @types/node, @types/express, tsup ^8.0.0. Verify pnpm install succeeds.

---

### NEST-002: Project scaffold - TypeScript configuration

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-001
- **Agent:** architect
- **Estimate:** ~20min
- **Description:** Create tsconfig.json and tsconfig.build.json with strict mode, ES2022 target, decorator support, and declaration output.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/tsconfig.json with: target ES2022, module commonjs, strict true, experimentalDecorators true, emitDecoratorMetadata true, declaration true, declarationMap true, sourceMap true, outDir "./dist", rootDir "./src", esModuleInterop true, skipLibCheck true. Create /Users/maximiliano/Documents/My Apps/nest-auth/tsconfig.build.json that extends ./tsconfig.json and excludes ["**/*.spec.ts", "test/", "node_modules/"]. Verify tsc --noEmit succeeds after creating a minimal src/server/index.ts.

---

### NEST-003: Project scaffold - ESLint, Jest, and misc config files

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-001
- **Agent:** architect
- **Estimate:** ~20min
- **Description:** Configure ESLint with @typescript-eslint, Jest with ts-jest preset and 80% coverage thresholds, .gitignore, LICENSE (MIT), and empty CHANGELOG.md.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/.eslintrc.js with @typescript-eslint plugin and NestJS-appropriate rules. Create /Users/maximiliano/Documents/My Apps/nest-auth/jest.config.ts with preset ts-jest, rootDir src/, coverage thresholds of 80% for branches, functions, lines, and statements. Create .gitignore (node_modules/, dist/, coverage/, .env). Create LICENSE with MIT license per section 1.4 of the spec. Create CHANGELOG.md as empty placeholder. Create src/server/index.ts as empty barrel export. Verify `pnpm build` compiles without errors.

---

### NEST-004: Project scaffold - directory structure

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-001
- **Agent:** architect
- **Estimate:** ~20min
- **Description:** Create all source subdirectories under src/ as specified in the development plan.

**Prompt for the agent:**

> Create the following directory structure under /Users/maximiliano/Documents/My Apps/nest-auth/src/: server/ (interfaces/, config/, services/, controllers/, guards/, decorators/, redis/, dto/, crypto/, errors/, oauth/, constants/, providers/, hooks/), shared/, client/, react/, nextjs/. Each directory should have a .gitkeep file or index.ts placeholder as appropriate. Verify the structure is correct.

---

### NEST-005: Interface - BymaxAuthModuleOptions

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-004
- **Agent:** typescript-reviewer
- **Estimate:** ~45min
- **Description:** Implement the main module options interface with all 15 configuration groups as specified in section 4.1 of the technical specification.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/interfaces/auth-module-options.interface.ts. Implement interface BymaxAuthModuleOptions with all 15 groups from section 4.1 of /Users/maximiliano/Documents/My Apps/nest-auth/docs/technical_specification.md: jwt (secret, algorithm, accessExpiresIn, refreshExpiresInDays, refreshGraceWindowSeconds), password (saltRounds, minLength, maxLength), tokenDelivery ('cookie'|'bearer'|'both'), cookies (accessTokenName, refreshTokenName, sessionSignalName, secure, sameSite, httpOnly, refreshCookiePath, resolveDomains), mfa (encryptionKey, issuer, totpWindow, recoveryCodeCount), sessions (enabled, maxSessions, maxSessionsResolver, newSessionAlert), bruteForce (maxAttempts, windowSeconds), passwordReset (method, otpLength, otpTtlSeconds, tokenTtlSeconds), emailVerification (required, otpTtlSeconds), platform (enabled, platformHierarchy), invitations (enabled, tokenTtlDays, maxPendingPerTenant), roles (hierarchy), blockedStatuses, oauth (google, github, etc.), controllers (auth, mfa, sessions, passwordReset, platform, oauth, invitations). Type tenantIdResolver as (req: import('express').Request) => string | Promise<string>. Add routePrefix (default 'auth'), namespace for Redis. Add JSDoc to every property. All groups except jwt should be optional.

---

### NEST-006: Interface - AuthUser and IUserRepository

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-004
- **Agent:** typescript-reviewer
- **Estimate:** ~30min
- **Description:** Implement AuthUser interface (15 fields) and IUserRepository interface (11 methods) per the spec.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/interfaces/user-repository.interface.ts. Implement AuthUser with 15 fields: id, email, name, passwordHash (string|null for OAuth users), role, status, tenantId, emailVerified, mfaEnabled (optional), mfaSecret (optional), mfaRecoveryCodes (optional string[]), lastLoginAt (Date|null), deletedAt (Date|null), updatedAt (Date), createdAt. Implement IUserRepository with 11 methods: findById(id, tenantId?): Promise<AuthUser|null>, findByEmail(email, tenantId): Promise<AuthUser|null>, create(data) where data accepts passwordHash: string|null, updatePassword(id, hash), updateMfa(id, data: {mfaEnabled, mfaSecret, mfaRecoveryCodes}), updateLastLogin(id), updateStatus(id, status), updateEmailVerified(id, verified), findByOAuthId(provider, oauthId, tenantId), linkOAuth(userId, provider, oauthId), createWithOAuth(data). Add JSDoc on every method.

---

### NEST-007: Interface - AuthPlatformUser and IPlatformUserRepository

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-004
- **Agent:** typescript-reviewer
- **Estimate:** ~30min
- **Description:** Implement AuthPlatformUser interface (13 fields) and IPlatformUserRepository interface (6 methods).

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/interfaces/platform-user-repository.interface.ts. Implement AuthPlatformUser with 13 fields as specified in the spec. Implement IPlatformUserRepository with 6 methods: findById, findByEmail, updateLastLogin, updateMfa, updatePassword, updateStatus. Add JSDoc on every method. Reference section 11 of /Users/maximiliano/Documents/My Apps/nest-auth/docs/technical_specification.md.

---

### NEST-008: Interface - IEmailProvider

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-004
- **Agent:** typescript-reviewer
- **Estimate:** ~30min
- **Description:** Implement IEmailProvider with 7 email methods, each accepting optional locale parameter.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/interfaces/email-provider.interface.ts. Implement IEmailProvider with 7 methods: sendPasswordResetToken(email, token, locale?), sendPasswordResetOtp(email, otp, locale?), sendEmailVerificationOtp(email, otp, locale?), sendMfaEnabledNotification(email, locale?), sendMfaDisabledNotification(email, locale?), sendNewSessionAlert(email, sessionInfo, locale?), sendInvitation(email, inviteData, locale?). All methods return Promise<void>. Add JSDoc with parameter descriptions. Reference section 10 of the technical spec.

---

### NEST-009: Interface - IAuthHooks, HookContext, and related types

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-004
- **Agent:** typescript-reviewer
- **Estimate:** ~30min
- **Description:** Implement IAuthHooks interface with 12 optional hooks, HookContext, BeforeRegisterResult, OAuthLoginResult, and OAuthProfile types.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/interfaces/auth-hooks.interface.ts. Implement HookContext with { userId?, email?, tenantId?, ip: string, userAgent: string, headers: Record<string, string> } where headers are sanitized. Implement BeforeRegisterResult { allowed: boolean, reason?: string, modifiedData?: { role?, status?, emailVerified? } }. Implement OAuthLoginResult { action: 'link'|'create'|'reject', reason?: string }. Implement OAuthProfile { provider, providerId, email, name?, avatar? }. Implement IAuthHooks with 12 OPTIONAL methods (all with ?): beforeRegister, afterRegister, beforeLogin, afterLogin, afterLogout, afterMfaEnabled, afterMfaDisabled, onNewSession, afterEmailVerified, afterPasswordReset, onOAuthLogin, afterInvitationAccepted. Add JSDoc. Also implement sanitizeHeaders(headers: Record<string,string>): Record<string,string> function that blocklists ['authorization','cookie','x-api-key','x-auth-token','x-csrf-token','x-session-id'] plus pattern /^x-.\*-token$/i. Include unit tests for sanitizeHeaders in a separate spec file.

---

### NEST-010: Interface - JWT Payload types

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-004
- **Agent:** typescript-reviewer
- **Estimate:** ~30min
- **Description:** Implement DashboardJwtPayload, PlatformJwtPayload, and MfaTempPayload interfaces.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/interfaces/jwt-payload.interface.ts. Implement DashboardJwtPayload with fields: jti (string), sub (string), tenantId (string), role (string), type (literal 'dashboard'), status (string), mfaVerified (boolean), iat (number), exp (number). Note: emailVerified is NOT a JWT claim. Implement PlatformJwtPayload with: jti, sub, role, type (literal 'platform'), mfaVerified, iat, exp. Implement MfaTempPayload with: sub, type (literal 'mfa_challenge'), context ('dashboard'|'platform'), iat, exp. Add JSDoc explaining each interface's purpose.

---

### NEST-011: Interface - AuthResult, PlatformAuthResult, MfaChallengeResult

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-006
- **Agent:** typescript-reviewer
- **Estimate:** ~30min
- **Description:** Implement result interfaces needed from Phase 1 onwards for compilation of later phases.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/interfaces/auth-result.interface.ts. Implement AuthResult { user: AuthUser, accessToken: string, rawRefreshToken: string, sessionHash?: string }. Implement PlatformAuthResult { admin: AuthPlatformUser, accessToken: string, rawRefreshToken: string }. Implement MfaChallengeResult { mfaRequired: true, mfaToken: string }. IMPORTANT: Use rawRefreshToken (never refreshToken) as field name everywhere. These are defined here (not in services) so Phase 1 barrel export can include them. Import AuthUser from ./user-repository.interface and AuthPlatformUser from ./platform-user-repository.interface. Add JSDoc.

---

### NEST-012: Interface - AuthenticatedRequest types

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-010
- **Agent:** typescript-reviewer
- **Estimate:** ~30min
- **Description:** Implement AuthenticatedRequest and PlatformAuthenticatedRequest interfaces extending Express Request.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/interfaces/authenticated-request.interface.ts. Implement AuthenticatedRequest extending import('express').Request with user: DashboardJwtPayload. Implement PlatformAuthenticatedRequest extending Request with user: PlatformJwtPayload. Import payload types from ./jwt-payload.interface. Add JSDoc.

---

### NEST-013: Interface - OAuthProviderPlugin

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-004
- **Agent:** typescript-reviewer
- **Estimate:** ~30min
- **Description:** Implement the OAuthProviderPlugin interface with native methods (without Passport).

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/interfaces/oauth-provider.interface.ts. Implement OAuthProviderPlugin { name: string, authorizeUrl(state: string): string, exchangeCode(code: string): Promise<{ access_token: string }>, fetchProfile(accessToken: string): Promise<OAuthProfile> }. No dependency on Passport — each plugin implements the OAuth2 flow natively via `fetch`. Import OAuthProfile from ./auth-hooks.interface.

---

### NEST-014: Constants - Injection tokens (6 Symbols)

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-004
- **Agent:** architect
- **Estimate:** ~30min
- **Description:** Create the 6 Symbol-based injection tokens used for DI throughout the package.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/bymax-auth.constants.ts. Export 6 Symbols: BYMAX_AUTH_OPTIONS = Symbol('BYMAX_AUTH_OPTIONS'), BYMAX_AUTH_USER_REPOSITORY = Symbol('BYMAX_AUTH_USER_REPOSITORY'), BYMAX_AUTH_PLATFORM_USER_REPOSITORY = Symbol('BYMAX_AUTH_PLATFORM_USER_REPOSITORY'), BYMAX_AUTH_EMAIL_PROVIDER = Symbol('BYMAX_AUTH_EMAIL_PROVIDER'), BYMAX_AUTH_HOOKS = Symbol('BYMAX_AUTH_HOOKS'), BYMAX_AUTH_REDIS_CLIENT = Symbol('BYMAX_AUTH_REDIS_CLIENT'). Use descriptive Symbol names. Export with `export const` (not export type).

---

### NEST-015: Config - Default options

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-005
- **Agent:** architect
- **Estimate:** ~30min
- **Description:** Implement the default options object with all default values from table 4.2 of the spec.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/config/default-options.ts. Export a DEFAULT_OPTIONS constant (typed as DeepPartial<BymaxAuthModuleOptions> or a dedicated DefaultOptions type) with all default values from table 4.2 of /Users/maximiliano/Documents/My Apps/nest-auth/docs/technical_specification.md. Key defaults: jwt.algorithm 'HS256', jwt.accessExpiresIn '15m', jwt.refreshExpiresInDays 7, jwt.refreshGraceWindowSeconds 30, password.saltRounds 12, password.minLength 8, password.maxLength 128, tokenDelivery 'cookie', cookies (accessTokenName 'access_token', refreshTokenName 'refresh_token', sessionSignalName 'has_session', secure true, sameSite 'strict', httpOnly true), mfa.totpWindow 1, mfa.recoveryCodeCount 8, sessions.enabled false, sessions.maxSessions 5, bruteForce.maxAttempts 5, bruteForce.windowSeconds 900, passwordReset.method 'token', passwordReset.otpLength 6, passwordReset.otpTtlSeconds 600, passwordReset.tokenTtlSeconds 3600, emailVerification.required false, emailVerification.otpTtlSeconds 600, routePrefix 'auth', namespace 'auth', blockedStatuses ['BANNED','INACTIVE','SUSPENDED'], platform.enabled false.

---

### NEST-016: Config - resolveOptions implementation

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-005, NEST-015
- **Agent:** security-reviewer
- **Estimate:** ~30min
- **Description:** Implement resolveOptions() with shallow merge per group and all security validations (jwt.secret entropy, mfa.encryptionKey, algorithm pinning, etc.).

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/config/resolved-options.ts. Export type ResolvedOptions (BymaxAuthModuleOptions with all defaults applied — all optional groups become required). Export function resolveOptions(userOptions: BymaxAuthModuleOptions): ResolvedOptions. Implementation: (1) Shallow merge per group using spread: { ...defaults.jwt, ...userOptions.jwt } — NOT JSON.parse/stringify, to preserve function properties like maxSessionsResolver, tenantIdResolver, resolveDomains. (2) Validate jwt.secret: length >= 32 chars, Shannon entropy >= 3.5 bits/char, reject repetitive patterns (e.g., 'aaaa...', '1234...' repeating). (3) Validate jwt.algorithm: if provided must be exactly 'HS256', throw if different. (4) Validate mfa.encryptionKey conditionally: if mfa group provided, encryptionKey required, must decode from base64 to exactly 32 bytes. (5) Validate roles.hierarchy: cannot be empty object. (6) Validate platformHierarchy required if platform.enabled. (7) Validate that clientId and clientSecret are configured for each enabled OAuth provider. (8) Validate passwordReset.otpLength <= 8 (above 8 crypto.randomInt exceeds MAX_SAFE_INTEGER). (9) Log warning if routePrefix differs from 'auth' and cookies.refreshCookiePath not explicitly configured. Throw descriptive exceptions for each validation failure.

---

### NEST-017: Config - resolveOptions tests

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-016
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** Write comprehensive unit tests for resolveOptions covering success paths and all validation failures.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/config/resolved-options.spec.ts. Test cases: (1) Success with valid minimal config (jwt.secret of 32+ chars with high entropy). (2) Reject jwt.secret shorter than 32 chars. (3) Reject jwt.secret with low entropy (e.g., 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'). (4) Reject jwt.algorithm other than HS256. (5) Accept jwt.algorithm HS256 explicitly. (6) Reject mfa.encryptionKey that doesn't decode to 32 bytes. (7) Accept valid mfa.encryptionKey (32 bytes base64). (8) Reject empty roles.hierarchy. (9) Reject platform.enabled without platformHierarchy. (10) Verify functions are preserved after merge (pass a tenantIdResolver function, assert it's still a function after resolve). (11) Verify shallow merge doesn't deep-clone functions. (12) Reject otpLength > 8. (13) Warning logged when routePrefix differs from 'auth' without explicit refreshCookiePath. All tests should use descriptive names and verify exact error messages.

---

### NEST-018: Constants - Throttle configs

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-004
- **Agent:** architect
- **Estimate:** ~30min
- **Description:** Create AUTH_THROTTLE_CONFIGS with 14 endpoint rate limiting configurations per section 16.2.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/constants/throttle-configs.ts. Export AUTH_THROTTLE_CONFIGS object with 14 named throttler configurations per section 16.2 of /Users/maximiliano/Documents/My Apps/nest-auth/docs/technical_specification.md. Each config uses the @nestjs/throttler >= 6.0.0 named throttler API: { default: { limit, ttl } }. Include configs for: register, login, refresh, verifyEmail, resendVerification, mfaSetup, mfaChallenge, mfaDisable, forgotPassword, resetPassword, sessionsList, sessionsRevoke, platformLogin, invitationAccept. Reference the exact limits and TTL windows from the spec.

---

### NEST-019: Constants - barrel export and re-exports

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-014, NEST-018
- **Agent:** architect
- **Estimate:** ~15min
- **Description:** Create constants/index.ts with re-exports of public constants.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/constants/index.ts. Re-export AUTH_THROTTLE_CONFIGS from ./throttle-configs. Re-export AUTH_ERROR_CODES from ../errors/auth-error-codes (will be created in NEST-020).

---

### NEST-020: Error codes - AUTH_ERROR_CODES and AUTH_ERROR_MESSAGES

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-004
- **Agent:** code-reviewer
- **Estimate:** ~30min
- **Description:** Implement all 33 error codes as a const object with Portuguese message mappings per section 15 of the spec.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/errors/auth-error-codes.ts. Export AUTH_ERROR_CODES typed with `as const` containing all 33 codes from table 15.3 of /Users/maximiliano/Documents/My Apps/nest-auth/docs/technical_specification.md. Must include: INVALID_CREDENTIALS, EMAIL_ALREADY_EXISTS, TOKEN_INVALID, TOKEN_EXPIRED, TOKEN_REVOKED, REFRESH_TOKEN_INVALID, REFRESH_TOKEN_EXPIRED, INSUFFICIENT_ROLE, ACCOUNT_LOCKED, ACCOUNT_BANNED, ACCOUNT_INACTIVE, ACCOUNT_SUSPENDED, FORBIDDEN, PENDING_APPROVAL, MFA_REQUIRED, MFA_INVALID_CODE, MFA_ALREADY_ENABLED, MFA_NOT_ENABLED, MFA_SETUP_REQUIRED, MFA_TEMP_TOKEN_INVALID, EMAIL_NOT_VERIFIED, OTP_EXPIRED, OTP_INVALID, OTP_MAX_ATTEMPTS, SESSION_LIMIT_REACHED, SESSION_NOT_FOUND, OAUTH_FAILED, OAUTH_EMAIL_MISMATCH, PLATFORM_AUTH_REQUIRED, INVITATION_INVALID, INVITATION_EXPIRED, PASSWORD_RESET_TOKEN_INVALID, VALIDATION_ERROR. Also export AUTH_ERROR_MESSAGES mapping each code to a Portuguese message string.

---

### NEST-021: Error system - AuthException class

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-020
- **Agent:** code-reviewer
- **Estimate:** ~30min
- **Description:** Implement AuthException extending HttpException with automatic message lookup and standard error format.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/errors/auth-exception.ts. Implement class AuthException extends HttpException. Constructor: (code: string, statusCode: number = 401, details?: Record<string,unknown>). The response body format must be { error: { code, message, details? } } where message is looked up from AUTH_ERROR_MESSAGES[code]. If code not found in messages, use code as message. Import AUTH_ERROR_MESSAGES from ./auth-error-codes. Export the class.

---

### NEST-022: Error system - tests

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-020, NEST-021
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** Write unit tests for AUTH_ERROR_CODES and AuthException covering format, message lookup, and status codes.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/errors/auth-exception.spec.ts. Test: (1) AuthException creates correct response format { error: { code, message } }. (2) Message is auto-looked up from AUTH_ERROR_MESSAGES. (3) Default status code is 401. (4) Custom status code works (e.g., 403 for FORBIDDEN). (5) Details are included when provided. (6) Unknown code uses code as message. (7) AUTH_ERROR_CODES has exactly 33 entries. (8) AUTH_ERROR_CODES is typed as const (verify a specific code is a string literal type at compile time).

---

### NEST-023: Utilities - sleep and hasRole

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-004
- **Agent:** code-reviewer
- **Estimate:** ~30min
- **Description:** Implement sleep utility for timing normalization and hasRole utility for hierarchical role verification.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/utils/sleep.ts with export function sleep(ms: number): Promise<void> wrapping setTimeout in a Promise. Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/utils/roles.util.ts with export function hasRole(userRole: string, requiredRole: string, hierarchy: Record<string, string[]>): boolean. The hasRole function checks: (1) exact match userRole === requiredRole returns true, (2) if hierarchy[userRole] includes requiredRole returns true, (3) otherwise false. The hierarchy must be fully denormalized — each role lists ALL transitive descendants. This is a single-level lookup, NOT recursive. Add JSDoc warning that hierarchy must be denormalized. Write unit tests for both utilities: sleep resolves after delay, hasRole exact match, inherited role, insufficient role, missing role in hierarchy.

---

### NEST-024: Crypto - AES-256-GCM encrypt/decrypt

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-004
- **Agent:** security-reviewer
- **Estimate:** ~30min
- **Description:** Implement AES-256-GCM encryption and decryption functions using Node.js crypto module.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/crypto/aes-gcm.ts. Implement export function encrypt(plaintext: string, keyBase64: string): string — generate 12-byte IV with crypto.randomBytes(12), decode key from base64, create cipher with crypto.createCipheriv('aes-256-gcm', keyBuffer, iv), return format base64(iv):base64(authTag):base64(ciphertext). Implement export function decrypt(ciphertext: string, keyBase64: string): string — parse the iv:authTag:ciphertext format, create decipher with crypto.createDecipheriv, setAuthTag, return plaintext. NEVER reuse IVs. Key must be exactly 32 bytes when decoded from base64.

---

### NEST-025: Crypto - secure token and SHA-256

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-004
- **Agent:** security-reviewer
- **Estimate:** ~30min
- **Description:** Implement generateSecureToken and sha256 utility functions using Node.js crypto.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/crypto/secure-token.ts. Implement export function generateSecureToken(bytes: number = 32): string using crypto.randomBytes(bytes).toString('hex'). Implement export function sha256(input: string): string using crypto.createHash('sha256').update(input).digest('hex'). Both functions use Node.js built-in crypto module only.

---

### NEST-026: Crypto - tests

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-024, NEST-025
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** Write comprehensive tests for AES-GCM and secure token utilities.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/crypto/aes-gcm.spec.ts. Tests: (1) Round-trip encrypt then decrypt returns original plaintext. (2) Test with various data sizes (empty string, short, long). (3) Two consecutive encryptions produce different ciphertexts (IV uniqueness). (4) Decrypt fails with tampered authTag (integrity check). (5) Decrypt fails with wrong key. (6) Output format matches base64:base64:base64 pattern. Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/crypto/secure-token.spec.ts. Tests: (1) generateSecureToken returns hex string of correct length (default 64 hex chars for 32 bytes). (2) generateSecureToken with custom bytes parameter. (3) sha256 returns consistent hash for same input. (4) sha256 returns different hashes for different inputs. (5) sha256 output is 64-char hex string.

---

### NEST-027: Redis - AuthRedisService implementation

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-014, NEST-005
- **Agent:** database-reviewer
- **Estimate:** ~60min
- **Description:** Implement AuthRedisService wrapping ioredis with automatic namespace prefixing and all required operations.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/redis/auth-redis.service.ts. Implement @Injectable() class AuthRedisService. Inject BYMAX_AUTH_REDIS_CLIENT (ioredis instance) and BYMAX_AUTH_OPTIONS (for namespace). All methods prefix keys with {namespace}: automatically. Methods: get(key): Promise<string|null>, set(key, value, ttl?): Promise<void> (if ttl use SET key value EX ttl), del(key): Promise<void>, incr(key): Promise<number>, expire(key, ttl): Promise<void>, ttl(key): Promise<number>, sadd(setKey, member): Promise<number>, srem(setKey, member): Promise<number>, smembers(setKey): Promise<string[]>, sismember(setKey, member): Promise<boolean>, eval(script, keys, args): Promise<any> (for Lua scripts — document this any with JSDoc). This service is internal — NOT exported in the public barrel.

---

### NEST-028: Redis - AuthRedisModule

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-027
- **Agent:** database-reviewer
- **Estimate:** ~45min
- **Description:** Create the internal NestJS module that registers AuthRedisService as a provider.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/redis/auth-redis.module.ts. Implement @Module({ providers: [AuthRedisService], exports: [AuthRedisService] }) class AuthRedisModule. This is an internal module, not exported publicly.

---

### NEST-029: Redis - AuthRedisService tests

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-027
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** Write unit tests for AuthRedisService with ioredis mocks verifying namespace prefixing and all operations.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/redis/auth-redis.service.spec.ts. Mock ioredis instance. Test with namespace 'auth'. Tests: (1) get('mykey') calls redis.get('auth:mykey'). (2) set('k','v',60) calls redis.set('auth:k','v','EX',60). (3) set without TTL calls redis.set without EX. (4) del prefixes key. (5) incr prefixes key. (6) expire prefixes key. (7) ttl prefixes key. (8) sadd prefixes set key. (9) srem prefixes set key. (10) smembers prefixes and returns array. (11) sismember prefixes and returns boolean. (12) eval passes prefixed keys. Use NestJS Test.createTestingModule with mock providers.

---

### NEST-030: Service - PasswordService

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-014, NEST-005
- **Agent:** code-reviewer
- **Estimate:** ~30min
- **Description:** Implement PasswordService with `node:crypto` scrypt hash and compare, constant-time verification.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/services/password.service.ts. Implement @Injectable() class PasswordService. Use `node:crypto` scrypt with parameters N=2^15, r=8, p=1, keyLen=64. Implement async hash(plain: string): Promise<string>: generate a 16-byte salt via `crypto.randomBytes(16)`, derive a key with `crypto.scrypt(plain, salt, 64, { N: 2**15, r: 8, p: 1 })`, return the format `scrypt:{salt_hex}:{derived_hex}`. Implement async compare(plain: string, hash: string): Promise<boolean>: parse salt and derived from the format, re-derive the key with the same salt and parameters, compare with `crypto.timingSafeEqual`. Add JSDoc.

---

### NEST-031: Service - PasswordService tests

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-030
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** Write unit tests for PasswordService hash/compare operations.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/services/password.service.spec.ts. Tests: (1) hash produces a string in the `scrypt:{salt_hex}:{derived_hex}` format. (2) compare returns true for the correct password. (3) compare returns false for the incorrect password. (4) Different hashes are generated for the same password (random salt). (5) compare uses timingSafeEqual (verify that buffers of different sizes return false). Use NestJS Test.createTestingModule.

---

### NEST-032: Service - TokenManagerService implementation

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-014, NEST-010, NEST-011, NEST-027, NEST-025
- **Agent:** security-reviewer
- **Estimate:** ~60min
- **Description:** Implement TokenManagerService with JWT issuance, opaque refresh tokens, Lua-based rotation, and MFA temp tokens.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/services/token-manager.service.ts. Implement @Injectable() class TokenManagerService. Inject JwtService (@nestjs/jwt), BYMAX_AUTH_OPTIONS, AuthRedisService. Methods: (1) issueAccess(payload: Omit<DashboardJwtPayload,'jti'|'iat'|'exp'>): generate jti internally with crypto.randomUUID(), sign JWT with HS256 and accessExpiresIn. (2) issueTokens(user, ip, userAgent, extraClaims?): call issueAccess, generate refresh with crypto.randomUUID(), store in Redis as rt:{sha256(refresh)} -> JSON {userId,tenantId,role,device,ip,createdAt}, TTL=refreshExpiresInDays\*86400, return AuthResult. (3) issuePlatformTokens(admin, ip, userAgent): similar but type:'platform' and refresh prefix prt:. (4) reissueTokens(oldRefresh, ip, userAgent): atomic Lua script per section 12.4 — get old session, generate new refresh, create rotation pointer rp:{sha256(old)}->new TTL=refreshGraceWindowSeconds, create new session rt:{sha256(new)}, delete old. If old not found check grace window rp:{sha256(old)}. If nothing found throw REFRESH_TOKEN_INVALID. (5) decodeToken(token): decode JWT without validating expiration, validate jti exists, add @internal JSDoc warning. (6) issueMfaTempToken(userId, context: 'dashboard'|'platform'): JWT with type:'mfa_challenge', context claim, 5min exp. Store in Redis mfa:{sha256(token)}->userId, TTL 300s. (7) verifyMfaTempToken(token): verify JWT, find in Redis, consume (delete), return {userId, context} — DEVIATION from spec which returns just string.

---

### NEST-033: Service - TokenManagerService tests

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-032
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** Write comprehensive unit tests for TokenManagerService covering all token operations.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/services/token-manager.service.spec.ts. Mock JwtService and AuthRedisService. Tests: (1) issueAccess generates jti and signs JWT. (2) issueTokens stores refresh in Redis with correct TTL. (3) issuePlatformTokens uses type:'platform'. (4) reissueTokens creates rotation pointer and new session. (5) reissueTokens with expired old token uses grace window. (6) reissueTokens with no old and no grace window throws REFRESH_TOKEN_INVALID. (7) decodeToken returns payload with jti. (8) decodeToken throws TOKEN_INVALID if no jti. (9) issueMfaTempToken stores in Redis with TTL 300. (10) verifyMfaTempToken returns {userId, context}. (11) verifyMfaTempToken consumes token (deletes from Redis). (12) verifyMfaTempToken throws MFA_TEMP_TOKEN_INVALID if not in Redis.

---

### NEST-034: Service - TokenDeliveryService implementation

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-014, NEST-005
- **Agent:** code-reviewer
- **Estimate:** ~60min
- **Description:** Implement TokenDeliveryService handling cookie/bearer/both modes for token delivery and extraction.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/services/token-delivery.service.ts. Implement @Injectable() class TokenDeliveryService. Inject BYMAX_AUTH_OPTIONS for tokenDelivery mode and cookies config. Methods: (1) deliverAuthResponse(res, authResult, req?): mode cookie -> set cookies (access httpOnly, refresh httpOnly with path, session signal non-httpOnly) + return {user}. Mode bearer -> return {user, accessToken, refreshToken}. Mode both -> set cookies + return all. Use discriminated return types. (2) deliverRefreshResponse(res, result, req?): same logic for refresh. (3) extractAccessToken(req): cookie mode -> req.cookies[accessTokenName]. bearer -> Authorization Bearer header. both -> cookie first then header. (4) extractRefreshToken(req): cookie -> req.cookies[refreshTokenName]. bearer -> req.body.refreshToken. both -> cookie first then body. (5) clearAuthSession(res, req?): clear all auth cookies on resolved domains. bearer mode -> no-op. (6) resolveCookieDomains(req): call user's resolveDomains if configured, or use extractDomain. (7) extractDomain(req): validate hostname with /^[a-z0-9.-]+$/i, reject invalid chars, fallback to configured domain. Configure cookies per table 14.1: HttpOnly, Secure in prod, SameSite, correct paths. Use @Res({passthrough:true}) pattern.

---

### NEST-035: Service - TokenDeliveryService tests

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-034
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** Write unit tests for TokenDeliveryService covering all three modes and security validations.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/services/token-delivery.service.spec.ts. Mock Express Request and Response objects. Tests for each mode (cookie, bearer, both): (1) deliverAuthResponse sets correct cookies in cookie mode. (2) deliverAuthResponse returns tokens in bearer mode. (3) deliverAuthResponse does both in both mode. (4) extractAccessToken reads from cookie in cookie mode. (5) extractAccessToken reads from header in bearer mode. (6) extractAccessToken tries cookie first in both mode. (7) extractRefreshToken reads from cookie vs body correctly. (8) clearAuthSession clears cookies in cookie mode, no-op in bearer. (9) extractDomain with valid hostname returns domain. (10) extractDomain with malicious hostname (special chars) falls back to default. (11) Cookie attributes: HttpOnly, Secure, SameSite, path.

---

### NEST-036: Service - BruteForceService implementation

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-027, NEST-014
- **Agent:** security-reviewer
- **Estimate:** ~60min
- **Description:** Implement BruteForceService with Redis-backed attempt tracking and lockout logic.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/services/brute-force.service.ts. Implement @Injectable() class BruteForceService. Inject AuthRedisService and BYMAX_AUTH_OPTIONS (bruteForce.maxAttempts, bruteForce.windowSeconds). Methods: (1) async isLockedOut(identifier: string): Promise<boolean> — get lf:{identifier}, parse as number, return count >= maxAttempts. (2) async recordFailure(identifier: string): Promise<void> — INCR lf:{identifier}, EXPIRE lf:{identifier} windowSeconds. (3) async resetFailures(identifier: string): Promise<void> — DEL lf:{identifier}. (4) async getRemainingLockoutSeconds(identifier: string): Promise<number> — TTL lf:{identifier}, return 0 if not locked or key doesn't exist.

---

### NEST-037: Service - BruteForceService tests

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-036
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** Write unit tests for BruteForceService covering lockout, failure recording, and reset.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/services/brute-force.service.spec.ts. Mock AuthRedisService. Tests: (1) isLockedOut returns false when no attempts recorded. (2) isLockedOut returns false when attempts < maxAttempts. (3) isLockedOut returns true when attempts >= maxAttempts. (4) recordFailure calls incr and expire with correct key and TTL. (5) resetFailures calls del with correct key. (6) getRemainingLockoutSeconds returns TTL when locked. (7) getRemainingLockoutSeconds returns 0 when not locked.

---

### NEST-038: Providers - NoOpEmailProvider

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-008
- **Agent:** code-reviewer
- **Estimate:** ~30min
- **Description:** Implement NoOpEmailProvider that logs all email operations via NestJS Logger without sending real emails.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/providers/no-op-email.provider.ts. Implement @Injectable() class NoOpEmailProvider implements IEmailProvider. Use NestJS Logger (private readonly logger = new Logger(NoOpEmailProvider.name)). Each of the 7 methods (sendPasswordResetToken, sendPasswordResetOtp, sendEmailVerificationOtp, sendMfaEnabledNotification, sendMfaDisabledNotification, sendNewSessionAlert, sendInvitation) should log the method name and email address, then return Promise.resolve(). Per section 10.3 of the spec.

---

### NEST-039: Hooks - NoOpAuthHooks

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-009
- **Agent:** code-reviewer
- **Estimate:** ~30min
- **Description:** Implement NoOpAuthHooks with safe defaults, including the standard onOAuthLogin logic.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/hooks/no-op-auth.hooks.ts. Implement @Injectable() class NoOpAuthHooks implements IAuthHooks. beforeRegister returns { allowed: true }. All other hooks are no-op (return void/undefined). onOAuthLogin implements default safe logic: if existing user with matching email -> return { action: 'link' }; if no existing user -> return { action: 'create' }; if email mismatch -> return { action: 'reject', reason: 'Email mismatch' }. IMPORTANT: Use explicit types from IAuthHooks for all parameters — never use `any` for sessionInfo, use { device: string; ip: string; sessionHash: string } instead. This is a deliberate deviation from the spec section 9.3 which uses \_sessionInfo: any.

---

### NEST-040: Providers and Hooks - tests

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-038, NEST-039
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** Write unit tests for NoOpEmailProvider and NoOpAuthHooks.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/providers/no-op-email.provider.spec.ts. Test that each method resolves without error and logs the call. Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/hooks/no-op-auth.hooks.spec.ts. Test: (1) beforeRegister returns { allowed: true }. (2) onOAuthLogin with matching email returns { action: 'link' }. (3) onOAuthLogin with new user returns { action: 'create' }. (4) onOAuthLogin with email mismatch returns { action: 'reject' }. (5) Other hooks do not throw.

---

### NEST-041: Barrel export - Phase 1

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-005, NEST-006, NEST-007, NEST-008, NEST-009, NEST-010, NEST-011, NEST-012, NEST-013, NEST-014, NEST-018, NEST-020, NEST-021, NEST-023, NEST-038, NEST-039
- **Agent:** architect
- **Estimate:** ~15min
- **Description:** Update src/server/index.ts with all Phase 1 exports, using export type for interfaces and export for values.

**Prompt for the agent:**

> Update /Users/maximiliano/Documents/My Apps/nest-auth/src/server/index.ts with all Phase 1 exports. Use `export type` for interfaces and type aliases: BymaxAuthModuleOptions, AuthUser, IUserRepository, AuthPlatformUser, IPlatformUserRepository, IEmailProvider, IAuthHooks, HookContext, BeforeRegisterResult, OAuthLoginResult, OAuthProfile, DashboardJwtPayload, PlatformJwtPayload, MfaTempPayload, AuthResult, PlatformAuthResult, MfaChallengeResult, AuthenticatedRequest, PlatformAuthenticatedRequest, OAuthProviderPlugin, ResolvedOptions. Use `export` (value) for: BYMAX_AUTH_OPTIONS, BYMAX_AUTH_USER_REPOSITORY, BYMAX_AUTH_PLATFORM_USER_REPOSITORY, BYMAX_AUTH_EMAIL_PROVIDER, BYMAX_AUTH_HOOKS, BYMAX_AUTH_REDIS_CLIENT (from constants), AuthException, AUTH_ERROR_CODES, AUTH_ERROR_MESSAGES, AUTH_THROTTLE_CONFIGS, NoOpEmailProvider, NoOpAuthHooks, encrypt, decrypt, generateSecureToken, sha256, sleep, hasRole. Do NOT export AuthRedisService (internal). Verify proper import paths.

---

### NEST-042: Phase 1 validation - build and test

- **Phase:** 1
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-041
- **Agent:** architect
- **Estimate:** ~30min
- **Description:** Run full build and test suite, verify compilation is clean and coverage meets 80% threshold.

**Prompt for the agent:**

> Run the following validation checks for Phase 1 completion: (1) `pnpm build` must compile with zero errors. (2) `pnpm test --coverage` must pass with >= 80% coverage on branches, functions, lines, statements. (3) Verify all interfaces are exported correctly (check index.ts for both export type and export). (4) Verify AuthResult, PlatformAuthResult, MfaChallengeResult are defined and exported. (5) Verify resolveOptions validates jwt.secret, mfa.encryptionKey, jwt.algorithm and preserves functions after merge. (6) Verify encrypt/decrypt AES-256-GCM round-trip works and IVs are unique. (7) Verify Redis namespace prefixing. (8) Verify PasswordService hash/compare round-trip. (9) Verify BruteForceService lockout. (10) Verify TokenManagerService token operations. (11) Verify TokenDeliveryService in all 3 modes. (12) Verify 33 error codes in AUTH_ERROR_CODES. (13) Verify extractDomain rejects malicious hostnames. Fix any issues found.

---

## Phase 2 — Core Authentication

### NEST-043: Guard - native JwtAuthGuard

- **Phase:** 2
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-042
- **Agent:** security-reviewer
- **Estimate:** ~30min
- **Description:** Implement a native JwtAuthGuard with `CanActivate`, without Passport, using `@nestjs/jwt` JwtService.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/guards/jwt-auth.guard.ts. Implement class JwtAuthGuard `implements CanActivate`. Inject `JwtService` (from `@nestjs/jwt`), `TokenDeliveryService`, `AuthRedisService`, `Reflector` and `BYMAX_AUTH_OPTIONS`. In the `canActivate(context: ExecutionContext)` method: (1) Check the `@Public()` decorator via `Reflector` — if present, return true without validation. (2) Extract the token from the cookie or Authorization header via `tokenDeliveryService.extractAccessToken(req)`. If absent, throw `UnauthorizedException` TOKEN_MISSING. (3) Verify the JWT with `jwtService.verify(token, { algorithms: ['HS256'] })`. CRITICAL: pin `algorithms: ['HS256']` to prevent algorithm confusion attacks (CVE-2015-9235). (4) Verify `payload.jti` exists and is a string — throw TOKEN_INVALID if absent. (5) Verify `payload.type === 'dashboard'` — reject 'platform' and 'mfa_challenge'. (6) Verify blacklist via `authRedis.isBlacklisted(jti)` — if blacklisted, throw TOKEN_REVOKED. (7) Populate `request.user` with the validated payload. (8) Respect the `@Public()` decorator. Return true.

---

### NEST-044: Utility - assertTokenType helper

- **Phase:** 2
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-021
- **Agent:** code-reviewer
- **Estimate:** ~20min
- **Description:** Implement a reusable `assertTokenType` helper that validates the `type` claim of a JWT payload. Used by JwtAuthGuard (accepts 'dashboard') and JwtPlatformGuard (accepts 'platform') to avoid duplicating token type validation logic.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/guards/utils/assert-token-type.ts. Implement export function assertTokenType(payload: { type?: string }, expectedType: string): void. If payload.type !== expectedType, throw AuthException with AUTH_ERROR_CODES.TOKEN_INVALID and 401 status. Add JSDoc explaining this is a shared guard utility to centralize token type validation. Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/guards/utils/assert-token-type.spec.ts with tests: (1) Matching type does not throw. (2) Mismatched type throws TOKEN_INVALID. (3) Missing type field throws TOKEN_INVALID. (4) Null payload.type throws TOKEN_INVALID.

---

### NEST-045: JwtAuthGuard unit tests

- **Phase:** 2
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-043
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** Unit tests for the native JwtAuthGuard implemented in NEST-043, covering all token validation scenarios and the @Public() metadata.

**Prompt for the agent:**

> Write unit tests for `src/server/guards/jwt-auth.guard.ts` (the native guard implemented in NEST-043, without Passport).
> Create file `src/server/guards/__tests__/jwt-auth.guard.spec.ts`. Mock `JwtService`, `AuthRedisService`, `TokenDeliveryService`.
> Test scenarios:
>
> 1. Valid dashboard token with correct signature → accepted, `request.user` populated with payload.
> 2. Expired token → rejected with `TOKEN_INVALID`.
> 3. Token with `jti` in the Redis blacklist → rejected with `TOKEN_REVOKED`.
> 4. Token with `type: 'platform'` → rejected (guard only accepts dashboard tokens).
> 5. Token with `type: 'mfa_challenge'` → rejected with `TOKEN_INVALID`.
> 6. Endpoint with `@Public()` decorator → skip validation, return true without verifying the token.
> 7. Request without token (header and cookie absent) → rejected with `TOKEN_INVALID`.
> 8. Verify that `algorithms: ['HS256']` is pinned in the call to `jwtService.verify` (rejects `alg: none`).
>
> Acceptance criteria:
>
> - All 8 scenarios tested and passing
> - Coverage >= 90% on the guard file
> - No use of Passport in the tests

---

### NEST-046: Guard - RolesGuard

- **Phase:** 2
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-023, NEST-014
- **Agent:** code-reviewer
- **Estimate:** ~30min
- **Description:** Implement RolesGuard with hierarchical role checking using denormalized hierarchy.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/guards/roles.guard.ts. Implement @Injectable() class RolesGuard implements CanActivate. Inject Reflector and BYMAX_AUTH_OPTIONS. In canActivate: read required roles from ROLES_KEY metadata via reflector.getAllAndOverride. If no roles required return true. Get request.user.role. Use the hasRole utility from utils/roles.util.ts to check against roles.hierarchy. If no role satisfies, throw AuthException with INSUFFICIENT_ROLE (403). IMPORTANT: hierarchy must be fully denormalized — document in JSDoc that OWNER: ['ADMIN','MEMBER','VIEWER'] not just OWNER: ['ADMIN'].

---

### NEST-047: Guard - UserStatusGuard

- **Phase:** 2
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-027, NEST-014
- **Agent:** code-reviewer
- **Estimate:** ~30min
- **Description:** Implement UserStatusGuard with Redis caching and status-specific error mapping.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/guards/user-status.guard.ts. Implement @Injectable() class UserStatusGuard implements CanActivate. Inject AuthRedisService, BYMAX_AUTH_USER_REPOSITORY, BYMAX_AUTH_OPTIONS. In canActivate: (1) If route is public (no user on request) return true. (2) Extract user.sub from request. (3) Check Redis cache us:{userId}. (4) If cache miss, call userRepo.findById(userId), cache result with userStatusCacheTtlSeconds TTL. (5) Check status against blockedStatuses array from options. (6) Map status to specific error: BANNED->ACCOUNT_BANNED (403), INACTIVE->ACCOUNT_INACTIVE (403), SUSPENDED->ACCOUNT_SUSPENDED (403), PENDING_APPROVAL->PENDING_APPROVAL (403). (7) If not blocked return true.

---

### NEST-048: Guards - tests

- **Phase:** 2
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-045, NEST-046, NEST-047
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** Write unit tests for all three guards covering all branches.

**Prompt for the agent:**

> Create test files for each guard. /Users/maximiliano/Documents/My Apps/nest-auth/src/server/guards/jwt-auth.guard.spec.ts: (1) Public route returns true without JWT. (2) Protected route without token throws. (3) Protected route with valid token passes. (4) handleRequest maps errors correctly. /Users/maximiliano/Documents/My Apps/nest-auth/src/server/guards/roles.guard.spec.ts: (1) No roles metadata allows access. (2) Exact role match allows. (3) Hierarchical role (OWNER accessing ADMIN route) allows. (4) Insufficient role throws INSUFFICIENT_ROLE 403. /Users/maximiliano/Documents/My Apps/nest-auth/src/server/guards/user-status.guard.spec.ts: (1) Public route (no user) returns true. (2) ACTIVE status passes. (3) BANNED status throws ACCOUNT_BANNED. (4) INACTIVE throws ACCOUNT_INACTIVE. (5) Cache hit uses cached value. (6) Cache miss fetches from repository and caches.

---

### NEST-049: Decorator - @CurrentUser

- **Phase:** 2
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-004
- **Agent:** code-reviewer
- **Estimate:** ~20min
- **Description:** Implement @CurrentUser param decorator that extracts request.user or a specific property.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/decorators/current-user.decorator.ts. Implement export const CurrentUser = createParamDecorator((data: string | undefined, ctx: ExecutionContext) => { const request = ctx.switchToHttp().getRequest(); const user = request.user; return data ? user?.[data] : user; }). Add JSDoc: /\*_ Extracts the authenticated user from the request. @param property Optional property to extract (e.g., 'sub' for userId). Consumer must type the parameter explicitly: @CurrentUser('sub') userId: string _/

---

### NEST-050: Decorator - @Roles and @Public

- **Phase:** 2
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-004
- **Agent:** code-reviewer
- **Estimate:** ~20min
- **Description:** Implement @Roles and @Public metadata decorators for use with RolesGuard and JwtAuthGuard.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/decorators/roles.decorator.ts. Export const ROLES_KEY = 'roles'. Export const Roles = (...roles: string[]) => SetMetadata(ROLES_KEY, roles). Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/decorators/public.decorator.ts. Export const IS_PUBLIC_KEY = 'isPublic'. Export const Public = () => SetMetadata(IS_PUBLIC_KEY, true). Add JSDoc to both.

---

### NEST-051: Decorators - tests

- **Phase:** 2
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-049, NEST-050
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** Write unit tests for all decorators.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/decorators/current-user.decorator.spec.ts. Test: (1) Returns full user object when no property specified. (2) Returns specific property when property specified (e.g., 'sub'). (3) Returns undefined when user not present. Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/decorators/roles.decorator.spec.ts. Test that @Roles('ADMIN') sets metadata correctly. Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/decorators/public.decorator.spec.ts. Test that @Public() sets IS_PUBLIC_KEY to true.

---

### NEST-052: DTO - RegisterDto

- **Phase:** 2
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-004
- **Agent:** typescript-reviewer
- **Estimate:** ~20min
- **Description:** Implement RegisterDto with class-validator decorators including email, password, name, and tenantId.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/dto/register.dto.ts. Implement class RegisterDto with: @IsEmail() email: string, @IsString() @MinLength(8) @MaxLength(128) password: string (MaxLength 128 — practical input limit to prevent DoS), @IsString() @MinLength(2) name: string, @IsString() @IsNotEmpty() tenantId: string (@IsNotEmpty prevents empty string passing @IsString). Export the class.

---

### NEST-053: DTO - LoginDto

- **Phase:** 2
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-004
- **Agent:** typescript-reviewer
- **Estimate:** ~20min
- **Description:** Implement LoginDto with deliberate omission of @MinLength on password for anti-enumeration.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/dto/login.dto.ts. Implement class LoginDto with: @IsEmail() email: string, @IsString() @MaxLength(128) password: string, @IsString() @IsNotEmpty() tenantId: string. IMPORTANT: Deliberately NO @MinLength on password — all passwords pass to the scrypt comparison so as not to reveal whether the password is too short before comparison (anti-enumeration). Add JSDoc on password field: /\*_ Deliberately without @MinLength — every password passes to scrypt compare to prevent revealing minimum length requirements before comparison _/. Export the class.

---

### NEST-054: DTOs - validation tests

- **Phase:** 2
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-052, NEST-053
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** Write validation tests for RegisterDto and LoginDto using class-validator.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/dto/register.dto.spec.ts. Use class-validator's validate() function. Tests: (1) Valid DTO passes. (2) Invalid email fails. (3) Password shorter than 8 chars fails. (4) Password longer than 128 chars fails. (5) Name shorter than 2 chars fails. (6) Empty tenantId fails. Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/dto/login.dto.spec.ts. Tests: (1) Valid DTO passes. (2) Invalid email fails. (3) Password longer than 128 fails. (4) Short password (e.g., '1') passes validation (deliberate — no MinLength). (5) Empty tenantId fails.

---

### NEST-055: Service - OtpService implementation (moved from Phase 4)

- **Phase:** 2
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-027, NEST-020, NEST-023
- **Agent:** security-reviewer
- **Estimate:** ~60min
- **Description:** Implement OtpService with secure OTP generation, Redis storage, constant-time comparison, and timing normalization.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/services/otp.service.ts. Implement @Injectable() class OtpService. Inject AuthRedisService. Methods: (1) generate(length=6): use crypto.randomInt(0, 10\*\*length) — NEVER Math.random(). Pad with zeros: String(num).padStart(length,'0'). (2) store(purpose, identifier, code, ttlSeconds): Redis key otp:{purpose}:{identifier} -> JSON {code, attempts:0}, with TTL. (3) verify(purpose, identifier, code): get from Redis. If not found throw OTP_EXPIRED. Check attempts >= 5 throw OTP_MAX_ATTEMPTS. Constant-time comparison: convert both to Buffer.from(x,'utf8'), if different lengths return OTP_INVALID without calling timingSafeEqual (it throws RangeError on length mismatch). Use crypto.timingSafeEqual for same-length. If invalid increment attempts throw OTP_INVALID. If valid delete key. TIMING NORMALIZATION: const start = Date.now(), before each return/throw: await sleep(Math.max(0, 100 - (Date.now()-start))). Returns void. (4) incrementAttempts(purpose, identifier): read JSON, increment attempts field, write back with same TTL. Reference section 5.1 of the development plan.

---

### NEST-056: Service - OtpService tests

- **Phase:** 2
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-055
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** Write unit tests for OtpService covering generation, storage, verification, expiration, and timing.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/services/otp.service.spec.ts. Mock AuthRedisService. Tests: (1) generate(6) produces 6-digit string. (2) generate pads with leading zeros (mock crypto.randomInt to return 42 -> '000042'). (3) store calls Redis set with correct key format and TTL. (4) verify with correct code succeeds and deletes key. (5) verify with expired OTP (not in Redis) throws OTP_EXPIRED. (6) verify with wrong code increments attempts and throws OTP_INVALID. (7) verify with 5+ attempts throws OTP_MAX_ATTEMPTS. (8) verify with different-length code returns OTP_INVALID without calling timingSafeEqual. (9) Timing normalization: all branches take similar time (verify elapsed > 90ms for all cases).

---

### NEST-057: Service - AuthService implementation

- **Phase:** 2
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-030, NEST-032, NEST-034, NEST-036, NEST-055, NEST-014, NEST-020, NEST-021
- **Agent:** code-reviewer
- **Estimate:** ~60min
- **Description:** Implement AuthService with register, login, logout, refresh, getMe, verifyEmail, and resendVerificationEmail methods.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/services/auth.service.ts. Implement @Injectable() class AuthService. Inject: BYMAX_AUTH_OPTIONS, BYMAX_AUTH_USER_REPOSITORY (IUserRepository), BYMAX_AUTH_EMAIL_PROVIDER (IEmailProvider), BYMAX_AUTH_HOOKS (IAuthHooks), PasswordService, TokenManagerService, BruteForceService, AuthRedisService, OtpService, @Optional() SessionService. Methods per Appendix A of the spec: (1) register(dto, req): resolve tenantId via tenantIdResolver if configured, call hooks.beforeRegister (reject if not allowed, apply modifiedData), check email exists, hash password, create user, if emailVerification.required generate+store+send OTP, issue tokens, call hooks.afterRegister (catch errors log don't propagate), return AuthResult. (2) login(dto, req): resolve tenantId, compute brute-force id sha256(tenantId+':'+email), check lockout (throw ACCOUNT_LOCKED with Retry-After header), call hooks.beforeLogin, find user, check status against blockedStatuses, check emailVerified if required, compare password, if mfaEnabled issue mfaTempToken return MfaChallengeResult, otherwise reset brute-force+issue tokens+update lastLogin+hooks.afterLogin return AuthResult. (3) logout(accessToken, refreshToken, userId): decode token for jti+exp, blacklist rv:{jti} with remaining TTL, delete rt:{sha256(refresh)}, hooks.afterLogout. (4) refresh(oldRefresh, ip, userAgent): delegate to tokenManager.reissueTokens. (5) getMe(userId): findById, throw TOKEN_INVALID if not found. (6) verifyEmail(tenantId, email, userId, otp): verify via otpService, update emailVerified, hooks.afterEmailVerified. (7) resendVerificationEmail(tenantId, email): atomic cooldown SET resend:email_verification:{sha256(tenantId+':'+email)} 1 NX EX 60, if nil return success silently, otherwise find user+generate OTP+store+send. Timing normalization on resend.

---

### NEST-058: Service - AuthService tests

- **Phase:** 2
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-057
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** Write comprehensive unit tests for AuthService covering all methods and edge cases.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/services/auth.service.spec.ts. Mock all dependencies. Tests for register: (1) Success creates user and returns AuthResult. (2) Duplicate email throws EMAIL_ALREADY_EXISTS. (3) Hook rejects with reason. (4) Hook modifiedData applied. (5) Email verification OTP sent when required. Tests for login: (6) Success returns AuthResult. (7) Invalid credentials records brute-force failure. (8) Brute-force lockout throws ACCOUNT_LOCKED. (9) Blocked status throws specific error. (10) MFA enabled returns MfaChallengeResult. (11) Email not verified throws EMAIL_NOT_VERIFIED. (12) tenantIdResolver is called when configured. Tests for logout: (13) Blacklists JWT jti. (14) Deletes refresh token. Tests for refresh: (15) Delegates to reissueTokens. Tests for getMe: (16) Returns user. (17) Not found throws TOKEN_INVALID. Tests for verifyEmail: (18) Verifies OTP and updates user. Tests for resendVerificationEmail: (19) Cooldown prevents duplicate sends. (20) Success generates and sends new OTP.

---

### NEST-059: Controller - AuthController implementation

- **Phase:** 2
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-057, NEST-034, NEST-045, NEST-052, NEST-053
- **Agent:** code-reviewer
- **Estimate:** ~30min
- **Description:** Implement AuthController with 7 endpoints for register, login, logout, refresh, me, verify-email, and resend-verification.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/controllers/auth.controller.ts. Implement @Controller() class AuthController. Inject AuthService and TokenDeliveryService. 7 endpoints: (1) POST /register: @Public(), @Throttle(AUTH_THROTTLE_CONFIGS.register), @UsePipes(ValidationPipe), body: RegisterDto. Call authService.register(dto, req), deliver via tokenDeliveryService.deliverAuthResponse(res, result, req). Use @Res({passthrough:true}). (2) POST /login: @Public(), @Throttle(login). Call authService.login(dto, req). If MfaChallengeResult (mfaRequired=true) return directly, else deliver via tokenDeliveryService. (3) POST /logout: @UseGuards(JwtAuthGuard). Extract access+refresh tokens via tokenDeliveryService, call authService.logout, call tokenDeliveryService.clearAuthSession. (4) POST /refresh: @Public(), @Throttle(refresh). Extract refresh via tokenDeliveryService, call authService.refresh, deliver new tokens. (5) GET /me: @UseGuards(JwtAuthGuard). Call authService.getMe(user.sub). (6) POST /verify-email: @Public(), @Throttle(verifyEmail). (7) POST /resend-verification: @Public(), @Throttle(resendVerification). Extract req.ip and req.headers['user-agent'] for all service calls.

---

### NEST-060: Controller - AuthController tests

- **Phase:** 2
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-059
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** Write unit tests for AuthController with mocked services.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/server/controllers/auth.controller.spec.ts. Mock AuthService and TokenDeliveryService. Tests: (1) POST /register calls authService.register and tokenDeliveryService.deliverAuthResponse. (2) POST /login with normal result calls deliverAuthResponse. (3) POST /login with MFA result returns MfaChallengeResult directly. (4) POST /logout extracts tokens and calls logout+clearAuthSession. (5) POST /refresh extracts refresh token and delivers new tokens. (6) GET /me returns user data. (7) POST /verify-email calls verifyEmail. (8) POST /resend-verification calls resendVerificationEmail. (9) Verify guards are applied (JwtAuthGuard on protected routes, Public on public routes).

---

### NEST-061: Module - BymaxAuthModule dynamic module

- **Phase:** 2
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-057, NEST-059, NEST-043, NEST-045, NEST-046, NEST-047, NEST-055, NEST-038, NEST-039
- **Agent:** architect
- **Estimate:** ~45min
- **Description:** Implement the main dynamic module with registerAsync, conditional providers/controllers, and route prefix support.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/bymax-auth.module.ts. Implement @Module({}) class BymaxAuthModule with static registerAsync(options: { imports?, inject?, useFactory, providers? }): DynamicModule. In the method: (1) useFactory resolves user config, call resolveOptions to apply defaults+validate, register resolved options as provider with BYMAX_AUTH_OPTIONS token. (2) Register mandatory providers: AuthRedisService, PasswordService, TokenManagerService, TokenDeliveryService, BruteForceService, OtpService, AuthService, JwtAuthGuard, RolesGuard, UserStatusGuard. (3) Register fallback providers: if BYMAX_AUTH_HOOKS not in user providers -> register NoOpAuthHooks. If BYMAX_AUTH_EMAIL_PROVIDER not in user providers -> register NoOpEmailProvider. (4) Build controllers array dynamically: include AuthController if controllers.auth !== false. (5) Import JwtModule.registerAsync with secret and signOptions from resolved options. (6) Use RouterModule.register([{ path: routePrefix, module: BymaxAuthModule }]) for dynamic route prefix. (8) DO NOT register guards as APP_GUARD — each controller applies guards explicitly. (9) Merge user's providers array with internal providers.

---

### NEST-062: Module - BymaxAuthModule tests

- **Phase:** 2
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-061
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** Write integration tests for the dynamic module verifying compilation, validation, and conditional registration.

**Prompt for the agent:**

> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/bymax-auth.module.spec.ts. Tests: (1) Module compiles and initializes with valid minimal config (jwt.secret with 32+ chars high entropy, mock Redis client, mock user repository). (2) Validation fails with weak jwt.secret (short or low entropy). (3) AuthController is NOT registered when controllers.auth is false. (4) AuthController IS registered by default. (5) NoOpEmailProvider is used when no email provider is given. (6) NoOpAuthHooks is used when no hooks provider is given. (7) Route prefix is applied correctly. Use NestJS Test.createTestingModule for integration testing.

---

### NEST-063: Barrel export - Phase 2

- **Phase:** 2
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-061, NEST-049, NEST-050, NEST-052, NEST-053
- **Agent:** architect
- **Estimate:** ~15min
- **Description:** Update src/server/index.ts with all Phase 2 exports.

**Prompt for the agent:**

> Update /Users/maximiliano/Documents/My Apps/nest-auth/src/server/index.ts adding Phase 2 exports. Add: export { BymaxAuthModule } from './bymax-auth.module'. export { AuthService } from './services/auth.service'. export { JwtAuthGuard } from './guards/jwt-auth.guard'. export { RolesGuard } from './guards/roles.guard'. export { UserStatusGuard } from './guards/user-status.guard'. export { CurrentUser } from './decorators/current-user.decorator'. export { Roles, ROLES_KEY } from './decorators/roles.decorator'. export { Public, IS_PUBLIC_KEY } from './decorators/public.decorator'. export { RegisterDto } from './dto/register.dto'. export { LoginDto } from './dto/login.dto'. Note: AuthResult and MfaChallengeResult types were already exported in Phase 1 from interfaces/auth-result.interface. Verify no duplicate exports.

---

### NEST-064: Phase 2 validation - build and test

- **Phase:** 2
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-063
- **Agent:** architect
- **Estimate:** ~30min
- **Description:** Run full build and test suite for Phase 2, verify all flows work end-to-end and coverage meets 80%.

**Prompt for the agent:**

> Run Phase 2 validation: (1) `pnpm build` compiles without errors. (2) `pnpm test --coverage` passes with >= 80% coverage. (3) Verify register -> login -> refresh -> logout flow works (via unit tests confirming correct service calls and data flow). (4) Guards work: public routes skip JWT, protected routes require JWT, roles are checked hierarchically. (5) TokenDelivery works in all 3 modes. (6) Brute-force blocks after N attempts with Retry-After header. (7) Dynamic module compiles and initializes. (8) Controllers are registered conditionally. (9) Route prefix works via RouterModule. (10) tenantIdResolver is called when configured. (11) OtpService constant-time comparison works. Fix any issues found.

---

## Phase 3 — Multi-Factor Authentication (MFA)

### NEST-065: MFA DTOs

- **Phase:** 3
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-026
- **Agent:** typescript-reviewer
- **Estimate:** ~20min
- **Description:** Create the three MFA DTO files with class-validator decorators for MFA setup verification, challenge, and disable flows.

**Prompt for the agent:**

> Create three DTO files in `src/server/dto/`:
>
> 1. `src/server/dto/mfa-verify.dto.ts` — class `MfaVerifyDto` with field: `@IsString() @IsNotEmpty() @Length(6, 6) code: string`.
> 2. `src/server/dto/mfa-challenge.dto.ts` — class `MfaChallengeDto` with fields: `@IsString() @IsNotEmpty() mfaTempToken: string` and `@IsString() @IsNotEmpty() @MaxLength(128) code: string`.
> 3. `src/server/dto/mfa-disable.dto.ts` — class `MfaDisableDto` with field: `@IsString() @IsNotEmpty() @Length(6, 6) code: string`. Add a JSDoc comment noting that only TOTP codes are accepted for disabling MFA (recovery codes are not accepted by design decision). Mention that recovery without TOTP requires administrative intervention.
>
> All DTOs must import decorators from `class-validator`. Follow the existing DTO patterns already in the project from Phase 2. Export all DTOs from their respective files.
>
> Acceptance criteria:
>
> - All three files compile without errors
> - Validation decorators match the exact constraints specified
> - JSDoc on MfaDisableDto explains the TOTP-only restriction

---

### NEST-066: SkipMfa decorator

- **Phase:** 3
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-026
- **Agent:** code-reviewer
- **Estimate:** ~20min
- **Description:** Create the SkipMfa decorator that sets metadata to bypass MfaRequiredGuard on specific endpoints.

**Prompt for the agent:**

> Create file `src/server/decorators/skip-mfa.decorator.ts`.
>
> Implementation:
>
> - Define a constant `SKIP_MFA_KEY = 'skipMfa'` and export it.
> - Create and export a decorator `SkipMfa` using `SetMetadata(SKIP_MFA_KEY, true)` from `@nestjs/common`.
>
> Follow the same pattern as other decorators in `src/server/decorators/` from Phase 2 (e.g., `@Public()` if it exists).
>
> Acceptance criteria:
>
> - `@SkipMfa()` can be applied to controller methods
> - The constant `SKIP_MFA_KEY` is exported for use by the guard
> - File compiles without errors

---

### NEST-067: MfaRequiredGuard

- **Phase:** 3
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-066
- **Agent:** security-reviewer
- **Estimate:** ~30min
- **Description:** Create the MfaRequiredGuard that checks if a user with MFA enabled has completed MFA verification, respecting the SkipMfa decorator.

**Prompt for the agent:**

> Create file `src/server/guards/mfa-required.guard.ts`.
>
> Implementation:
>
> - Implement `CanActivate` from `@nestjs/common`.
> - Inject `Reflector` to read metadata.
> - In `canActivate(context)`:
>   1. Check if `@SkipMfa()` is set via `reflector.getAllAndOverride(SKIP_MFA_KEY, [context.getHandler(), context.getClass()])`. If true, return true.
>   2. Extract `request.user` from the execution context.
>   3. If the user has MFA enabled (`user.mfaEnabled === true`) but `user.mfaVerified !== true`, throw an exception using the `MFA_REQUIRED` error code from the project's error constants.
>   4. Otherwise, return true.
>
> Import `SKIP_MFA_KEY` from `src/server/decorators/skip-mfa.decorator.ts`. Use the project's `AuthException` class for throwing errors, following existing guard patterns from Phase 2.
>
> Acceptance criteria:
>
> - Guard passes when MFA is not enabled on the user
> - Guard passes when MFA is enabled and `mfaVerified` is true in JWT
> - Guard throws `MFA_REQUIRED` when MFA is enabled but not verified
> - Guard passes when `@SkipMfa()` is applied regardless of MFA state

---

### NEST-068: MfaService — encrypt/decrypt helpers and recovery code utilities

- **Phase:** 3
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-026
- **Agent:** security-reviewer
- **Estimate:** ~30min
- **Description:** Implement the MfaService skeleton with encryptSecret, decryptSecret, hashRecoveryCodes, and verifyRecoveryCode private methods.

**Prompt for the agent:**

> Create file `src/server/services/mfa.service.ts` with an `@Injectable()` class `MfaService`.
>
> Inject the following dependencies (follow existing DI patterns from Phase 2 services):
>
> - `@Inject(BYMAX_AUTH_OPTIONS) options`
> - `@Inject(BYMAX_AUTH_USER_REPOSITORY) userRepo`
> - `@Optional() @Inject(BYMAX_AUTH_PLATFORM_USER_REPOSITORY) platformUserRepo`
> - `AuthRedisService`
> - `TokenManagerService`
> - `@Optional() SessionService`
> - `BruteForceService`
> - `@Inject(BYMAX_AUTH_EMAIL_PROVIDER) emailProvider`
> - `@Inject(BYMAX_AUTH_HOOKS) hooks`
> - `PasswordService`
>
> If `context === 'platform'` and `platformUserRepo` is not available, throw a descriptive error.
>
> Implement these private/utility methods:
>
> 1. `private encryptSecret(secret: string): string` — delegates to `aes-gcm.encrypt(secret, this.options.encryptionKey)` from `src/server/utils/aes-gcm.ts` (already exists from Phase 1).
> 2. `private decryptSecret(encrypted: string): string` — delegates to `aes-gcm.decrypt(encrypted, this.options.encryptionKey)`.
> 3. `private async hashRecoveryCodes(count: number): Promise<{ plainCodes: string[]; hashedCodes: string[] }>`:
>    - Generate `count` random codes using `crypto.randomBytes`.
>    - Format each as `xxxx-xxxx-xxxx` using alphanumeric characters.
>    - Hash each code via `PasswordService.hash()` (scrypt).
>    - Return both plain and hashed arrays.
> 4. `private async verifyRecoveryCode(code: string, hashedCodes: string[]): Promise<number>`:
>    - Iterate over `hashedCodes`, comparing each one with `PasswordService.compare()` (uses `crypto.timingSafeEqual` internally).
>    - Return the index if found, -1 if not found.
>
> Leave the public methods (`setup`, `verifyAndEnable`, `challenge`, `disable`) as stubs that throw `NotImplementedError` for now — they will be implemented in subsequent tasks.
>
> Acceptance criteria:
>
> - File compiles with all injections properly typed
> - `hashRecoveryCodes(8)` produces 8 codes in `xxxx-xxxx-xxxx` format
> - `verifyRecoveryCode` returns correct index or -1
> - encrypt/decrypt round-trips correctly using aes-gcm utils

---

### NEST-069: MfaService.setup()

- **Phase:** 3
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-068
- **Agent:** code-reviewer
- **Estimate:** ~30min
- **Description:** Implement the MFA setup method that generates TOTP secret, QR code URI, and recovery codes with idempotency via Redis.

**Prompt for the agent:**

> In `src/server/services/mfa.service.ts`, implement the `async setup(userId: string): Promise<MfaSetupResult>` method:
>
> 1. Fetch the user via `userRepo.findById(userId)`. Check if MFA is already enabled — if yes, throw `MFA_ALREADY_ENABLED`.
> 2. **Idempotency check:** Look up Redis key `mfa_setup:{sha256(userId)}`. If it exists and has TTL > 0, parse and return the existing result (secret, qrCodeUri, recoveryCodes) instead of generating new ones.
> 3. Generate the TOTP secret: use `crypto.randomBytes(20)` from `node:crypto` and encode it in Base32 via the `src/server/crypto/totp.ts` utility.
> 4. Encrypt the secret using `this.encryptSecret(secretBase32)`.
> 5. Generate 8 recovery codes using `this.hashRecoveryCodes(8)`.
> 6. Store in Redis temporarily: key `mfa_setup:{sha256(userId)}` with value `{ encryptedSecret, hashedCodes, plainCodes, secret: secret.base32 }`, TTL 10 minutes (600 seconds). Use `sha256(userId)` as the key per the spec's identifier hashing principle.
> 7. Generate the QR code URI via `buildTotpUri(secretBase32, email, issuer)` from `src/server/crypto/totp.ts`, where `issuer` comes from `this.options.mfa.issuer` or `this.options.appName`.
> 8. Return `MfaSetupResult { secret: secretBase32, qrCodeUri, recoveryCodes: plainCodes }`.
>
> The `MfaSetupResult` type should be defined/exported from this file (or imported if already defined): `{ secret: string; qrCodeUri: string; recoveryCodes: string[] }`.
>
> Acceptance criteria:
>
> - Calling setup twice within 10 min returns the same result (idempotency)
> - The QR URI correctly follows the otpauth:// format (generated via `buildTotpUri`)
> - Recovery codes are in xxxx-xxxx-xxxx format
> - Redis key uses sha256(userId)

---

### NEST-070: MfaService.verifyAndEnable()

- **Phase:** 3
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-069
- **Agent:** security-reviewer
- **Estimate:** ~30min
- **Description:** Implement the method that validates a TOTP code against the pending setup and permanently enables MFA for the user.

**Prompt for the agent:**

> In `src/server/services/mfa.service.ts`, implement `async verifyAndEnable(userId: string, code: string): Promise<void>`:
>
> 1. Fetch the setup data from Redis key `mfa_setup:{sha256(userId)}`. If not found, throw `MFA_SETUP_REQUIRED`.
> 2. Decrypt the secret using `this.decryptSecret(encryptedSecret)`.
> 3. Validate the TOTP code using `verifyTotp(secret, code, window)` from `src/server/crypto/totp.ts` with window = `this.options.mfa.totpWindow` (or the config default). If invalid, throw `MFA_INVALID_CODE`.
> 4. Persist MFA to the database: `userRepo.updateMfa({ mfaEnabled: true, mfaSecret: encryptedSecret, mfaRecoveryCodes: hashedCodes })`.
> 5. Delete the temporary Redis setup key.
> 6. **Session invalidation:** Get all session hashes from `sess:{userId}` SET. For each session hash, delete the refresh token `rt:{sessionHash}`. Then clear the SET. Note: active access tokens cannot be blacklisted since `jti` is not stored — they remain valid up to `accessExpiresIn` (default 15 min). Document this limitation with a code comment.
> 7. Send notification: `emailProvider.sendMfaEnabledNotification(user)`.
> 8. Execute hook: `hooks.afterMfaEnabled({ userId })`.
>
> Acceptance criteria:
>
> - Valid TOTP code enables MFA and persists encrypted secret + hashed recovery codes
> - Invalid TOTP code throws MFA_INVALID_CODE without modifying database
> - Missing setup throws MFA_SETUP_REQUIRED
> - All existing sessions are invalidated after MFA is enabled
> - Email notification and hook are called on success

---

### NEST-071: MfaService.challenge()

- **Phase:** 3
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-070
- **Agent:** security-reviewer
- **Estimate:** ~30min
- **Description:** Implement the MFA challenge method that validates TOTP or recovery codes during login, handling both dashboard and platform contexts with brute-force protection.

**Prompt for the agent:**

> In `src/server/services/mfa.service.ts`, implement `async challenge(mfaTempToken: string, code: string, ip: string, userAgent: string): Promise<AuthResult | PlatformAuthResult>`:
>
> 1. Verify `mfaTempToken` via `tokenManager.verifyMfaTempToken(mfaTempToken)` — returns `{ userId, context }` where context is `'dashboard'` or `'platform'`.
> 2. Compute brute-force identifier: `sha256(userId)`.
> 3. Check lockout: `bruteForce.isLockedOut(identifier)`. If locked, throw appropriate error.
> 4. Fetch user from the correct repository based on `context`:
>    - `'dashboard'` -> `userRepo.findById(userId)`
>    - `'platform'` -> `platformUserRepo.findById(userId)` (throw descriptive error if platformUserRepo is null)
> 5. Decrypt `user.mfaSecret`.
> 6. Determine if `code` is a TOTP code (6 digits) or recovery code (other format):
>    - **If TOTP:** Validate with `verifyTotp()` from `src/server/crypto/totp.ts`. Check anti-replay: if the Redis key `tu:{userId}:{code}` exists, reject it as already used. If valid, set `tu:{userId}:{code}` with TTL 90 seconds.
>    - **If recovery code:** Call `this.verifyRecoveryCode(code, user.mfaRecoveryCodes)`. If found (index >= 0), remove it from the array via `userRepo.updateMfa()` with the code at that index removed.
> 7. If invalid: record brute-force failure. If failures >= 5, also revoke the `mfaTempToken` (force re-authentication). Throw `MFA_INVALID_CODE`.
> 8. If valid:
>    - Reset brute-force counter.
>    - Issue tokens with `mfaVerified: true`:
>      - `'dashboard'`: `tokenManager.issueTokens(user, ip, userAgent, { mfaVerified: true })` -> return `AuthResult`
>      - `'platform'`: issue platform tokens -> return `PlatformAuthResult`
>    - Create session if `sessions.enabled` and context is `'dashboard'`: call `sessionService.createSession()`.
>    - Execute `hooks.afterLogin()`.
> 9. Return the result matching the context.
>
> Import `AuthResult` and `PlatformAuthResult` from `src/server/interfaces/auth-result.interface.ts`.
>
> Acceptance criteria:
>
> - Valid TOTP code returns AuthResult with mfaVerified: true
> - Valid recovery code returns AuthResult and removes the used code
> - Anti-replay prevents reuse of same TOTP code within 90s
> - Brute-force lockout works after threshold
> - After 5 failures, mfaTempToken is revoked
> - Platform context returns PlatformAuthResult
> - Session is created for dashboard context when sessions enabled

---

### NEST-072: MfaService.disable()

- **Phase:** 3
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-070
- **Agent:** code-reviewer
- **Estimate:** ~30min
- **Description:** Implement MFA disable method requiring a valid TOTP code with brute-force protection.

**Prompt for the agent:**

> In `src/server/services/mfa.service.ts`, implement `async disable(userId: string, code: string): Promise<void>`:
>
> 1. Fetch user via `userRepo.findById(userId)`.
> 2. If MFA is not enabled, throw `MFA_NOT_ENABLED`.
> 3. Check brute-force lockout: `bruteForce.isLockedOut(sha256(userId))` — uses the same identifier as `challenge`.
> 4. Decrypt `user.mfaSecret`.
> 5. Validate the TOTP code using `verifyTotp()` from `src/server/crypto/totp.ts`. Only TOTP codes are accepted (recovery codes are not).
> 6. If invalid: record failure via `bruteForce.recordFailure(sha256(userId))`, throw `MFA_INVALID_CODE`.
> 7. If valid: reset brute-force counter.
> 8. Disable MFA: `userRepo.updateMfa({ mfaEnabled: false, mfaSecret: null, mfaRecoveryCodes: null })`.
> 9. Send notification: `emailProvider.sendMfaDisabledNotification(user)`.
> 10. Execute hook: `hooks.afterMfaDisabled({ userId })`.
>
> Acceptance criteria:
>
> - Valid TOTP code disables MFA and clears secret/recovery codes from DB
> - MFA not enabled throws MFA_NOT_ENABLED
> - Invalid code records brute-force failure
> - Only TOTP codes accepted (recovery codes must not work)
> - Email notification and hook called on success

---

### NEST-073: MfaController

- **Phase:** 3
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-065, NEST-071, NEST-072
- **Agent:** code-reviewer
- **Estimate:** ~30min
- **Description:** Create the MFA controller with four endpoints for setup, verify, challenge, and disable, applying appropriate guards and throttle decorators.

**Prompt for the agent:**

> Create file `src/server/controllers/mfa.controller.ts`.
>
> Implementation:
>
> - `@Controller()` with prefix `{routePrefix}/mfa` (resolve routePrefix from injected options).
> - Inject `MfaService` and `TokenDeliveryService`.
>
> Implement 4 endpoints:
>
> 1. `POST /setup` — Guard: `JwtAuthGuard`. Throttle: `mfaSetup`. Calls `mfaService.setup(user.sub)` where `user` is extracted from `@Request()`. Returns the `MfaSetupResult`.
> 2. `POST /verify` — Guard: `JwtAuthGuard`. No special throttle. Body: `MfaVerifyDto`. Calls `mfaService.verifyAndEnable(user.sub, dto.code)`.
> 3. `POST /challenge` — Public (no auth guard, user has no JWT yet). Throttle: `mfaChallenge`. Body: `MfaChallengeDto`. Calls `mfaService.challenge(dto.mfaTempToken, dto.code, ip, userAgent)`. Deliver tokens via `tokenDeliveryService`.
> 4. `POST /disable` — Guard: `JwtAuthGuard`. Throttle: `mfaDisable`. Body: `MfaDisableDto`. Calls `mfaService.disable(user.sub, dto.code)`.
>
> Extract `ip` from `request.ip` and `userAgent` from `request.headers['user-agent']`. Follow the same controller patterns from Phase 2's `AuthController`.
>
> Acceptance criteria:
>
> - All 4 endpoints defined with correct HTTP methods and routes
> - Guards applied correctly (challenge is public, others require JWT)
> - Throttle decorators applied to setup, challenge, and disable
> - DTOs used for request body validation
> - Token delivery via tokenDeliveryService on challenge endpoint

---

### NEST-074: MFA module integration

- **Phase:** 3
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-073, NEST-067
- **Agent:** architect
- **Estimate:** ~45min
- **Description:** Register MfaService, MfaController, and MfaRequiredGuard conditionally in the dynamic module based on MFA configuration.

**Prompt for the agent:**

> Modify the dynamic module registration file (the main `BymaxAuthModule` or equivalent in `src/`) to conditionally register Phase 3 components:
>
> 1. Register `MfaService` as a provider ONLY when `options.mfa` is configured (truthy).
> 2. Register `MfaController` as a controller ONLY when `options.mfa` is configured AND `options.controllers?.mfa !== false`.
> 3. Register `MfaRequiredGuard` as a provider (always available when MFA is configured, so consumers can use it).
>
> Follow the existing conditional registration patterns from Phase 2 (e.g., how AuthController is conditionally registered).
>
> Acceptance criteria:
>
> - When `mfa` config is absent, MfaService and MfaController are not registered
> - When `mfa` config is present but `controllers.mfa` is false, MfaService is registered but MfaController is not
> - When `mfa` config is present, MfaRequiredGuard is available for injection
> - No circular dependency issues

---

### NEST-075: MFA barrel exports

- **Phase:** 3
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-074
- **Agent:** code-reviewer
- **Estimate:** ~15min
- **Description:** Update the main index.ts barrel export to include all Phase 3 public APIs.

**Prompt for the agent:**

> Update `src/server/index.ts` (the main barrel export file) to add the following exports:
>
> - `export { MfaRequiredGuard } from './guards/mfa-required.guard'`
> - `export { SkipMfa } from './decorators/skip-mfa.decorator'`
> - `export type { MfaSetupResult } from './services/mfa.service'`
> - `export { MfaVerifyDto } from './dto/mfa-verify.dto'`
> - `export { MfaChallengeDto } from './dto/mfa-challenge.dto'`
> - `export { MfaDisableDto } from './dto/mfa-disable.dto'`
>
> Follow the existing grouping/ordering conventions in the barrel file.
>
> Acceptance criteria:
>
> - All 6 exports are present in index.ts
> - Types are exported with `export type` syntax
> - File compiles without errors

---

### NEST-076: MfaService unit tests

- **Phase:** 3
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-072
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** Write comprehensive unit tests for MfaService covering all flows including setup idempotency, challenge with both contexts, and edge cases.

**Prompt for the agent:**

> Create test file `src/server/services/__tests__/mfa.service.spec.ts` (or follow the project's existing test file convention).
>
> Write unit tests for `MfaService` covering:
>
> 1. **setup():**
>    - Generates secret, QR code URI, and 8 recovery codes
>    - The QR code URI follows the `otpauth://totp/` format (generated via `buildTotpUri`)
>    - Recovery codes are in `xxxx-xxxx-xxxx` format
>    - Throws `MFA_ALREADY_ENABLED` if MFA already enabled
>    - Idempotency: calling setup twice returns same result (mock Redis to return existing data)
> 2. **verifyAndEnable():**
>    - Valid TOTP code enables MFA, persists to DB
>    - Invalid TOTP code throws `MFA_INVALID_CODE`, does not modify DB
>    - Missing setup (no Redis data) throws `MFA_SETUP_REQUIRED`
>    - Existing sessions are invalidated
>    - Email notification and hook are called
> 3. **challenge():**
>    - Valid TOTP code with `context: 'dashboard'` returns `AuthResult` with `mfaVerified: true`
>    - Valid TOTP code with `context: 'platform'` returns `PlatformAuthResult`
>    - Valid recovery code works and removes the used code
>    - Anti-replay: reusing same TOTP code within 90s is rejected
>    - Brute-force lockout after threshold
>    - After 5 failures, mfaTempToken is revoked
>    - Session is created for dashboard context when sessions enabled
> 4. **disable():**
>    - Valid TOTP code disables MFA
>    - Throws `MFA_NOT_ENABLED` when MFA not enabled
>    - Invalid code records brute-force failure
>    - Email notification and hook called on success
>
> Mock all dependencies (userRepo, platformUserRepo, Redis, tokenManager, bruteForce, emailProvider, hooks, sessionService). Use Jest. Aim for >= 80% coverage of mfa.service.ts.
>
> Acceptance criteria:
>
> - All test cases pass
> - Covers happy path and error paths for all 4 public methods
> - Both dashboard and platform contexts tested for challenge
> - Anti-replay and brute-force scenarios tested

---

### NEST-077: MfaController unit tests

- **Phase:** 3
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-073
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** Write unit tests for MfaController verifying correct routing, guard application, and delegation to MfaService.

**Prompt for the agent:**

> Create test file `src/server/controllers/__tests__/mfa.controller.spec.ts`.
>
> Write unit tests for `MfaController` covering:
>
> 1. `POST /setup` — calls `mfaService.setup()` with user ID from JWT, requires JwtAuthGuard
> 2. `POST /verify` — calls `mfaService.verifyAndEnable()` with user ID and code from DTO
> 3. `POST /challenge` — calls `mfaService.challenge()` with mfaTempToken, code, ip, userAgent; delivers tokens via tokenDeliveryService
> 4. `POST /disable` — calls `mfaService.disable()` with user ID and code from DTO
>
> Mock `MfaService` and `TokenDeliveryService`. Use NestJS testing utilities (`Test.createTestingModule`). Verify that each endpoint delegates correctly to the service layer.
>
> Acceptance criteria:
>
> - All 4 endpoints tested
> - Service methods called with correct arguments
> - Token delivery verified on challenge endpoint
> - Tests pass

---

### NEST-078: MfaRequiredGuard and SkipMfa unit tests

- **Phase:** 3
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-067
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** Write unit tests for MfaRequiredGuard verifying it correctly enforces MFA verification and respects the SkipMfa decorator.

**Prompt for the agent:**

> Create test file `src/server/guards/__tests__/mfa-required.guard.spec.ts`.
>
> Test cases:
>
> 1. User without MFA enabled -> guard passes (returns true)
> 2. User with MFA enabled and `mfaVerified: true` in JWT -> guard passes
> 3. User with MFA enabled and `mfaVerified: false` or missing -> guard throws `MFA_REQUIRED`
> 4. Endpoint decorated with `@SkipMfa()` -> guard passes regardless of MFA status
> 5. No user on request -> guard handles gracefully
>
> Mock the `Reflector` and execution context. Follow existing guard test patterns from Phase 2.
>
> Acceptance criteria:
>
> - All 5 scenarios tested
> - Tests pass

---

### NEST-079: Phase 3 validation — integration smoke test

- **Phase:** 3
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-076, NEST-077, NEST-078, NEST-075
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** Write an integration-style test that validates the full MFA flow: setup, verify, challenge, and disable, plus edge cases like anti-replay and brute-force.

**Prompt for the agent:**

> Create test file `src/__tests__/mfa-integration.spec.ts` (or equivalent).
>
> Write integration-level tests (can still use mocked repositories but test the full service chain) that validate the Phase 3 checklist:
>
> 1. Full flow: setup -> verifyAndEnable -> challenge (with TOTP) works end-to-end
> 2. Setup is idempotent (concurrent calls return same result)
> 3. Recovery codes work as alternative to TOTP in challenge
> 4. All recovery codes consumed -> user blocked without TOTP
> 5. Anti-replay of TOTP code prevents reuse within 90s window
> 6. Brute-force on challenge: lockout after threshold, temp token revoked after 5 failures
> 7. Brute-force identifier is `sha256(userId)` (independent from login brute-force)
> 8. Challenge with `context: 'platform'` returns PlatformAuthResult
> 9. After enabling MFA, existing sessions are invalidated
> 10. Disable requires TOTP (recovery codes rejected)
> 11. `@SkipMfa()` bypasses MfaRequiredGuard
>
> Acceptance criteria:
>
> - All 11 scenarios have passing tests
> - Tests validate the checklist items from section 4.7 of the development plan

---

## Phase 4 — Sessions and Password Reset

### NEST-080: Password Reset and Verification DTOs

- **Phase:** 4
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-026
- **Agent:** typescript-reviewer
- **Estimate:** ~45min
- **Description:** Create all six DTOs for password reset and email verification flows with proper validation decorators.

**Prompt for the agent:**

> Create the following 6 DTO files in `src/server/dto/`:
>
> 1. `src/server/dto/forgot-password.dto.ts` — class `ForgotPasswordDto`:
>    - `@IsEmail() email: string`
>    - `@IsString() @IsNotEmpty() tenantId: string`
> 2. `src/server/dto/reset-password.dto.ts` — class `ResetPasswordDto`:
>    - `@IsEmail() email: string`
>    - `@IsString() @MinLength(8) @MaxLength(128) newPassword: string`
>    - `@IsOptional() @IsString() @IsNotEmpty() token?: string`
>    - `@IsOptional() @IsString() @IsNotEmpty() otp?: string`
>    - `@IsOptional() @IsString() @IsNotEmpty() verifiedToken?: string`
>    - `@IsString() @IsNotEmpty() tenantId: string`
>    - Add JSDoc comment: `@IsNotEmpty()` on optional fields ensures that if present, they are not empty strings (which would produce a valid but incorrect `sha256("")`).
> 3. `src/server/dto/verify-otp.dto.ts` — class `VerifyOtpDto`:
>    - `@IsEmail() email: string`
>    - `@IsString() @IsNotEmpty() @Length(6, 8) otp: string` (min 6 = default, max 8 = max otpLength)
>    - `@IsString() @IsNotEmpty() tenantId: string`
> 4. `src/server/dto/resend-otp.dto.ts` — class `ResendOtpDto`:
>    - `@IsEmail() email: string`
>    - `@IsString() @IsNotEmpty() tenantId: string`
> 5. `src/server/dto/verify-email.dto.ts` — class `VerifyEmailDto`:
>    - `@IsEmail() email: string`
>    - `@IsString() @IsNotEmpty() otp: string`
>    - `@IsString() @IsNotEmpty() tenantId: string`
> 6. `src/server/dto/resend-verification.dto.ts` — class `ResendVerificationDto`:
>    - `@IsEmail() email: string`
>    - `@IsString() @IsNotEmpty() tenantId: string`
>
> Follow existing DTO patterns from Phase 2. Import all decorators from `class-validator`.
>
> Acceptance criteria:
>
> - All 6 files compile without errors
> - Validation constraints match exactly as specified
> - Optional fields in ResetPasswordDto have both @IsOptional() and @IsNotEmpty()

---

### NEST-081: SessionService — createSession and enforceSessionLimit

- **Phase:** 4
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-026
- **Agent:** code-reviewer
- **Estimate:** ~30min
- **Description:** Create the SessionService with session creation, FIFO session limit enforcement, and user-agent parsing.

**Prompt for the agent:**

> Create file `src/server/services/session.service.ts` with an `@Injectable()` class `SessionService`.
>
> Inject: `BYMAX_AUTH_OPTIONS`, `BYMAX_AUTH_USER_REPOSITORY`, `AuthRedisService`, `@Inject(BYMAX_AUTH_EMAIL_PROVIDER) emailProvider`, `@Inject(BYMAX_AUTH_HOOKS) hooks`.
>
> Export the `SessionInfo` interface from this file:

---

### NEST-082: SessionService — listSessions and revokeSession

- **Phase:** 4
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-081
- **Agent:** code-reviewer
- **Estimate:** ~30min
- **Description:** Implement session listing with current-session marking and single session revocation with ownership validation.

**Prompt for the agent:**

> In `src/server/services/session.service.ts`, implement:
>
> 1. `async listSessions(userId: string, currentSessionHash?: string): Promise<SessionInfo[]>`:
>    - Get all hashes from SET: `SMEMBERS sess:{userId}`.
>    - For each hash, get details from `sd:{hash}`. If details are null (expired), remove the stale hash from the SET via `SREM`.
>    - Set `isCurrent: hash === currentSessionHash` for each session.
>    - Sort by `createdAt` descending (newest first).
>    - Return `SessionInfo[]`.
> 2. `async revokeSession(userId: string, sessionHash: string): Promise<void>`:
>    - **Ownership validation:** `SISMEMBER sess:{userId} sessionHash`. If not a member, throw `SESSION_NOT_FOUND` (prevents BOLA/IDOR attacks).
>    - Delete refresh token: `DEL rt:{sessionHash}`.
>    - Remove from SET: `SREM sess:{userId} sessionHash`.
>    - Delete session details: `DEL sd:{sessionHash}`.
> 3. `async revokeAllExceptCurrent(userId: string, currentSessionHash: string): Promise<void>`:
>    - Get all session hashes from SET.
>    - Filter out `currentSessionHash`.
>    - Revoke each remaining session individually.
>
> Acceptance criteria:
>
> - listSessions returns all active sessions with correct isCurrent marking
> - Stale sessions (expired sd: keys) are cleaned up
> - revokeSession validates ownership before deleting
> - Attempting to revoke another user's session throws SESSION_NOT_FOUND
> - revokeAllExceptCurrent keeps only the current session

---

### NEST-083: SessionService — rotateSession with atomic Lua script

- **Phase:** 4
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-082
- **Agent:** database-reviewer
- **Estimate:** ~30min
- **Description:** Implement session rotation during refresh token rotation using an atomic Lua script that handles both token and session updates.

**Prompt for the agent:**

> In `src/server/services/session.service.ts`, implement:
>
> `async rotateSession(userId: string, oldRefreshToken: string, newRefreshToken: string): Promise<void>`:
>
> - Compute `oldHash = sha256(oldRefreshToken)` and `newHash = sha256(newRefreshToken)`.
> - This must be atomic with the refresh token rotation. Extend the existing Lua script for refresh token rotation (from Phase 2's `token-manager.service.ts` or `auth-redis.service.ts`) to also handle session keys.
> - The Lua script should:
>   1.  SREM `sess:{userId}` oldHash
>   2.  SADD `sess:{userId}` newHash
>   3.  Copy session details from `sd:{oldHash}` to `sd:{newHash}` with updated `lastActivityAt`
>   4.  DEL `sd:{oldHash}`
>   5.  EXPIRE `sess:{userId}` with the refresh TTL
> - The script must be **parametrizable** with key prefixes (`rt/rp/sess/sd` for dashboard, `prt/prp/psess/psd` for platform) instead of hardcoding prefixes. This prevents inconsistencies if the process crashes between token rotation and session update.
> - This method is a **deviation from the spec** (section 6.4 does not define `rotateSession`). Add a code comment documenting this: `// Deviation from spec: rotateSession added to maintain sess:{} SET consistency during refresh`.
>
> Also update the refresh token rotation logic in the relevant service (likely `TokenManagerService` or `AuthRedisService`) to call this Lua script with the additional session keys when `sessions.enabled`.
>
> Acceptance criteria:
>
> - Rotation atomically updates both token and session data in a single Lua script
> - Old session details are removed, new ones created with updated lastActivityAt
> - Lua script supports parameterized prefixes for dashboard/platform
> - sess:{userId} SET TTL is renewed
> - Comment documents the spec deviation

---

### NEST-084: SessionController

- **Phase:** 4
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-082
- **Agent:** code-reviewer
- **Estimate:** ~30min
- **Description:** Create the session controller with endpoints for listing, revoking single, and revoking all sessions.

**Prompt for the agent:**

> Create file `src/server/controllers/session.controller.ts`.
>
> Implementation:
>
> - `@Controller()` with prefix `{routePrefix}/sessions`.
> - Inject `SessionService`.
> - All endpoints require `JwtAuthGuard`.
>
> Implement 3 endpoints:
>
> 1. `GET /` — List sessions. Extract `userId` from `request.user.sub`. Extract `currentSessionHash` from JWT claims (if present) or compute via `sha256(refreshToken)` from the cookie. Call `sessionService.listSessions(userId, currentSessionHash)`.
> 2. `DELETE /:id` — Revoke a specific session. The `:id` param is the `sessionHash`. Call `sessionService.revokeSession(userId, sessionHash)`. The ownership check happens in the service.
> 3. `DELETE /all` — Revoke all sessions except current. Extract `currentSessionHash` same as in GET. Call `sessionService.revokeAllExceptCurrent(userId, currentSessionHash)`.
>
> Ensure route ordering: `/all` must be defined before `/:id` so NestJS doesn't interpret "all" as an id parameter.
>
> Acceptance criteria:
>
> - All 3 endpoints defined with correct HTTP methods
> - JwtAuthGuard applied to all endpoints
> - currentSessionHash correctly extracted
> - Route ordering prevents /all from matching /:id

---

### NEST-085: PasswordResetService — initiateReset

- **Phase:** 4
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-080
- **Agent:** security-reviewer
- **Estimate:** ~30min
- **Description:** Create PasswordResetService and implement the initiate reset method supporting both token and OTP flows with timing normalization.

**Prompt for the agent:**

> Create file `src/server/services/password-reset.service.ts` with an `@Injectable()` class `PasswordResetService`.
>
> Inject: `BYMAX_AUTH_OPTIONS`, `BYMAX_AUTH_USER_REPOSITORY`, `BYMAX_AUTH_EMAIL_PROVIDER`, `BYMAX_AUTH_HOOKS`, `OtpService`, `PasswordService`, `AuthRedisService`, `@Optional() SessionService`.
>
> Implement `async initiateReset(email: string, tenantId: string): Promise<void>`:
>
> 1. Record start time: `const start = Date.now()`.
> 2. Look up user by email (and tenantId if multi-tenant). Do NOT reveal whether the user exists — always return success to the caller.
> 3. If user exists, determine the reset method from `options.passwordReset.method` (`'token'` or `'otp'`):
>    - **Token method:**
>      - Generate secure token: `crypto.randomBytes(32).toString('hex')` (or use a `generateSecureToken` util).
>      - Store in Redis: `pr:{sha256(token)}` with value `userId`, TTL = `options.passwordReset.tokenTtlSeconds`.
>      - Send email: `emailProvider.sendPasswordResetToken(user, token)`.
>    - **OTP method:**
>      - Generate OTP: `otpService.generate(options.passwordReset.otpLength || 6)`.
>      - Compute identifier: `sha256(tenantId + ':' + email)`.
>      - Store: `otpService.store('password_reset', identifier, otp, options.passwordReset.otpTtlSeconds)`.
>      - Send email: `emailProvider.sendPasswordResetOtp(user, otp)`.
> 4. **Timing normalization:** Before returning, ensure constant response time: `await sleep(Math.max(0, TARGET_MS - (Date.now() - start)))` where TARGET_MS is a reasonable value (e.g., 200ms). This prevents side-channel attacks that could enumerate users.
>
> Acceptance criteria:
>
> - Token method generates secure random token and stores with TTL in Redis
> - OTP method delegates to OtpService correctly
> - Non-existent user does not cause different behavior or timing
> - Timing normalization prevents user enumeration via response time
> - Email sent only when user exists

---

### NEST-086: PasswordResetService — resetPassword

- **Phase:** 4
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-085
- **Agent:** security-reviewer
- **Estimate:** ~30min
- **Description:** Implement the resetPassword method supporting three validation modes (token, OTP, verifiedToken) with session invalidation and cross-tenant protection.

**Prompt for the agent:**

> In `src/server/services/password-reset.service.ts`, implement `async resetPassword(dto: ResetPasswordDto): Promise<void>`:
>
> 1. Validate exactly one of `token`, `otp`, or `verifiedToken` is present. If none or multiple, throw a validation error.
> 2. **If `verifiedToken` present:**
>    - Look up Redis key `prv:{sha256(verifiedToken)}` which contains `{ email, tenantId }`.
>    - If not found, throw appropriate error (token expired/invalid).
>    - Verify that `dto.tenantId` matches the stored `tenantId` (prevents cross-tenant password reset).
>    - Look up user by email.
> 3. **If `token` present:**
>    - Look up Redis key `pr:{sha256(token)}` which contains `userId`.
>    - If not found, throw appropriate error.
>    - Look up user by userId.
> 4. **If `otp` present:**
>    - Compute identifier: `sha256(dto.tenantId + ':' + dto.email)`.
>    - Validate via `otpService.verify('password_reset', identifier, dto.otp)` — this consumes the OTP.
>    - Look up user by email.
> 5. Hash the new password: `passwordService.hash(dto.newPassword)`.
> 6. Update in database: `userRepo.updatePassword(userId, hashedPassword)`.
> 7. Consume the token/verifiedToken from Redis (DEL the key).
> 8. Invalidate all user sessions: if `sessionService` available, revoke all sessions for the user.
> 9. Invalidate user status cache: `DEL us:{userId}`.
> 10. Execute hook: `hooks.afterPasswordReset({ userId })`.
>
> Acceptance criteria:
>
> - Token-based reset works end-to-end
> - OTP-based reset consumes the OTP
> - VerifiedToken-based reset validates cross-tenant
> - Cross-tenant attempt with mismatched tenantId is rejected
> - All sessions invalidated after reset
> - User status cache cleared
> - Hook called on success

---

### NEST-087: PasswordResetService — verifyOtp and resendOtp

- **Phase:** 4
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-085
- **Agent:** security-reviewer
- **Estimate:** ~30min
- **Description:** Implement the OTP verification (which produces a verifiedToken) and OTP resend with atomic cooldown.

**Prompt for the agent:**

> In `src/server/services/password-reset.service.ts`, implement:
>
> 1. `async verifyOtp(email: string, otp: string, tenantId: string): Promise<{ verifiedToken: string }>`:
>    - Compute identifier: `sha256(tenantId + ':' + email)`.
>    - Validate OTP: `otpService.verify('password_reset', identifier, otp)` — this CONSUMES the OTP.
>    - Generate a temporary verification token: `crypto.randomUUID()`.
>    - Store in Redis: `prv:{sha256(token)}` with value `{ email, tenantId }`, TTL = 300 seconds (5 minutes).
>    - Return `{ verifiedToken: token }`.
> 2. `async resendOtp(email: string, tenantId: string): Promise<void>`:
>    - **Atomic cooldown:** Use `SET resend:password_reset:{sha256(tenantId+':'+email)} 1 NX EX 60`. The `NX` flag ensures only the first concurrent request proceeds (prevents TOCTOU race condition). If the SET returns `null`, cooldown is active — return success without generating a new OTP.
>    - Record start time for timing normalization.
>    - Look up user by email — always return success regardless of existence (anti-enumeration).
>    - If user exists: generate new OTP via `otpService.generate()`, store via `otpService.store()`, send via `emailProvider.sendPasswordResetOtp()`.
>    - Apply timing normalization before returning.
>
> Acceptance criteria:
>
> - verifyOtp consumes OTP and returns a verifiedToken valid for 5 minutes
> - verifiedToken stored in Redis with correct structure
> - resendOtp respects 60-second cooldown via atomic NX operation
> - Cooldown prevents multiple OTP generations within 60s
> - Non-existent user returns success without leak
> - Timing normalization applied in resendOtp

---

### NEST-088: PasswordResetController

- **Phase:** 4
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-086, NEST-087
- **Agent:** code-reviewer
- **Estimate:** ~30min
- **Description:** Create the password reset controller with four public endpoints for forgot-password, reset, OTP verification, and OTP resend.

**Prompt for the agent:**

> Create file `src/server/controllers/password-reset.controller.ts`.
>
> Implementation:
>
> - `@Controller()` with prefix `{routePrefix}/password`.
> - Inject `PasswordResetService`.
> - All endpoints are public (no auth guards).
>
> Implement 4 endpoints:
>
> 1. `POST /forgot-password` — Throttle: `forgotPassword`. Body: `ForgotPasswordDto`. Call `passwordResetService.initiateReset(dto.email, dto.tenantId)`.
> 2. `POST /reset-password` — Throttle: `resetPassword`. Body: `ResetPasswordDto`. Call `passwordResetService.resetPassword(dto)`.
> 3. `POST /verify-otp` — Throttle: `verifyOtp`. Body: `VerifyOtpDto`. Call `passwordResetService.verifyOtp(dto.email, dto.otp, dto.tenantId)`.
> 4. `POST /resend-otp` — Throttle: `resendPasswordOtp`. Body: `ResendOtpDto`. Call `passwordResetService.resendOtp(dto.email, dto.tenantId)`.
>
> Follow existing controller patterns from Phase 2. Apply throttle decorators using the project's throttle mechanism.
>
> Acceptance criteria:
>
> - All 4 endpoints defined with correct routes and HTTP methods
> - All endpoints are public
> - Throttle decorators applied per the spec table
> - DTOs used for request body validation
> - Correct delegation to PasswordResetService methods

---

### NEST-089: Phase 4 module integration — SessionService and PasswordResetService

- **Phase:** 4
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-084, NEST-088
- **Agent:** architect
- **Estimate:** ~45min
- **Description:** Register SessionService, PasswordResetService, and their controllers conditionally in the dynamic module.

**Prompt for the agent:**

> Modify the dynamic module registration (in `BymaxAuthModule` or equivalent) to add Phase 4 components:
>
> 1. `OtpService` — already registered in Phase 2, no changes needed. Verify it's present.
> 2. Register `SessionService` as a provider ONLY when `options.sessions?.enabled === true`.
> 3. Register `PasswordResetService` always (password reset is a core feature).
> 4. Register `SessionController` ONLY when `options.sessions?.enabled === true` AND `options.controllers?.sessions !== false`.
> 5. Register `PasswordResetController` ONLY when `options.controllers?.passwordReset !== false`.
>
> Update barrel exports in `src/server/index.ts`:
>
> - `export { ForgotPasswordDto, ResetPasswordDto, VerifyOtpDto, ResendOtpDto, VerifyEmailDto, ResendVerificationDto }`
> - `export type { SessionInfo } from './services/session.service'`
>
> Acceptance criteria:
>
> - SessionService only registered when sessions enabled
> - PasswordResetService always registered
> - Controllers conditionally registered based on config
> - Barrel exports updated
> - No circular dependencies

---

### NEST-090: AuthService integration with SessionService

- **Phase:** 4
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-083, NEST-089
- **Agent:** planner
- **Estimate:** ~30min
- **Description:** Integrate SessionService into AuthService's login, logout, and refresh flows, and into MfaService's challenge flow.

**Prompt for the agent:**

> Modify `src/server/services/auth.service.ts` and potentially `src/server/services/token-manager.service.ts`:
>
> 1. Add `@Optional() SessionService` injection to `AuthService` (if not already present).
> 2. In `login()`: After successfully issuing tokens, if `this.sessionService` is available (sessions enabled), call `this.sessionService.createSession(userId, rawRefreshToken, ip, userAgent)`. Include `sessionHash` (sha256 of refresh token) in the returned `AuthResult`.
> 3. In `logout()`: Call `this.sessionService?.revokeSession(userId, sessionHash)` where `sessionHash` is derived from `sha256(rawRefreshToken)` extracted from the cookie or request. This removes the session from the `sess:{userId}` SET.
> 4. In `refresh()`: Call `this.sessionService?.rotateSession(userId, oldRefreshToken, newRefreshToken)` to keep `sess:` and `sd:` synchronized during token rotation. This should use the atomic Lua script from NEST-073.
> 5. In `MfaService.challenge()` (`src/server/services/mfa.service.ts`): After issuing tokens with `mfaVerified: true` and `context === 'dashboard'`, call `sessionService.createSession()` if sessions are enabled.
>
> Add comments at integration points: `// Phase 4: SessionService integration`.
>
> Acceptance criteria:
>
> - Login creates a session when sessions enabled
> - Logout revokes the session
> - Refresh rotates the session atomically
> - MFA challenge creates session for dashboard context
> - sessionHash included in AuthResult when sessions enabled
> - All integration points have documenting comments
> - Existing tests still pass (may need mock updates)

---

### NEST-091: SessionService unit tests

- **Phase:** 4
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-083
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** Write comprehensive unit tests for SessionService covering creation, listing, revocation, FIFO eviction, and rotation.

**Prompt for the agent:**

> Create test file `src/server/services/__tests__/session.service.spec.ts`.
>
> Write unit tests covering:
>
> 1. **createSession:** Creates session hash, stores details in Redis, adds to SET, sets TTL, calls hooks
> 2. **listSessions:** Returns all sessions with details, marks current session, sorts by createdAt descending, cleans up stale entries
> 3. **revokeSession (own session):** Deletes refresh token, removes from SET, deletes details
> 4. **revokeSession (another user's session):** Throws SESSION_NOT_FOUND (BOLA/IDOR prevention)
> 5. **revokeAllExceptCurrent:** Keeps only current session, revokes all others
> 6. **enforceSessionLimit:** When limit is 3 and 4 sessions exist, oldest is evicted (FIFO)
> 7. **enforceSessionLimit with custom resolver:** Uses maxSessionsResolver when provided
> 8. **rotateSession:** Old hash removed, new hash added, details copied with updated lastActivityAt, old details deleted
> 9. **parseUserAgent:** Returns meaningful device string
>
> Mock `AuthRedisService`, `emailProvider`, `hooks`, and user repository. Use Jest.
>
> Acceptance criteria:
>
> - All 9 test groups pass
> - BOLA prevention verified
> - FIFO eviction logic verified
> - Rotation atomicity tested (mock Lua script execution)
> - > = 80% coverage of session.service.ts

---

### NEST-092: PasswordResetService unit tests

- **Phase:** 4
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-087
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** Write unit tests for PasswordResetService covering token and OTP flows, cross-tenant protection, timing normalization, and cooldown.

**Prompt for the agent:**

> Create test file `src/server/services/__tests__/password-reset.service.spec.ts`.
>
> Write unit tests covering:
>
> 1. **initiateReset (token method):** Generates token, stores in Redis with TTL, sends email
> 2. **initiateReset (OTP method):** Generates OTP via OtpService, stores, sends email
> 3. **initiateReset (non-existent user):** Returns success without sending email (anti-enumeration)
> 4. **initiateReset timing normalization:** Response time is consistent regardless of user existence
> 5. **resetPassword (token):** Validates token from Redis, hashes password, updates DB, invalidates sessions, clears cache
> 6. **resetPassword (OTP):** Validates via OtpService, resets password
> 7. **resetPassword (verifiedToken):** Validates from Redis, checks tenantId match
> 8. **resetPassword (cross-tenant):** Mismatched tenantId is rejected
> 9. **verifyOtp:** Consumes OTP, generates verifiedToken, stores in Redis with 5-min TTL
> 10. **resendOtp:** Generates and sends new OTP
> 11. **resendOtp (cooldown active):** Returns success without generating new OTP when within 60s cooldown
> 12. **resendOtp (non-existent user):** Returns success without leak
>
> Mock all dependencies. Use Jest.
>
> Acceptance criteria:
>
> - All 12 test groups pass
> - Cross-tenant rejection verified
> - Anti-enumeration (no user existence leak) verified
> - Cooldown atomicity tested
> - > = 80% coverage

---

### NEST-093: SessionController unit tests

- **Phase:** 4
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-084
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** Write unit tests for SessionController verifying correct endpoint behavior and delegation to SessionService.

**Prompt for the agent:**

> Create test file `src/server/controllers/__tests__/session.controller.spec.ts`.
>
> Write unit tests covering:
>
> 1. `GET /` — calls `sessionService.listSessions()` with userId and currentSessionHash
> 2. `DELETE /:id` — calls `sessionService.revokeSession()` with userId and sessionHash from params
> 3. `DELETE /all` — calls `sessionService.revokeAllExceptCurrent()` with userId and currentSessionHash
> 4. Verify JwtAuthGuard is applied to all endpoints
> 5. Verify currentSessionHash extraction from JWT or cookie
>
> Mock `SessionService`. Use NestJS testing utilities.
>
> Acceptance criteria:
>
> - All 3 endpoints tested
> - Guard application verified
> - Correct delegation to service methods

---

### NEST-094: PasswordResetController unit tests

- **Phase:** 4
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-088
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** Write unit tests for PasswordResetController verifying all four endpoints delegate correctly.

**Prompt for the agent:**

> Create test file `src/server/controllers/__tests__/password-reset.controller.spec.ts`.
>
> Write unit tests covering:
>
> 1. `POST /forgot-password` — calls `initiateReset()` with email and tenantId from DTO
> 2. `POST /reset-password` — calls `resetPassword()` with full DTO
> 3. `POST /verify-otp` — calls `verifyOtp()` with email, otp, tenantId
> 4. `POST /resend-otp` — calls `resendOtp()` with email, tenantId
> 5. All endpoints are public (no auth guard)
> 6. Throttle decorators are applied
>
> Mock `PasswordResetService`. Use NestJS testing utilities.
>
> Acceptance criteria:
>
> - All 4 endpoints tested
> - Correct delegation verified
> - Public access verified

---

### NEST-095: AuthService integration tests update

- **Phase:** 4
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-090
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** Update existing AuthService tests to cover the new SessionService integration points in login, logout, and refresh flows.

**Prompt for the agent:**

> Update the existing AuthService test file (likely `src/server/services/__tests__/auth.service.spec.ts` or similar) to add test cases for Phase 4 SessionService integration:
>
> 1. **login() with sessions enabled:** Verify `sessionService.createSession()` is called after token issuance. Verify `sessionHash` is included in the returned `AuthResult`.
> 2. **login() with sessions disabled:** Verify `sessionService` is not called. Verify `AuthResult` does not include `sessionHash`.
> 3. **logout() with sessions enabled:** Verify `sessionService.revokeSession()` is called with correct userId and sessionHash derived from `sha256(rawRefreshToken)`.
> 4. **refresh() with sessions enabled:** Verify `sessionService.rotateSession()` is called with userId, old refresh token, and new refresh token.
> 5. **MFA challenge with sessions enabled:** Verify `sessionService.createSession()` is called after MFA challenge success with dashboard context.
>
> Add `SessionService` as a mock to the test module setup. Ensure existing tests still pass with the new optional dependency.
>
> Acceptance criteria:
>
> - 5 new test cases added and passing
> - Existing tests unbroken
> - Mock SessionService properly configured as optional

---

### NEST-096: Phase 4 validation — integration smoke test

- **Phase:** 4
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-091, NEST-092, NEST-093, NEST-094, NEST-095
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** Write integration-level tests validating the full Phase 4 checklist including password reset flows, session management, and edge cases.

**Prompt for the agent:**

> Create test file `src/__tests__/phase4-integration.spec.ts`.
>
> Write integration-level tests that validate the Phase 4 checklist (section 5.9):
>
> 1. Password reset by token: email -> token -> resetPassword (full flow)
> 2. Password reset by OTP: email -> OTP -> verifyOtp -> verifiedToken -> resetPassword (full flow)
> 3. OTP resend works and sends new OTP
> 4. Cross-tenant reset rejected (verifiedToken with wrong tenantId)
> 5. Sessions: create, list (with isCurrent), revoke single, revoke all except current
> 6. FIFO eviction respects configured session limit
> 7. Email verification functional (if verify-email is part of Phase 4)
> 8. Timing normalization on anti-enumeration endpoints (forgot-password, resend-otp — verify consistent timing)
> 9. DTOs validate correctly: VerifyOtpDto, ResendOtpDto, VerifyEmailDto, ResendVerificationDto
> 10. `logout()` derives sessionHash via `sha256(rawRefreshToken)` for revokeSession
> 11. Cooldown of OTP resend (60s) works via Redis NX key
> 12. Coverage >= 80% for all Phase 4 files
>
> Use mocked repositories but real service chain where possible.
>
> Acceptance criteria:
>
> - All 11 scenarios have passing tests
> - Validates the complete checklist from section 5.9
> - Overall Phase 4 coverage >= 80%

---

## Phase 5 — Platform, OAuth and Invitations

### NEST-097: native JwtPlatformGuard

- **Phase:** 5
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-042, NEST-034, NEST-027
- **Agent:** code-reviewer
- **Estimate:** ~30min
- **Description:** Implement a native JwtPlatformGuard with `CanActivate`, without Passport, using `@nestjs/jwt` JwtService. Same pattern as Phase 2's JwtAuthGuard but isolating by claim type: 'platform'.

**Prompt for the agent:**

> Create the file `src/server/guards/jwt-platform.guard.ts`. Implement `JwtPlatformGuard` that `implements CanActivate`. Inject `JwtService` (from `@nestjs/jwt`), `TokenDeliveryService`, `AuthRedisService` and `BYMAX_AUTH_OPTIONS`. In the `canActivate(context: ExecutionContext)` method:
>
> - Extract the token from the Authorization header (Bearer) via `tokenDeliveryService.extractAccessToken(req)` and, if configured for cookie/both mode, also from the access token cookie.
> - Verify the JWT with `jwtService.verify(token, { algorithms: ['HS256'] })`. MANDATORILY pin `algorithms: ['HS256']` — identical to Phase 2's `JwtAuthGuard`.
> - Verify that `payload.type === 'platform'`. If not, throw `UnauthorizedException` with code `PLATFORM_AUTH_REQUIRED`.
> - Verify that `payload.jti` exists. If not, throw `UnauthorizedException` with code `TOKEN_INVALID`.
> - Verify blacklist via `authRedis.isBlacklisted(jti)`. If blacklisted, throw `UnauthorizedException` with `TOKEN_REVOKED`.
> - Populate `request.user` with the validated payload. Return true.
>   Follow the same structural pattern as Phase 2's `src/server/guards/jwt-auth.guard.ts`.
>   Acceptance criteria: compiles without errors, pins HS256, validates type === 'platform', verifies jti and blacklist, tokens with type 'dashboard' are rejected.

---

### NEST-098: JwtPlatformGuard unit tests

- **Phase:** 5
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** NEST-097
- **Agent:** security-reviewer
- **Estimate:** ~25min
- **Description:** Unit tests for the native JwtPlatformGuard, verifying validation of platform tokens, rejection of dashboard tokens, and HS256 algorithm pinning.

**Prompt for the agent:**

> Write unit tests for `src/server/guards/jwt-platform.guard.ts`:
>
> 1. Token with `type: 'platform'` and valid signature → accepted, `request.user` populated.
> 2. Token with `type: 'dashboard'` → rejected with `PLATFORM_AUTH_REQUIRED`.
> 3. Token with `type: 'mfa_challenge'` → rejected with `TOKEN_INVALID`.
> 4. Token without `jti` → rejected with `TOKEN_INVALID`.
> 5. Token with `jti` in the Redis blacklist → rejected with `TOKEN_REVOKED`.
> 6. Expired token → rejected with `TOKEN_INVALID`.
> 7. Verify that `algorithms: ['HS256']` is pinned (without `alg: none`).
> 8. Endpoint with `@Public()` → skip validation, return true.
> 9. Mock `JwtService`, `AuthRedisService`, `TokenDeliveryService`.
>
> Acceptance criteria:
>
> - All 9 scenarios tested and passing
> - Coverage >= 90% on the guard file
> - No use of Passport in the tests

---

### NEST-099: Platform Roles Guard

- **Phase:** 5
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-098
- **Agent:** code-reviewer
- **Estimate:** ~30min
- **Description:** Create a roles guard that uses platformHierarchy to verify platform admin permissions.

**Prompt for the agent:**

> Create the file `src/server/guards/platform-roles.guard.ts`. Implement `PlatformRolesGuard`:
>
> - Uses `Reflector` to read the required roles set by `@PlatformRoles()`.
> - Extracts the role from `request.user` (from the JWT payload).
> - Verifies whether the user's role is >= the required role using `platformHierarchy` from the module options (analogous to Phase 2's `RolesGuard` which uses `roles.hierarchy`).
> - If the hierarchy is not configured (`platform.roles.hierarchy`), throws `ForbiddenException` with `INSUFFICIENT_ROLE`.
> - Use the same utility logic `hasRole()` from `src/server/utils/roles.util.ts`.
>   Acceptance criteria: an admin with a sufficient role passes, an insufficient role receives 403 INSUFFICIENT_ROLE.

---

### NEST-100: PlatformRoles Decorator

- **Phase:** 5
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** None
- **Agent:** typescript-reviewer
- **Estimate:** ~20min
- **Description:** Create the @PlatformRoles() decorator for platform endpoints.

**Prompt for the agent:**

> Create the file `src/server/decorators/platform-roles.decorator.ts`. Implement the `@PlatformRoles(...roles: string[])` decorator:
>
> - Uses `SetMetadata` from `@nestjs/common` with key `'platformRoles'` (or an exported constant `PLATFORM_ROLES_KEY`).
> - Accepts a spread of strings representing the required roles.
> - Export `PlatformRoles` and `PLATFORM_ROLES_KEY`.
>   Follow the pattern of Phase 2's `src/server/decorators/roles.decorator.ts`.
>   Acceptance criteria: the decorator compiles, sets metadata correctly, the PLATFORM_ROLES_KEY constant is exported.

---

### NEST-101: PlatformLoginDto

- **Phase:** 5
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** None
- **Agent:** typescript-reviewer
- **Estimate:** ~20min
- **Description:** Create the platform login DTO with email and password validations.

**Prompt for the agent:**

> Create the file `src/server/dto/platform-login.dto.ts`. Implement `PlatformLoginDto` with:
>
> - `@IsEmail() email: string`
> - `@IsString() @IsNotEmpty() @MaxLength(128) password: string`
>   Use decorators from `class-validator`. The `@MaxLength(128)` is a practical input limit to prevent DoS.
>   Export the class.
>   Acceptance criteria: validation works for invalid email, empty password, password > 128 chars.

---

### NEST-102: PlatformAuthService - login()

- **Phase:** 5
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-097, NEST-101, NEST-010, NEST-050
- **Agent:** code-reviewer
- **Estimate:** ~30min
- **Description:** Implement the login() method of PlatformAuthService with brute-force, MFA redirect and token issuance.

**Prompt for the agent:**

> Create the file `src/server/services/platform-auth.service.ts`. Implement `PlatformAuthService` (injectable) with the method `login(dto: PlatformLoginDto, ip: string, userAgent: string)`:
>
> 1. Brute-force check: use `BruteForceService` with identifier `sha256('platform:' + email)` — the 'platform:' prefix avoids collision with dashboard identifiers `sha256(tenantId + ':' + email)`.
> 2. Fetch the admin via `platformUserRepo.findByEmail(email)`. If not found, increment brute-force and throw `INVALID_CREDENTIALS` (without revealing that the email does not exist).
> 3. Compare the password via `CryptoService.comparePassword(dto.password, admin.passwordHash)`.
> 4. If the password is invalid, increment brute-force and throw `INVALID_CREDENTIALS`.
> 5. Reset the brute-force counter on success.
> 6. If the admin has MFA enabled: return `{ mfaRequired: true, mfaTempToken }` using `tokenManager.issueMfaTempToken(admin.id, 'platform')`.
> 7. If no MFA: issue tokens with `tokenManager.issuePlatformTokens({ sub: admin.id, type: 'platform', role: admin.role })`.
> 8. Refresh token with prefix `prt:` in Redis.
> 9. Maintain the SET `psess:{userId}` with the session hash. Maintain details in `psd:{sessionHash}`.
> 10. Return `AuthResult` with tokens.
>     Inject: `IPlatformUserRepository`, `TokenManagerService`, `BruteForceService`, `CryptoService`, `TokenDeliveryService`, module options.
>     Acceptance criteria: login with correct credentials returns tokens, login with MFA returns mfaRequired, the brute-force identifier uses the 'platform:' prefix.

---

### NEST-103: PlatformAuthService - logout()

- **Phase:** 5
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-102
- **Agent:** code-reviewer
- **Estimate:** ~30min
- **Description:** Implement platform admin logout with blacklist and Redis cleanup.

**Prompt for the agent:**

> In the file `src/server/services/platform-auth.service.ts`, add the method `logout(userId: string, jti: string, refreshToken: string, sessionHash: string)`:
>
> 1. Blacklist the access JWT: SET `rv:{jti}` with TTL = accessExpiresIn.
> 2. Delete the refresh token: DEL `prt:{sha256(refreshToken)}`.
> 3. Remove the session from the SET: SREM `psess:{userId}` the `sessionHash`.
> 4. Delete the session details: DEL `psd:{sessionHash}`.
>    Acceptance criteria: after logout, the access token is in the blacklist, the refresh token is deleted, the session is removed from the SET and the details are deleted.

---

### NEST-104: PlatformAuthService - refresh()

- **Phase:** 5
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-102
- **Agent:** code-reviewer
- **Estimate:** ~30min
- **Description:** Implement platform token refresh with rotation and session update.

**Prompt for the agent:**

> In the file `src/server/services/platform-auth.service.ts`, add the method `refresh(refreshToken: string, ip: string, userAgent: string)`:
>
> 1. Use `tokenManager.reissuePlatformTokens(refreshToken)` which performs rotation with prefix `prt:` and pointer `prp:`.
> 2. Update the SET `psess:{userId}` and details `psd:{sessionHash}` during rotation.
> 3. MANDATORILY: Renew the TTL of the SET `psess:{userId}` with `EXPIRE` on every rotation (prevents expiration of the SET while individual tokens are renewed).
> 4. Return the new tokens.
>    Acceptance criteria: refresh returns new tokens, the psess SET has its TTL renewed, the session is updated.

---

### NEST-105: PlatformAuthService - getMe()

- **Phase:** 5
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-102
- **Agent:** code-reviewer
- **Estimate:** ~30min
- **Description:** Implement getMe to return the authenticated admin's data.

**Prompt for the agent:**

> In the file `src/server/services/platform-auth.service.ts`, add the method `getMe(userId: string)`:
>
> 1. Fetch the admin via `platformUserRepo.findById(userId)`.
> 2. If not found, throw `NotFoundException`.
> 3. Return the admin's data (without passwordHash).
>    Acceptance criteria: returns the admin's data without sensitive fields.

---

### NEST-106: PlatformAuthService - revokeAllPlatformSessions()

- **Phase:** 5
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-102
- **Agent:** code-reviewer
- **Estimate:** ~30min
- **Description:** Implement revocation of all platform sessions of an admin using the psess SET.

**Prompt for the agent:**

> In the file `src/server/services/platform-auth.service.ts`, add the method `revokeAllPlatformSessions(userId: string)`:
>
> 1. Use `SMEMBERS psess:{userId}` to enumerate all active session hashes.
> 2. For each hash: DEL `prt:{hash}`, DEL `psd:{hash}`.
> 3. DEL the SET `psess:{userId}`.
>    IMPORTANT: Do NOT use `SCAN prt:*` (O(N) over all keys). The SET guarantees O(M) where M = the admin's sessions.
>    DEVIATION FROM SPEC: Spec section 6.9 references `auth:prp:{userId}` as the sessions SET. `prp:` is a rotation pointer. The correct SET is `psess:{userId}`.
>    Acceptance criteria: all of the admin's sessions are removed, the operation is O(M) not O(N), the psess SET is deleted.

---

### NEST-107: PlatformAuthController - 6 endpoints

- **Phase:** 5
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-098, NEST-099, NEST-100, NEST-102, NEST-103, NEST-104, NEST-105, NEST-106
- **Agent:** code-reviewer
- **Estimate:** ~30min
- **Description:** Create a controller with the 6 platform authentication endpoints.

**Prompt for the agent:**

> Create the file `src/server/controllers/platform-auth.controller.ts`. Implement `PlatformAuthController` with the 6 endpoints:
>
> 1. `POST /login` — public, `@Throttle(AUTH_THROTTLE_CONFIGS.platformLogin)`. Calls `platformAuthService.login()`. Uses `TokenDeliveryService` to deliver tokens.
> 2. `POST /mfa/challenge` — public (requires mfaToken in the body), `@Throttle(AUTH_THROTTLE_CONFIGS.mfaChallenge)`. Reuses `MfaService.challenge()` — the `context: 'platform'` in the temp token directs the flow to issue platform tokens. Uses `TokenDeliveryService`.
> 3. `GET /me` — protected with `@UseGuards(JwtPlatformGuard)`. Calls `platformAuthService.getMe()`.
> 4. `POST /logout` — protected with `@UseGuards(JwtPlatformGuard)`. Calls `platformAuthService.logout()`. Uses `TokenDeliveryService` to clear cookies if applicable.
> 5. `POST /refresh` — public, `@Throttle(AUTH_THROTTLE_CONFIGS.refresh)`. Calls `platformAuthService.refresh()`. Uses `TokenDeliveryService`.
> 6. `DELETE /sessions` — protected with `@UseGuards(JwtPlatformGuard)`. Calls `platformAuthService.revokeAllPlatformSessions()`.
>    KNOWN LIMITATION: There is no `PlatformUserStatusGuard`. If an admin is banned after login, the JWT remains valid until it expires. Mitigation: the host app must call `revokeAllPlatformSessions()`. Add a JSDoc comment documenting this.
>    All endpoints use `TokenDeliveryService` for token delivery and extraction (same pattern as `AuthController`).
>    Acceptance criteria: 6 endpoints implemented, throttle on login/mfa/refresh, guards applied, TokenDeliveryService used in all.

---

### NEST-108: Platform Auth Unit Tests

- **Phase:** 5
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-107
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** Write complete unit tests for PlatformAuthService and PlatformAuthController.

**Prompt for the agent:**

> Create the file `src/server/services/__tests__/platform-auth.service.spec.ts` and `src/server/controllers/__tests__/platform-auth.controller.spec.ts`. Required tests:
> For PlatformAuthService:
>
> 1. `login()` with valid credentials without MFA returns tokens with type 'platform'.
> 2. `login()` with MFA enabled returns `{ mfaRequired: true, mfaTempToken }`.
> 3. `login()` with invalid credentials increments brute-force and throws INVALID_CREDENTIALS.
> 4. `login()` with an account in lockout throws ACCOUNT_LOCKED.
> 5. `logout()` blacklists the jti, deletes the refresh token and removes the session.
> 6. `refresh()` returns new tokens and renews the TTL of the psess SET.
> 7. `getMe()` returns the admin's data.
> 8. `revokeAllPlatformSessions()` enumerates via SMEMBERS and deletes each session.
> 9. `revokeAllPlatformSessions()` deletes the psess SET.
>    For JwtPlatformGuard:
> 10. A token with type 'dashboard' is rejected with PLATFORM_AUTH_REQUIRED.
> 11. A token with type 'platform' is accepted.
> 12. A token without jti is rejected with TOKEN_INVALID.
>     Mock: IPlatformUserRepository, TokenManagerService, BruteForceService, CryptoService, Redis, TokenDeliveryService.
>     Acceptance criteria: all tests pass, coverage >= 80% for platform-auth.service.ts.

---

### NEST-109: OAuthModule - Module Setup

- **Phase:** 5
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-035
- **Agent:** architect
- **Estimate:** ~45min
- **Description:** Create a dynamic OAuth module that registers providers based on the configuration.

**Prompt for the agent:**

> Create the file `src/server/oauth/oauth.module.ts`. Implement `OAuthModule` as a dynamic module:
>
> - A static method `register(options)` or `forRoot(options)` that receives the OAuth configuration.
> - Registers OAuth providers based on the configured providers (e.g.: if google is configured, registers GoogleOAuthPlugin, GoogleStrategy, GoogleAuthGuard).
> - Imported conditionally by `BymaxAuthModule` — only registered if `oauth` is present in the configuration.
> - Registers `OAuthService` as a provider.
> - Registers routes dynamically for each configured provider: `GET /{routePrefix}/{provider}?tenantId=xxx` and `GET /{routePrefix}/{provider}/callback`.
>   Acceptance criteria: the module compiles, registers providers conditionally, dynamic routes registered.

---

### NEST-110: OAuthService - initiateOAuth()

- **Phase:** 5
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-109
- **Agent:** code-reviewer
- **Estimate:** ~30min
- **Description:** Implement the start of the OAuth flow with CSRF state generation and redirect.

**Prompt for the agent:**

> Create the file `src/server/oauth/oauth.service.ts`. Implement `OAuthService` with the method `initiateOAuth(provider: string, tenantId: string)`:
>
> 1. Generate a random state with `crypto.randomBytes(32).toString('hex')` (64 hex characters).
> 2. Store in Redis: `os:{sha256(state)}` with value `{ tenantId }` and TTL 10 min (600s).
> 3. NOTE: The package does NOT validate that tenantId exists (database-agnostic). The `onOAuthLogin` hook is the validation point. Document with JSDoc that without `onOAuthLogin`, tenant spoofing is possible.
> 4. Build the redirect URL to the provider with query params: `client_id`, `redirect_uri`, `scope`, `state`.
> 5. Return an HTTP 302 redirect to the provider's URL.
>    Inject: Redis, module options (with per-provider OAuth config).
>    Acceptance criteria: state generated and stored with 10min TTL, URL built correctly, 302 redirect returned.

---

### NEST-111: OAuthService - handleCallback()

- **Phase:** 5
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-110
- **Agent:** code-reviewer
- **Estimate:** ~30min
- **Description:** Implement OAuth callback processing with state validation, user creation/linking and token issuance.

**Prompt for the agent:**

> In the file `src/server/oauth/oauth.service.ts`, add the method `handleCallback(provider: string, code: string, state: string, ip: string, userAgent: string)`. The method uses the provider's plugin to exchange the code and fetch the profile:
>
> 1. Validate the state in Redis: GET `os:{sha256(state)}`. If not found, throw `OAUTH_FAILED`.
> 2. Extract `tenantId` from the stored state.
> 3. Consume the state: DEL `os:{sha256(state)}` (single-use).
> 4. Fetch existing user: `userRepo.findByOAuthId(provider, providerId, tenantId)`.
> 5. Execute `hooks.onOAuthLogin(profile, existingUser, { tenantId, ip, userAgent })`.
> 6. According to the hook result:
>    - `action: 'create'`: create user via `userRepo.createWithOAuth(createData)`.
>    - `action: 'link'`: link via `userRepo.linkOAuth(userId, provider, providerId)`.
>    - `action: 'reject'`: throw an exception with `rejectReason`.
> 7. Issue tokens via `tokenManager.issueTokens()`.
> 8. Create session if enabled (via SessionService).
> 9. Return `AuthResult`.
>    Acceptance criteria: state validated and consumed, hook executed, the 3 actions (create/link/reject) work, tokens issued.

---

### NEST-112: Google OAuth Plugin

- **Phase:** 5
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-109
- **Agent:** code-reviewer
- **Estimate:** ~30min
- **Description:** Implement Google OAuth plugin with strategy and guard.

**Prompt for the agent:**

> Create the file `src/server/oauth/google/google-oauth.plugin.ts`. Implement `GoogleOAuthPlugin` that implements the `OAuthProviderPlugin` interface. It must expose `name: 'google'`. Configuration via `clientId`, `clientSecret`, `callbackUrl`, `scope` (default: `['email', 'profile']`). Implement native methods without Passport:
>
> - `authorizeUrl(state: string): string` — builds Google OAuth2 authorization URL with query params (client_id, redirect_uri, scope, state, response_type=code).
> - `exchangeCode(code: string): Promise<{ access_token: string }>` — exchanges authorization code for an access token via `fetch` POST to `https://oauth2.googleapis.com/token`.
> - `fetchProfile(accessToken: string): Promise<OAuthProfile>` — fetches profile via `fetch` GET to `https://www.googleapis.com/oauth2/v2/userinfo`, extracts `email`, `name`, `picture`, `providerId`.
>   Do NOT create `google.strategy.ts` nor `google-auth.guard.ts` (no Passport).
>   Acceptance criteria: plugin implements the interface, native methods with fetch, no dependency on passport-google-oauth20.

---

### NEST-113: OAuth Unit Tests

- **Phase:** 5
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-111, NEST-112
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** Write tests for OAuthService covering the full flow, CSRF state and tenantId resolution.

**Prompt for the agent:**

> Create the file `src/server/oauth/__tests__/oauth.service.spec.ts`. Required tests:
>
> 1. `initiateOAuth()` generates a 64-char hex state and stores it in Redis with TTL 600s.
> 2. `handleCallback()` with action 'create': creates a user and issues tokens.
> 3. `handleCallback()` with action 'link': links OAuth to an existing user and issues tokens.
> 4. `handleCallback()` with action 'reject': throws an exception with rejectReason.
> 5. `handleCallback()` with an invalid state (not found in Redis): throws OAUTH_FAILED.
> 6. State is consumed (single-use): a second call with the same state fails.
> 7. `tenantId` is correctly extracted from the stored state.
> 8. Google plugin extracts profile with the correct fields.
>    Mock: Redis, IUserRepository, TokenManagerService, hooks, SessionService.
>    Acceptance criteria: all tests pass, coverage >= 80% for oauth.service.ts.

---

### NEST-114: CreateInvitationDto

- **Phase:** 5
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** None
- **Agent:** typescript-reviewer
- **Estimate:** ~20min
- **Description:** Create DTO for invitation creation with email, role and optional tenantName.

**Prompt for the agent:**

> Create the file `src/server/dto/create-invitation.dto.ts`. Implement `CreateInvitationDto`:
>
> - `@IsEmail() email: string`
> - `@IsString() @IsNotEmpty() role: string`
> - `@IsOptional() @IsString() tenantName?: string`
>   NOTE: `tenantId` is NOT in the DTO — it is extracted from the inviter's JWT in the controller. Validation of `role` against `roles.hierarchy` is done in the service, not in the DTO (class-validator has no access to the DI context). `tenantName` is an optional field added for `IEmailProvider.sendInvitation()` — if not provided, it uses `tenantId` as a fallback.
>   Acceptance criteria: validation works, tenantId absent from the DTO, tenantName optional.

---

### NEST-115: AcceptInvitationDto

- **Phase:** 5
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** None
- **Agent:** typescript-reviewer
- **Estimate:** ~20min
- **Description:** Create DTO for invitation acceptance with token, name and password.

**Prompt for the agent:**

> Create the file `src/server/dto/accept-invitation.dto.ts`. Implement `AcceptInvitationDto`:
>
> - `@IsString() @IsNotEmpty() token: string`
> - `@IsString() @MinLength(2) name: string`
> - `@IsString() @MinLength(8) @MaxLength(128) password: string`
>   The `@MaxLength(128)` is a practical input limit to prevent DoS.
>   Acceptance criteria: validation works for empty token, name < 2, password < 8, password > 128.

---

### NEST-116: InvitationService - invite()

- **Phase:** 5
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-114, NEST-010
- **Agent:** code-reviewer
- **Estimate:** ~30min
- **Description:** Implement invitation creation with role validation against the hierarchy and secure storage in Redis.

**Prompt for the agent:**

> Create the file `src/server/services/invitation.service.ts`. Implement `InvitationService` with the method `invite(inviterId: string, email: string, role: string, tenantId: string, tenantName?: string)`:
>
> 1. Validate that the `role` exists in the configured `roles.hierarchy`. If it does not exist, throw `INSUFFICIENT_ROLE`.
> 2. Authorization validation: fetch the inviter via `userRepo.findById(inviterId)`, verify that the inviter's role >= requested role using `hasRole()` from `src/server/utils/roles.util.ts`. If not authorized, throw `INSUFFICIENT_ROLE`.
> 3. Generate a secure token via `generateSecureToken(32)`.
> 4. Store: `inv:{sha256(token)}` with value `{ email, role, tenantId, inviterId }` and TTL = `tokenTtlSeconds` (from the invitations config).
> 5. Fetch the inviter's name via `userRepo.findById(inviterId)` to include in the email.
> 6. If `tenantName` is not provided, use `tenantId` as a fallback.
> 7. Send the email via `emailProvider.sendInvitation({ email, token, inviterName, tenantName, role })`.
> 8. The raw token is NEVER logged (only NoOpEmailProvider logs it truncated).
>    Inject: IUserRepository, IEmailProvider, Redis, module options.
>    Acceptance criteria: role validated against the hierarchy, inviter authorization verified, token stored with TTL, email sent.

---

### NEST-117: InvitationService - acceptInvitation()

- **Phase:** 5
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-116, NEST-115
- **Agent:** code-reviewer
- **Estimate:** ~30min
- **Description:** Implement invitation acceptance with user creation and token issuance.

**Prompt for the agent:**

> In the file `src/server/services/invitation.service.ts`, add the method `acceptInvitation(dto: AcceptInvitationDto, ip: string, userAgent: string)`:
>
> 1. Fetch the invitation: GET `inv:{sha256(dto.token)}`. If not found, throw `INVALID_INVITATION_TOKEN`.
> 2. Check whether the email already exists in the tenant via `userRepo.findByEmail(invitation.email, invitation.tenantId)`. If it exists, throw an error.
> 3. Hash the password via `CryptoService.hashPassword(dto.password)`.
> 4. Create the user with: email from the invitation, name from the DTO, passwordHash, role from the invitation, tenantId from the invitation, `emailVerified: true` (the invitation implies email verification).
> 5. Consume the invitation: DEL `inv:{sha256(dto.token)}`.
> 6. Issue tokens via `tokenManager.issueTokens()`.
> 7. Run `hooks.afterInvitationAccepted({ user, invitation })` if the hook is configured.
> 8. Return `AuthResult`.
>    Acceptance criteria: invitation consumed, user created with emailVerified true, tokens issued, hook executed.

---

### NEST-118: InvitationController

- **Phase:** 5
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-116, NEST-117
- **Agent:** code-reviewer
- **Estimate:** ~30min
- **Description:** Create controller with endpoints to create and accept invitations.

**Prompt for the agent:**

> Create the file `src/server/controllers/invitation.controller.ts`. Implement `InvitationController`:
>
> 1. `POST /` — protected with `@UseGuards(JwtAuthGuard, RolesGuard)`. Extracts `tenantId` from the JWT (req.user.tenantId), NOT from the body. `tenantName` comes from the body (`dto.tenantName`) or uses `tenantId` as a fallback. Calls `invitationService.invite(req.user.sub, dto.email, dto.role, tenantId, dto.tenantName)`.
> 2. `POST /accept` — public, with `@Throttle(AUTH_THROTTLE_CONFIGS.invitationAccept)`. Calls `invitationService.acceptInvitation(dto, ip, userAgent)`. Uses `TokenDeliveryService` to deliver tokens.
>    DEVIATION FROM SPEC: the spec's DTO does not include `tenantName`, but `IEmailProvider.sendInvitation()` requires it. Optional field added.
>    Acceptance criteria: POST / extracts tenantId from the JWT, POST /accept is public with throttle, TokenDeliveryService used.

---

### NEST-119: Invitation Unit Tests

- **Phase:** 5
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-118
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** Write unit tests for InvitationService covering creation, acceptance, and validations.

**Prompt for the agent:**

> Create the files `src/server/services/__tests__/invitation.service.spec.ts` and `src/server/controllers/__tests__/invitation.controller.spec.ts`. Required tests:
>
> 1. `invite()` with a valid role and an authorized inviter: token generated and email sent.
> 2. `invite()` with a role nonexistent in the hierarchy: throws INSUFFICIENT_ROLE.
> 3. `invite()` with an unauthorized inviter (lower role): throws INSUFFICIENT_ROLE.
> 4. `acceptInvitation()` with a valid token: creates a user with emailVerified true and returns tokens.
> 5. `acceptInvitation()` with an invalid/expired token: throws INVALID_INVITATION_TOKEN.
> 6. `acceptInvitation()` with an email already existing in the tenant: throws an error.
> 7. Invitation consumed after acceptance (second acceptance fails).
> 8. Controller POST / extracts tenantId from the JWT, not from the body.
> 9. `afterInvitationAccepted` hook is executed.
>    Mock: IUserRepository, IEmailProvider, Redis, TokenManagerService, CryptoService, hooks.
>    Acceptance criteria: all tests pass, coverage >= 80%.

---

### NEST-120: Phase 5 Dynamic Module Integration

- **Phase:** 5
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-107, NEST-109, NEST-118
- **Agent:** architect
- **Estimate:** ~45min
- **Description:** Integrate PlatformAuth, OAuth and Invitations into the main dynamic module with conditional registration.

**Prompt for the agent:**

> Update the file `src/server/bymax-auth.module.ts` (the main dynamic module) to:
>
> 1. Register `PlatformAuthService`, `PlatformAuthController`, `JwtPlatformStrategy`, `JwtPlatformGuard`, `PlatformRolesGuard` if `platform.enabled` is true in the configuration.
> 2. Import `OAuthModule` if `oauth` is present and configured.
> 3. Register `InvitationService` and `InvitationController` if `invitations.enabled` is true.
> 4. Ensure controllers are added to the `controllers` array dynamically (not hardcoded).
> 5. Ensure there are no DI cycles: `InvitationService` uses `hasRole()` from `utils/roles.util.ts`, does NOT inject `RolesGuard`.
>    Acceptance criteria: each feature is only registered if enabled in the config, the module compiles with any combination of features.

---

### NEST-121: Phase 5 Barrel Export Update

- **Phase:** 5
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-120
- **Agent:** architect
- **Estimate:** ~15min
- **Description:** Update the barrel export with all Phase 5 exports.

**Prompt for the agent:**

> Update the file `src/server/index.ts` to add the following exports:
>
> - `export { JwtPlatformGuard } from './guards/jwt-platform.guard'`
> - `export { PlatformRolesGuard } from './guards/platform-roles.guard'`
> - `export { PlatformRoles } from './decorators/platform-roles.decorator'`
> - `export type { PlatformAuthResult }` — confirm it was already defined and exported in Phase 1, if not, add it.
> - `export { PlatformLoginDto } from './dto/platform-login.dto'`
> - `export { AcceptInvitationDto } from './dto/accept-invitation.dto'`
> - `export { CreateInvitationDto } from './dto/create-invitation.dto'`
>   IMPORTANT: DTOs use `export` (never `export type`) to preserve `class-validator` metadata at runtime.
>   Acceptance criteria: all new exports present in index.ts, DTOs with regular export (not type export).

---

## Phase 6 — Integration, Polishing and Publishing

### NEST-122: WsJwtGuard

- **Phase:** 6
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-026
- **Agent:** code-reviewer
- **Estimate:** ~30min
- **Description:** Create a WebSocket guard that extracts the JWT from the handshake and validates the dashboard type.

**Prompt for the agent:**

> Create the file `src/server/guards/ws-jwt.guard.ts`. Implement `WsJwtGuard`:
>
> 1. In `canActivate(context)`: check whether `@nestjs/websockets` is available via try/catch on `require.resolve('@nestjs/websockets')`. If not available, throw a descriptive error: "WsJwtGuard requires @nestjs/websockets to be installed". This check must be at runtime (canActivate), not just compile-time.
> 2. Extract the token from `client.handshake.headers.authorization` (format `Bearer <token>`). Do NOT extract from query params (security).
> 3. Validate the JWT using the same secret/options as the module.
> 4. Verify `payload.type === 'dashboard'`. Reject `platform` and `mfa_challenge` tokens.
> 5. Check the blacklist: `rv:{jti}`.
> 6. Populate `client.data.user` with the payload.
> 7. Return true if valid.
>    Acceptance criteria: token extracted from the header (not query), 'platform' type rejected, 'dashboard' type accepted, peer dep check at runtime.

---

### NEST-123: SelfOrAdminGuard

- **Phase:** 6
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-026
- **Agent:** code-reviewer
- **Estimate:** ~30min
- **Description:** Create a guard that allows access if the userId in the param === JWT.sub or if the role is admin. Protection against IDOR.

**Prompt for the agent:**

> Create the file `src/server/guards/self-or-admin.guard.ts`. Implement `SelfOrAdminGuard`:
>
> 1. Compare `req.params.userId` (or `req.params.id`) with `req.user.sub`.
> 2. If they match: allow access.
> 3. If they do not match: check whether the user's role is admin in the hierarchy using `hasRole()` from `src/server/utils/roles.util.ts`.
> 4. For session hashes in `DELETE /sessions/:id`: validate the SHA-256 hex format (64 characters, regex `[a-f0-9]{64}`). If the format is invalid, reject.
> 5. If neither self nor admin: throw `ForbiddenException`.
>    IMPORTANT: This guard does NOT validate that the target resource belongs to the JWT's `tenantId`. In multi-tenant contexts, the controller/service must additionally verify ownership. Add a JSDoc comment documenting this limitation.
>    Acceptance criteria: self-access allowed, admin-access allowed, other-user rejected, session hash validated against the regex.

---

### NEST-124: OptionalAuthGuard

- **Phase:** 6
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-026
- **Agent:** code-reviewer
- **Estimate:** ~30min
- **Description:** Create a guard that tries to authenticate via JWT but does not fail if the token is absent.

**Prompt for the agent:**

> Create the file `src/server/guards/optional-auth.guard.ts`. Implement `OptionalAuthGuard`:
>
> 1. Extends `JwtAuthGuard` (from Phase 2).
> 2. Override `handleRequest(err, user, info)`:
>    - If the token is absent (info indicates 'No auth token'): return `null` (do NOT throw an exception).
>    - If the token is present but invalid: throw the exception normally.
>    - If the token is valid: return `user`.
> 3. `request.user` will be `null` if there is no token, or the payload if authenticated.
>    Acceptance criteria: no token -> user null (no exception), invalid token -> exception, valid token -> user populated.

---

### NEST-125: Additional Guards Unit Tests

- **Phase:** 6
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-122, NEST-123, NEST-124
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** Write unit tests for WsJwtGuard, SelfOrAdminGuard and OptionalAuthGuard.

**Prompt for the agent:**

> Create test files for the 3 guards:
>
> - `src/server/guards/__tests__/ws-jwt.guard.spec.ts`
> - `src/server/guards/__tests__/self-or-admin.guard.spec.ts`
> - `src/server/guards/__tests__/optional-auth.guard.spec.ts`
>   Required tests:
>   WsJwtGuard:
>
> 1. Token with type 'platform' is rejected.
> 2. Token with type 'dashboard' is accepted and client.data.user populated.
> 3. Token with type 'mfa_challenge' is rejected.
> 4. Token in the blacklist is rejected.
> 5. Without @nestjs/websockets installed: throws a descriptive error.
> 6. Token extracted from the header, not from the query param.
>    SelfOrAdminGuard:
> 7. req.params.userId === req.user.sub: access allowed.
> 8. req.params.userId !== req.user.sub but user is admin: access allowed.
> 9. req.params.userId !== req.user.sub and user is not admin: ForbiddenException.
> 10. Session hash with an invalid format (not SHA-256 hex): rejected.
>     OptionalAuthGuard:
> 11. No token: request.user is null, no exception.
> 12. Valid token: request.user is the JWT payload.
> 13. Invalid/expired token: throws an exception.
>     Mock: Redis, ExecutionContext, JWT verify.
>     Acceptance criteria: all 13 tests pass.

---

### NEST-126: E2E Test - Full Auth Flow

- **Phase:** 6
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-035, NEST-080
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** E2E test of the full flow: register, login, refresh, /me, logout in both cookie and bearer modes.

**Prompt for the agent:**

> Create the file `test/e2e/auth-flow.e2e-spec.ts`. Implement an E2E test using `@nestjs/testing` with `Test.createTestingModule` and `supertest`:
>
> 1. Configure the test module with `BymaxAuthModule.registerAsync()`, mock of `IUserRepository` and `IEmailProvider`, test Redis (or mock).
> 2. Bearer mode scenario:
>    - POST /auth/register -> 201, body contains accessToken and refreshToken.
>    - POST /auth/login -> 200, body contains tokens.
>    - POST /auth/refresh with refreshToken -> 200, new tokens.
>    - GET /auth/me with Authorization header -> 200, user data.
>    - POST /auth/logout -> 200.
>    - GET /auth/me with the old token -> 401 (blacklisted).
> 3. Cookie mode scenario:
>    - POST /auth/login -> 200, Set-Cookie cookies with HttpOnly.
>    - GET /auth/me (cookies sent automatically) -> 200.
>      Acceptance criteria: the full flow works in both modes, tokens are correctly issued and invalidated.

---

### NEST-127: E2E Test - MFA Flow

- **Phase:** 6
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-050, NEST-126
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** E2E test of the full MFA flow including setup, verify, challenge with TOTP and recovery code.

**Prompt for the agent:**

> Create the file `test/e2e/mfa-flow.e2e-spec.ts`. Implement:
>
> 1. Register -> Login -> POST /auth/mfa/setup (returns secret and QR) -> POST /auth/mfa/verify (with a valid TOTP, returns recovery codes) -> POST /auth/logout.
> 2. Login again -> response with mfaRequired: true and mfaTempToken -> POST /auth/mfa/challenge with TOTP -> tokens issued.
> 3. Login -> mfaTempToken -> POST /auth/mfa/challenge with a recovery code -> tokens issued (recovery code consumed).
>    Use `verifyTotp()` from `src/server/crypto/totp.ts` or a local implementation with `node:crypto` to generate valid TOTP codes in the test.
>    Acceptance criteria: setup + verify works, challenge with TOTP works, challenge with recovery code works and is consumed.

---

### NEST-128: E2E Test - Sessions Flow

- **Phase:** 6
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-080, NEST-126
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** E2E test of the sessions flow: login on 3 devices, list, revoke one, revoke all except the current one.

**Prompt for the agent:**

> Create the file `test/e2e/sessions-flow.e2e-spec.ts`. Implement:
>
> 1. Login with 3 different user-agents (simulate 3 devices).
> 2. GET /auth/sessions -> lists 3 sessions, one with `isCurrent: true`.
> 3. DELETE /auth/sessions/:id (revoke a specific session) -> session removed.
> 4. GET /auth/sessions -> lists 2 sessions.
> 5. DELETE /auth/sessions (revoke all except the current one) -> only the current session remains.
> 6. GET /auth/sessions -> lists 1 session.
>    Acceptance criteria: sessions listed correctly, individual and bulk revocation work, isCurrent correct.

---

### NEST-129: E2E Test - Password Reset Flow

- **Phase:** 6
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-085, NEST-126
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** E2E test of the two password reset methods: token and OTP.

**Prompt for the agent:**

> Create the file `test/e2e/password-reset-flow.e2e-spec.ts`. Implement:
>
> 1. Token method:
>    - POST /auth/password/forgot with email -> 200 (generic response, does not reveal whether the email exists).
>    - Extract the token from the IEmailProvider mock.
>    - POST /auth/password/reset with token and new password -> 200.
>    - Login with the new password -> success.
> 2. OTP method:
>    - POST /auth/password/forgot with email -> 200.
>    - Extract the OTP from the IEmailProvider mock.
>    - POST /auth/password/verify-otp with OTP -> 200, returns verifiedToken.
>    - POST /auth/password/reset with verifiedToken and new password -> 200.
>    - Login with the new password -> success.
>      Acceptance criteria: both methods work end-to-end, password effectively changed.

---

### NEST-130: E2E Test - Invitations Flow

- **Phase:** 6
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-118, NEST-126
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** E2E test of the invitations flow: admin creates an invitation, recipient accepts, login.

**Prompt for the agent:**

> Create the file `test/e2e/invitations-flow.e2e-spec.ts`. Implement:
>
> 1. Login as admin (with a sufficient role).
> 2. POST /auth/invitations with email and role -> 201.
> 3. Extract the token from the IEmailProvider mock.
> 4. POST /auth/invitations/accept with token, name and password -> 200, tokens issued.
> 5. Login with the invitation's email and password -> success.
> 6. User created with emailVerified: true and the invitation's role.
>    Acceptance criteria: invitation created, accepted, user created with the correct role and emailVerified.

---

### NEST-131: E2E Test - OAuth Flow (Mock)

- **Phase:** 6
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-111, NEST-126
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** E2E test of the OAuth flow with a mocked provider.

**Prompt for the agent:**

> Create the file `test/e2e/oauth-flow.e2e-spec.ts`. Implement:
>
> 1. Mock the OAuth provider (do not make a real call to Google).
> 2. GET /auth/oauth/google?tenantId=xxx -> redirect 302 with state in the URL.
> 3. Simulate the callback: GET /auth/oauth/google/callback with profile and a valid state.
> 4. Hook onOAuthLogin returns action 'create' -> user created, tokens issued.
> 5. Second callback with the same providerId: hook returns action 'link' -> user linked.
> 6. Callback with an invalid state -> OAUTH_FAILED error.
>    Acceptance criteria: create and link flows work, CSRF state validated.

---

### NEST-132: E2E Test - FIFO Session Eviction

- **Phase:** 6
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-080, NEST-126
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** E2E test of FIFO eviction when the session limit is exceeded.

**Prompt for the agent:**

> Create the file `test/e2e/session-eviction.e2e-spec.ts`. Implement:
>
> 1. Configure the module with `sessions.maxPerUser: 5`.
> 2. Login with 6 different user-agents (simulate 6 devices).
> 3. Verify that the oldest session (first login) was automatically removed.
> 4. GET /auth/sessions -> returns exactly 5 sessions.
> 5. Verify that `isCurrent` is true only for the last session used.
>    Acceptance criteria: the 6th login evicts the 1st session, the list returns 5 sessions, isCurrent correct.

---

### NEST-133: E2E Test - Refresh Concurrency

- **Phase:** 6
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-035, NEST-126
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** E2E test of two simultaneous refresh requests with grace window.

**Prompt for the agent:**

> Create the file `test/e2e/refresh-concurrency.e2e-spec.ts`. Implement:
>
> 1. Login and obtain the refreshToken.
> 2. Send two POST /auth/refresh requests simultaneously (Promise.all) with the same refreshToken.
> 3. The first request succeeds with new tokens.
> 4. The second request uses the grace window and returns the SAME new token (does not generate a third one).
> 5. The original refreshToken no longer works after the grace window expires.
>    Acceptance criteria: both requests return success, return the same new tokens, original token invalidated.

---

### NEST-134: E2E Test - Security Scenarios

- **Phase:** 6
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-126, NEST-127
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** E2E test of security scenarios: brute-force, blacklist, cross-tenant, role, token without jti, MFA cross-context, OTP cooldown.

**Prompt for the agent:**

> Create the file `test/e2e/security.e2e-spec.ts`. Implement:
>
> 1. Brute-force: 10 login attempts with the wrong password -> response with status 429 and `Retry-After` header.
> 2. Token blacklist: logout -> reuse the access token -> 401.
> 3. Cross-tenant: login in tenant A -> access a resource with tenantId B in the JWT -> 403.
> 4. Insufficient role: login as MEMBER -> access endpoint @Roles('ADMIN') -> 403.
> 5. Token without `jti`: craft a JWT without jti -> 401 TOKEN_INVALID.
> 6. MFA temp token 'dashboard' used on the platform endpoint -> rejected.
> 7. OTP cooldown: send forgot password -> immediately send again (< 60s) -> success returned but a new OTP is NOT generated.
>    Acceptance criteria: all 7 security scenarios verified and passing.

---

### NEST-135: Security Review - Password and Crypto

- **Phase:** 6
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-010
- **Agent:** security-reviewer
- **Estimate:** ~45min
- **Description:** Review all password and cryptography operations against the Appendix B checklist.

**Prompt for the agent:**

> Perform a security review verifying the following items in the project files:
>
> 1. `src/server/services/password.service.ts`: passwords hashed with scrypt (N=2^15, r=8, p=1). Verify the cost parameters.
> 2. `src/server/services/password.service.ts`: constant-time comparison on passwords via `crypto.timingSafeEqual()`.
> 3. `src/server/services/crypto.service.ts`: TOTP secrets encrypted with AES-256-GCM. Verify the use of `createCipheriv('aes-256-gcm')`.
> 4. MFA recovery codes hashed with scrypt via PasswordService (not stored in plain text).
> 5. Refresh tokens are opaque (UUID v4, not JWT).
> 6. Comparison of OTPs and recovery codes uses `timingSafeEqual` with buffers of the same length.
>    Produce a report with status (PASS/FAIL) for each item and remediation recommendations if FAIL.
>    Acceptance criteria: all 6 items verified, report produced with evidence (lines of code).

---

### NEST-136: Security Review - Token and Session

- **Phase:** 6
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-035, NEST-080
- **Agent:** security-reviewer
- **Estimate:** ~45min
- **Description:** Review the security of tokens, refresh, blacklist and cookies.

**Prompt for the agent:**

> Perform a security review verifying:
>
> 1. `src/server/services/token-manager.service.ts`: refresh rotation with grace window implemented.
> 2. Blacklist of access tokens via `rv:{jti}` in Redis.
> 3. `src/server/services/token-delivery.service.ts`: HttpOnly cookies in cookie/both mode.
> 4. Refresh cookie with SameSite Strict.
> 5. Path restricted to `/auth` (or configured) on the refresh cookie.
> 6. Algorithm pinning in the JWT Strategy: `algorithms: ['HS256']` in `src/strategies/jwt.strategy.ts` AND `src/strategies/jwt-platform.strategy.ts`.
> 7. SHA-256 used in all Redis keys (refresh tokens, sessions, OTPs, etc.).
>    Produce a report with PASS/FAIL status for each item.
>    Acceptance criteria: all 7 items verified with code evidence.

---

### NEST-137: Security Review - Anti-Enumeration and Brute Force

- **Phase:** 6
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-026, NEST-085
- **Agent:** security-reviewer
- **Estimate:** ~45min
- **Description:** Review protections against user enumeration, brute-force and sanitization.

**Prompt for the agent:**

> Perform a security review verifying:
>
> 1. `src/server/services/brute-force.service.ts`: brute-force by email scoped per tenant (identifier uses `sha256(tenantId + ':' + email)`).
> 2. Rate limiting per IP: verify that `@Throttle()` with configs from `AUTH_THROTTLE_CONFIGS` is present on all sensitive endpoints (login, register, forgot-password, mfa/challenge, refresh, invitation/accept, platform/login).
> 3. Non-disclosure of user existence: login with a nonexistent email returns the same message as a wrong password. forgot-password always returns success.
> 4. PII masked in logs: verify that the NestJS Logger does not log emails, passwords, tokens in plain text.
> 5. Anti-replay of TOTP codes: verify that used codes are stored and rejected if reused.
> 6. OTP with a limit of 5 attempts.
> 7. Header sanitization in the HookContext: verify that sensitive headers (Authorization, Cookie) are removed before passing to the hook.
>    Produce a PASS/FAIL report for each item.
>    Acceptance criteria: all 7 items verified.

---

### NEST-138: JSDoc Documentation - Services

- **Phase:** 6
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-107, NEST-118, NEST-122
- **Agent:** planner
- **Estimate:** ~45min
- **Description:** Add JSDoc to all public methods of all services.

**Prompt for the agent:**

> Add complete JSDoc documentation to all public methods of the following service files:
>
> - `src/server/services/auth.service.ts`
> - `src/server/services/token-manager.service.ts`
> - `src/server/services/token-delivery.service.ts`
> - `src/server/services/brute-force.service.ts`
> - `src/server/services/crypto.service.ts`
> - `src/server/services/mfa.service.ts`
> - `src/server/services/session.service.ts`
> - `src/server/services/password-reset.service.ts`
> - `src/server/services/otp.service.ts`
> - `src/server/services/platform-auth.service.ts`
> - `src/server/services/invitation.service.ts`
> - `src/server/oauth/oauth.service.ts`
>   Each JSDoc must include: the method description, `@param` for each parameter with type and description, `@returns` with type and description, `@throws` listing possible exceptions.
>   Acceptance criteria: all public methods of all services have complete JSDoc.

---

### NEST-139: JSDoc Documentation - Guards and Decorators

- **Phase:** 6
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-125
- **Agent:** planner
- **Estimate:** ~20min
- **Description:** Add JSDoc to all exported guards and decorators.

**Prompt for the agent:**

> Add complete JSDoc documentation to the following files:
> Guards: `jwt-auth.guard.ts`, `jwt-platform.guard.ts`, `roles.guard.ts`, `platform-roles.guard.ts`, `user-status.guard.ts`, `mfa-verified.guard.ts`, `ws-jwt.guard.ts`, `self-or-admin.guard.ts`, `optional-auth.guard.ts` (all in `src/server/guards/`).
> Decorators: `current-user.decorator.ts`, `roles.decorator.ts`, `platform-roles.decorator.ts`, `public.decorator.ts` (all in `src/server/decorators/`).
> Each JSDoc must include: the guard/decorator description, usage examples, security notes where applicable (e.g., cross-tenant limitations of SelfOrAdminGuard, peer dep of WsJwtGuard).
> Acceptance criteria: all public guards and decorators have JSDoc with examples.

---

### NEST-140: README.md - Quick Start and Configuration

- **Phase:** 6
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-120
- **Agent:** planner
- **Estimate:** ~45min
- **Description:** Create a README with installation, minimal configuration, registerAsync and IUserRepository implementation.

**Prompt for the agent:**

> Create the file `README.md` in the project root with the following sections:
>
> 1. **Installation:** `npm install @bymax-one/nest-auth` with a list of peer dependencies.
> 2. **Minimal configuration:** a complete example of `BymaxAuthModule.registerAsync()` with `useFactory` showing the required options (jwt.secret, repositories).
> 3. **IUserRepository example:** a complete reference implementation with all required methods, including a note about typing.
> 4. **IEmailProvider example:** a reference implementation with a SECURITY NOTE: all user values interpolated into HTML must be escaped (`escapeHtml(name)`) to prevent XSS in the notifications.
> 5. **Endpoints table:** all 14+ endpoints with method, path, auth, guard and description.
> 6. **Guards and decorators table:** name, type, description.
> 7. **Security section:** domain allowlist in `resolveDomains`, recovery without TOTP requires admin intervention, `@MaxLength(128)` on passwords.
> 8. **Note about @nestjs/throttler:** >= 6.0.0 required for `AUTH_THROTTLE_CONFIGS`.
>    Acceptance criteria: README complete and functional, code examples correct and testable.

---

### NEST-141: CHANGELOG.md v1.0.0

- **Phase:** 6
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-140
- **Agent:** planner
- **Estimate:** ~45min
- **Description:** Populate CHANGELOG.md with a v1.0.0 entry detailing all features.

**Prompt for the agent:**

> Update the file `CHANGELOG.md` (created in Phase 1) with the v1.0.0 entry. Include all implemented features organized by category:
>
> - **Authentication:** register, login, logout, refresh, getMe, email verification
> - **MFA:** TOTP setup/verify, challenge, recovery codes, disable
> - **Sessions:** list, revoke, revoke all, FIFO eviction
> - **Password Reset:** token method, OTP method
> - **Platform Admin:** login, logout, refresh, getMe, revoke all sessions, MFA
> - **OAuth:** extensible plugin system, Google provider
> - **Invitations:** create, accept
> - **Guards:** JwtAuthGuard, JwtPlatformGuard, RolesGuard, PlatformRolesGuard, UserStatusGuard, MfaVerifiedGuard, WsJwtGuard, SelfOrAdminGuard, OptionalAuthGuard
> - **Security:** scrypt, AES-256-GCM, native TOTP, brute-force protection, CSRF state, constant-time comparison, algorithm pinning
>   Format: Keep a Changelog (https://keepachangelog.com).
>   Acceptance criteria: v1.0.0 entry complete with all features listed.

---

### NEST-142: Phase 6 Barrel Export Update

- **Phase:** 6
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-122, NEST-123, NEST-124
- **Agent:** architect
- **Estimate:** ~15min
- **Description:** Add WsJwtGuard, SelfOrAdminGuard and OptionalAuthGuard to the barrel export.

**Prompt for the agent:**

> Update the file `src/server/index.ts` to add:
>
> - `export { WsJwtGuard } from './guards/ws-jwt.guard'`
> - `export { SelfOrAdminGuard } from './guards/self-or-admin.guard'`
> - `export { OptionalAuthGuard } from './guards/optional-auth.guard'`
>   Verify that `export type` is used for types/interfaces and regular `export` for classes (preserve runtime metadata).
>   Acceptance criteria: 3 new guards exported in index.ts.

---

### NEST-143: Final Barrel Export Review

- **Phase:** 6
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-142
- **Agent:** architect
- **Estimate:** ~15min
- **Description:** Complete review of the barrel export to ensure everything public is exported and export type vs export is correct.

**Prompt for the agent:**

> Review the file `src/server/index.ts` completely:
>
> 1. Verify that ALL public items are exported: all services, controllers, guards, decorators, DTOs, interfaces, types, constants.
> 2. Verify that `export type` is used for interfaces and types (e.g., AuthUser, IUserRepository, IEmailProvider, AuthModuleOptions, PlatformAuthResult).
> 3. Verify that regular `export` (without `type`) is used for: DTO classes (preserve class-validator metadata), guards, decorators, services, the module.
> 4. Verify that there are no duplicate or circular exports.
> 5. List any public item that is missing.
>    Acceptance criteria: barrel export complete and correct, type/regular export distinction verified.

---

### NEST-144: Module Options Validation

- **Phase:** 6
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-120
- **Agent:** code-reviewer
- **Estimate:** ~45min
- **Description:** Validate options at module initialization with clear error messages.

**Prompt for the agent:**

> Review and improve the option validation in `src/server/bymax-auth.module.ts` (or `src/server/utils/resolve-options.ts`):
>
> 1. Verify that `jwt.secret` is required and not empty. Message: "BymaxAuthModule: jwt.secret is required".
> 2. Verify that `userRepository` is provided. Message: "BymaxAuthModule: userRepository is required".
> 3. If `platform.enabled`, verify that `platformUserRepository` is provided. Message: "BymaxAuthModule: platformUserRepository is required when platform is enabled".
> 4. If `oauth` is configured, verify that at least one provider has `clientId` and `clientSecret`.
> 5. If `mfa.enabled`, verify that `mfa.encryptionKey` is provided and is 32 bytes (256 bits).
> 6. Verify that `resolveOptions` uses a shallow merge per group (spread), NOT `JSON.parse/stringify` (which strips functions/hooks).
>    All validations must throw a descriptive `Error` at the time of module initialization.
>    Acceptance criteria: each invalid configuration produces a clear message, functions/hooks survive the merge.

---

### NEST-145: Structured Logging Review

- **Phase:** 6
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-120
- **Agent:** code-reviewer
- **Estimate:** ~45min
- **Description:** Ensure structured logs with the NestJS Logger in all services, without PII.

**Prompt for the agent:**

> Review all services to ensure:
>
> 1. Each service uses `private readonly logger = new Logger(ServiceName.name)` from `@nestjs/common`.
> 2. Logs on important operations: login (success/failure), register, logout, refresh, MFA setup/challenge, password reset, invitation create/accept, OAuth callback.
> 3. PII is NEVER logged in plain text: emails masked (e.g., `m***@example.com`), tokens NEVER logged, passwords NEVER logged.
> 4. Use the appropriate level: `logger.log()` for normal operations, `logger.warn()` for suspicious attempts (brute-force, invalid token), `logger.error()` for unexpected errors.
> 5. Include useful context: userId (ok, it is not sensitive PII), tenantId, operation, IP (consider whether necessary).
>    Services to review: auth, platform-auth, mfa, session, password-reset, otp, invitation, oauth, brute-force, token-manager.
>    Acceptance criteria: all services have a Logger, PII masked, correct log levels.

---

### NEST-146: Build and Package Verification

- **Phase:** 6
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-143
- **Agent:** code-reviewer
- **Estimate:** ~45min
- **Description:** Verify that the build produces a clean dist/ with types and sourcemaps, and that package.json has the correct files.

**Prompt for the agent:**

> Verify the build configuration:
>
> 1. Run `pnpm build` and verify that it produces `dist/` without errors or warnings.
> 2. Verify that `dist/` contains: `.js` files, `.d.ts` type declarations, `.js.map` sourcemaps.
> 3. Verify that `tsconfig.json` has: `declaration: true`, `declarationMap: true`, `sourceMap: true`, `outDir: "dist"`.
> 4. Verify `package.json`:
>    - `"main": "dist/index.js"`
>    - `"types": "dist/index.d.ts"`
>    - `"files": ["dist/"]` — only dist published (no src, tests, docs).
> 5. Run `pnpm pack` and verify the tarball contents — only dist/ and package.json/README/LICENSE/CHANGELOG.
> 6. Verify that it does NOT include: `src/`, `test/`, `node_modules/`, `.env`, `tsconfig.json`.
>    Acceptance criteria: clean build, types and sourcemaps generated, package.json correct, pnpm pack contains only what is needed.

---

### NEST-147: Local Installation Test

- **Phase:** 6
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-146
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** Test local installation of the package in a test NestJS project.

**Prompt for the agent:**

> Test local installation:
>
> 1. Create a temporary directory with a minimal NestJS project (`nest new test-app` or manual scaffold).
> 2. Install the local package: `pnpm install ../nest-auth` (path relative to the tarball or directory).
> 3. Verify that the import works: `import { BymaxAuthModule, JwtAuthGuard, AuthService } from '@bymax-one/nest-auth'`.
> 4. Verify that types are available: `import type { AuthUser, IUserRepository, AuthModuleOptions } from '@bymax-one/nest-auth'`.
> 5. Verify that `BymaxAuthModule.registerAsync()` compiles without errors in app.module.ts.
> 6. Verify that DTOs retain class-validator metadata (they were not exported with `export type`).
>    Acceptance criteria: the package installs, imports and compiles correctly in an external project.

---

### NEST-148: Test Coverage Verification

- **Phase:** 6
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-134
- **Agent:** tester
- **Estimate:** ~30min
- **Description:** Run test coverage and ensure >= 80% on branches, functions and lines.

**Prompt for the agent:**

> Run `pnpm test:cov` and analyze the report:
>
> 1. Verify total coverage >= 80% for: branches, functions, lines, statements.
> 2. Identify files with coverage < 80%.
> 3. For each file below 80%, list the uncovered methods/branches.
> 4. Write additional tests to cover the most critical gaps (prioritize services and guards over controllers).
> 5. Re-run coverage and confirm >= 80%.
>    Acceptance criteria: total coverage >= 80% on all metrics, clean report.

---

### NEST-149: Throttle Config Verification

- **Phase:** 6
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-107, NEST-118
- **Agent:** security-reviewer
- **Estimate:** ~45min
- **Description:** Verify that all 14 sensitive endpoints have @Throttle with AUTH_THROTTLE_CONFIGS.

**Prompt for the agent:**

> Verify that `@Throttle()` with configurations from `AUTH_THROTTLE_CONFIGS` is present on ALL sensitive endpoints. Complete list to verify:
>
> 1. POST /auth/register
> 2. POST /auth/login
> 3. POST /auth/refresh
> 4. POST /auth/mfa/setup
> 5. POST /auth/mfa/verify
> 6. POST /auth/mfa/challenge
> 7. POST /auth/password/forgot
> 8. POST /auth/password/verify-otp
> 9. POST /auth/password/reset
> 10. POST /auth/invitations/accept
> 11. POST /auth/platform/login
> 12. POST /auth/platform/mfa/challenge
> 13. POST /auth/platform/refresh
> 14. POST /auth/verify-email
>     For each endpoint, verify that the throttle config is appropriate (e.g., login more restrictive than /me).
>     Acceptance criteria: all 14 endpoints verified with @Throttle, appropriate configs.

---

### NEST-150: npm Publish Preparation

- **Phase:** 6
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-146, NEST-148, NEST-141
- **Agent:** planner
- **Estimate:** ~30min
- **Description:** Run the final publish checklist: build, coverage, pack, publish.

**Prompt for the agent:**

> Run the publish checklist:
>
> 1. `pnpm build` — verify zero errors and zero warnings.
> 2. `pnpm test:cov` — verify coverage >= 80%.
> 3. `pnpm pack` — verify the package contents (only dist, package.json, README, LICENSE, CHANGELOG).
> 4. Verify `package.json`: name `@bymax-one/nest-auth`, version `1.0.0`, license, repository, keywords, correct peerDependencies.
> 5. Verify that `.npmignore` or `files` in package.json excludes src/, test/, docs/, .github/.
> 6. Prepare the publish command: `pnpm publish --access public`.
>    Do NOT run the publish automatically — only prepare and validate.
>    Acceptance criteria: clean build, coverage OK, correct pack, complete package.json, ready to publish.

---

### NEST-151: Phase 6 Final Validation Checklist

- **Phase:** 6
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-148, NEST-149, NEST-146, NEST-140, NEST-138, NEST-139, NEST-143
- **Agent:** planner
- **Estimate:** ~45min
- **Description:** Run the final Phase 6 validation checklist verifying all criteria.

**Prompt for the agent:**

> Run and verify each item of the Phase 6 validation checklist:
>
> 1. [ ] All E2E tests passing (including refresh concurrency and FIFO eviction).
> 2. [ ] Total coverage >= 80%.
> 3. [ ] Build without errors or warnings.
> 4. [ ] README complete and functional with security sections.
> 5. [ ] JSDoc on all public exports.
> 6. [ ] All 14 endpoints have `@Throttle()` with configs from `AUTH_THROTTLE_CONFIGS`.
> 7. [ ] Security checklist 100% verified (Appendix B).
> 8. [ ] `WsJwtGuard` verifies `payload.type === 'dashboard'`.
> 9. [ ] Barrel export distinguishes `export type` from `export` correctly.
> 10. [ ] Package ready for publishing to npm.
>         For each item, mark PASS or FAIL with evidence. If any FAIL, list the corrective action.
>         Acceptance criteria: all 10 items PASS.

---

## Phase 7 — Shared + Client Subpath

### NEST-152: Shared types - AuthUserClient, AuthResult, AuthErrorResponse

- **Phase:** 7
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** NEST-151
- **Agent:** typescript-reviewer
- **Estimate:** ~30min
- **Description:** Create the types shared between server and client: a subset of AuthUser for frontend consumption, authentication result types, error response and JWT payloads.

**Prompt for the agent:**

> Create the following shared type files:
>
> 1. `src/shared/types/auth-user.types.ts` — type `AuthUserClient` containing a subset of `AuthUser` for use on the client: `id`, `email`, `name`, `role`, `tenantId`, `status`, `mfaEnabled`, `avatarUrl`. Use `Pick` or a standalone interface.
> 2. `src/shared/types/auth-result.types.ts` — types `AuthResult` (user + tokens info) and `MfaChallengeResult` (tempToken + available methods).
> 3. `src/shared/types/auth-error.types.ts` — type `AuthErrorResponse` with fields: `message`, `error`, `statusCode`, `code` (the lib's error code).
> 4. `src/shared/types/jwt-payload.types.ts` — types `DashboardJwtPayload`, `PlatformJwtPayload`, `MfaTempPayload` (re-export or redefinition of the server types).
> 5. `src/shared/types/auth-config.types.ts` — types for cookie names (`AuthCookieNames`), role types (`AuthRole`), cookie configurations.
>
> All types must be `export type` or `export interface`. Zero external dependencies — pure TypeScript only.
>
> Acceptance criteria:
>
> - Each file compiles in isolation with `tsc --noEmit`
> - No runtime dependency (types only)
> - Types are compatible with the server exports
> - JSDoc in English on all exported types

---

### NEST-153: Shared constants - cookies, error codes, routes

- **Phase:** 7
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** NEST-152
- **Agent:** security-reviewer
- **Estimate:** ~25min
- **Description:** Create shared constants for cookie names, error codes and authentication routes, ensuring consistency between server and client.

**Prompt for the agent:**

> Create the following shared constant files:
>
> 1. `src/shared/constants/cookie-defaults.ts` — export constants:
>    - `AUTH_ACCESS_COOKIE_NAME = 'access_token'`
>    - `AUTH_REFRESH_COOKIE_NAME = 'refresh_token'`
>    - `AUTH_HAS_SESSION_COOKIE_NAME = 'has_session'`
>    - `AUTH_REFRESH_COOKIE_PATH = '/auth'`
> 2. `src/shared/constants/error-codes.ts` — re-export `AUTH_ERROR_CODES` from the main module or redefine the relevant codes for the client.
> 3. `src/shared/constants/routes.ts` — object `AUTH_ROUTES` with all the endpoint paths: `signIn`, `signUp`, `refresh`, `logout`, `me`, `forgotPassword`, `resetPassword`, `mfaSetup`, `mfaVerify`, `mfaChallenge`, `mfaDisable`, etc.
>
> All constants must use `as const` for type-safety. Zero external dependencies.
>
> Acceptance criteria:
>
> - Cookie constants match exactly what the server uses
> - `AUTH_ROUTES` covers all the lib's public endpoints
> - Compiles without errors
> - JSDoc in English on all exports

---

### NEST-154: Shared barrel export and compilation tests

- **Phase:** 7
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** NEST-152, NEST-153
- **Agent:** architect
- **Estimate:** ~15min
- **Description:** Create the barrel export of the shared subpath and verify that there are no external dependencies and that the types are compatible with the server exports.

**Prompt for the agent:**

> 1. Create `src/shared/index.ts` exporting all types and constants from the `types/*` and `constants/*` modules.
> 2. Use `export type` for interfaces/types and `export` for value constants.
> 3. Verify that the `shared` subpath has zero external dependencies (only TypeScript types and pure constants).
> 4. Create a compilation test that imports everything from `src/shared/index.ts` and verifies that it compiles without errors.
> 5. Verify that the exported types are compatible with the server types (e.g., `AuthUserClient` is a subset of `AuthUser`).
>
> Acceptance criteria:
>
> - `src/shared/index.ts` exports all types and constants
> - Zero external dependencies in the shared subpath
> - Compilation test passes
> - Types compatible with the server exports

---

### NEST-155: createAuthFetch - fetch wrapper core

- **Phase:** 7
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** NEST-154
- **Agent:** security-reviewer
- **Estimate:** ~45min
- **Description:** Implement the fetch wrapper that manages credentials, intercepts 401s, attempts automatic refresh and retries the original request.

**Prompt for the agent:**

> Create `src/client/createAuthFetch.ts` with the following implementation:
>
> 1. Function `createAuthFetch(config)` that returns a typed fetch wrapper.
> 2. The wrapper must:
>    - Add `credentials: 'include'` and default headers (`Content-Type: application/json`) to all requests.
>    - Intercept 401 responses: check via `shouldSkipRefreshOnUrl` whether the URL is an auth endpoint (must not attempt refresh).
>    - If it is not an auth endpoint: attempt refresh via `POST /api/auth/client-refresh`.
>    - Implement single-flight refresh dedup via a shared promise (if a refresh is already in progress, wait for the same one).
>    - On a successful refresh: retry the original request.
>    - On a failed refresh: call the `onSessionExpired` callback.
> 3. Import cookie/route constants from `../shared`.
> 4. Zero external dependencies — only native `fetch`.
>
> Acceptance criteria:
>
> - Wrapper adds credentials and headers automatically
> - 401 on a normal endpoint triggers refresh + retry
> - 401 on an auth endpoint does NOT trigger refresh
> - Single-flight dedup works (only 1 simultaneous refresh)
> - onSessionExpired callback is called when refresh fails
> - Zero external dependencies

---

### NEST-156: shouldSkipRefreshOnUrl implementation

- **Phase:** 7
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** NEST-154
- **Agent:** code-reviewer
- **Estimate:** ~15min
- **Description:** Implement the internal function that determines which URLs must not trigger automatic refresh upon receiving a 401.

**Prompt for the agent:**

> Implement the function `shouldSkipRefreshOnUrl(url: string): boolean` in `src/client/createAuthFetch.ts` (internal function, not exported):
>
> 1. The function must return `true` for the following URLs (match by `endsWith` or `includes` on the pathname):
>    - `/auth/sign-in`
>    - `/auth/sign-up`
>    - `/auth/refresh`
>    - `/api/auth/client-refresh`
>    - `/api/auth/silent-refresh`
>    - `/auth/forgot-password`
>    - `/auth/verify`
>    - `/auth/reset-password`
> 2. Import `AUTH_ROUTES` from `../shared` to maintain consistency with the server routes.
> 3. Extract the pathname from the URL using `new URL(url)` with error handling for relative URLs.
>
> Acceptance criteria:
>
> - All URLs in the skip list return `true`
> - Normal URLs (e.g., `/api/users`, `/api/workouts`) return `false`
> - Works with absolute and relative URLs
> - Uses constants from `AUTH_ROUTES` where possible

---

### NEST-157: Single-flight refresh dedup

- **Phase:** 7
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** NEST-155
- **Agent:** security-reviewer
- **Estimate:** ~20min
- **Description:** Ensure that multiple requests receiving a 401 simultaneously share a single refresh call, avoiding race conditions.

**Prompt for the agent:**

> Implement the single-flight refresh dedup pattern in `src/client/createAuthFetch.ts`:
>
> 1. Module variable `refreshPromise: Promise<Response> | null = null`.
> 2. When a 401 is intercepted and refresh is needed:
>    - If `refreshPromise` already exists: wait (`await refreshPromise`).
>    - If it does not exist: create a new refresh promise, assign it to `refreshPromise`.
>    - Use `.finally(() => { refreshPromise = null })` to clear the reference.
> 3. All requests that received a 401 during the refresh must wait for the same promise and then retry.
>
> Acceptance criteria:
>
> - With 5 simultaneous requests receiving a 401, only 1 POST /refresh is made
> - All 5 requests are retried after a successful refresh
> - If refresh fails, all 5 receive the error
> - `.finally()` clears `refreshPromise` on success and failure
> - Unit test with a fetch mock proves the dedup

---

### NEST-158: createAuthClient factory

- **Phase:** 7
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** NEST-155, NEST-156, NEST-157
- **Agent:** architect
- **Estimate:** ~40min
- **Description:** Create the main client factory that exposes typed methods for all authentication operations, using createAuthFetch internally.

**Prompt for the agent:**

> Create `src/client/createAuthClient.ts`:
>
> 1. Interface `AuthClientConfig`:
>    - `baseUrl: string` — the server base URL (e.g., `http://localhost:3000`)
>    - `refreshEndpoint?: string` — the refresh endpoint (default: `/api/auth/client-refresh`)
>    - `credentials?: RequestCredentials` — default: `'include'`
>    - `defaultHeaders?: Record<string, string>` — extra headers
>    - `onSessionExpired?: () => void` — callback when the session expires
>    - `timeout?: number` — timeout in ms (default: 30000)
> 2. Interface `AuthClient` with methods:
>    - `login(email: string, password: string, options?: { tenantId?: string }): Promise<AuthResult>`
>    - `register(data: RegisterInput): Promise<AuthResult>`
>    - `logout(): Promise<void>`
>    - `refresh(): Promise<AuthResult>`
>    - `getMe(): Promise<AuthUserClient>`
>    - `mfaChallenge(tempToken: string, code: string): Promise<AuthResult>`
>    - `forgotPassword(email: string, tenantId?: string): Promise<void>`
>    - `resetPassword(token: string, otp: string, newPassword: string): Promise<void>`
> 3. Function `createAuthClient(config: AuthClientConfig): AuthClient` that uses `createAuthFetch` internally.
> 4. Each method fetches the correct endpoint using `AUTH_ROUTES`.
>
> Acceptance criteria:
>
> - All methods correctly typed
> - Uses createAuthFetch for all requests
> - Config with sensible defaults
> - Consistent error handling (throw on non-2xx)
> - JSDoc in English on all methods and interfaces

---

### NEST-159: Client barrel export and tests

- **Phase:** 7
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** NEST-158
- **Agent:** code-reviewer
- **Estimate:** ~30min
- **Description:** Create the barrel export of the client subpath and unit tests covering refresh dedup, skip list, error handling and each AuthClient method.

**Prompt for the agent:**

> 1. Create `src/client/index.ts` exporting: `createAuthClient`, `createAuthFetch`, and all relevant types (`AuthClientConfig`, `AuthClient`).
> 2. Write unit tests in `src/client/__tests__/`:
>    - Mock `global.fetch` to simulate responses.
>    - Test refresh dedup: 5 simultaneous requests with 401 → only 1 refresh.
>    - Test skip list: 401 on `/auth/sign-in` does not trigger refresh.
>    - Test error handling: non-2xx responses throw with `AuthErrorResponse`.
>    - Test each `AuthClient` method: `login`, `register`, `logout`, `refresh`, `getMe`, `mfaChallenge`, `forgotPassword`, `resetPassword`.
>    - Test that `onSessionExpired` is called when refresh fails.
>
> Acceptance criteria:
>
> - Barrel export compiles without errors
> - All tests pass
> - Coverage >= 80% in the client files
> - The fetch mock does not leak between tests

---

### NEST-160: Phase 7 validation

- **Phase:** 7
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** NEST-154, NEST-159
- **Agent:** architect
- **Estimate:** ~20min
- **Description:** Final validation of Phase 7 — verify that shared and client have zero external dependencies, types are compatible, coverage is adequate and the build compiles.

**Prompt for the agent:**

> Run the complete Phase 7 validation:
>
> 1. Verify that `src/shared/` has zero external dependencies (only TypeScript types and constants).
> 2. Verify that `src/client/` has zero external dependencies (only native `fetch` and imports from `../shared`).
> 3. Verify that the shared types are compatible with the server exports (e.g., `AuthUserClient` is a subset of `AuthUser`).
> 4. Run `pnpm test --coverage` and verify coverage >= 80%.
> 5. Run `pnpm build` and verify compilation without errors.
> 6. Verify that the shared and client barrel exports are correct.
>
> Acceptance criteria:
>
> - Shared: zero external dependencies
> - Client: zero external dependencies (only native fetch)
> - Types compatible with the server
> - Coverage >= 80%
> - Build without errors

---

## Phase 8 — React Subpath

### NEST-161: AuthContext and types

- **Phase:** 8
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** NEST-160
- **Agent:** typescript-reviewer
- **Estimate:** ~20min
- **Description:** Create the React context for authentication and define the AuthContextValue types with status, user and auth methods.

**Prompt for the agent:**

> Create `src/react/context.ts`:
>
> 1. Define type `AuthStatus = 'authenticated' | 'unauthenticated' | 'loading'`.
> 2. Define interface `AuthContextValue`:
>    - `user: AuthUserClient | null`
>    - `status: AuthStatus`
>    - `isLoading: boolean`
>    - `login: (email: string, password: string, options?: { tenantId?: string }) => Promise<AuthResult>`
>    - `register: (data: RegisterInput) => Promise<AuthResult>`
>    - `logout: () => Promise<void>`
>    - `refresh: () => Promise<void>`
>    - `forgotPassword: (email: string, tenantId?: string) => Promise<void>`
>    - `resetPassword: (token: string, otp: string, newPassword: string) => Promise<void>`
>    - `lastValidation: Date | null`
> 3. Create `AuthContext` using `React.createContext<AuthContextValue | null>(null)`.
> 4. Import types from `../shared`.
>
> Acceptance criteria:
>
> - Context created with initial value `null`
> - All types imported from `../shared`
> - JSDoc in English on all types
> - Compiles without errors

---

### NEST-162: AuthProvider component

- **Phase:** 8
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** NEST-161
- **Agent:** code-reviewer
- **Estimate:** ~40min
- **Description:** Implement the AuthProvider component that manages session state, automatic revalidation and exposes the authentication context to the component tree.

**Prompt for the agent:**

> Create `src/react/AuthProvider.tsx`:
>
> 1. Props of the interface `AuthProviderProps`:
>    - `children: React.ReactNode`
>    - `client: AuthClient` (instance created with `createAuthClient`)
>    - `onSessionExpired?: () => void`
>    - `revalidateInterval?: number` (default: `300000` — 5 minutes)
> 2. Manage state via `useReducer` with actions: `SET_USER`, `SET_LOADING`, `CLEAR_SESSION`, `SET_ERROR`.
> 3. On mount (`useEffect`): call `client.getMe()` to check for an existing session.
> 4. Configure `setInterval` for automatic revalidation with the configured interval.
> 5. Implement methods that call `client.*` and update the reducer state.
> 6. Call `onSessionExpired` when the session expires (refresh fails).
> 7. Provide `AuthContext.Provider` with the computed value.
>
> Acceptance criteria:
>
> - AuthProvider renders children correctly
> - `client.getMe()` is called on mount
> - Automatic revalidation works at the configured interval
> - State transitions correctly: loading → authenticated/unauthenticated
> - `onSessionExpired` is called when the session expires
> - Cleanup of intervals on unmount

---

### NEST-163: useSession hook

- **Phase:** 8
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** NEST-162
- **Agent:** code-reviewer
- **Estimate:** ~20min
- **Description:** Create a useSession hook that exposes the current session data (user, status, loading) from the AuthContext.

**Prompt for the agent:**

> Create `src/react/useSession.ts`:
>
> 1. Hook `useSession()` that reads from the `AuthContext` via `useContext`.
> 2. Returns a typed object:
>    - `user: AuthUserClient | null`
>    - `status: AuthStatus` (`'authenticated'` | `'unauthenticated'` | `'loading'`)
>    - `isLoading: boolean`
>    - `refresh: () => Promise<void>`
>    - `lastValidation: Date | null`
> 3. Throw a descriptive error if used outside the `AuthProvider`.
>
> Acceptance criteria:
>
> - Returns correct data from the context
> - Clear throw if used outside the AuthProvider
> - Correct types in the return value
> - JSDoc in English

---

### NEST-164: useAuth hook

- **Phase:** 8
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** NEST-162
- **Agent:** code-reviewer
- **Estimate:** ~20min
- **Description:** Create a useAuth hook that exposes the authentication methods (login, register, logout, etc.) from the AuthContext.

**Prompt for the agent:**

> Create `src/react/useAuth.ts`:
>
> 1. Hook `useAuth()` that reads from the `AuthContext` via `useContext`.
> 2. Returns a typed object with authentication methods:
>    - `login: (email: string, password: string, options?: { tenantId?: string }) => Promise<AuthResult>`
>    - `register: (data: RegisterInput) => Promise<AuthResult>`
>    - `logout: () => Promise<void>`
>    - `forgotPassword: (email: string, tenantId?: string) => Promise<void>`
>    - `resetPassword: (token: string, otp: string, newPassword: string) => Promise<void>`
> 3. Each wrapper method calls the corresponding client method and updates the context state.
> 4. Throw a descriptive error if used outside the `AuthProvider`.
>
> Acceptance criteria:
>
> - All auth methods available
> - Clear throw if used outside the AuthProvider
> - Correct types in the return value
> - JSDoc in English

---

### NEST-165: useAuthStatus hook

- **Phase:** 8
- **Status:** DONE ✅
- **Priority:** Low
- **Dependencies:** NEST-163
- **Agent:** code-reviewer
- **Estimate:** ~10min
- **Description:** Convenience hook that returns only the authentication status in a simplified form (isAuthenticated, isLoading).

**Prompt for the agent:**

> Create `src/react/useAuthStatus.ts`:
>
> 1. Hook `useAuthStatus()` that uses `useSession` internally.
> 2. Returns a simplified object:
>    - `isAuthenticated: boolean` (true when `status === 'authenticated'`)
>    - `isLoading: boolean` (true when `status === 'loading'`)
> 3. Convenience hook for use in route guards and conditional rendering.
>
> Acceptance criteria:
>
> - `isAuthenticated` is `true` only when status is `'authenticated'`
> - `isLoading` is `true` only when status is `'loading'`
> - Uses `useSession` internally (does not duplicate logic)
> - JSDoc in English

---

### NEST-166: React barrel export

- **Phase:** 8
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** NEST-161, NEST-162, NEST-163, NEST-164, NEST-165
- **Agent:** architect
- **Estimate:** ~10min
- **Description:** Create the barrel export of the react subpath with all components, hooks and types exported.

**Prompt for the agent:**

> Create `src/react/index.ts`:
>
> 1. Export the component: `AuthProvider`.
> 2. Export the hooks: `useSession`, `useAuth`, `useAuthStatus`.
> 3. Export the types: `AuthContextValue`, `AuthStatus`, `AuthProviderProps`.
> 4. Use `export type` for interfaces and `export` for components/hooks.
> 5. Verify that it compiles without errors.
>
> Acceptance criteria:
>
> - All public exports of the react subpath are in the barrel
> - `export type` used correctly for types
> - Compiles without errors
> - No circular imports

---

### NEST-167: React hooks tests

- **Phase:** 8
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** NEST-166
- **Agent:** code-reviewer
- **Estimate:** ~45min
- **Description:** Complete unit tests of the React hooks using React Testing Library, with a mocked AuthClient to isolate behavior.

**Prompt for the agent:**

> Write tests in `src/react/__tests__/`:
>
> 1. Configure a mock of the `AuthClient` for all tests.
> 2. Test `AuthProvider`:
>    - Renders children correctly
>    - Calls `client.getMe()` on mount
>    - Transitions from `loading` → `authenticated` when getMe returns a user
>    - Transitions from `loading` → `unauthenticated` when getMe fails
> 3. Test `useSession`:
>    - Returns the correct status on each transition
>    - Throws when used outside the AuthProvider
> 4. Test `useAuth`:
>    - `login` calls `client.login` and updates state
>    - `logout` calls `client.logout` and clears state
>    - Throws when used outside the AuthProvider
> 5. Test revalidation:
>    - `setInterval` configured with the correct interval
>    - Cleanup on unmount
> 6. Use `@testing-library/react` with `renderHook` and `act`.
>
> Acceptance criteria:
>
> - All tests pass
> - Coverage >= 80% in the react files
> - The AuthClient mock does not leak between tests
> - Tests are isolated and deterministic

---

### NEST-168: Phase 8 validation

- **Phase:** 8
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** NEST-167
- **Agent:** architect
- **Estimate:** ~15min
- **Description:** Final validation of Phase 8 — verify the React peer dependency, test coverage, and that the build compiles without errors.

**Prompt for the agent:**

> Run the complete Phase 8 validation:
>
> 1. Verify that `react` is declared as a `peerDependency` with `^19` (not as a direct dependency).
> 2. Verify that the hooks are tested in isolation with a mocked AuthClient.
> 3. Run `pnpm test --coverage` and verify coverage >= 80% in the `src/react/` files.
> 4. Run `pnpm build` and verify compilation without errors.
> 5. Verify that there are no external dependencies besides `react` as a peer dep.
> 6. Verify that the barrel export of `src/react/index.ts` is complete.
>
> Acceptance criteria:
>
> - React ^19 as a peerDependency only
> - Hooks tested in isolation
> - Coverage >= 80%
> - Build without errors

---

## Phase 9 — Next.js Subpath

### NEST-169: isBackgroundRequest helper

- **Phase:** 9
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** NEST-160
- **Agent:** code-reviewer
- **Estimate:** ~15min
- **Description:** Create a helper to detect Next.js parallel requests via headers. Returns a boolean indicating whether the request is a background request (RSC, prefetch or state-tree).

**Prompt for the agent:**

> Create `src/nextjs/helpers/isBackgroundRequest.ts`. The function receives a Request (or NextRequest) and checks for Next.js parallel/background request headers: `RSC: 1`, `Next-Router-Prefetch: 1`, `Next-Router-State-Tree` (presence). Return `true` if any of these headers are detected. This is used by the proxy to return 401 instead of redirect for background requests, preventing redirect loops in client-side navigation. Export the function and its return type. Add JSDoc explaining why background requests need special handling. Verify with `pnpm build`.

---

### NEST-170: buildSilentRefreshUrl helper

- **Phase:** 9
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** NEST-160
- **Agent:** code-reviewer
- **Estimate:** ~10min
- **Description:** Create a helper that builds the URL for `/api/auth/silent-refresh` with a redirect parameter. Accepts a NextRequest and a destination string.

**Prompt for the agent:**

> Create `src/nextjs/helpers/buildSilentRefreshUrl.ts`. The function accepts a NextRequest and a `redirectTo` string parameter. It builds and returns a URL pointing to `/api/auth/silent-refresh` with the `redirect` query parameter set to the provided destination. Use the request's origin to build absolute URLs. Handle edge cases: missing redirectTo defaults to current pathname, encode the redirect param properly. Export the function with JSDoc. Verify with `pnpm build`.

---

### NEST-171: dedupeSetCookieHeaders + parseSetCookieHeader

- **Phase:** 9
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** NEST-160
- **Agent:** security-reviewer
- **Estimate:** ~25min
- **Description:** Create helpers for deduplication and parsing of Set-Cookie headers. Critical for multi-domain white-label setups where multiple Set-Cookie headers may collide.

**Prompt for the agent:**

> Create `src/nextjs/helpers/dedupeSetCookieHeaders.ts` with two exported functions:
>
> 1. `parseSetCookieHeader(raw: string)`: parse a raw Set-Cookie string into an object with properties: `name`, `value`, `httpOnly`, `secure`, `sameSite`, `path`, `domain`, `maxAge`, `expires`. Handle all standard cookie attributes case-insensitively.
> 2. `dedupeSetCookieHeaders(cookies: string[])`: deduplicate an array of Set-Cookie strings where the dedup key is `(name + domain)` — last writer wins. This is critical for multi-domain white-label setups where the backend may send duplicate cookies for different domains.
>    Include a `getSetCookie()` fallback for pre-Node 18.14 environments where `Headers.getSetCookie()` is not available (use `get('set-cookie')` and split on comma boundaries that are NOT inside cookie values). Add JSDoc for all exports. Verify with `pnpm build`.

---

### NEST-172: JWT helpers (decodeJwtToken, verifyJwtToken)

- **Phase:** 9
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** NEST-160
- **Agent:** security-reviewer
- **Estimate:** ~35min
- **Description:** Create JWT helpers for use in the Next.js Edge Runtime. Includes Base64 decoding without signature verification and HS256 verification via the Web Crypto API.

**Prompt for the agent:**

> Create `src/nextjs/helpers/jwt.ts` with the following exports:
>
> 1. `decodeJwtToken(token: string)`: Base64-decode JWT payload without signature verification. Return `DecodedToken` interface with `isValid` computed from `exp` claim. Handle malformed tokens gracefully (return `{ isValid: false }`).
> 2. `verifyJwtToken(token: string, secret?: string)`: HS256 verification using Web Crypto API (`crypto.subtle.importKey` + `crypto.subtle.verify`). CRITICAL: implement algorithm pinning — reject any token with `alg` !== `HS256` (prevents `alg:none` attacks and RS256 confusion). If `secret` (JWT_SECRET) is not provided, fallback to `decodeJwtToken` (decode-only mode).
> 3. Helper functions: `isTokenExpired(token: DecodedToken): boolean`, `getUserRole(token: DecodedToken): string`, `getUserId(token: DecodedToken): string`, `getTenantId(token: DecodedToken): string | undefined`.
>    Define `DecodedToken` interface with standard JWT claims (sub, exp, iat, role, tenantId, etc.). All functions must work in Edge Runtime (no Node.js-specific APIs). Verify with `pnpm build`.

---

### NEST-173: createAuthProxy - config interface and factory skeleton

- **Phase:** 9
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** NEST-169, NEST-170, NEST-171, NEST-172
- **Agent:** architect
- **Estimate:** ~30min
- **Description:** Create the proxy configuration interface and the skeleton of the factory function. Defines the public contract of the Next.js module.

**Prompt for the agent:**

> Create `src/nextjs/createAuthProxy.ts` with the following:
>
> 1. Define `AuthProxyConfig` interface with properties: `publicRoutes: string[]`, `publicRoutesRedirectIfAuthenticated: string[]`, `protectedRoutes: Array<{ pattern: string, allowedRoles: string[], redirectPath?: string }>`, `loginPath: string`, `getDefaultDashboard: (role: string) => string`, `apiBase: string`, `jwtSecret?: string`, `maxRefreshAttempts?: number` (default 2), `cookieNames: { access: string, refresh: string, hasSession: string }`, `userHeaders: { userId: string, role: string, tenantId: string, tenantDomain: string }`, `blockedUserStatuses: string[]`.
> 2. Create `createAuthProxy(config: AuthProxyConfig)` factory function that returns `{ proxy: (request: NextRequest) => Promise<NextResponse>, config }`. The proxy function skeleton should: classify the route (public, protected, API), and call the appropriate handler (to be implemented in NEST-174, NEST-175, NEST-176).
> 3. The factory pattern allows the consuming Next.js app to configure once and export `proxy` for Next.js 16's proxy.ts convention.
>    Export the config interface and factory. Verify with `pnpm build`.

---

### NEST-174: createAuthProxy - public route handling

- **Phase:** 9
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** NEST-173
- **Agent:** security-reviewer
- **Estimate:** ~40min
- **Description:** Implement public route logic in the proxy, including protection against infinite redirect loops. The two guards (`_r` counter and `reason=expired`) were discovered and validated in bymax-fitness-ai.

**Prompt for the agent:**

> Implement public route handling in `src/nextjs/createAuthProxy.ts`:
>
> 1. If user is authenticated AND route is in `publicRoutesRedirectIfAuthenticated` → redirect to dashboard via `getDefaultDashboard(role)`.
> 2. If `has_session` cookie exists AND `reason` query param !== `expired` AND `_r` counter < `maxRefreshAttempts` → redirect to silent-refresh (via `buildSilentRefreshUrl`), incrementing `_r` param.
> 3. If `reason=expired` → show the page as-is (break the redirect loop). This is CRITICAL: it prevents infinite redirect when the backend confirms the session is truly expired.
> 4. If `_r` >= `maxRefreshAttempts` → show the page as-is (break the redirect loop). This is the second safety net: even without `reason=expired`, the counter prevents infinite redirects.
> 5. The `_r` param is incremented on each silent-refresh redirect attempt.
>    CRITICAL: These two guards (steps 3 and 4) are defense-in-depth against the infinite redirect loop discovered in bymax-fitness-ai. Both must be present. Add inline comments explaining the loop prevention logic. Verify with `pnpm build`.

---

### NEST-175: createAuthProxy - protected route handling

- **Phase:** 9
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** NEST-173
- **Agent:** security-reviewer
- **Estimate:** ~35min
- **Description:** Implement protected route logic in the proxy, including JWT verification, RBAC and user status blocking.

**Prompt for the agent:**

> Implement protected route handling in `src/nextjs/createAuthProxy.ts`:
>
> 1. No token + `has_session` cookie + `_r` < max → redirect to silent-refresh (same counter logic as public routes).
> 2. No token + no `has_session` → redirect to `loginPath`.
> 3. Invalid/expired token → same `has_session`/silent-refresh logic as step 1.
> 4. Valid token + blocked status (check `blockedUserStatuses` array, e.g., BANNED, INACTIVE, EXPIRED) → redirect to `loginPath` with `reason` query param indicating the block reason.
> 5. Valid token + role NOT in `allowedRoles` for matched route → redirect to `getDefaultDashboard(userRole)` with `error=forbidden` query param.
> 6. Valid token + allowed role → `NextResponse.next()` with user headers injected (x-user-id, x-user-role, x-tenant-id, x-tenant-domain).
>    Use `verifyJwtToken` for token validation. Reuse the `_r` counter mechanism from public routes. Verify with `pnpm build`.

---

### NEST-176: createAuthProxy - background request handling + user headers

- **Phase:** 9
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** NEST-173
- **Agent:** code-reviewer
- **Estimate:** ~20min
- **Description:** Integrate background request detection and user header propagation after successful authentication.

**Prompt for the agent:**

> Implement background request handling and user header propagation in `src/nextjs/createAuthProxy.ts`:
>
> 1. At the beginning of the proxy function (before public/protected route logic), check `isBackgroundRequest(request)`. If true AND the user is not authenticated, return a 401 Response instead of redirecting. This prevents Next.js RSC/prefetch/state-tree requests from triggering redirect chains.
> 2. After successful authentication in protected routes: propagate user information via request headers using the configured `userHeaders` mapping — set `x-user-id`, `x-user-role`, `x-tenant-id`, `x-tenant-domain` from the decoded JWT token.
> 3. After successful authentication: clean up the `_r` query parameter from the URL to avoid leaking internal state to the page. Use `NextResponse.rewrite()` or URL manipulation to strip it.
>    Add JSDoc explaining why background requests need 401 instead of redirect. Verify with `pnpm build`.

---

### NEST-177: createSilentRefreshHandler

- **Phase:** 9
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** NEST-171
- **Agent:** security-reviewer
- **Estimate:** ~40min
- **Description:** Create a handler for the `/api/auth/silent-refresh` route. Performs a silent token refresh via the backend and redirects back with updated cookies.

**Prompt for the agent:**

> Create `src/nextjs/createSilentRefreshHandler.ts`:
>
> 1. Export a factory `createSilentRefreshHandler(config)` that returns a GET handler for `/api/auth/silent-refresh`.
> 2. GET handler logic: extract `redirect` query param as destination. Forward cookies from the incoming request to the backend `POST /auth/refresh` endpoint.
> 3. On success (2xx from backend): redirect to destination URL with `Set-Cookie` headers propagated using `dedupeSetCookieHeaders` to avoid duplicates.
> 4. On failure (non-2xx from backend): redirect to `loginPath?reason=expired`. Clear all 3 cookies: access token (path `/`), refresh token (path `/api/auth`), has_session (path `/`). Set each with `Max-Age=0`.
> 5. CRITICAL — Open redirect defense: validate that `redirect` param starts with `/`, does NOT start with `//`, and resolves to the same origin after URL resolution. Reject anything else by defaulting to `loginPath`.
> 6. Include `getSetCookie()` fallback for older runtimes (pre-Node 18.14).
>    Export the factory and its config type. Verify with `pnpm build`.

---

### NEST-178: createClientRefreshHandler

- **Phase:** 9
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** NEST-171
- **Agent:** code-reviewer
- **Estimate:** ~20min
- **Description:** Create a POST handler for client-side refresh. Acts as a same-origin bridge so that the client JavaScript can renew tokens.

**Prompt for the agent:**

> Create `src/nextjs/createClientRefreshHandler.ts`:
>
> 1. Export a factory `createClientRefreshHandler(config)` that returns a POST handler.
> 2. POST handler logic: forward cookies from the incoming request to the backend `POST /auth/refresh` endpoint.
> 3. On success: return `200` response with `Set-Cookie` headers propagated via `dedupeSetCookieHeaders`.
> 4. On failure: return `401` response with empty body.
> 5. This handler acts as a same-origin bridge for client-side JavaScript refresh — the browser sends cookies automatically, and we forward them to the backend API.
>    Export the factory and config type. Verify with `pnpm build`.

---

### NEST-179: createLogoutHandler

- **Phase:** 9
- **Status:** DONE ✅
- **Priority:** Medium
- **Dependencies:** NEST-171
- **Agent:** code-reviewer
- **Estimate:** ~15min
- **Description:** Create a POST handler for logout. Forwards to the backend and clears cookies on the response.

**Prompt for the agent:**

> Create `src/nextjs/createLogoutHandler.ts`:
>
> 1. Export a factory `createLogoutHandler(config)` that returns a POST handler.
> 2. POST handler logic: forward cookies from the incoming request to the backend `POST /auth/logout` endpoint.
> 3. Regardless of backend response: clear all auth cookies (access token at `/`, refresh token at `/api/auth`, has_session at `/`) by setting `Max-Age=0`.
> 4. Return redirect to `loginPath` or a 200 response (configurable).
>    Export the factory and config type. Verify with `pnpm build`.

---

### NEST-180: Next.js barrel export

- **Phase:** 9
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** NEST-173, NEST-174, NEST-175, NEST-176, NEST-177, NEST-178, NEST-179
- **Agent:** architect
- **Estimate:** ~10min
- **Description:** Create the barrel export of the `nextjs` subpath gathering all factories, helpers and types.

**Prompt for the agent:**

> Create `src/nextjs/index.ts` as the barrel export for the Next.js subpath. Export all public APIs:
>
> - Factories: `createAuthProxy`, `createSilentRefreshHandler`, `createClientRefreshHandler`, `createLogoutHandler`
> - Helpers: `isBackgroundRequest`, `buildSilentRefreshUrl`, `dedupeSetCookieHeaders`, `parseSetCookieHeader`, `decodeJwtToken`, `verifyJwtToken`, `isTokenExpired`, `getUserRole`, `getUserId`, `getTenantId`
> - Types: `AuthProxyConfig`, `DecodedToken`, and any other public interfaces
>   Use `export type` for type-only exports to ensure proper tree-shaking. Verify with `pnpm build`. Ensure no circular dependencies.

---

### NEST-181: Proxy tests - redirect loop prevention

- **Phase:** 9
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** NEST-180
- **Agent:** security-reviewer
- **Estimate:** ~45min
- **Description:** Critical tests to validate that the infinite redirect loop prevention mechanism works correctly. These scenarios were discovered in production in bymax-fitness-ai.

**Prompt for the agent:**

> Create tests for the redirect loop prevention logic in the proxy. File: `src/nextjs/__tests__/createAuthProxy.loop.spec.ts`.
> Test scenarios:
>
> 1. `_r` counter increments on each silent-refresh redirect attempt.
> 2. `_r` counter reaching `maxRefreshAttempts` stops the redirect loop and shows the page.
> 3. `reason=expired` query param stops the redirect loop on public routes.
> 4. Combination: `_r` at max AND `reason=expired` — both guards work as defense-in-depth.
> 5. `_r` param is cleaned up from the URL after successful authentication.
> 6. `_r` counter resets when navigating to a different route.
>    Mock `NextRequest` and `NextResponse` appropriately. Use `jest.fn()` or equivalent for URL manipulation. These tests are CRITICAL — they validate the fix for the infinite redirect loop discovered in bymax-fitness-ai. Verify with `pnpm test`.

---

### NEST-182: Proxy tests - background requests, RBAC, status blocking

- **Phase:** 9
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** NEST-180
- **Agent:** code-reviewer
- **Estimate:** ~35min
- **Description:** Tests for background request detection, role-based access control and user status blocking.

**Prompt for the agent:**

> Create tests for proxy RBAC and background request handling. File: `src/nextjs/__tests__/createAuthProxy.rbac.spec.ts`.
> Test scenarios:
>
> 1. `isBackgroundRequest` returns 401 for requests with `RSC: 1` header.
> 2. `isBackgroundRequest` returns 401 for requests with `Next-Router-Prefetch: 1` header.
> 3. `isBackgroundRequest` returns 401 for requests with `Next-Router-State-Tree` header.
> 4. Background requests with valid auth pass through normally.
> 5. RBAC: user with wrong role is redirected to their default dashboard with `error=forbidden`.
> 6. RBAC: user with correct role passes through.
> 7. Status blocking: BANNED user is redirected to login with `reason=banned`.
> 8. Status blocking: INACTIVE user is redirected to login with `reason=inactive`.
> 9. User header propagation: verify `x-user-id`, `x-user-role`, `x-tenant-id`, `x-tenant-domain` are set on the request.
> 10. Authenticated user visiting a public-but-redirect route (e.g., `/auth/login` configured via `publicRoutesRedirectIfAuthenticated`) gets redirected to their dashboard.
>     Mock `NextRequest` and `NextResponse`. Verify with `pnpm test`.

---

### NEST-183: Route handler tests

- **Phase:** 9
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** NEST-180
- **Agent:** code-reviewer
- **Estimate:** ~30min
- **Description:** Tests for the route handlers (silent-refresh, client-refresh, logout), including open redirect defense.

**Prompt for the agent:**

> Create tests for route handlers. File: `src/nextjs/__tests__/routeHandlers.spec.ts`.
> Test scenarios for `createSilentRefreshHandler`:
>
> 1. Success path: backend returns 2xx → redirect to destination with Set-Cookie propagated.
> 2. Failure path: backend returns 401 → redirect to loginPath with `reason=expired`, all 3 cookies cleared.
> 3. Open redirect defense: `redirect=/valid/path` works, `redirect=//evil.com` is rejected, `redirect=https://evil.com` is rejected.
> 4. Cookie deduplication: multiple Set-Cookie headers are deduplicated correctly.
>    Test scenarios for `createClientRefreshHandler`:
> 5. Success: backend 2xx → response 200 with Set-Cookie.
> 6. Failure: backend 401 → response 401.
>    Test scenarios for `createLogoutHandler`:
> 7. Cookies are cleared regardless of backend response.
>    Mock `fetch` for backend calls. Verify with `pnpm test`.

---

### NEST-184: JWT helper tests

- **Phase:** 9
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** NEST-172
- **Agent:** security-reviewer
- **Estimate:** ~25min
- **Description:** Security tests for the JWT helpers, including validation against known attacks such as `alg:none` and RS256/HS256 confusion.

**Prompt for the agent:**

> Create tests for JWT helpers. File: `src/nextjs/__tests__/jwt.spec.ts`.
> Test scenarios for `decodeJwtToken`:
>
> 1. Valid JWT with future `exp` → `isValid: true` with correct claims.
> 2. Expired JWT → `isValid: false` with claims still accessible.
> 3. Malformed JWT (not 3 parts) → `isValid: false`.
> 4. Invalid Base64 in payload → `isValid: false`.
>    Test scenarios for `verifyJwtToken`:
> 5. Valid HS256 token with correct secret → verified successfully.
> 6. Valid HS256 token with wrong secret → verification fails.
> 7. SECURITY: `alg:none` attack → rejected (algorithm pinning).
> 8. SECURITY: RS256 token presented to HS256 verifier → rejected.
> 9. Fallback: when JWT_SECRET is not provided, falls back to `decodeJwtToken` (decode-only).
>    Test helper functions: `isTokenExpired`, `getUserRole`, `getUserId`, `getTenantId`.
>    Use real JWT tokens generated in test setup (base64-encode manually or use a test helper). Verify with `pnpm test`.

---

### NEST-185: Phase 9 validation

- **Phase:** 9
- **Status:** DONE ✅
- **Priority:** High
- **Dependencies:** NEST-180, NEST-181, NEST-182, NEST-183, NEST-184
- **Agent:** architect
- **Estimate:** ~20min
- **Description:** Final checklist for Phase 9 — validate that the Next.js subpath is complete, tested and ready for integration.

**Prompt for the agent:**

> Execute the Phase 9 validation checklist:
>
> 1. [ ] Verify peer dependencies: `next ^16` and `react ^19` are declared.
> 2. [ ] Verify proxy logic has 90%+ test coverage on critical paths (redirect loop, RBAC, status blocking).
> 3. [ ] Verify ALL redirect loop scenarios are tested (NEST-181).
> 4. [ ] Verify `pnpm build` compiles without errors.
> 5. [ ] Verify open redirect defense is tested (NEST-183).
> 6. [ ] Verify `alg:none` and RS256 confusion attacks are tested (NEST-184).
> 7. [ ] Verify barrel export includes all public APIs with correct `export type` usage.
> 8. [ ] Verify all helpers work in Edge Runtime (no Node.js-specific APIs except where fallback is provided).
> 9. [ ] Verify `dedupeSetCookieHeaders` handles multi-domain white-label scenarios.
> 10. [ ] Verify background request detection covers RSC, prefetch, and state-tree headers.
>         For each item, mark PASS or FAIL with evidence. If any FAIL, list corrective action.
>         Acceptance criteria: all 10 items PASS.

---

## Critical Path

The critical path determines the minimum duration of the project. The longest dependency chains are:

**Main Chain (Phases 1-2):**

1. NEST-001 (scaffold) → NEST-005 (interfaces) → NEST-015 (defaults) → NEST-016 (resolveOptions) → NEST-041 (Phase 1 barrel) → NEST-042 (Phase 1 validation)
2. NEST-042 → NEST-043 (JWT Strategy) → NEST-057 (AuthService) → NEST-059 (AuthController) → NEST-061 (BymaxAuthModule) → NEST-064 (Phase 2 validation)

**MFA Chain (Phase 3):** 3. NEST-064 → NEST-068 (MfaService helpers) → NEST-069 (MfaService skeleton) → NEST-070 (setup) → NEST-071 (verifyAndEnable) → NEST-072 (challenge) → NEST-073 (MfaController) → NEST-074 (module integration) → NEST-079 (Phase 3 validation)

**Sessions + Password Reset Chain (Phase 4):** 4. NEST-064 → NEST-081 (SessionService create) → NEST-082 (list/revoke) → NEST-083 (rotate) → NEST-086 (integration) → NEST-096 (Phase 4 validation) 5. NEST-064 → NEST-085 (PasswordResetService initiate) → NEST-086 (resetPassword) → NEST-087 (verifyOtp/resendOtp) → NEST-088 (controller) → NEST-096 (Phase 4 validation)

**Platform + OAuth + Invitations Chain (Phase 5):** 6. NEST-064 → NEST-097 (JWT Platform Strategy) → NEST-101 (PlatformAuthService login) → NEST-107 (controller) → NEST-119 (module integration) → NEST-120 (barrel) 7. NEST-064 → NEST-109 (OAuthModule) → NEST-110 (OAuthService initiate) → NEST-111 (callback) → NEST-119 (module integration) 8. NEST-064 → NEST-115 (InvitationService invite) → NEST-116 (accept) → NEST-117 (controller) → NEST-119 (module integration)

**Integration Chain (Phase 6):** 9. NEST-120 → NEST-122 (WsJwtGuard) → NEST-141 (Test Coverage) → NEST-149 (npm Publish Prep) → NEST-151 (Final Validation)

**Frontend Chain (Phases 7-9):** 10. NEST-151 → NEST-152 (shared types) → NEST-154 (shared barrel) → NEST-155 (createAuthFetch) → NEST-158 (createAuthClient) → NEST-160 (Phase 7 validation) 11. NEST-160 → NEST-161 (AuthContext) → NEST-162 (AuthProvider) → NEST-167 (tests) → NEST-168 (Phase 8 validation) 12. NEST-160 → NEST-173 (createAuthProxy skeleton) → NEST-174 (public routes) → NEST-177 (silent-refresh) → NEST-181 (proxy tests) → NEST-185 (Phase 9 validation)

**Estimated critical path duration:** ~8 weeks (1 developer + AI agent)

## Parallelizable Tasks

Groups of tasks that can be executed simultaneously:

**Phase 1 — Initial parallelism:**

- NEST-002, NEST-003, NEST-004 (all depend only on NEST-001)
- NEST-005 to NEST-013 (interfaces, all depend on NEST-004)
- NEST-014, NEST-018, NEST-020, NEST-023 (constants and utils, depend on NEST-004)
- NEST-024, NEST-025 (crypto utils, depend on NEST-004)
- NEST-027, NEST-030 (Redis and Password services, depend on NEST-014)

**Phase 2 — Parallelism:**

- NEST-049, NEST-050 (decorators, depend on NEST-004)
- NEST-052, NEST-053 (DTOs, depend on NEST-004)
- NEST-043, NEST-045, NEST-046, NEST-047 (strategy and guards, post-Phase 1)

**Phase 3 + 4 — Can run in parallel:**

- Phase 3 (MFA: NEST-065..079) and Phase 4 (Sessions + Password Reset: NEST-080..096) both depend on Phase 2, but are independent of each other until integration

**Phase 5 — Three parallel tracks:**

- Platform Auth (NEST-097..108)
- OAuth (NEST-108..113)
- Invitations (NEST-113..118)

**Phase 6 — Parallelism in tests and reviews:**

- E2E tests (NEST-125..132) can run in parallel with each other
- Security reviews (NEST-134..136) can run in parallel
- JSDoc (NEST-137..138) can run in parallel with tests

**Phase 8 + 9 — Can run in parallel:**

- Phase 8 (React: NEST-161..168) and Phase 9 (Next.js: NEST-169..185) both depend on Phase 7, but are independent of each other
- Within Phase 9, helpers (NEST-169..172) can run in parallel
- Tests (NEST-181..184) can run in parallel with each other
4