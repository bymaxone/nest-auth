# Development Tasks — @bymax-one/nest-auth

> Gerado em: 2026-04-11
> Baseado em: [development_plan.md](./development_plan.md) e [technical_specification.md](./technical_specification.md)
> Total de tasks: 151

---

## Controle de Status

| Status | Emoji | Descricao |
|--------|-------|-----------|
| TODO | ⬜ | Nao iniciada |
| IN_PROGRESS | 🔄 | Em andamento |
| DONE | ✅ | Concluida e verificada |
| BLOCKED | 🚫 | Bloqueada por dependencia |
| REVIEW | 👀 | Em revisao |

## Agentes Especialistas

| Agente | Quando usar |
|--------|------------|
| `architect` | Design de interfaces, modulo dinamico, estrutura de projeto, barrel exports |
| `planner` | Planejamento de sub-sistemas complexos |
| `typescript-reviewer` | Revisao de tipagem, interfaces, generics, DTOs |
| `security-reviewer` | Crypto (AES-GCM, bcrypt), JWT, brute-force, constant-time, CSRF |
| `code-reviewer` | Qualidade geral, patterns NestJS, services, controllers, guards |
| `database-reviewer` | Operacoes Redis, scripts Lua, design de chaves |
| `general-purpose` | Scaffold, configuracao, setup inicial, testes |

## Dashboard de Progresso

| Fase | Total | TODO | DONE | Progresso |
|------|-------|------|------|-----------|
| Fase 1 — Fundacao e Infraestrutura | 42 | 42 | 0 | 0% |
| Fase 2 — Autenticacao Core | 22 | 22 | 0 | 0% |
| Fase 3 — Autenticacao Multi-Fator (MFA) | 15 | 15 | 0 | 0% |
| Fase 4 — Sessoes e Reset de Senha | 17 | 17 | 0 | 0% |
| Fase 5 — Plataforma, OAuth e Convites | 25 | 25 | 0 | 0% |
| Fase 6 — Integracao, Polimento e Publicacao | 30 | 30 | 0 | 0% |
| **TOTAL** | **151** | **151** | **0** | **0%** |

---

## Fase 1 — Fundacao e Infraestrutura

### ⬜ NEST-001: Project scaffold - package.json and npm init
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Alta
- **Dependencias:** Nenhuma
- **Agente:** architect
- **Estimativa:** ~20min
- **Descricao:** Initialize the npm package with scope @bymax-one, configure package.json with name, version, peer dependencies, scripts (build, lint, test, test:cov, prepublishOnly), and "files": ["dist"].

**Prompt para o agente:**
> Create the package.json for @bymax-one/nest-auth v1.0.0. Run `npm init` with scope @bymax-one. Configure scripts: "build": "tsc -p tsconfig.build.json", "lint": "eslint src/**/*.ts", "test": "jest", "test:cov": "jest --coverage", "prepublishOnly": "npm run build". Set "files": ["dist"] for precise publish control. Add peer dependencies as specified in section 18 of /Users/maximiliano/Documents/My Apps/nest-auth/docs/technical_specification.md: @nestjs/common, @nestjs/core, @nestjs/jwt, @nestjs/passport, @nestjs/throttler, passport, passport-jwt, ioredis, class-validator, class-transformer, bcrypt, express. Add otpauth ^9.0.0 as a direct dependency. Install devDependencies: @nestjs/testing, jest, ts-jest, typescript, @types/bcrypt, @types/passport-jwt, @types/node, @types/express. Verify npm install succeeds.

---

### ⬜ NEST-002: Project scaffold - TypeScript configuration
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-001
- **Agente:** architect
- **Estimativa:** ~20min
- **Descricao:** Create tsconfig.json and tsconfig.build.json with strict mode, ES2022 target, decorator support, and declaration output.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/tsconfig.json with: target ES2022, module commonjs, strict true, experimentalDecorators true, emitDecoratorMetadata true, declaration true, declarationMap true, sourceMap true, outDir "./dist", rootDir "./src", esModuleInterop true, skipLibCheck true. Create /Users/maximiliano/Documents/My Apps/nest-auth/tsconfig.build.json that extends ./tsconfig.json and excludes ["**/*.spec.ts", "test/", "node_modules/"]. Verify tsc --noEmit succeeds after creating a minimal src/index.ts.

---

### ⬜ NEST-003: Project scaffold - ESLint, Jest, and misc config files
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-001
- **Agente:** architect
- **Estimativa:** ~20min
- **Descricao:** Configure ESLint with @typescript-eslint, Jest with ts-jest preset and 80% coverage thresholds, .gitignore, LICENSE (MIT), and empty CHANGELOG.md.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/.eslintrc.js with @typescript-eslint plugin and NestJS-appropriate rules. Create /Users/maximiliano/Documents/My Apps/nest-auth/jest.config.ts with preset ts-jest, rootDir src/, coverage thresholds of 80% for branches, functions, lines, and statements. Create .gitignore (node_modules/, dist/, coverage/, .env). Create LICENSE with MIT license per section 1.4 of the spec. Create CHANGELOG.md as empty placeholder. Create src/index.ts as empty barrel export. Verify `npm run build` compiles without errors.

---

### ⬜ NEST-004: Project scaffold - directory structure
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-001
- **Agente:** architect
- **Estimativa:** ~20min
- **Descricao:** Create all source subdirectories under src/ as specified in the development plan.

**Prompt para o agente:**
> Create the following directory structure under /Users/maximiliano/Documents/My Apps/nest-auth/src/: interfaces/, config/, services/, controllers/, guards/, decorators/, strategies/, redis/, dto/, crypto/, errors/, oauth/, constants/, providers/, hooks/. Each directory should have a .gitkeep file or index.ts placeholder as appropriate. Verify the structure is correct.

---

### ⬜ NEST-005: Interface - BymaxAuthModuleOptions
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-004
- **Agente:** typescript-reviewer
- **Estimativa:** ~45min
- **Descricao:** Implement the main module options interface with all 15 configuration groups as specified in section 4.1 of the technical specification.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/interfaces/auth-module-options.interface.ts. Implement interface BymaxAuthModuleOptions with all 15 groups from section 4.1 of /Users/maximiliano/Documents/My Apps/nest-auth/docs/technical_specification.md: jwt (secret, algorithm, accessExpiresIn, refreshExpiresInDays, refreshGraceWindowSeconds), password (saltRounds, minLength, maxLength), tokenDelivery ('cookie'|'bearer'|'both'), cookies (accessTokenName, refreshTokenName, sessionSignalName, secure, sameSite, httpOnly, refreshCookiePath, resolveDomains), mfa (encryptionKey, issuer, totpWindow, recoveryCodeCount), sessions (enabled, maxSessions, maxSessionsResolver, newSessionAlert), bruteForce (maxAttempts, windowSeconds), passwordReset (method, otpLength, otpTtlSeconds, tokenTtlSeconds), emailVerification (required, otpTtlSeconds), platformAdmin (enabled, platformHierarchy), invitations (enabled, tokenTtlDays, maxPendingPerTenant), roles (hierarchy), blockedStatuses, oauth (google, github, etc.), controllers (auth, mfa, sessions, passwordReset, platform, oauth, invitations). Type tenantIdResolver as (req: import('express').Request) => string | Promise<string>. Add routePrefix (default 'auth'), namespace for Redis. Add JSDoc to every property. All groups except jwt should be optional.

---

### ⬜ NEST-006: Interface - AuthUser and IUserRepository
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-004
- **Agente:** typescript-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implement AuthUser interface (15 fields) and IUserRepository interface (11 methods) per the spec.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/interfaces/user-repository.interface.ts. Implement AuthUser with 15 fields: id, email, name, passwordHash (string|null for OAuth users), role, status, tenantId, emailVerified, mfaEnabled (optional), mfaSecret (optional), mfaRecoveryCodes (optional string[]), lastLoginAt (Date|null), oauthProvider (optional), oauthId (optional), createdAt. Implement IUserRepository with 11 methods: findById(id, tenantId?): Promise<AuthUser|null>, findByEmail(email, tenantId): Promise<AuthUser|null>, create(data) where data accepts passwordHash: string|null, updatePassword(id, hash), updateMfa(id, data: {mfaEnabled, mfaSecret, mfaRecoveryCodes}), updateLastLogin(id), updateStatus(id, status), updateEmailVerified(id, verified), findByOAuthId(provider, oauthId, tenantId), linkOAuth(userId, provider, oauthId), createWithOAuth(data). Add JSDoc on every method.

---

### ⬜ NEST-007: Interface - AuthPlatformUser and IPlatformUserRepository
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-004
- **Agente:** typescript-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implement AuthPlatformUser interface (13 fields) and IPlatformUserRepository interface (6 methods).

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/interfaces/platform-user-repository.interface.ts. Implement AuthPlatformUser with 13 fields as specified in the spec. Implement IPlatformUserRepository with 6 methods: findById, findByEmail, updateLastLogin, updateMfa, updatePassword, updateStatus. Add JSDoc on every method. Reference section 11 of /Users/maximiliano/Documents/My Apps/nest-auth/docs/technical_specification.md.

---

### ⬜ NEST-008: Interface - IEmailProvider
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-004
- **Agente:** typescript-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implement IEmailProvider with 7 email methods, each accepting optional locale parameter.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/interfaces/email-provider.interface.ts. Implement IEmailProvider with 7 methods: sendPasswordResetToken(email, token, locale?), sendPasswordResetOtp(email, otp, locale?), sendEmailVerificationOtp(email, otp, locale?), sendMfaEnabledNotification(email, locale?), sendMfaDisabledNotification(email, locale?), sendNewSessionAlert(email, sessionInfo, locale?), sendInvitation(email, inviteData, locale?). All methods return Promise<void>. Add JSDoc with parameter descriptions. Reference section 10 of the technical spec.

---

### ⬜ NEST-009: Interface - IAuthHooks, HookContext, and related types
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-004
- **Agente:** typescript-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implement IAuthHooks interface with 12 optional hooks, HookContext, BeforeRegisterResult, OAuthLoginResult, and OAuthProfile types.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/interfaces/auth-hooks.interface.ts. Implement HookContext with { userId?, email?, tenantId?, ip: string, userAgent: string, headers: Record<string, string> } where headers are sanitized. Implement BeforeRegisterResult { allowed: boolean, reason?: string, modifiedData?: { role?, status?, emailVerified? } }. Implement OAuthLoginResult { action: 'link'|'create'|'reject', reason?: string }. Implement OAuthProfile { provider, providerId, email, name?, avatar? }. Implement IAuthHooks with 12 OPTIONAL methods (all with ?): beforeRegister, afterRegister, beforeLogin, afterLogin, afterLogout, afterMfaEnabled, afterMfaDisabled, onNewSession, afterEmailVerified, afterPasswordReset, onOAuthLogin, afterInvitationAccepted. Add JSDoc. Also implement sanitizeHeaders(headers: Record<string,string>): Record<string,string> function that blocklists ['authorization','cookie','x-api-key','x-auth-token','x-csrf-token','x-session-id'] plus pattern /^x-.*-token$/i. Include unit tests for sanitizeHeaders in a separate spec file.

---

### ⬜ NEST-010: Interface - JWT Payload types
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-004
- **Agente:** typescript-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implement DashboardJwtPayload, PlatformJwtPayload, and MfaTempPayload interfaces.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/interfaces/jwt-payload.interface.ts. Implement DashboardJwtPayload with fields: jti (string), sub (string), tenantId (string), role (string), type (literal 'dashboard'), status (string), mfaVerified (boolean), iat (number), exp (number). Note: emailVerified is NOT a JWT claim. Implement PlatformJwtPayload with: jti, sub, role, type (literal 'platform'), mfaVerified, iat, exp. Implement MfaTempPayload with: sub, type (literal 'mfa_challenge'), context ('dashboard'|'platform'), iat, exp. Add JSDoc explaining each interface's purpose.

---

### ⬜ NEST-011: Interface - AuthResult, PlatformAuthResult, MfaChallengeResult
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-006
- **Agente:** typescript-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implement result interfaces needed from Phase 1 onwards for compilation of later phases.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/interfaces/auth-result.interface.ts. Implement AuthResult { user: AuthUser, accessToken: string, rawRefreshToken: string, sessionHash?: string }. Implement PlatformAuthResult { admin: AuthPlatformUser, accessToken: string, rawRefreshToken: string }. Implement MfaChallengeResult { mfaRequired: true, mfaToken: string }. IMPORTANT: Use rawRefreshToken (never refreshToken) as field name everywhere. These are defined here (not in services) so Phase 1 barrel export can include them. Import AuthUser from ./user-repository.interface and AuthPlatformUser from ./platform-user-repository.interface. Add JSDoc.

---

### ⬜ NEST-012: Interface - AuthenticatedRequest types
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-010
- **Agente:** typescript-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implement AuthenticatedRequest and PlatformAuthenticatedRequest interfaces extending Express Request.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/interfaces/authenticated-request.interface.ts. Implement AuthenticatedRequest extending import('express').Request with user: DashboardJwtPayload. Implement PlatformAuthenticatedRequest extending Request with user: PlatformJwtPayload. Import payload types from ./jwt-payload.interface. Add JSDoc.

---

### ⬜ NEST-013: Interface - OAuthProviderPlugin
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-004
- **Agente:** typescript-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implement OAuthProviderPlugin interface with deliberate any escape hatch for Passport profiles.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/interfaces/oauth-provider.interface.ts. Implement OAuthProviderPlugin { name: string, strategy: any, guard: any, extractProfile(passportUser: any): OAuthProfile }. The `any` on extractProfile's param is a deliberate escape hatch because Passport profiles are untyped — add JSDoc /** @param passportUser Raw Passport profile object — uses `any` because Passport provider profiles have no shared type */ explaining this. Import OAuthProfile from ./auth-hooks.interface.

---

### ⬜ NEST-014: Constants - Injection tokens (6 Symbols)
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-004
- **Agente:** architect
- **Estimativa:** ~30min
- **Descricao:** Create the 6 Symbol-based injection tokens used for DI throughout the package.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/bymax-one-nest-auth.constants.ts. Export 6 Symbols: BYMAX_AUTH_OPTIONS = Symbol('BYMAX_AUTH_OPTIONS'), BYMAX_AUTH_USER_REPOSITORY = Symbol('BYMAX_AUTH_USER_REPOSITORY'), BYMAX_AUTH_PLATFORM_USER_REPOSITORY = Symbol('BYMAX_AUTH_PLATFORM_USER_REPOSITORY'), BYMAX_AUTH_EMAIL_PROVIDER = Symbol('BYMAX_AUTH_EMAIL_PROVIDER'), BYMAX_AUTH_HOOKS = Symbol('BYMAX_AUTH_HOOKS'), BYMAX_AUTH_REDIS_CLIENT = Symbol('BYMAX_AUTH_REDIS_CLIENT'). Use descriptive Symbol names. Export with `export const` (not export type).

---

### ⬜ NEST-015: Config - Default options
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-005
- **Agente:** architect
- **Estimativa:** ~30min
- **Descricao:** Implement the default options object with all default values from table 4.2 of the spec.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/config/default-options.ts. Export a DEFAULT_OPTIONS constant (typed as DeepPartial<BymaxAuthModuleOptions> or a dedicated DefaultOptions type) with all default values from table 4.2 of /Users/maximiliano/Documents/My Apps/nest-auth/docs/technical_specification.md. Key defaults: jwt.algorithm 'HS256', jwt.accessExpiresIn '15m', jwt.refreshExpiresInDays 7, jwt.refreshGraceWindowSeconds 30, password.saltRounds 12, password.minLength 8, password.maxLength 72, tokenDelivery 'cookie', cookies (accessTokenName 'access_token', refreshTokenName 'refresh_token', sessionSignalName 'has_session', secure true, sameSite 'strict', httpOnly true), mfa.totpWindow 1, mfa.recoveryCodeCount 8, sessions.enabled false, sessions.maxSessions 5, bruteForce.maxAttempts 5, bruteForce.windowSeconds 900, passwordReset.method 'token', passwordReset.otpLength 6, passwordReset.otpTtlSeconds 600, passwordReset.tokenTtlSeconds 3600, emailVerification.required false, emailVerification.otpTtlSeconds 600, routePrefix 'auth', namespace 'auth', blockedStatuses ['BANNED','INACTIVE','SUSPENDED'], platformAdmin.enabled false.

---

### ⬜ NEST-016: Config - resolveOptions implementation
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-005, NEST-015
- **Agente:** security-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implement resolveOptions() with shallow merge per group and all security validations (jwt.secret entropy, mfa.encryptionKey, algorithm pinning, etc.).

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/config/resolved-options.ts. Export type ResolvedOptions (BymaxAuthModuleOptions with all defaults applied — all optional groups become required). Export function resolveOptions(userOptions: BymaxAuthModuleOptions): ResolvedOptions. Implementation: (1) Shallow merge per group using spread: { ...defaults.jwt, ...userOptions.jwt } — NOT JSON.parse/stringify, to preserve function properties like maxSessionsResolver, tenantIdResolver, resolveDomains. (2) Validate jwt.secret: length >= 32 chars, Shannon entropy >= 3.5 bits/char, reject repetitive patterns (e.g., 'aaaa...', '1234...' repeating). (3) Validate jwt.algorithm: if provided must be exactly 'HS256', throw if different. (4) Validate mfa.encryptionKey conditionally: if mfa group provided, encryptionKey required, must decode from base64 to exactly 32 bytes. (5) Validate roles.hierarchy: cannot be empty object. (6) Validate platformHierarchy required if platformAdmin.enabled. (7) Validate peer dependencies: if oauth.google configured, verify passport-google-oauth20 is importable via require.resolve() — throw descriptive error if absent. (8) Validate passwordReset.otpLength <= 8 (above 8 crypto.randomInt exceeds MAX_SAFE_INTEGER). (9) Log warning if routePrefix differs from 'auth' and cookies.refreshCookiePath not explicitly configured. Throw descriptive exceptions for each validation failure.

---

### ⬜ NEST-017: Config - resolveOptions tests
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-016
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Write comprehensive unit tests for resolveOptions covering success paths and all validation failures.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/config/resolved-options.spec.ts. Test cases: (1) Success with valid minimal config (jwt.secret of 32+ chars with high entropy). (2) Reject jwt.secret shorter than 32 chars. (3) Reject jwt.secret with low entropy (e.g., 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'). (4) Reject jwt.algorithm other than HS256. (5) Accept jwt.algorithm HS256 explicitly. (6) Reject mfa.encryptionKey that doesn't decode to 32 bytes. (7) Accept valid mfa.encryptionKey (32 bytes base64). (8) Reject empty roles.hierarchy. (9) Reject platformAdmin.enabled without platformHierarchy. (10) Verify functions are preserved after merge (pass a tenantIdResolver function, assert it's still a function after resolve). (11) Verify shallow merge doesn't deep-clone functions. (12) Reject otpLength > 8. (13) Warning logged when routePrefix differs from 'auth' without explicit refreshCookiePath. All tests should use descriptive names and verify exact error messages.

---

### ⬜ NEST-018: Constants - Throttle configs
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-004
- **Agente:** architect
- **Estimativa:** ~30min
- **Descricao:** Create AUTH_THROTTLE_CONFIGS with 14 endpoint rate limiting configurations per section 16.2.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/constants/throttle-configs.ts. Export AUTH_THROTTLE_CONFIGS object with 14 named throttler configurations per section 16.2 of /Users/maximiliano/Documents/My Apps/nest-auth/docs/technical_specification.md. Each config uses the @nestjs/throttler >= 6.0.0 named throttler API: { default: { limit, ttl } }. Include configs for: register, login, refresh, verifyEmail, resendVerification, mfaSetup, mfaChallenge, mfaDisable, forgotPassword, resetPassword, sessionsList, sessionsRevoke, platformLogin, invitationAccept. Reference the exact limits and TTL windows from the spec.

---

### ⬜ NEST-019: Constants - barrel export and re-exports
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-014, NEST-018
- **Agente:** architect
- **Estimativa:** ~15min
- **Descricao:** Create constants/index.ts with re-exports of public constants.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/constants/index.ts. Re-export AUTH_THROTTLE_CONFIGS from ./throttle-configs. Re-export AUTH_ERROR_CODES from ../errors/auth-error-codes (will be created in NEST-020).

---

### ⬜ NEST-020: Error codes - AUTH_ERROR_CODES and AUTH_ERROR_MESSAGES
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-004
- **Agente:** code-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implement all 33 error codes as a const object with Portuguese message mappings per section 15 of the spec.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/errors/auth-error-codes.ts. Export AUTH_ERROR_CODES typed with `as const` containing all 33 codes from table 15.3 of /Users/maximiliano/Documents/My Apps/nest-auth/docs/technical_specification.md. Must include: INVALID_CREDENTIALS, EMAIL_ALREADY_EXISTS, TOKEN_INVALID, TOKEN_EXPIRED, TOKEN_REVOKED, REFRESH_TOKEN_INVALID, REFRESH_TOKEN_EXPIRED, INSUFFICIENT_ROLE, ACCOUNT_LOCKED, ACCOUNT_BANNED, ACCOUNT_INACTIVE, ACCOUNT_SUSPENDED, FORBIDDEN, PENDING_APPROVAL, MFA_REQUIRED, MFA_INVALID_CODE, MFA_ALREADY_ENABLED, MFA_NOT_ENABLED, MFA_SETUP_REQUIRED, MFA_TEMP_TOKEN_INVALID, EMAIL_NOT_VERIFIED, OTP_EXPIRED, OTP_INVALID, OTP_MAX_ATTEMPTS, SESSION_LIMIT_REACHED, SESSION_NOT_FOUND, OAUTH_FAILED, OAUTH_EMAIL_MISMATCH, PLATFORM_AUTH_REQUIRED, INVITATION_INVALID, INVITATION_EXPIRED, PASSWORD_RESET_TOKEN_INVALID, VALIDATION_ERROR. Also export AUTH_ERROR_MESSAGES mapping each code to a Portuguese message string.

---

### ⬜ NEST-021: Error system - AuthException class
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-020
- **Agente:** code-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implement AuthException extending HttpException with automatic message lookup and standard error format.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/errors/auth-exception.ts. Implement class AuthException extends HttpException. Constructor: (code: string, statusCode: number = 401, details?: Record<string,unknown>). The response body format must be { error: { code, message, details? } } where message is looked up from AUTH_ERROR_MESSAGES[code]. If code not found in messages, use code as message. Import AUTH_ERROR_MESSAGES from ./auth-error-codes. Export the class.

---

### ⬜ NEST-022: Error system - tests
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-020, NEST-021
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Write unit tests for AUTH_ERROR_CODES and AuthException covering format, message lookup, and status codes.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/errors/auth-exception.spec.ts. Test: (1) AuthException creates correct response format { error: { code, message } }. (2) Message is auto-looked up from AUTH_ERROR_MESSAGES. (3) Default status code is 401. (4) Custom status code works (e.g., 403 for FORBIDDEN). (5) Details are included when provided. (6) Unknown code uses code as message. (7) AUTH_ERROR_CODES has exactly 33 entries. (8) AUTH_ERROR_CODES is typed as const (verify a specific code is a string literal type at compile time).

---

### ⬜ NEST-023: Utilities - sleep and hasRole
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-004
- **Agente:** code-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implement sleep utility for timing normalization and hasRole utility for hierarchical role verification.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/utils/sleep.ts with export function sleep(ms: number): Promise<void> wrapping setTimeout in a Promise. Create /Users/maximiliano/Documents/My Apps/nest-auth/src/utils/roles.util.ts with export function hasRole(userRole: string, requiredRole: string, hierarchy: Record<string, string[]>): boolean. The hasRole function checks: (1) exact match userRole === requiredRole returns true, (2) if hierarchy[userRole] includes requiredRole returns true, (3) otherwise false. The hierarchy must be fully denormalized — each role lists ALL transitive descendants. This is a single-level lookup, NOT recursive. Add JSDoc warning that hierarchy must be denormalized. Write unit tests for both utilities: sleep resolves after delay, hasRole exact match, inherited role, insufficient role, missing role in hierarchy.

---

### ⬜ NEST-024: Crypto - AES-256-GCM encrypt/decrypt
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-004
- **Agente:** security-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implement AES-256-GCM encryption and decryption functions using Node.js crypto module.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/crypto/aes-gcm.ts. Implement export function encrypt(plaintext: string, keyBase64: string): string — generate 12-byte IV with crypto.randomBytes(12), decode key from base64, create cipher with crypto.createCipheriv('aes-256-gcm', keyBuffer, iv), return format base64(iv):base64(authTag):base64(ciphertext). Implement export function decrypt(ciphertext: string, keyBase64: string): string — parse the iv:authTag:ciphertext format, create decipher with crypto.createDecipheriv, setAuthTag, return plaintext. NEVER reuse IVs. Key must be exactly 32 bytes when decoded from base64.

---

### ⬜ NEST-025: Crypto - secure token and SHA-256
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-004
- **Agente:** security-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implement generateSecureToken and sha256 utility functions using Node.js crypto.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/crypto/secure-token.ts. Implement export function generateSecureToken(bytes: number = 32): string using crypto.randomBytes(bytes).toString('hex'). Implement export function sha256(input: string): string using crypto.createHash('sha256').update(input).digest('hex'). Both functions use Node.js built-in crypto module only.

---

### ⬜ NEST-026: Crypto - tests
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-024, NEST-025
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Write comprehensive tests for AES-GCM and secure token utilities.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/crypto/aes-gcm.spec.ts. Tests: (1) Round-trip encrypt then decrypt returns original plaintext. (2) Test with various data sizes (empty string, short, long). (3) Two consecutive encryptions produce different ciphertexts (IV uniqueness). (4) Decrypt fails with tampered authTag (integrity check). (5) Decrypt fails with wrong key. (6) Output format matches base64:base64:base64 pattern. Create /Users/maximiliano/Documents/My Apps/nest-auth/src/crypto/secure-token.spec.ts. Tests: (1) generateSecureToken returns hex string of correct length (default 64 hex chars for 32 bytes). (2) generateSecureToken with custom bytes parameter. (3) sha256 returns consistent hash for same input. (4) sha256 returns different hashes for different inputs. (5) sha256 output is 64-char hex string.

---

### ⬜ NEST-027: Redis - AuthRedisService implementation
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-014, NEST-005
- **Agente:** database-reviewer
- **Estimativa:** ~60min
- **Descricao:** Implement AuthRedisService wrapping ioredis with automatic namespace prefixing and all required operations.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/redis/auth-redis.service.ts. Implement @Injectable() class AuthRedisService. Inject BYMAX_AUTH_REDIS_CLIENT (ioredis instance) and BYMAX_AUTH_OPTIONS (for namespace). All methods prefix keys with {namespace}: automatically. Methods: get(key): Promise<string|null>, set(key, value, ttl?): Promise<void> (if ttl use SET key value EX ttl), del(key): Promise<void>, incr(key): Promise<number>, expire(key, ttl): Promise<void>, ttl(key): Promise<number>, sadd(setKey, member): Promise<number>, srem(setKey, member): Promise<number>, smembers(setKey): Promise<string[]>, sismember(setKey, member): Promise<boolean>, eval(script, keys, args): Promise<any> (for Lua scripts — document this any with JSDoc). This service is internal — NOT exported in the public barrel.

---

### ⬜ NEST-028: Redis - AuthRedisModule
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-027
- **Agente:** database-reviewer
- **Estimativa:** ~45min
- **Descricao:** Create the internal NestJS module that registers AuthRedisService as a provider.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/redis/auth-redis.module.ts. Implement @Module({ providers: [AuthRedisService], exports: [AuthRedisService] }) class AuthRedisModule. This is an internal module, not exported publicly.

---

### ⬜ NEST-029: Redis - AuthRedisService tests
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-027
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Write unit tests for AuthRedisService with ioredis mocks verifying namespace prefixing and all operations.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/redis/auth-redis.service.spec.ts. Mock ioredis instance. Test with namespace 'auth'. Tests: (1) get('mykey') calls redis.get('auth:mykey'). (2) set('k','v',60) calls redis.set('auth:k','v','EX',60). (3) set without TTL calls redis.set without EX. (4) del prefixes key. (5) incr prefixes key. (6) expire prefixes key. (7) ttl prefixes key. (8) sadd prefixes set key. (9) srem prefixes set key. (10) smembers prefixes and returns array. (11) sismember prefixes and returns boolean. (12) eval passes prefixed keys. Use NestJS Test.createTestingModule with mock providers.

---

### ⬜ NEST-030: Service - PasswordService
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-014, NEST-005
- **Agente:** code-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implement PasswordService with bcrypt hash and compare, configurable salt rounds.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/services/password.service.ts. Implement @Injectable() class PasswordService. Inject BYMAX_AUTH_OPTIONS to read password.saltRounds (default 12). Implement async hash(plain: string): Promise<string> using bcrypt.hash(plain, saltRounds). Implement async compare(plain: string, hash: string): Promise<boolean> using bcrypt.compare (already constant-time). Add JSDoc.

---

### ⬜ NEST-031: Service - PasswordService tests
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-030
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Write unit tests for PasswordService hash/compare operations.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/services/password.service.spec.ts. Tests: (1) hash produces a valid bcrypt string. (2) compare returns true for correct password. (3) compare returns false for wrong password. (4) Salt rounds from config are respected (use a mock config with saltRounds=10). Use NestJS Test.createTestingModule.

---

### ⬜ NEST-032: Service - TokenManagerService implementation
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-014, NEST-010, NEST-011, NEST-027, NEST-025
- **Agente:** security-reviewer
- **Estimativa:** ~60min
- **Descricao:** Implement TokenManagerService with JWT issuance, opaque refresh tokens, Lua-based rotation, and MFA temp tokens.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/services/token-manager.service.ts. Implement @Injectable() class TokenManagerService. Inject JwtService (@nestjs/jwt), BYMAX_AUTH_OPTIONS, AuthRedisService. Methods: (1) issueAccess(payload: Omit<DashboardJwtPayload,'jti'|'iat'|'exp'>): generate jti internally with crypto.randomUUID(), sign JWT with HS256 and accessExpiresIn. (2) issueTokens(user, ip, userAgent, extraClaims?): call issueAccess, generate refresh with crypto.randomUUID(), store in Redis as rt:{sha256(refresh)} -> JSON {userId,tenantId,role,device,ip,createdAt}, TTL=refreshExpiresInDays*86400, return AuthResult. (3) issuePlatformTokens(admin, ip, userAgent): similar but type:'platform' and refresh prefix prt:. (4) reissueTokens(oldRefresh, ip, userAgent): atomic Lua script per section 12.4 — get old session, generate new refresh, create rotation pointer rp:{sha256(old)}->new TTL=refreshGraceWindowSeconds, create new session rt:{sha256(new)}, delete old. If old not found check grace window rp:{sha256(old)}. If nothing found throw REFRESH_TOKEN_INVALID. (5) decodeToken(token): decode JWT without validating expiration, validate jti exists, add @internal JSDoc warning. (6) issueMfaTempToken(userId, context: 'dashboard'|'platform'): JWT with type:'mfa_challenge', context claim, 5min exp. Store in Redis mfa:{sha256(token)}->userId, TTL 300s. (7) verifyMfaTempToken(token): verify JWT, find in Redis, consume (delete), return {userId, context} — DEVIATION from spec which returns just string.

---

### ⬜ NEST-033: Service - TokenManagerService tests
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-032
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Write comprehensive unit tests for TokenManagerService covering all token operations.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/services/token-manager.service.spec.ts. Mock JwtService and AuthRedisService. Tests: (1) issueAccess generates jti and signs JWT. (2) issueTokens stores refresh in Redis with correct TTL. (3) issuePlatformTokens uses type:'platform'. (4) reissueTokens creates rotation pointer and new session. (5) reissueTokens with expired old token uses grace window. (6) reissueTokens with no old and no grace window throws REFRESH_TOKEN_INVALID. (7) decodeToken returns payload with jti. (8) decodeToken throws TOKEN_INVALID if no jti. (9) issueMfaTempToken stores in Redis with TTL 300. (10) verifyMfaTempToken returns {userId, context}. (11) verifyMfaTempToken consumes token (deletes from Redis). (12) verifyMfaTempToken throws MFA_TEMP_TOKEN_INVALID if not in Redis.

---

### ⬜ NEST-034: Service - TokenDeliveryService implementation
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-014, NEST-005
- **Agente:** code-reviewer
- **Estimativa:** ~60min
- **Descricao:** Implement TokenDeliveryService handling cookie/bearer/both modes for token delivery and extraction.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/services/token-delivery.service.ts. Implement @Injectable() class TokenDeliveryService. Inject BYMAX_AUTH_OPTIONS for tokenDelivery mode and cookies config. Methods: (1) deliverAuthResponse(res, authResult, req?): mode cookie -> set cookies (access httpOnly, refresh httpOnly with path, session signal non-httpOnly) + return {user}. Mode bearer -> return {user, accessToken, refreshToken}. Mode both -> set cookies + return all. Use discriminated return types. (2) deliverRefreshResponse(res, result, req?): same logic for refresh. (3) extractAccessToken(req): cookie mode -> req.cookies[accessTokenName]. bearer -> Authorization Bearer header. both -> cookie first then header. (4) extractRefreshToken(req): cookie -> req.cookies[refreshTokenName]. bearer -> req.body.refreshToken. both -> cookie first then body. (5) clearAuthSession(res, req?): clear all auth cookies on resolved domains. bearer mode -> no-op. (6) resolveCookieDomains(req): call user's resolveDomains if configured, or use extractDomain. (7) extractDomain(req): validate hostname with /^[a-z0-9.-]+$/i, reject invalid chars, fallback to configured domain. Configure cookies per table 14.1: HttpOnly, Secure in prod, SameSite, correct paths. Use @Res({passthrough:true}) pattern.

---

### ⬜ NEST-035: Service - TokenDeliveryService tests
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-034
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Write unit tests for TokenDeliveryService covering all three modes and security validations.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/services/token-delivery.service.spec.ts. Mock Express Request and Response objects. Tests for each mode (cookie, bearer, both): (1) deliverAuthResponse sets correct cookies in cookie mode. (2) deliverAuthResponse returns tokens in bearer mode. (3) deliverAuthResponse does both in both mode. (4) extractAccessToken reads from cookie in cookie mode. (5) extractAccessToken reads from header in bearer mode. (6) extractAccessToken tries cookie first in both mode. (7) extractRefreshToken reads from cookie vs body correctly. (8) clearAuthSession clears cookies in cookie mode, no-op in bearer. (9) extractDomain with valid hostname returns domain. (10) extractDomain with malicious hostname (special chars) falls back to default. (11) Cookie attributes: HttpOnly, Secure, SameSite, path.

---

### ⬜ NEST-036: Service - BruteForceService implementation
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-027, NEST-014
- **Agente:** security-reviewer
- **Estimativa:** ~60min
- **Descricao:** Implement BruteForceService with Redis-backed attempt tracking and lockout logic.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/services/brute-force.service.ts. Implement @Injectable() class BruteForceService. Inject AuthRedisService and BYMAX_AUTH_OPTIONS (bruteForce.maxAttempts, bruteForce.windowSeconds). Methods: (1) async isLockedOut(identifier: string): Promise<boolean> — get lf:{identifier}, parse as number, return count >= maxAttempts. (2) async recordFailure(identifier: string): Promise<void> — INCR lf:{identifier}, EXPIRE lf:{identifier} windowSeconds. (3) async resetFailures(identifier: string): Promise<void> — DEL lf:{identifier}. (4) async getRemainingLockoutSeconds(identifier: string): Promise<number> — TTL lf:{identifier}, return 0 if not locked or key doesn't exist.

---

### ⬜ NEST-037: Service - BruteForceService tests
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-036
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Write unit tests for BruteForceService covering lockout, failure recording, and reset.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/services/brute-force.service.spec.ts. Mock AuthRedisService. Tests: (1) isLockedOut returns false when no attempts recorded. (2) isLockedOut returns false when attempts < maxAttempts. (3) isLockedOut returns true when attempts >= maxAttempts. (4) recordFailure calls incr and expire with correct key and TTL. (5) resetFailures calls del with correct key. (6) getRemainingLockoutSeconds returns TTL when locked. (7) getRemainingLockoutSeconds returns 0 when not locked.

---

### ⬜ NEST-038: Providers - NoOpEmailProvider
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-008
- **Agente:** code-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implement NoOpEmailProvider that logs all email operations via NestJS Logger without sending real emails.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/providers/no-op-email.provider.ts. Implement @Injectable() class NoOpEmailProvider implements IEmailProvider. Use NestJS Logger (private readonly logger = new Logger(NoOpEmailProvider.name)). Each of the 7 methods (sendPasswordResetToken, sendPasswordResetOtp, sendEmailVerificationOtp, sendMfaEnabledNotification, sendMfaDisabledNotification, sendNewSessionAlert, sendInvitation) should log the method name and email address, then return Promise.resolve(). Per section 10.3 of the spec.

---

### ⬜ NEST-039: Hooks - NoOpAuthHooks
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-009
- **Agente:** code-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implement NoOpAuthHooks with safe defaults, including the standard onOAuthLogin logic.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/hooks/no-op-auth.hooks.ts. Implement @Injectable() class NoOpAuthHooks implements IAuthHooks. beforeRegister returns { allowed: true }. All other hooks are no-op (return void/undefined). onOAuthLogin implements default safe logic: if existing user with matching email -> return { action: 'link' }; if no existing user -> return { action: 'create' }; if email mismatch -> return { action: 'reject', reason: 'Email mismatch' }. IMPORTANT: Use explicit types from IAuthHooks for all parameters — never use `any` for sessionInfo, use { device: string; ip: string; sessionHash: string } instead. This is a deliberate deviation from the spec section 9.3 which uses _sessionInfo: any.

---

### ⬜ NEST-040: Providers and Hooks - tests
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-038, NEST-039
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Write unit tests for NoOpEmailProvider and NoOpAuthHooks.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/providers/no-op-email.provider.spec.ts. Test that each method resolves without error and logs the call. Create /Users/maximiliano/Documents/My Apps/nest-auth/src/hooks/no-op-auth.hooks.spec.ts. Test: (1) beforeRegister returns { allowed: true }. (2) onOAuthLogin with matching email returns { action: 'link' }. (3) onOAuthLogin with new user returns { action: 'create' }. (4) onOAuthLogin with email mismatch returns { action: 'reject' }. (5) Other hooks do not throw.

---

### ⬜ NEST-041: Barrel export - Phase 1
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-005, NEST-006, NEST-007, NEST-008, NEST-009, NEST-010, NEST-011, NEST-012, NEST-013, NEST-014, NEST-018, NEST-020, NEST-021, NEST-023, NEST-038, NEST-039
- **Agente:** architect
- **Estimativa:** ~15min
- **Descricao:** Update src/index.ts with all Phase 1 exports, using export type for interfaces and export for values.

**Prompt para o agente:**
> Update /Users/maximiliano/Documents/My Apps/nest-auth/src/index.ts with all Phase 1 exports. Use `export type` for interfaces and type aliases: BymaxAuthModuleOptions, AuthUser, IUserRepository, AuthPlatformUser, IPlatformUserRepository, IEmailProvider, IAuthHooks, HookContext, BeforeRegisterResult, OAuthLoginResult, OAuthProfile, DashboardJwtPayload, PlatformJwtPayload, MfaTempPayload, AuthResult, PlatformAuthResult, MfaChallengeResult, AuthenticatedRequest, PlatformAuthenticatedRequest, OAuthProviderPlugin, ResolvedOptions. Use `export` (value) for: BYMAX_AUTH_OPTIONS, BYMAX_AUTH_USER_REPOSITORY, BYMAX_AUTH_PLATFORM_USER_REPOSITORY, BYMAX_AUTH_EMAIL_PROVIDER, BYMAX_AUTH_HOOKS, BYMAX_AUTH_REDIS_CLIENT (from constants), AuthException, AUTH_ERROR_CODES, AUTH_ERROR_MESSAGES, AUTH_THROTTLE_CONFIGS, NoOpEmailProvider, NoOpAuthHooks, encrypt, decrypt, generateSecureToken, sha256, sleep, hasRole. Do NOT export AuthRedisService (internal). Verify proper import paths.

---

### ⬜ NEST-042: Phase 1 validation - build and test
- **Fase:** 1
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-041
- **Agente:** architect
- **Estimativa:** ~30min
- **Descricao:** Run full build and test suite, verify compilation is clean and coverage meets 80% threshold.

**Prompt para o agente:**
> Run the following validation checks for Phase 1 completion: (1) `npm run build` must compile with zero errors. (2) `npm run test -- --coverage` must pass with >= 80% coverage on branches, functions, lines, statements. (3) Verify all interfaces are exported correctly (check index.ts for both export type and export). (4) Verify AuthResult, PlatformAuthResult, MfaChallengeResult are defined and exported. (5) Verify resolveOptions validates jwt.secret, mfa.encryptionKey, jwt.algorithm and preserves functions after merge. (6) Verify encrypt/decrypt AES-256-GCM round-trip works and IVs are unique. (7) Verify Redis namespace prefixing. (8) Verify PasswordService hash/compare round-trip. (9) Verify BruteForceService lockout. (10) Verify TokenManagerService token operations. (11) Verify TokenDeliveryService in all 3 modes. (12) Verify 33 error codes in AUTH_ERROR_CODES. (13) Verify extractDomain rejects malicious hostnames. Fix any issues found.

---

## Fase 2 — Autenticacao Core

### ⬜ NEST-043: Strategy - JwtStrategy (Passport)
- **Fase:** 2
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-042
- **Agente:** security-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implement JWT Passport strategy with algorithm pinning, blacklist checking, and type validation.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/strategies/jwt.strategy.ts. Implement class JwtStrategy extends PassportStrategy(Strategy, 'jwt') from @nestjs/passport. Inject BYMAX_AUTH_OPTIONS and TokenDeliveryService. In constructor super() call: configure jwtFromRequest to use a custom extractor that calls tokenDeliveryService.extractAccessToken(req). Set secretOrKey from options.jwt.secret. CRITICAL: pin algorithms: ['HS256'] to prevent algorithm confusion attacks (CVE-2015-9235). Set ignoreExpiration: false. In async validate(payload: DashboardJwtPayload): (1) Verify payload.jti exists and is string — throw TOKEN_INVALID if absent. (2) Verify payload.type === 'dashboard' — reject 'platform' and 'mfa_challenge' types. (3) Check blacklist in Redis: get rv:{payload.jti} — if exists throw TOKEN_REVOKED. (4) Return payload to populate request.user. Inject AuthRedisService for blacklist check.

---

### ⬜ NEST-044: Strategy - JwtStrategy tests
- **Fase:** 2
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-043
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Write unit tests for JwtStrategy covering valid tokens, type rejection, blacklist, and missing jti.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/strategies/jwt.strategy.spec.ts. Mock AuthRedisService and TokenDeliveryService. Tests: (1) Valid dashboard token passes validation. (2) Token without jti throws TOKEN_INVALID. (3) Token with type 'platform' is rejected. (4) Token with type 'mfa_challenge' is rejected. (5) Token with jti found in blacklist (rv:{jti}) throws TOKEN_REVOKED. (6) Token not in blacklist passes. (7) Algorithm is pinned to HS256 (verify constructor config).

---

### ⬜ NEST-045: Guard - JwtAuthGuard
- **Fase:** 2
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-043
- **Agente:** code-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implement JwtAuthGuard extending AuthGuard('jwt') with @Public() metadata support.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/guards/jwt-auth.guard.ts. Implement @Injectable() class JwtAuthGuard extends AuthGuard('jwt'). Inject Reflector. Override canActivate(context: ExecutionContext): check IS_PUBLIC_KEY metadata via reflector.getAllAndOverride. If public return true. Otherwise call super.canActivate(context). Override handleRequest(err, user, info) to throw AuthException with appropriate code (TOKEN_INVALID or TOKEN_EXPIRED based on info) if err or !user.

---

### ⬜ NEST-046: Guard - RolesGuard
- **Fase:** 2
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-023, NEST-014
- **Agente:** code-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implement RolesGuard with hierarchical role checking using denormalized hierarchy.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/guards/roles.guard.ts. Implement @Injectable() class RolesGuard implements CanActivate. Inject Reflector and BYMAX_AUTH_OPTIONS. In canActivate: read required roles from ROLES_KEY metadata via reflector.getAllAndOverride. If no roles required return true. Get request.user.role. Use the hasRole utility from utils/roles.util.ts to check against roles.hierarchy. If no role satisfies, throw AuthException with INSUFFICIENT_ROLE (403). IMPORTANT: hierarchy must be fully denormalized — document in JSDoc that OWNER: ['ADMIN','MEMBER','VIEWER'] not just OWNER: ['ADMIN'].

---

### ⬜ NEST-047: Guard - UserStatusGuard
- **Fase:** 2
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-027, NEST-014
- **Agente:** code-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implement UserStatusGuard with Redis caching and status-specific error mapping.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/guards/user-status.guard.ts. Implement @Injectable() class UserStatusGuard implements CanActivate. Inject AuthRedisService, BYMAX_AUTH_USER_REPOSITORY, BYMAX_AUTH_OPTIONS. In canActivate: (1) If route is public (no user on request) return true. (2) Extract user.sub from request. (3) Check Redis cache us:{userId}. (4) If cache miss, call userRepo.findById(userId), cache result with userStatusCacheTtlSeconds TTL. (5) Check status against blockedStatuses array from options. (6) Map status to specific error: BANNED->ACCOUNT_BANNED (403), INACTIVE->ACCOUNT_INACTIVE (403), SUSPENDED->ACCOUNT_SUSPENDED (403), PENDING_APPROVAL->PENDING_APPROVAL (403). (7) If not blocked return true.

---

### ⬜ NEST-048: Guards - tests
- **Fase:** 2
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-045, NEST-046, NEST-047
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Write unit tests for all three guards covering all branches.

**Prompt para o agente:**
> Create test files for each guard. /Users/maximiliano/Documents/My Apps/nest-auth/src/guards/jwt-auth.guard.spec.ts: (1) Public route returns true without JWT. (2) Protected route without token throws. (3) Protected route with valid token passes. (4) handleRequest maps errors correctly. /Users/maximiliano/Documents/My Apps/nest-auth/src/guards/roles.guard.spec.ts: (1) No roles metadata allows access. (2) Exact role match allows. (3) Hierarchical role (OWNER accessing ADMIN route) allows. (4) Insufficient role throws INSUFFICIENT_ROLE 403. /Users/maximiliano/Documents/My Apps/nest-auth/src/guards/user-status.guard.spec.ts: (1) Public route (no user) returns true. (2) ACTIVE status passes. (3) BANNED status throws ACCOUNT_BANNED. (4) INACTIVE throws ACCOUNT_INACTIVE. (5) Cache hit uses cached value. (6) Cache miss fetches from repository and caches.

---

### ⬜ NEST-049: Decorator - @CurrentUser
- **Fase:** 2
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-004
- **Agente:** code-reviewer
- **Estimativa:** ~20min
- **Descricao:** Implement @CurrentUser param decorator that extracts request.user or a specific property.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/decorators/current-user.decorator.ts. Implement export const CurrentUser = createParamDecorator((data: string | undefined, ctx: ExecutionContext) => { const request = ctx.switchToHttp().getRequest(); const user = request.user; return data ? user?.[data] : user; }). Add JSDoc: /** Extracts the authenticated user from the request. @param property Optional property to extract (e.g., 'sub' for userId). Consumer must type the parameter explicitly: @CurrentUser('sub') userId: string */

---

### ⬜ NEST-050: Decorator - @Roles and @Public
- **Fase:** 2
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-004
- **Agente:** code-reviewer
- **Estimativa:** ~20min
- **Descricao:** Implement @Roles and @Public metadata decorators for use with RolesGuard and JwtAuthGuard.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/decorators/roles.decorator.ts. Export const ROLES_KEY = 'roles'. Export const Roles = (...roles: string[]) => SetMetadata(ROLES_KEY, roles). Create /Users/maximiliano/Documents/My Apps/nest-auth/src/decorators/public.decorator.ts. Export const IS_PUBLIC_KEY = 'isPublic'. Export const Public = () => SetMetadata(IS_PUBLIC_KEY, true). Add JSDoc to both.

---

### ⬜ NEST-051: Decorators - tests
- **Fase:** 2
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-049, NEST-050
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Write unit tests for all decorators.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/decorators/current-user.decorator.spec.ts. Test: (1) Returns full user object when no property specified. (2) Returns specific property when property specified (e.g., 'sub'). (3) Returns undefined when user not present. Create /Users/maximiliano/Documents/My Apps/nest-auth/src/decorators/roles.decorator.spec.ts. Test that @Roles('ADMIN') sets metadata correctly. Create /Users/maximiliano/Documents/My Apps/nest-auth/src/decorators/public.decorator.spec.ts. Test that @Public() sets IS_PUBLIC_KEY to true.

---

### ⬜ NEST-052: DTO - RegisterDto
- **Fase:** 2
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-004
- **Agente:** typescript-reviewer
- **Estimativa:** ~20min
- **Descricao:** Implement RegisterDto with class-validator decorators including email, password, name, and tenantId.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/dto/register.dto.ts. Implement class RegisterDto with: @IsEmail() email: string, @IsString() @MinLength(8) @MaxLength(72) password: string (MaxLength 72 is mandatory — bcrypt truncates silently above 72 bytes), @IsString() @MinLength(2) name: string, @IsString() @IsNotEmpty() tenantId: string (@IsNotEmpty prevents empty string passing @IsString). Export the class.

---

### ⬜ NEST-053: DTO - LoginDto
- **Fase:** 2
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-004
- **Agente:** typescript-reviewer
- **Estimativa:** ~20min
- **Descricao:** Implement LoginDto with deliberate omission of @MinLength on password for anti-enumeration.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/dto/login.dto.ts. Implement class LoginDto with: @IsEmail() email: string, @IsString() @MaxLength(72) password: string, @IsString() @IsNotEmpty() tenantId: string. IMPORTANT: Deliberately NO @MinLength on password — all passwords pass to bcrypt comparison to not reveal if password is too short before comparison (anti-enumeration). Add JSDoc on password field: /** Deliberately without @MinLength — every password passes to bcrypt.compare to prevent revealing minimum length requirements before comparison */. Export the class.

---

### ⬜ NEST-054: DTOs - validation tests
- **Fase:** 2
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-052, NEST-053
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Write validation tests for RegisterDto and LoginDto using class-validator.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/dto/register.dto.spec.ts. Use class-validator's validate() function. Tests: (1) Valid DTO passes. (2) Invalid email fails. (3) Password shorter than 8 chars fails. (4) Password longer than 72 chars fails. (5) Name shorter than 2 chars fails. (6) Empty tenantId fails. Create /Users/maximiliano/Documents/My Apps/nest-auth/src/dto/login.dto.spec.ts. Tests: (1) Valid DTO passes. (2) Invalid email fails. (3) Password longer than 72 fails. (4) Short password (e.g., '1') passes validation (deliberate — no MinLength). (5) Empty tenantId fails.

---

### ⬜ NEST-055: Service - OtpService implementation (moved from Phase 4)
- **Fase:** 2
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-027, NEST-020, NEST-023
- **Agente:** security-reviewer
- **Estimativa:** ~60min
- **Descricao:** Implement OtpService with secure OTP generation, Redis storage, constant-time comparison, and timing normalization.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/services/otp.service.ts. Implement @Injectable() class OtpService. Inject AuthRedisService. Methods: (1) generate(length=6): use crypto.randomInt(0, 10**length) — NEVER Math.random(). Pad with zeros: String(num).padStart(length,'0'). (2) store(purpose, identifier, code, ttlSeconds): Redis key otp:{purpose}:{identifier} -> JSON {code, attempts:0}, with TTL. (3) verify(purpose, identifier, code): get from Redis. If not found throw OTP_EXPIRED. Check attempts >= 5 throw OTP_MAX_ATTEMPTS. Constant-time comparison: convert both to Buffer.from(x,'utf8'), if different lengths return OTP_INVALID without calling timingSafeEqual (it throws RangeError on length mismatch). Use crypto.timingSafeEqual for same-length. If invalid increment attempts throw OTP_INVALID. If valid delete key. TIMING NORMALIZATION: const start = Date.now(), before each return/throw: await sleep(Math.max(0, 100 - (Date.now()-start))). Returns void. (4) incrementAttempts(purpose, identifier): read JSON, increment attempts field, write back with same TTL. Reference section 5.1 of the development plan.

---

### ⬜ NEST-056: Service - OtpService tests
- **Fase:** 2
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-055
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Write unit tests for OtpService covering generation, storage, verification, expiration, and timing.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/services/otp.service.spec.ts. Mock AuthRedisService. Tests: (1) generate(6) produces 6-digit string. (2) generate pads with leading zeros (mock crypto.randomInt to return 42 -> '000042'). (3) store calls Redis set with correct key format and TTL. (4) verify with correct code succeeds and deletes key. (5) verify with expired OTP (not in Redis) throws OTP_EXPIRED. (6) verify with wrong code increments attempts and throws OTP_INVALID. (7) verify with 5+ attempts throws OTP_MAX_ATTEMPTS. (8) verify with different-length code returns OTP_INVALID without calling timingSafeEqual. (9) Timing normalization: all branches take similar time (verify elapsed > 90ms for all cases).

---

### ⬜ NEST-057: Service - AuthService implementation
- **Fase:** 2
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-030, NEST-032, NEST-034, NEST-036, NEST-055, NEST-014, NEST-020, NEST-021
- **Agente:** code-reviewer
- **Estimativa:** ~60min
- **Descricao:** Implement AuthService with register, login, logout, refresh, getMe, verifyEmail, and resendVerificationEmail methods.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/services/auth.service.ts. Implement @Injectable() class AuthService. Inject: BYMAX_AUTH_OPTIONS, BYMAX_AUTH_USER_REPOSITORY (IUserRepository), BYMAX_AUTH_EMAIL_PROVIDER (IEmailProvider), BYMAX_AUTH_HOOKS (IAuthHooks), PasswordService, TokenManagerService, BruteForceService, AuthRedisService, OtpService, @Optional() SessionService. Methods per Appendix A of the spec: (1) register(dto, req): resolve tenantId via tenantIdResolver if configured, call hooks.beforeRegister (reject if not allowed, apply modifiedData), check email exists, hash password, create user, if emailVerification.required generate+store+send OTP, issue tokens, call hooks.afterRegister (catch errors log don't propagate), return AuthResult. (2) login(dto, req): resolve tenantId, compute brute-force id sha256(tenantId+':'+email), check lockout (throw ACCOUNT_LOCKED with Retry-After header), call hooks.beforeLogin, find user, check status against blockedStatuses, check emailVerified if required, compare password, if mfaEnabled issue mfaTempToken return MfaChallengeResult, otherwise reset brute-force+issue tokens+update lastLogin+hooks.afterLogin return AuthResult. (3) logout(accessToken, refreshToken, userId): decode token for jti+exp, blacklist rv:{jti} with remaining TTL, delete rt:{sha256(refresh)}, hooks.afterLogout. (4) refresh(oldRefresh, ip, userAgent): delegate to tokenManager.reissueTokens. (5) getMe(userId): findById, throw TOKEN_INVALID if not found. (6) verifyEmail(tenantId, email, userId, otp): verify via otpService, update emailVerified, hooks.afterEmailVerified. (7) resendVerificationEmail(tenantId, email): atomic cooldown SET resend:email_verification:{sha256(tenantId+':'+email)} 1 NX EX 60, if nil return success silently, otherwise find user+generate OTP+store+send. Timing normalization on resend.

---

### ⬜ NEST-058: Service - AuthService tests
- **Fase:** 2
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-057
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Write comprehensive unit tests for AuthService covering all methods and edge cases.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/services/auth.service.spec.ts. Mock all dependencies. Tests for register: (1) Success creates user and returns AuthResult. (2) Duplicate email throws EMAIL_ALREADY_EXISTS. (3) Hook rejects with reason. (4) Hook modifiedData applied. (5) Email verification OTP sent when required. Tests for login: (6) Success returns AuthResult. (7) Invalid credentials records brute-force failure. (8) Brute-force lockout throws ACCOUNT_LOCKED. (9) Blocked status throws specific error. (10) MFA enabled returns MfaChallengeResult. (11) Email not verified throws EMAIL_NOT_VERIFIED. (12) tenantIdResolver is called when configured. Tests for logout: (13) Blacklists JWT jti. (14) Deletes refresh token. Tests for refresh: (15) Delegates to reissueTokens. Tests for getMe: (16) Returns user. (17) Not found throws TOKEN_INVALID. Tests for verifyEmail: (18) Verifies OTP and updates user. Tests for resendVerificationEmail: (19) Cooldown prevents duplicate sends. (20) Success generates and sends new OTP.

---

### ⬜ NEST-059: Controller - AuthController implementation
- **Fase:** 2
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-057, NEST-034, NEST-045, NEST-052, NEST-053
- **Agente:** code-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implement AuthController with 7 endpoints for register, login, logout, refresh, me, verify-email, and resend-verification.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/controllers/auth.controller.ts. Implement @Controller() class AuthController. Inject AuthService and TokenDeliveryService. 7 endpoints: (1) POST /register: @Public(), @Throttle(AUTH_THROTTLE_CONFIGS.register), @UsePipes(ValidationPipe), body: RegisterDto. Call authService.register(dto, req), deliver via tokenDeliveryService.deliverAuthResponse(res, result, req). Use @Res({passthrough:true}). (2) POST /login: @Public(), @Throttle(login). Call authService.login(dto, req). If MfaChallengeResult (mfaRequired=true) return directly, else deliver via tokenDeliveryService. (3) POST /logout: @UseGuards(JwtAuthGuard). Extract access+refresh tokens via tokenDeliveryService, call authService.logout, call tokenDeliveryService.clearAuthSession. (4) POST /refresh: @Public(), @Throttle(refresh). Extract refresh via tokenDeliveryService, call authService.refresh, deliver new tokens. (5) GET /me: @UseGuards(JwtAuthGuard). Call authService.getMe(user.sub). (6) POST /verify-email: @Public(), @Throttle(verifyEmail). (7) POST /resend-verification: @Public(), @Throttle(resendVerification). Extract req.ip and req.headers['user-agent'] for all service calls.

---

### ⬜ NEST-060: Controller - AuthController tests
- **Fase:** 2
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-059
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Write unit tests for AuthController with mocked services.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/controllers/auth.controller.spec.ts. Mock AuthService and TokenDeliveryService. Tests: (1) POST /register calls authService.register and tokenDeliveryService.deliverAuthResponse. (2) POST /login with normal result calls deliverAuthResponse. (3) POST /login with MFA result returns MfaChallengeResult directly. (4) POST /logout extracts tokens and calls logout+clearAuthSession. (5) POST /refresh extracts refresh token and delivers new tokens. (6) GET /me returns user data. (7) POST /verify-email calls verifyEmail. (8) POST /resend-verification calls resendVerificationEmail. (9) Verify guards are applied (JwtAuthGuard on protected routes, Public on public routes).

---

### ⬜ NEST-061: Module - BymaxAuthModule dynamic module
- **Fase:** 2
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-057, NEST-059, NEST-043, NEST-045, NEST-046, NEST-047, NEST-055, NEST-038, NEST-039
- **Agente:** architect
- **Estimativa:** ~45min
- **Descricao:** Implement the main dynamic module with registerAsync, conditional providers/controllers, and route prefix support.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/bymax-one-nest-auth.module.ts. Implement @Module({}) class BymaxAuthModule with static registerAsync(options: { imports?, inject?, useFactory, providers? }): DynamicModule. In the method: (1) useFactory resolves user config, call resolveOptions to apply defaults+validate, register resolved options as provider with BYMAX_AUTH_OPTIONS token. (2) Register mandatory providers: AuthRedisService, PasswordService, TokenManagerService, TokenDeliveryService, BruteForceService, OtpService, AuthService, JwtStrategy, JwtAuthGuard, RolesGuard, UserStatusGuard. (3) Register fallback providers: if BYMAX_AUTH_HOOKS not in user providers -> register NoOpAuthHooks. If BYMAX_AUTH_EMAIL_PROVIDER not in user providers -> register NoOpEmailProvider. (4) Build controllers array dynamically: include AuthController if controllers.auth !== false. (5) Import JwtModule.registerAsync with secret and signOptions from resolved options. (6) Import PassportModule.register({ defaultStrategy: 'jwt' }). (7) Use RouterModule.register([{ path: routePrefix, module: BymaxAuthModule }]) for dynamic route prefix. (8) DO NOT register guards as APP_GUARD — each controller applies guards explicitly. (9) Merge user's providers array with internal providers.

---

### ⬜ NEST-062: Module - BymaxAuthModule tests
- **Fase:** 2
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-061
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Write integration tests for the dynamic module verifying compilation, validation, and conditional registration.

**Prompt para o agente:**
> Create /Users/maximiliano/Documents/My Apps/nest-auth/src/bymax-one-nest-auth.module.spec.ts. Tests: (1) Module compiles and initializes with valid minimal config (jwt.secret with 32+ chars high entropy, mock Redis client, mock user repository). (2) Validation fails with weak jwt.secret (short or low entropy). (3) AuthController is NOT registered when controllers.auth is false. (4) AuthController IS registered by default. (5) NoOpEmailProvider is used when no email provider is given. (6) NoOpAuthHooks is used when no hooks provider is given. (7) Route prefix is applied correctly. Use NestJS Test.createTestingModule for integration testing.

---

### ⬜ NEST-063: Barrel export - Phase 2
- **Fase:** 2
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-061, NEST-049, NEST-050, NEST-052, NEST-053
- **Agente:** architect
- **Estimativa:** ~15min
- **Descricao:** Update src/index.ts with all Phase 2 exports.

**Prompt para o agente:**
> Update /Users/maximiliano/Documents/My Apps/nest-auth/src/index.ts adding Phase 2 exports. Add: export { BymaxAuthModule } from './bymax-one-nest-auth.module'. export { AuthService } from './services/auth.service'. export { JwtAuthGuard } from './guards/jwt-auth.guard'. export { RolesGuard } from './guards/roles.guard'. export { UserStatusGuard } from './guards/user-status.guard'. export { CurrentUser } from './decorators/current-user.decorator'. export { Roles, ROLES_KEY } from './decorators/roles.decorator'. export { Public, IS_PUBLIC_KEY } from './decorators/public.decorator'. export { RegisterDto } from './dto/register.dto'. export { LoginDto } from './dto/login.dto'. Note: AuthResult and MfaChallengeResult types were already exported in Phase 1 from interfaces/auth-result.interface. Verify no duplicate exports.

---

### ⬜ NEST-064: Phase 2 validation - build and test
- **Fase:** 2
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-063
- **Agente:** architect
- **Estimativa:** ~30min
- **Descricao:** Run full build and test suite for Phase 2, verify all flows work end-to-end and coverage meets 80%.

**Prompt para o agente:**
> Run Phase 2 validation: (1) `npm run build` compiles without errors. (2) `npm run test -- --coverage` passes with >= 80% coverage. (3) Verify register -> login -> refresh -> logout flow works (via unit tests confirming correct service calls and data flow). (4) Guards work: public routes skip JWT, protected routes require JWT, roles are checked hierarchically. (5) TokenDelivery works in all 3 modes. (6) Brute-force blocks after N attempts with Retry-After header. (7) Dynamic module compiles and initializes. (8) Controllers are registered conditionally. (9) Route prefix works via RouterModule. (10) tenantIdResolver is called when configured. (11) OtpService constant-time comparison works. Fix any issues found.

---

## Fase 3 — Autenticacao Multi-Fator (MFA)

### ⬜ NEST-065: MFA DTOs
- **Fase:** 3
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-026
- **Agente:** typescript-reviewer
- **Estimativa:** ~20min
- **Descricao:** Create the three MFA DTO files with class-validator decorators for MFA setup verification, challenge, and disable flows.

**Prompt para o agente:**
> Create three DTO files in `src/dto/`:
> 
> 1. `src/dto/mfa-verify.dto.ts` — class `MfaVerifyDto` with field: `@IsString() @IsNotEmpty() @Length(6, 6) code: string`.
> 
> 2. `src/dto/mfa-challenge.dto.ts` — class `MfaChallengeDto` with fields: `@IsString() @IsNotEmpty() mfaTempToken: string` and `@IsString() @IsNotEmpty() @MaxLength(128) code: string`.
> 
> 3. `src/dto/mfa-disable.dto.ts` — class `MfaDisableDto` with field: `@IsString() @IsNotEmpty() @Length(6, 6) code: string`. Add a JSDoc comment noting that only TOTP codes are accepted for disabling MFA (recovery codes are not accepted by design decision). Mention that recovery without TOTP requires administrative intervention.
> 
> All DTOs must import decorators from `class-validator`. Follow the existing DTO patterns already in the project from Phase 2. Export all DTOs from their respective files.
> 
> Acceptance criteria:
> - All three files compile without errors
> - Validation decorators match the exact constraints specified
> - JSDoc on MfaDisableDto explains the TOTP-only restriction

---

### ⬜ NEST-066: SkipMfa decorator
- **Fase:** 3
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-026
- **Agente:** code-reviewer
- **Estimativa:** ~20min
- **Descricao:** Create the SkipMfa decorator that sets metadata to bypass MfaRequiredGuard on specific endpoints.

**Prompt para o agente:**
> Create file `src/decorators/skip-mfa.decorator.ts`.
> 
> Implementation:
> - Define a constant `SKIP_MFA_KEY = 'skipMfa'` and export it.
> - Create and export a decorator `SkipMfa` using `SetMetadata(SKIP_MFA_KEY, true)` from `@nestjs/common`.
> 
> Follow the same pattern as other decorators in `src/decorators/` from Phase 2 (e.g., `@Public()` if it exists).
> 
> Acceptance criteria:
> - `@SkipMfa()` can be applied to controller methods
> - The constant `SKIP_MFA_KEY` is exported for use by the guard
> - File compiles without errors

---

### ⬜ NEST-067: MfaRequiredGuard
- **Fase:** 3
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-066
- **Agente:** security-reviewer
- **Estimativa:** ~30min
- **Descricao:** Create the MfaRequiredGuard that checks if a user with MFA enabled has completed MFA verification, respecting the SkipMfa decorator.

**Prompt para o agente:**
> Create file `src/guards/mfa-required.guard.ts`.
> 
> Implementation:
> - Implement `CanActivate` from `@nestjs/common`.
> - Inject `Reflector` to read metadata.
> - In `canActivate(context)`:
>   1. Check if `@SkipMfa()` is set via `reflector.getAllAndOverride(SKIP_MFA_KEY, [context.getHandler(), context.getClass()])`. If true, return true.
>   2. Extract `request.user` from the execution context.
>   3. If the user has MFA enabled (`user.mfaEnabled === true`) but `user.mfaVerified !== true`, throw an exception using the `MFA_REQUIRED` error code from the project's error constants.
>   4. Otherwise, return true.
> 
> Import `SKIP_MFA_KEY` from `src/decorators/skip-mfa.decorator.ts`. Use the project's `AuthException` class for throwing errors, following existing guard patterns from Phase 2.
> 
> Acceptance criteria:
> - Guard passes when MFA is not enabled on the user
> - Guard passes when MFA is enabled and `mfaVerified` is true in JWT
> - Guard throws `MFA_REQUIRED` when MFA is enabled but not verified
> - Guard passes when `@SkipMfa()` is applied regardless of MFA state

---

### ⬜ NEST-068: MfaService — encrypt/decrypt helpers and recovery code utilities
- **Fase:** 3
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-026
- **Agente:** security-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implement the MfaService skeleton with encryptSecret, decryptSecret, hashRecoveryCodes, and verifyRecoveryCode private methods.

**Prompt para o agente:**
> Create file `src/services/mfa.service.ts` with an `@Injectable()` class `MfaService`.
> 
> Inject the following dependencies (follow existing DI patterns from Phase 2 services):
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
> 1. `private encryptSecret(secret: string): string` — delegates to `aes-gcm.encrypt(secret, this.options.encryptionKey)` from `src/utils/aes-gcm.ts` (already exists from Phase 1).
> 
> 2. `private decryptSecret(encrypted: string): string` — delegates to `aes-gcm.decrypt(encrypted, this.options.encryptionKey)`.
> 
> 3. `private async hashRecoveryCodes(count: number): Promise<{ plainCodes: string[]; hashedCodes: string[] }>`:
>    - Generate `count` random codes using `crypto.randomBytes`.
>    - Format each as `xxxx-xxxx-xxxx` using alphanumeric characters.
>    - Hash each code with bcrypt.
>    - Return both plain and hashed arrays.
> 
> 4. `private async verifyRecoveryCode(code: string, hashedCodes: string[]): Promise<number>`:
>    - Iterate over `hashedCodes`, compare each with `bcrypt.compare` (which is constant-time internally).
>    - Return the index if found, -1 if not found.
> 
> Leave the public methods (`setup`, `verifyAndEnable`, `challenge`, `disable`) as stubs that throw `NotImplementedError` for now — they will be implemented in subsequent tasks.
> 
> Acceptance criteria:
> - File compiles with all injections properly typed
> - `hashRecoveryCodes(8)` produces 8 codes in `xxxx-xxxx-xxxx` format
> - `verifyRecoveryCode` returns correct index or -1
> - encrypt/decrypt round-trips correctly using aes-gcm utils

---

### ⬜ NEST-069: MfaService.setup()
- **Fase:** 3
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-068
- **Agente:** code-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implement the MFA setup method that generates TOTP secret, QR code URI, and recovery codes with idempotency via Redis.

**Prompt para o agente:**
> In `src/services/mfa.service.ts`, implement the `async setup(userId: string): Promise<MfaSetupResult>` method:
> 
> 1. Fetch the user via `userRepo.findById(userId)`. Check if MFA is already enabled — if yes, throw `MFA_ALREADY_ENABLED`.
> 
> 2. **Idempotency check:** Look up Redis key `mfa_setup:{sha256(userId)}`. If it exists and has TTL > 0, parse and return the existing result (secret, qrCodeUri, recoveryCodes) instead of generating new ones. This prevents CPU waste from bcrypt on concurrent calls.
> 
> 3. Generate a TOTP secret: use the `otpauth` library to create a random 20-byte secret (`new Secret({ size: 20 })`).
> 
> 4. Encrypt the secret using `this.encryptSecret(secret.base32)`.
> 
> 5. Generate 8 recovery codes using `this.hashRecoveryCodes(8)`.
> 
> 6. Store in Redis temporarily: key `mfa_setup:{sha256(userId)}` with value `{ encryptedSecret, hashedCodes, plainCodes, secret: secret.base32 }`, TTL 10 minutes (600 seconds). Use `sha256(userId)` as the key per the spec's identifier hashing principle.
> 
> 7. Generate QR code URI: `otpauth://totp/${issuer}:${email}?secret=${secret.base32}&issuer=${issuer}` where `issuer` comes from `this.options.mfa.issuer` or `this.options.appName`.
> 
> 8. Return `MfaSetupResult { secret: secret.base32, qrCodeUri, recoveryCodes: plainCodes }`.
> 
> The `MfaSetupResult` type should be defined/exported from this file (or imported if already defined): `{ secret: string; qrCodeUri: string; recoveryCodes: string[] }`.
> 
> Acceptance criteria:
> - Calling setup twice within 10 min returns the same result (idempotency)
> - QR URI follows the otpauth:// format correctly
> - Recovery codes are in xxxx-xxxx-xxxx format
> - Redis key uses sha256(userId)

---

### ⬜ NEST-070: MfaService.verifyAndEnable()
- **Fase:** 3
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-069
- **Agente:** security-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implement the method that validates a TOTP code against the pending setup and permanently enables MFA for the user.

**Prompt para o agente:**
> In `src/services/mfa.service.ts`, implement `async verifyAndEnable(userId: string, code: string): Promise<void>`:
> 
> 1. Fetch the setup data from Redis key `mfa_setup:{sha256(userId)}`. If not found, throw `MFA_SETUP_REQUIRED`.
> 
> 2. Decrypt the secret using `this.decryptSecret(encryptedSecret)`.
> 
> 3. Validate the TOTP code using the `otpauth` library with window = `this.options.mfa.totpWindow` (or default from config). If invalid, throw `MFA_INVALID_CODE`.
> 
> 4. Persist MFA to the database: `userRepo.updateMfa({ mfaEnabled: true, mfaSecret: encryptedSecret, mfaRecoveryCodes: hashedCodes })`.
> 
> 5. Delete the temporary Redis setup key.
> 
> 6. **Session invalidation:** Get all session hashes from `sess:{userId}` SET. For each session hash, delete the refresh token `rt:{sessionHash}`. Then clear the SET. Note: active access tokens cannot be blacklisted since `jti` is not stored — they remain valid up to `accessExpiresIn` (default 15 min). Document this limitation with a code comment.
> 
> 7. Send notification: `emailProvider.sendMfaEnabledNotification(user)`.
> 
> 8. Execute hook: `hooks.afterMfaEnabled({ userId })`.
> 
> Acceptance criteria:
> - Valid TOTP code enables MFA and persists encrypted secret + hashed recovery codes
> - Invalid TOTP code throws MFA_INVALID_CODE without modifying database
> - Missing setup throws MFA_SETUP_REQUIRED
> - All existing sessions are invalidated after MFA is enabled
> - Email notification and hook are called on success

---

### ⬜ NEST-071: MfaService.challenge()
- **Fase:** 3
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-070
- **Agente:** security-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implement the MFA challenge method that validates TOTP or recovery codes during login, handling both dashboard and platform contexts with brute-force protection.

**Prompt para o agente:**
> In `src/services/mfa.service.ts`, implement `async challenge(mfaTempToken: string, code: string, ip: string, userAgent: string): Promise<AuthResult | PlatformAuthResult>`:
> 
> 1. Verify `mfaTempToken` via `tokenManager.verifyMfaTempToken(mfaTempToken)` — returns `{ userId, context }` where context is `'dashboard'` or `'platform'`.
> 
> 2. Compute brute-force identifier: `sha256(userId)`.
> 
> 3. Check lockout: `bruteForce.isLockedOut(identifier)`. If locked, throw appropriate error.
> 
> 4. Fetch user from the correct repository based on `context`:
>    - `'dashboard'` -> `userRepo.findById(userId)`
>    - `'platform'` -> `platformUserRepo.findById(userId)` (throw descriptive error if platformUserRepo is null)
> 
> 5. Decrypt `user.mfaSecret`.
> 
> 6. Determine if `code` is a TOTP code (6 digits) or recovery code (other format):
>    - **If TOTP:** Validate with `otpauth` library. Check anti-replay: if Redis key `tu:{userId}:{code}` exists, reject as already used. If valid, set `tu:{userId}:{code}` with TTL 90 seconds.
>    - **If recovery code:** Call `this.verifyRecoveryCode(code, user.mfaRecoveryCodes)`. If found (index >= 0), remove it from the array via `userRepo.updateMfa()` with the code at that index removed.
> 
> 7. If invalid: record brute-force failure. If failures >= 5, also revoke the `mfaTempToken` (force re-authentication). Throw `MFA_INVALID_CODE`.
> 
> 8. If valid:
>    - Reset brute-force counter.
>    - Issue tokens with `mfaVerified: true`:
>      - `'dashboard'`: `tokenManager.issueTokens(user, ip, userAgent, { mfaVerified: true })` -> return `AuthResult`
>      - `'platform'`: issue platform tokens -> return `PlatformAuthResult`
>    - Create session if `sessions.enabled` and context is `'dashboard'`: call `sessionService.createSession()`.
>    - Execute `hooks.afterLogin()`.
> 
> 9. Return the result matching the context.
> 
> Import `AuthResult` and `PlatformAuthResult` from `src/interfaces/auth-result.interface.ts`.
> 
> Acceptance criteria:
> - Valid TOTP code returns AuthResult with mfaVerified: true
> - Valid recovery code returns AuthResult and removes the used code
> - Anti-replay prevents reuse of same TOTP code within 90s
> - Brute-force lockout works after threshold
> - After 5 failures, mfaTempToken is revoked
> - Platform context returns PlatformAuthResult
> - Session is created for dashboard context when sessions enabled

---

### ⬜ NEST-072: MfaService.disable()
- **Fase:** 3
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-070
- **Agente:** code-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implement MFA disable method requiring a valid TOTP code with brute-force protection.

**Prompt para o agente:**
> In `src/services/mfa.service.ts`, implement `async disable(userId: string, code: string): Promise<void>`:
> 
> 1. Fetch user via `userRepo.findById(userId)`.
> 2. If MFA is not enabled, throw `MFA_NOT_ENABLED`.
> 3. Check brute-force lockout: `bruteForce.isLockedOut(sha256(userId))` — uses the same identifier as `challenge`.
> 4. Decrypt `user.mfaSecret`.
> 5. Validate the TOTP code using `otpauth`. Only TOTP codes are accepted (no recovery codes).
> 6. If invalid: record failure via `bruteForce.recordFailure(sha256(userId))`, throw `MFA_INVALID_CODE`.
> 7. If valid: reset brute-force counter.
> 8. Disable MFA: `userRepo.updateMfa({ mfaEnabled: false, mfaSecret: null, mfaRecoveryCodes: null })`.
> 9. Send notification: `emailProvider.sendMfaDisabledNotification(user)`.
> 10. Execute hook: `hooks.afterMfaDisabled({ userId })`.
> 
> Acceptance criteria:
> - Valid TOTP code disables MFA and clears secret/recovery codes from DB
> - MFA not enabled throws MFA_NOT_ENABLED
> - Invalid code records brute-force failure
> - Only TOTP codes accepted (recovery codes must not work)
> - Email notification and hook called on success

---

### ⬜ NEST-073: MfaController
- **Fase:** 3
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-065, NEST-071, NEST-072
- **Agente:** code-reviewer
- **Estimativa:** ~30min
- **Descricao:** Create the MFA controller with four endpoints for setup, verify, challenge, and disable, applying appropriate guards and throttle decorators.

**Prompt para o agente:**
> Create file `src/controllers/mfa.controller.ts`.
> 
> Implementation:
> - `@Controller()` with prefix `{routePrefix}/mfa` (resolve routePrefix from injected options).
> - Inject `MfaService` and `TokenDeliveryService`.
> 
> Implement 4 endpoints:
> 
> 1. `POST /setup` — Guard: `JwtAuthGuard`. Throttle: `mfaSetup`. Calls `mfaService.setup(user.sub)` where `user` is extracted from `@Request()`. Returns the `MfaSetupResult`.
> 
> 2. `POST /verify` — Guard: `JwtAuthGuard`. No special throttle. Body: `MfaVerifyDto`. Calls `mfaService.verifyAndEnable(user.sub, dto.code)`.
> 
> 3. `POST /challenge` — Public (no auth guard, user has no JWT yet). Throttle: `mfaChallenge`. Body: `MfaChallengeDto`. Calls `mfaService.challenge(dto.mfaTempToken, dto.code, ip, userAgent)`. Deliver tokens via `tokenDeliveryService`.
> 
> 4. `POST /disable` — Guard: `JwtAuthGuard`. Throttle: `mfaDisable`. Body: `MfaDisableDto`. Calls `mfaService.disable(user.sub, dto.code)`.
> 
> Extract `ip` from `request.ip` and `userAgent` from `request.headers['user-agent']`. Follow the same controller patterns from Phase 2's `AuthController`.
> 
> Acceptance criteria:
> - All 4 endpoints defined with correct HTTP methods and routes
> - Guards applied correctly (challenge is public, others require JWT)
> - Throttle decorators applied to setup, challenge, and disable
> - DTOs used for request body validation
> - Token delivery via tokenDeliveryService on challenge endpoint

---

### ⬜ NEST-074: MFA module integration
- **Fase:** 3
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-073, NEST-067
- **Agente:** architect
- **Estimativa:** ~45min
- **Descricao:** Register MfaService, MfaController, and MfaRequiredGuard conditionally in the dynamic module based on MFA configuration.

**Prompt para o agente:**
> Modify the dynamic module registration file (the main `BymaxAuthModule` or equivalent in `src/`) to conditionally register Phase 3 components:
> 
> 1. Register `MfaService` as a provider ONLY when `options.mfa` is configured (truthy).
> 2. Register `MfaController` as a controller ONLY when `options.mfa` is configured AND `options.controllers?.mfa !== false`.
> 3. Register `MfaRequiredGuard` as a provider (always available when MFA is configured, so consumers can use it).
> 
> Follow the existing conditional registration patterns from Phase 2 (e.g., how AuthController is conditionally registered).
> 
> Acceptance criteria:
> - When `mfa` config is absent, MfaService and MfaController are not registered
> - When `mfa` config is present but `controllers.mfa` is false, MfaService is registered but MfaController is not
> - When `mfa` config is present, MfaRequiredGuard is available for injection
> - No circular dependency issues

---

### ⬜ NEST-075: MFA barrel exports
- **Fase:** 3
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-074
- **Agente:** code-reviewer
- **Estimativa:** ~15min
- **Descricao:** Update the main index.ts barrel export to include all Phase 3 public APIs.

**Prompt para o agente:**
> Update `src/index.ts` (the main barrel export file) to add the following exports:
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
> - All 6 exports are present in index.ts
> - Types are exported with `export type` syntax
> - File compiles without errors

---

### ⬜ NEST-076: MfaService unit tests
- **Fase:** 3
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-072
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Write comprehensive unit tests for MfaService covering all flows including setup idempotency, challenge with both contexts, and edge cases.

**Prompt para o agente:**
> Create test file `src/services/__tests__/mfa.service.spec.ts` (or follow the project's existing test file convention).
> 
> Write unit tests for `MfaService` covering:
> 
> 1. **setup():**
>    - Generates secret, QR code URI, and 8 recovery codes
>    - QR code URI follows `otpauth://totp/` format
>    - Recovery codes are in `xxxx-xxxx-xxxx` format
>    - Throws `MFA_ALREADY_ENABLED` if MFA already enabled
>    - Idempotency: calling setup twice returns same result (mock Redis to return existing data)
> 
> 2. **verifyAndEnable():**
>    - Valid TOTP code enables MFA, persists to DB
>    - Invalid TOTP code throws `MFA_INVALID_CODE`, does not modify DB
>    - Missing setup (no Redis data) throws `MFA_SETUP_REQUIRED`
>    - Existing sessions are invalidated
>    - Email notification and hook are called
> 
> 3. **challenge():**
>    - Valid TOTP code with `context: 'dashboard'` returns `AuthResult` with `mfaVerified: true`
>    - Valid TOTP code with `context: 'platform'` returns `PlatformAuthResult`
>    - Valid recovery code works and removes the used code
>    - Anti-replay: reusing same TOTP code within 90s is rejected
>    - Brute-force lockout after threshold
>    - After 5 failures, mfaTempToken is revoked
>    - Session is created for dashboard context when sessions enabled
> 
> 4. **disable():**
>    - Valid TOTP code disables MFA
>    - Throws `MFA_NOT_ENABLED` when MFA not enabled
>    - Invalid code records brute-force failure
>    - Email notification and hook called on success
> 
> Mock all dependencies (userRepo, platformUserRepo, Redis, tokenManager, bruteForce, emailProvider, hooks, sessionService). Use Jest. Aim for >= 80% coverage of mfa.service.ts.
> 
> Acceptance criteria:
> - All test cases pass
> - Covers happy path and error paths for all 4 public methods
> - Both dashboard and platform contexts tested for challenge
> - Anti-replay and brute-force scenarios tested

---

### ⬜ NEST-077: MfaController unit tests
- **Fase:** 3
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-073
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Write unit tests for MfaController verifying correct routing, guard application, and delegation to MfaService.

**Prompt para o agente:**
> Create test file `src/controllers/__tests__/mfa.controller.spec.ts`.
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
> - All 4 endpoints tested
> - Service methods called with correct arguments
> - Token delivery verified on challenge endpoint
> - Tests pass

---

### ⬜ NEST-078: MfaRequiredGuard and SkipMfa unit tests
- **Fase:** 3
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-067
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Write unit tests for MfaRequiredGuard verifying it correctly enforces MFA verification and respects the SkipMfa decorator.

**Prompt para o agente:**
> Create test file `src/guards/__tests__/mfa-required.guard.spec.ts`.
> 
> Test cases:
> 1. User without MFA enabled -> guard passes (returns true)
> 2. User with MFA enabled and `mfaVerified: true` in JWT -> guard passes
> 3. User with MFA enabled and `mfaVerified: false` or missing -> guard throws `MFA_REQUIRED`
> 4. Endpoint decorated with `@SkipMfa()` -> guard passes regardless of MFA status
> 5. No user on request -> guard handles gracefully
> 
> Mock the `Reflector` and execution context. Follow existing guard test patterns from Phase 2.
> 
> Acceptance criteria:
> - All 5 scenarios tested
> - Tests pass

---

### ⬜ NEST-079: Phase 3 validation — integration smoke test
- **Fase:** 3
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-076, NEST-077, NEST-078, NEST-075
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Write an integration-style test that validates the full MFA flow: setup, verify, challenge, and disable, plus edge cases like anti-replay and brute-force.

**Prompt para o agente:**
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
> - All 11 scenarios have passing tests
> - Tests validate the checklist items from section 4.7 of the development plan

---

## Fase 4 — Sessoes e Reset de Senha

### ⬜ NEST-080: Password Reset and Verification DTOs
- **Fase:** 4
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-026
- **Agente:** typescript-reviewer
- **Estimativa:** ~45min
- **Descricao:** Create all six DTOs for password reset and email verification flows with proper validation decorators.

**Prompt para o agente:**
> Create the following 6 DTO files in `src/dto/`:
> 
> 1. `src/dto/forgot-password.dto.ts` — class `ForgotPasswordDto`:
>    - `@IsEmail() email: string`
>    - `@IsString() @IsNotEmpty() tenantId: string`
> 
> 2. `src/dto/reset-password.dto.ts` — class `ResetPasswordDto`:
>    - `@IsEmail() email: string`
>    - `@IsString() @MinLength(8) @MaxLength(72) newPassword: string`
>    - `@IsOptional() @IsString() @IsNotEmpty() token?: string`
>    - `@IsOptional() @IsString() @IsNotEmpty() otp?: string`
>    - `@IsOptional() @IsString() @IsNotEmpty() verifiedToken?: string`
>    - `@IsString() @IsNotEmpty() tenantId: string`
>    - Add JSDoc comment: `@IsNotEmpty()` on optional fields ensures that if present, they are not empty strings (which would produce a valid but incorrect `sha256("")`).
> 
> 3. `src/dto/verify-otp.dto.ts` — class `VerifyOtpDto`:
>    - `@IsEmail() email: string`
>    - `@IsString() @IsNotEmpty() @Length(6, 8) otp: string` (min 6 = default, max 8 = max otpLength)
>    - `@IsString() @IsNotEmpty() tenantId: string`
> 
> 4. `src/dto/resend-otp.dto.ts` — class `ResendOtpDto`:
>    - `@IsEmail() email: string`
>    - `@IsString() @IsNotEmpty() tenantId: string`
> 
> 5. `src/dto/verify-email.dto.ts` — class `VerifyEmailDto`:
>    - `@IsEmail() email: string`
>    - `@IsString() @IsNotEmpty() otp: string`
>    - `@IsString() @IsNotEmpty() tenantId: string`
> 
> 6. `src/dto/resend-verification.dto.ts` — class `ResendVerificationDto`:
>    - `@IsEmail() email: string`
>    - `@IsString() @IsNotEmpty() tenantId: string`
> 
> Follow existing DTO patterns from Phase 2. Import all decorators from `class-validator`.
> 
> Acceptance criteria:
> - All 6 files compile without errors
> - Validation constraints match exactly as specified
> - Optional fields in ResetPasswordDto have both @IsOptional() and @IsNotEmpty()

---

### ⬜ NEST-081: SessionService — createSession and enforceSessionLimit
- **Fase:** 4
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-026
- **Agente:** code-reviewer
- **Estimativa:** ~30min
- **Descricao:** Create the SessionService with session creation, FIFO session limit enforcement, and user-agent parsing.

**Prompt para o agente:**
> Create file `src/services/session.service.ts` with an `@Injectable()` class `SessionService`.
> 
> Inject: `BYMAX_AUTH_OPTIONS`, `BYMAX_AUTH_USER_REPOSITORY`, `AuthRedisService`, `@Inject(BYMAX_AUTH_EMAIL_PROVIDER) emailProvider`, `@Inject(BYMAX_AUTH_HOOKS) hooks`.
> 
> Export the `SessionInfo` interface from this file:

---

### ⬜ NEST-082: SessionService — listSessions and revokeSession
- **Fase:** 4
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-081
- **Agente:** code-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implement session listing with current-session marking and single session revocation with ownership validation.

**Prompt para o agente:**
> In `src/services/session.service.ts`, implement:
> 
> 1. `async listSessions(userId: string, currentSessionHash?: string): Promise<SessionInfo[]>`:
>    - Get all hashes from SET: `SMEMBERS sess:{userId}`.
>    - For each hash, get details from `sd:{hash}`. If details are null (expired), remove the stale hash from the SET via `SREM`.
>    - Set `isCurrent: hash === currentSessionHash` for each session.
>    - Sort by `createdAt` descending (newest first).
>    - Return `SessionInfo[]`.
> 
> 2. `async revokeSession(userId: string, sessionHash: string): Promise<void>`:
>    - **Ownership validation:** `SISMEMBER sess:{userId} sessionHash`. If not a member, throw `SESSION_NOT_FOUND` (prevents BOLA/IDOR attacks).
>    - Delete refresh token: `DEL rt:{sessionHash}`.
>    - Remove from SET: `SREM sess:{userId} sessionHash`.
>    - Delete session details: `DEL sd:{sessionHash}`.
> 
> 3. `async revokeAllExceptCurrent(userId: string, currentSessionHash: string): Promise<void>`:
>    - Get all session hashes from SET.
>    - Filter out `currentSessionHash`.
>    - Revoke each remaining session individually.
> 
> Acceptance criteria:
> - listSessions returns all active sessions with correct isCurrent marking
> - Stale sessions (expired sd: keys) are cleaned up
> - revokeSession validates ownership before deleting
> - Attempting to revoke another user's session throws SESSION_NOT_FOUND
> - revokeAllExceptCurrent keeps only the current session

---

### ⬜ NEST-083: SessionService — rotateSession with atomic Lua script
- **Fase:** 4
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-082
- **Agente:** database-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implement session rotation during refresh token rotation using an atomic Lua script that handles both token and session updates.

**Prompt para o agente:**
> In `src/services/session.service.ts`, implement:
> 
> `async rotateSession(userId: string, oldRefreshToken: string, newRefreshToken: string): Promise<void>`:
>    - Compute `oldHash = sha256(oldRefreshToken)` and `newHash = sha256(newRefreshToken)`.
>    - This must be atomic with the refresh token rotation. Extend the existing Lua script for refresh token rotation (from Phase 2's `token-manager.service.ts` or `auth-redis.service.ts`) to also handle session keys.
>    - The Lua script should:
>      1. SREM `sess:{userId}` oldHash
>      2. SADD `sess:{userId}` newHash
>      3. Copy session details from `sd:{oldHash}` to `sd:{newHash}` with updated `lastActivityAt`
>      4. DEL `sd:{oldHash}`
>      5. EXPIRE `sess:{userId}` with the refresh TTL
>    - The script must be **parametrizable** with key prefixes (`rt/rp/sess/sd` for dashboard, `prt/prp/psess/psd` for platform) instead of hardcoding prefixes. This prevents inconsistencies if the process crashes between token rotation and session update.
>    - This method is a **deviation from the spec** (section 6.4 does not define `rotateSession`). Add a code comment documenting this: `// Deviation from spec: rotateSession added to maintain sess:{} SET consistency during refresh`.
> 
> Also update the refresh token rotation logic in the relevant service (likely `TokenManagerService` or `AuthRedisService`) to call this Lua script with the additional session keys when `sessions.enabled`.
> 
> Acceptance criteria:
> - Rotation atomically updates both token and session data in a single Lua script
> - Old session details are removed, new ones created with updated lastActivityAt
> - Lua script supports parameterized prefixes for dashboard/platform
> - sess:{userId} SET TTL is renewed
> - Comment documents the spec deviation

---

### ⬜ NEST-084: SessionController
- **Fase:** 4
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-082
- **Agente:** code-reviewer
- **Estimativa:** ~30min
- **Descricao:** Create the session controller with endpoints for listing, revoking single, and revoking all sessions.

**Prompt para o agente:**
> Create file `src/controllers/session.controller.ts`.
> 
> Implementation:
> - `@Controller()` with prefix `{routePrefix}/sessions`.
> - Inject `SessionService`.
> - All endpoints require `JwtAuthGuard`.
> 
> Implement 3 endpoints:
> 
> 1. `GET /` — List sessions. Extract `userId` from `request.user.sub`. Extract `currentSessionHash` from JWT claims (if present) or compute via `sha256(refreshToken)` from the cookie. Call `sessionService.listSessions(userId, currentSessionHash)`.
> 
> 2. `DELETE /:id` — Revoke a specific session. The `:id` param is the `sessionHash`. Call `sessionService.revokeSession(userId, sessionHash)`. The ownership check happens in the service.
> 
> 3. `DELETE /all` — Revoke all sessions except current. Extract `currentSessionHash` same as in GET. Call `sessionService.revokeAllExceptCurrent(userId, currentSessionHash)`.
> 
> Ensure route ordering: `/all` must be defined before `/:id` so NestJS doesn't interpret "all" as an id parameter.
> 
> Acceptance criteria:
> - All 3 endpoints defined with correct HTTP methods
> - JwtAuthGuard applied to all endpoints
> - currentSessionHash correctly extracted
> - Route ordering prevents /all from matching /:id

---

### ⬜ NEST-085: PasswordResetService — initiateReset
- **Fase:** 4
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-080
- **Agente:** security-reviewer
- **Estimativa:** ~30min
- **Descricao:** Create PasswordResetService and implement the initiate reset method supporting both token and OTP flows with timing normalization.

**Prompt para o agente:**
> Create file `src/services/password-reset.service.ts` with an `@Injectable()` class `PasswordResetService`.
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
> - Token method generates secure random token and stores with TTL in Redis
> - OTP method delegates to OtpService correctly
> - Non-existent user does not cause different behavior or timing
> - Timing normalization prevents user enumeration via response time
> - Email sent only when user exists

---

### ⬜ NEST-086: PasswordResetService — resetPassword
- **Fase:** 4
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-085
- **Agente:** security-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implement the resetPassword method supporting three validation modes (token, OTP, verifiedToken) with session invalidation and cross-tenant protection.

**Prompt para o agente:**
> In `src/services/password-reset.service.ts`, implement `async resetPassword(dto: ResetPasswordDto): Promise<void>`:
> 
> 1. Validate exactly one of `token`, `otp`, or `verifiedToken` is present. If none or multiple, throw a validation error.
> 
> 2. **If `verifiedToken` present:**
>    - Look up Redis key `prv:{sha256(verifiedToken)}` which contains `{ email, tenantId }`.
>    - If not found, throw appropriate error (token expired/invalid).
>    - Verify that `dto.tenantId` matches the stored `tenantId` (prevents cross-tenant password reset).
>    - Look up user by email.
> 
> 3. **If `token` present:**
>    - Look up Redis key `pr:{sha256(token)}` which contains `userId`.
>    - If not found, throw appropriate error.
>    - Look up user by userId.
> 
> 4. **If `otp` present:**
>    - Compute identifier: `sha256(dto.tenantId + ':' + dto.email)`.
>    - Validate via `otpService.verify('password_reset', identifier, dto.otp)` — this consumes the OTP.
>    - Look up user by email.
> 
> 5. Hash the new password: `passwordService.hash(dto.newPassword)`.
> 6. Update in database: `userRepo.updatePassword(userId, hashedPassword)`.
> 7. Consume the token/verifiedToken from Redis (DEL the key).
> 8. Invalidate all user sessions: if `sessionService` available, revoke all sessions for the user.
> 9. Invalidate user status cache: `DEL us:{userId}`.
> 10. Execute hook: `hooks.afterPasswordReset({ userId })`.
> 
> Acceptance criteria:
> - Token-based reset works end-to-end
> - OTP-based reset consumes the OTP
> - VerifiedToken-based reset validates cross-tenant
> - Cross-tenant attempt with mismatched tenantId is rejected
> - All sessions invalidated after reset
> - User status cache cleared
> - Hook called on success

---

### ⬜ NEST-087: PasswordResetService — verifyOtp and resendOtp
- **Fase:** 4
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-085
- **Agente:** security-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implement the OTP verification (which produces a verifiedToken) and OTP resend with atomic cooldown.

**Prompt para o agente:**
> In `src/services/password-reset.service.ts`, implement:
> 
> 1. `async verifyOtp(email: string, otp: string, tenantId: string): Promise<{ verifiedToken: string }>`:
>    - Compute identifier: `sha256(tenantId + ':' + email)`.
>    - Validate OTP: `otpService.verify('password_reset', identifier, otp)` — this CONSUMES the OTP.
>    - Generate a temporary verification token: `crypto.randomUUID()`.
>    - Store in Redis: `prv:{sha256(token)}` with value `{ email, tenantId }`, TTL = 300 seconds (5 minutes).
>    - Return `{ verifiedToken: token }`.
> 
> 2. `async resendOtp(email: string, tenantId: string): Promise<void>`:
>    - **Atomic cooldown:** Use `SET resend:password_reset:{sha256(tenantId+':'+email)} 1 NX EX 60`. The `NX` flag ensures only the first concurrent request proceeds (prevents TOCTOU race condition). If the SET returns `null`, cooldown is active — return success without generating a new OTP.
>    - Record start time for timing normalization.
>    - Look up user by email — always return success regardless of existence (anti-enumeration).
>    - If user exists: generate new OTP via `otpService.generate()`, store via `otpService.store()`, send via `emailProvider.sendPasswordResetOtp()`.
>    - Apply timing normalization before returning.
> 
> Acceptance criteria:
> - verifyOtp consumes OTP and returns a verifiedToken valid for 5 minutes
> - verifiedToken stored in Redis with correct structure
> - resendOtp respects 60-second cooldown via atomic NX operation
> - Cooldown prevents multiple OTP generations within 60s
> - Non-existent user returns success without leak
> - Timing normalization applied in resendOtp

---

### ⬜ NEST-088: PasswordResetController
- **Fase:** 4
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-086, NEST-087
- **Agente:** code-reviewer
- **Estimativa:** ~30min
- **Descricao:** Create the password reset controller with four public endpoints for forgot-password, reset, OTP verification, and OTP resend.

**Prompt para o agente:**
> Create file `src/controllers/password-reset.controller.ts`.
> 
> Implementation:
> - `@Controller()` with prefix `{routePrefix}/password`.
> - Inject `PasswordResetService`.
> - All endpoints are public (no auth guards).
> 
> Implement 4 endpoints:
> 
> 1. `POST /forgot-password` — Throttle: `forgotPassword`. Body: `ForgotPasswordDto`. Call `passwordResetService.initiateReset(dto.email, dto.tenantId)`.
> 
> 2. `POST /reset-password` — Throttle: `resetPassword`. Body: `ResetPasswordDto`. Call `passwordResetService.resetPassword(dto)`.
> 
> 3. `POST /verify-otp` — Throttle: `verifyOtp`. Body: `VerifyOtpDto`. Call `passwordResetService.verifyOtp(dto.email, dto.otp, dto.tenantId)`.
> 
> 4. `POST /resend-otp` — Throttle: `resendPasswordOtp`. Body: `ResendOtpDto`. Call `passwordResetService.resendOtp(dto.email, dto.tenantId)`.
> 
> Follow existing controller patterns from Phase 2. Apply throttle decorators using the project's throttle mechanism.
> 
> Acceptance criteria:
> - All 4 endpoints defined with correct routes and HTTP methods
> - All endpoints are public
> - Throttle decorators applied per the spec table
> - DTOs used for request body validation
> - Correct delegation to PasswordResetService methods

---

### ⬜ NEST-089: Phase 4 module integration — SessionService and PasswordResetService
- **Fase:** 4
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-084, NEST-088
- **Agente:** architect
- **Estimativa:** ~45min
- **Descricao:** Register SessionService, PasswordResetService, and their controllers conditionally in the dynamic module.

**Prompt para o agente:**
> Modify the dynamic module registration (in `BymaxAuthModule` or equivalent) to add Phase 4 components:
> 
> 1. `OtpService` — already registered in Phase 2, no changes needed. Verify it's present.
> 2. Register `SessionService` as a provider ONLY when `options.sessions?.enabled === true`.
> 3. Register `PasswordResetService` always (password reset is a core feature).
> 4. Register `SessionController` ONLY when `options.sessions?.enabled === true` AND `options.controllers?.sessions !== false`.
> 5. Register `PasswordResetController` ONLY when `options.controllers?.passwordReset !== false`.
> 
> Update barrel exports in `src/index.ts`:
> - `export { ForgotPasswordDto, ResetPasswordDto, VerifyOtpDto, ResendOtpDto, VerifyEmailDto, ResendVerificationDto }`
> - `export type { SessionInfo } from './services/session.service'`
> 
> Acceptance criteria:
> - SessionService only registered when sessions enabled
> - PasswordResetService always registered
> - Controllers conditionally registered based on config
> - Barrel exports updated
> - No circular dependencies

---

### ⬜ NEST-090: AuthService integration with SessionService
- **Fase:** 4
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-083, NEST-089
- **Agente:** planner
- **Estimativa:** ~30min
- **Descricao:** Integrate SessionService into AuthService's login, logout, and refresh flows, and into MfaService's challenge flow.

**Prompt para o agente:**
> Modify `src/services/auth.service.ts` and potentially `src/services/token-manager.service.ts`:
> 
> 1. Add `@Optional() SessionService` injection to `AuthService` (if not already present).
> 
> 2. In `login()`: After successfully issuing tokens, if `this.sessionService` is available (sessions enabled), call `this.sessionService.createSession(userId, rawRefreshToken, ip, userAgent)`. Include `sessionHash` (sha256 of refresh token) in the returned `AuthResult`.
> 
> 3. In `logout()`: Call `this.sessionService?.revokeSession(userId, sessionHash)` where `sessionHash` is derived from `sha256(rawRefreshToken)` extracted from the cookie or request. This removes the session from the `sess:{userId}` SET.
> 
> 4. In `refresh()`: Call `this.sessionService?.rotateSession(userId, oldRefreshToken, newRefreshToken)` to keep `sess:` and `sd:` synchronized during token rotation. This should use the atomic Lua script from NEST-073.
> 
> 5. In `MfaService.challenge()` (`src/services/mfa.service.ts`): After issuing tokens with `mfaVerified: true` and `context === 'dashboard'`, call `sessionService.createSession()` if sessions are enabled.
> 
> Add comments at integration points: `// Phase 4: SessionService integration`.
> 
> Acceptance criteria:
> - Login creates a session when sessions enabled
> - Logout revokes the session
> - Refresh rotates the session atomically
> - MFA challenge creates session for dashboard context
> - sessionHash included in AuthResult when sessions enabled
> - All integration points have documenting comments
> - Existing tests still pass (may need mock updates)

---

### ⬜ NEST-091: SessionService unit tests
- **Fase:** 4
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-083
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Write comprehensive unit tests for SessionService covering creation, listing, revocation, FIFO eviction, and rotation.

**Prompt para o agente:**
> Create test file `src/services/__tests__/session.service.spec.ts`.
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
> - All 9 test groups pass
> - BOLA prevention verified
> - FIFO eviction logic verified
> - Rotation atomicity tested (mock Lua script execution)
> - >= 80% coverage of session.service.ts

---

### ⬜ NEST-092: PasswordResetService unit tests
- **Fase:** 4
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-087
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Write unit tests for PasswordResetService covering token and OTP flows, cross-tenant protection, timing normalization, and cooldown.

**Prompt para o agente:**
> Create test file `src/services/__tests__/password-reset.service.spec.ts`.
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
> - All 12 test groups pass
> - Cross-tenant rejection verified
> - Anti-enumeration (no user existence leak) verified
> - Cooldown atomicity tested
> - >= 80% coverage

---

### ⬜ NEST-093: SessionController unit tests
- **Fase:** 4
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-084
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Write unit tests for SessionController verifying correct endpoint behavior and delegation to SessionService.

**Prompt para o agente:**
> Create test file `src/controllers/__tests__/session.controller.spec.ts`.
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
> - All 3 endpoints tested
> - Guard application verified
> - Correct delegation to service methods

---

### ⬜ NEST-094: PasswordResetController unit tests
- **Fase:** 4
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-088
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Write unit tests for PasswordResetController verifying all four endpoints delegate correctly.

**Prompt para o agente:**
> Create test file `src/controllers/__tests__/password-reset.controller.spec.ts`.
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
> - All 4 endpoints tested
> - Correct delegation verified
> - Public access verified

---

### ⬜ NEST-095: AuthService integration tests update
- **Fase:** 4
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-090
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Update existing AuthService tests to cover the new SessionService integration points in login, logout, and refresh flows.

**Prompt para o agente:**
> Update the existing AuthService test file (likely `src/services/__tests__/auth.service.spec.ts` or similar) to add test cases for Phase 4 SessionService integration:
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
> - 5 new test cases added and passing
> - Existing tests unbroken
> - Mock SessionService properly configured as optional

---

### ⬜ NEST-096: Phase 4 validation — integration smoke test
- **Fase:** 4
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-091, NEST-092, NEST-093, NEST-094, NEST-095
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Write integration-level tests validating the full Phase 4 checklist including password reset flows, session management, and edge cases.

**Prompt para o agente:**
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
> - All 11 scenarios have passing tests
> - Validates the complete checklist from section 5.9
> - Overall Phase 4 coverage >= 80%

---

## Fase 5 — Plataforma, OAuth e Convites

### ⬜ NEST-097: JWT Platform Strategy
- **Fase:** 5
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-026, NEST-010
- **Agente:** code-reviewer
- **Estimativa:** ~30min
- **Descricao:** Criar a Passport strategy para JWT de plataforma que compartilha jwt.secret mas isola por claim type: 'platform'.

**Prompt para o agente:**
> Criar o arquivo `src/strategies/jwt-platform.strategy.ts`. Implementar uma Passport strategy (`passport-jwt`) chamada `JwtPlatformStrategy` que:
> - Extrai o JWT do header Authorization (Bearer) usando `ExtractJwt.fromAuthBearerToken()` e, se configurado para modo cookie/both, também do cookie de access token.
> - Usa o mesmo `jwt.secret` das opções do módulo (injetado via options).
> - OBRIGATORIAMENTE pina `algorithms: ['HS256']` — idêntico à `JwtStrategy` da Fase 2.
> - No método `validate(payload)`, verifica que `payload.type === 'platform'`. Se não, lança `UnauthorizedException` com código `PLATFORM_AUTH_REQUIRED`.
> - Verifica que `payload.jti` existe. Se não, lança `UnauthorizedException` com código `TOKEN_INVALID`.
> - Verifica a blacklist: consulta Redis pela chave `rv:{jti}`. Se existe, lança `UnauthorizedException` com `TOKEN_REVOKED`.
> - Retorna o payload validado.
> Seguir o mesmo padrão estrutural de `src/strategies/jwt.strategy.ts` da Fase 2. Usar `@Injectable()` e registrar como strategy `'jwt-platform'`. Arquivo de referência para padrão: `src/strategies/jwt.strategy.ts`.
> Critérios de aceitação: compila sem erros, pina HS256, valida type === 'platform', verifica jti e blacklist.

---

### ⬜ NEST-098: JWT Platform Guard
- **Fase:** 5
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-097
- **Agente:** code-reviewer
- **Estimativa:** ~30min
- **Descricao:** Criar guard que aceita apenas tokens platform e rejeita tokens dashboard com PLATFORM_AUTH_REQUIRED.

**Prompt para o agente:**
> Criar o arquivo `src/guards/jwt-platform.guard.ts`. Implementar `JwtPlatformGuard` que:
> - Extends `AuthGuard('jwt-platform')` do `@nestjs/passport`.
> - No método `handleRequest(err, user, info)`: se err ou !user, lança `UnauthorizedException` com código `PLATFORM_AUTH_REQUIRED`.
> - Valida que `user.jti` está presente (double-check). Se ausente, lança com código `TOKEN_INVALID`.
> - Exportar como `JwtPlatformGuard`.
> Seguir o padrão de `src/guards/jwt-auth.guard.ts` da Fase 2.
> Critérios de aceitação: tokens com type 'dashboard' são rejeitados, tokens com type 'platform' passam, tokens sem jti são rejeitados.

---

### ⬜ NEST-099: Platform Roles Guard
- **Fase:** 5
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-098
- **Agente:** code-reviewer
- **Estimativa:** ~30min
- **Descricao:** Criar guard de roles que usa platformHierarchy para verificar permissões de admin da plataforma.

**Prompt para o agente:**
> Criar o arquivo `src/guards/platform-roles.guard.ts`. Implementar `PlatformRolesGuard`:
> - Usa `Reflector` para ler os roles requeridos setados por `@PlatformRoles()`.
> - Extrai o role do `request.user` (do JWT payload).
> - Verifica se o role do usuário é >= ao role requerido usando `platformHierarchy` das opções do módulo (análogo ao `RolesGuard` da Fase 2 que usa `roles.hierarchy`).
> - Se a hierarquia não está configurada (`platformAdmin.roles.hierarchy`), lança `ForbiddenException` com `INSUFFICIENT_ROLE`.
> - Usar a mesma lógica utilitária `hasRole()` de `src/utils/roles.util.ts`.
> Critérios de aceitação: admin com role suficiente passa, role insuficiente recebe 403 INSUFFICIENT_ROLE.

---

### ⬜ NEST-100: PlatformRoles Decorator
- **Fase:** 5
- **Status:** TODO
- **Prioridade:** Alta
- **Dependencias:** Nenhuma
- **Agente:** typescript-reviewer
- **Estimativa:** ~20min
- **Descricao:** Criar decorator @PlatformRoles() para endpoints de plataforma.

**Prompt para o agente:**
> Criar o arquivo `src/decorators/platform-roles.decorator.ts`. Implementar o decorator `@PlatformRoles(...roles: string[])`:
> - Usa `SetMetadata` do `@nestjs/common` com chave `'platformRoles'` (ou constante exportada `PLATFORM_ROLES_KEY`).
> - Aceita um spread de strings representando os roles requeridos.
> - Exportar `PlatformRoles` e `PLATFORM_ROLES_KEY`.
> Seguir o padrão de `src/decorators/roles.decorator.ts` da Fase 2.
> Critérios de aceitação: decorator compila, seta metadata corretamente, constante PLATFORM_ROLES_KEY exportada.

---

### ⬜ NEST-101: PlatformLoginDto
- **Fase:** 5
- **Status:** TODO
- **Prioridade:** Alta
- **Dependencias:** Nenhuma
- **Agente:** typescript-reviewer
- **Estimativa:** ~20min
- **Descricao:** Criar DTO de login de plataforma com validações email e password.

**Prompt para o agente:**
> Criar o arquivo `src/dto/platform-login.dto.ts`. Implementar `PlatformLoginDto` com:
> - `@IsEmail() email: string`
> - `@IsString() @IsNotEmpty() @MaxLength(72) password: string`
> Usar decorators de `class-validator`. O `@MaxLength(72)` previne bcrypt bombing (bcrypt trunca em 72 bytes).
> Exportar a classe.
> Critérios de aceitação: validação funciona para email inválido, password vazio, password > 72 chars.

---

### ⬜ NEST-102: PlatformAuthService - login()
- **Fase:** 5
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-097, NEST-101, NEST-010, NEST-050
- **Agente:** code-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implementar o método login() do PlatformAuthService com brute-force, MFA redirect e emissão de tokens.

**Prompt para o agente:**
> Criar o arquivo `src/services/platform-auth.service.ts`. Implementar `PlatformAuthService` (injectable) com o método `login(dto: PlatformLoginDto, ip: string, userAgent: string)`:
> 1. Brute-force check: usar `BruteForceService` com identifier `sha256('platform:' + email)` — o prefixo 'platform:' evita colisão com dashboard identifiers `sha256(tenantId + ':' + email)`.
> 2. Buscar admin via `platformUserRepo.findByEmail(email)`. Se não encontrado, incrementar brute-force e lançar `INVALID_CREDENTIALS` (sem revelar que email não existe).
> 3. Comparar senha via `CryptoService.comparePassword(dto.password, admin.passwordHash)`.
> 4. Se senha inválida, incrementar brute-force e lançar `INVALID_CREDENTIALS`.
> 5. Reset brute-force counter em sucesso.
> 6. Se admin tem MFA habilitado: retornar `{ mfaRequired: true, mfaTempToken }` usando `tokenManager.issueMfaTempToken(admin.id, 'platform')`.
> 7. Se sem MFA: emitir tokens com `tokenManager.issuePlatformTokens({ sub: admin.id, type: 'platform', role: admin.role })`.
> 8. Refresh token com prefixo `prt:` no Redis.
> 9. Manter SET `psess:{userId}` com hash da sessão. Manter detalhes em `psd:{sessionHash}`.
> 10. Retornar `AuthResult` com tokens.
> Injetar: `IPlatformUserRepository`, `TokenManagerService`, `BruteForceService`, `CryptoService`, `TokenDeliveryService`, options do módulo.
> Critérios de aceitação: login com credenciais corretas retorna tokens, login com MFA retorna mfaRequired, brute-force identifier usa prefixo 'platform:'.

---

### ⬜ NEST-103: PlatformAuthService - logout()
- **Fase:** 5
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-102
- **Agente:** code-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implementar logout de admin da plataforma com blacklist e limpeza Redis.

**Prompt para o agente:**
> No arquivo `src/services/platform-auth.service.ts`, adicionar o método `logout(userId: string, jti: string, refreshToken: string, sessionHash: string)`:
> 1. Blacklist do access JWT: SET `rv:{jti}` com TTL = accessExpiresIn.
> 2. Deletar refresh token: DEL `prt:{sha256(refreshToken)}`.
> 3. Remover sessão do SET: SREM `psess:{userId}` o `sessionHash`.
> 4. Deletar detalhes da sessão: DEL `psd:{sessionHash}`.
> Critérios de aceitação: após logout, access token está na blacklist, refresh token deletado, sessão removida do SET e detalhes deletados.

---

### ⬜ NEST-104: PlatformAuthService - refresh()
- **Fase:** 5
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-102
- **Agente:** code-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implementar refresh de tokens de plataforma com rotação e atualização de sessão.

**Prompt para o agente:**
> No arquivo `src/services/platform-auth.service.ts`, adicionar o método `refresh(refreshToken: string, ip: string, userAgent: string)`:
> 1. Usar `tokenManager.reissuePlatformTokens(refreshToken)` que faz rotação com prefixo `prt:` e ponteiro `prp:`.
> 2. Atualizar SET `psess:{userId}` e detalhes `psd:{sessionHash}` durante rotação.
> 3. OBRIGATORIAMENTE: Renovar TTL do SET `psess:{userId}` com `EXPIRE` a cada rotação (previne expiração do SET enquanto tokens individuais são renovados).
> 4. Retornar novos tokens.
> Critérios de aceitação: refresh retorna novos tokens, SET psess tem TTL renovado, sessão atualizada.

---

### ⬜ NEST-105: PlatformAuthService - getMe()
- **Fase:** 5
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-102
- **Agente:** code-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implementar getMe para retornar dados do admin autenticado.

**Prompt para o agente:**
> No arquivo `src/services/platform-auth.service.ts`, adicionar o método `getMe(userId: string)`:
> 1. Buscar admin via `platformUserRepo.findById(userId)`.
> 2. Se não encontrado, lançar `NotFoundException`.
> 3. Retornar dados do admin (sem passwordHash).
> Critérios de aceitação: retorna dados do admin sem campos sensíveis.

---

### ⬜ NEST-106: PlatformAuthService - revokeAllPlatformSessions()
- **Fase:** 5
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-102
- **Agente:** code-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implementar revogação de todas as sessões de plataforma de um admin usando o SET psess.

**Prompt para o agente:**
> No arquivo `src/services/platform-auth.service.ts`, adicionar o método `revokeAllPlatformSessions(userId: string)`:
> 1. Usar `SMEMBERS psess:{userId}` para enumerar todos os session hashes ativos.
> 2. Para cada hash: DEL `prt:{hash}`, DEL `psd:{hash}`.
> 3. DEL o SET `psess:{userId}`.
> IMPORTANTE: NÃO usar `SCAN prt:*` (O(N) sobre todas as chaves). O SET garante O(M) onde M = sessões do admin.
> DESVIO DA SPEC: A spec seção 6.9 referencia `auth:prp:{userId}` como SET de sessões. `prp:` é ponteiro de rotação. O SET correto é `psess:{userId}`.
> Critérios de aceitação: todas as sessões do admin são removidas, operação é O(M) não O(N), SET psess deletado.

---

### ⬜ NEST-107: PlatformAuthController - 6 endpoints
- **Fase:** 5
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-098, NEST-099, NEST-100, NEST-102, NEST-103, NEST-104, NEST-105, NEST-106
- **Agente:** code-reviewer
- **Estimativa:** ~30min
- **Descricao:** Criar controller com os 6 endpoints de autenticação de plataforma.

**Prompt para o agente:**
> Criar o arquivo `src/controllers/platform-auth.controller.ts`. Implementar `PlatformAuthController` com os 6 endpoints:
> 1. `POST /login` — público, `@Throttle(AUTH_THROTTLE_CONFIGS.platformLogin)`. Chama `platformAuthService.login()`. Usa `TokenDeliveryService` para entregar tokens.
> 2. `POST /mfa/challenge` — público (requer mfaToken no body), `@Throttle(AUTH_THROTTLE_CONFIGS.mfaChallenge)`. Reutiliza `MfaService.challenge()` — o `context: 'platform'` no temp token direciona o fluxo para emitir tokens de plataforma. Usa `TokenDeliveryService`.
> 3. `GET /me` — protegido com `@UseGuards(JwtPlatformGuard)`. Chama `platformAuthService.getMe()`.
> 4. `POST /logout` — protegido com `@UseGuards(JwtPlatformGuard)`. Chama `platformAuthService.logout()`. Usa `TokenDeliveryService` para limpar cookies se aplicável.
> 5. `POST /refresh` — público, `@Throttle(AUTH_THROTTLE_CONFIGS.refresh)`. Chama `platformAuthService.refresh()`. Usa `TokenDeliveryService`.
> 6. `DELETE /sessions` — protegido com `@UseGuards(JwtPlatformGuard)`. Chama `platformAuthService.revokeAllPlatformSessions()`.
> LIMITAÇÃO CONHECIDA: Não existe `PlatformUserStatusGuard`. Se admin for banido após login, JWT permanece válido até expirar. Mitigação: app host deve chamar `revokeAllPlatformSessions()`. Adicionar comentário JSDoc documentando isto.
> Todos os endpoints usam `TokenDeliveryService` para entrega e extração de tokens (mesmo padrão do `AuthController`).
> Critérios de aceitação: 6 endpoints implementados, throttle em login/mfa/refresh, guards aplicados, TokenDeliveryService usado em todos.

---

### ⬜ NEST-108: Platform Auth Unit Tests
- **Fase:** 5
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-107
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Escrever testes unitários completos para PlatformAuthService e PlatformAuthController.

**Prompt para o agente:**
> Criar o arquivo `src/services/__tests__/platform-auth.service.spec.ts` e `src/controllers/__tests__/platform-auth.controller.spec.ts`. Testes requeridos:
> Para PlatformAuthService:
> 1. `login()` com credenciais válidas sem MFA retorna tokens com type 'platform'.
> 2. `login()` com MFA habilitado retorna `{ mfaRequired: true, mfaTempToken }`.
> 3. `login()` com credenciais inválidas incrementa brute-force e lança INVALID_CREDENTIALS.
> 4. `login()` com conta em lockout lança ACCOUNT_LOCKED.
> 5. `logout()` faz blacklist do jti, deleta refresh token e remove sessão.
> 6. `refresh()` retorna novos tokens e renova TTL do SET psess.
> 7. `getMe()` retorna dados do admin.
> 8. `revokeAllPlatformSessions()` enumera via SMEMBERS e deleta cada sessão.
> 9. `revokeAllPlatformSessions()` deleta o SET psess.
> Para JwtPlatformGuard:
> 10. Token com type 'dashboard' é rejeitado com PLATFORM_AUTH_REQUIRED.
> 11. Token com type 'platform' é aceito.
> 12. Token sem jti é rejeitado com TOKEN_INVALID.
> Mockar: IPlatformUserRepository, TokenManagerService, BruteForceService, CryptoService, Redis, TokenDeliveryService.
> Critérios de aceitação: todos os testes passam, cobertura >= 80% para platform-auth.service.ts.

---

### ⬜ NEST-109: OAuthModule - Module Setup
- **Fase:** 5
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-035
- **Agente:** architect
- **Estimativa:** ~45min
- **Descricao:** Criar módulo dinâmico OAuth que registra providers com base na configuração.

**Prompt para o agente:**
> Criar o arquivo `src/oauth/oauth.module.ts`. Implementar `OAuthModule` como módulo dinâmico:
> - Método estático `register(options)` ou `forRoot(options)` que recebe a configuração OAuth.
> - Registra providers OAuth com base nos providers configurados (ex: se google está configurado, registra GoogleOAuthPlugin, GoogleStrategy, GoogleAuthGuard).
> - Importado condicionalmente pelo `BymaxAuthModule` — só registrado se `oauth` está presente na configuração.
> - Registra `OAuthService` como provider.
> - Registra rotas dinamicamente para cada provider configurado: `GET /{routePrefix}/{provider}?tenantId=xxx` e `GET /{routePrefix}/{provider}/callback`.
> Critérios de aceitação: módulo compila, registra providers condicionalmente, rotas dinâmicas registradas.

---

### ⬜ NEST-110: OAuthService - initiateOAuth()
- **Fase:** 5
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-109
- **Agente:** code-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implementar início do fluxo OAuth com geração de state CSRF e redirect.

**Prompt para o agente:**
> Criar o arquivo `src/oauth/oauth.service.ts`. Implementar `OAuthService` com método `initiateOAuth(provider: string, tenantId: string)`:
> 1. Gerar state aleatório com `crypto.randomBytes(32).toString('hex')` (64 caracteres hex).
> 2. Armazenar no Redis: `os:{sha256(state)}` com valor `{ tenantId }` e TTL 10 min (600s).
> 3. NOTA: O pacote NÃO valida que tenantId existe (database-agnostic). O hook `onOAuthLogin` é o ponto de validação. Documentar com JSDoc que sem `onOAuthLogin`, tenant spoofing é possível.
> 4. Construir URL de redirect para o provider com query params: `client_id`, `redirect_uri`, `scope`, `state`.
> 5. Retornar redirect HTTP 302 para URL do provider.
> Injetar: Redis, options do módulo (com config OAuth por provider).
> Critérios de aceitação: state gerado e armazenado com TTL 10min, URL construída corretamente, redirect 302 retornado.

---

### ⬜ NEST-111: OAuthService - handleCallback()
- **Fase:** 5
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-110
- **Agente:** code-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implementar processamento de callback OAuth com validação de state, criação/vinculação de usuário e emissão de tokens.

**Prompt para o agente:**
> No arquivo `src/oauth/oauth.service.ts`, adicionar o método `handleCallback(profile: OAuthProfile, state: string, ip: string, userAgent: string)`:
> 1. Validar state no Redis: GET `os:{sha256(state)}`. Se não encontrado, lançar `OAUTH_FAILED`.
> 2. Extrair `tenantId` do state armazenado.
> 3. Consumir state: DEL `os:{sha256(state)}` (single-use).
> 4. Buscar usuário existente: `userRepo.findByOAuthId(provider, providerId, tenantId)`.
> 5. Executar `hooks.onOAuthLogin(profile, existingUser, { tenantId, ip, userAgent })`.
> 6. Conforme resultado do hook:
>    - `action: 'create'`: criar usuário via `userRepo.createWithOAuth(createData)`.
>    - `action: 'link'`: vincular via `userRepo.linkOAuth(userId, provider, providerId)`.
>    - `action: 'reject'`: lançar exceção com `rejectReason`.
> 7. Emitir tokens via `tokenManager.issueTokens()`.
> 8. Criar sessão se habilitado (via SessionService).
> 9. Retornar `AuthResult`.
> Critérios de aceitação: state validado e consumido, hook executado, 3 actions (create/link/reject) funcionam, tokens emitidos.

---

### ⬜ NEST-112: Google OAuth Plugin
- **Fase:** 5
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-109
- **Agente:** code-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implementar plugin Google OAuth com strategy e guard.

**Prompt para o agente:**
> Criar 3 arquivos:
> 1. `src/oauth/google/google-oauth.plugin.ts`: implementar `GoogleOAuthPlugin` que implementa a interface `OAuthProviderPlugin`. Deve expor `name: 'google'`, `strategy`, e `guard`. Configuração via `clientId`, `clientSecret`, `callbackUrl`, `scope` (default: `['email', 'profile']`).
> 2. `src/oauth/google/google.strategy.ts`: Passport strategy usando `passport-google-oauth20`. Extrai profile com `email`, `name`, `picture`, `providerId`. O callback chama `done(null, profile)`.
> 3. `src/oauth/google/google-auth.guard.ts`: `AuthGuard('google')`.
> NOTA: `passport-google-oauth20` é peer dependency opcional. Se não instalado, o plugin deve lançar erro descritivo no construtor.
> Critérios de aceitação: plugin implementa interface, strategy extrai profile corretamente, guard funciona com Passport.

---

### ⬜ NEST-113: OAuth Unit Tests
- **Fase:** 5
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-111, NEST-112
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Escrever testes para OAuthService cobrindo fluxo completo, state CSRF e tenantId resolution.

**Prompt para o agente:**
> Criar o arquivo `src/oauth/__tests__/oauth.service.spec.ts`. Testes requeridos:
> 1. `initiateOAuth()` gera state de 64 chars hex e armazena no Redis com TTL 600s.
> 2. `handleCallback()` com action 'create': cria usuário e emite tokens.
> 3. `handleCallback()` com action 'link': vincula OAuth a usuário existente e emite tokens.
> 4. `handleCallback()` com action 'reject': lança exceção com rejectReason.
> 5. `handleCallback()` com state inválido (não encontrado no Redis): lança OAUTH_FAILED.
> 6. State é consumido (single-use): segunda chamada com mesmo state falha.
> 7. `tenantId` é extraído corretamente do state armazenado.
> 8. Google plugin extrai profile com campos corretos.
> Mockar: Redis, IUserRepository, TokenManagerService, hooks, SessionService.
> Critérios de aceitação: todos os testes passam, cobertura >= 80% para oauth.service.ts.

---

### ⬜ NEST-114: CreateInvitationDto
- **Fase:** 5
- **Status:** TODO
- **Prioridade:** Alta
- **Dependencias:** Nenhuma
- **Agente:** typescript-reviewer
- **Estimativa:** ~20min
- **Descricao:** Criar DTO para criação de convites com email, role e tenantName opcional.

**Prompt para o agente:**
> Criar o arquivo `src/dto/create-invitation.dto.ts`. Implementar `CreateInvitationDto`:
> - `@IsEmail() email: string`
> - `@IsString() @IsNotEmpty() role: string`
> - `@IsOptional() @IsString() tenantName?: string`
> NOTA: `tenantId` NÃO está no DTO — é extraído do JWT do inviter no controller. A validação de `role` contra `roles.hierarchy` é feita no service, não no DTO (class-validator não tem acesso ao contexto de DI). `tenantName` é campo opcional adicionado para `IEmailProvider.sendInvitation()` — se não fornecido, usa `tenantId` como fallback.
> Critérios de aceitação: validação funciona, tenantId ausente do DTO, tenantName opcional.

---

### ⬜ NEST-115: AcceptInvitationDto
- **Fase:** 5
- **Status:** TODO
- **Prioridade:** Alta
- **Dependencias:** Nenhuma
- **Agente:** typescript-reviewer
- **Estimativa:** ~20min
- **Descricao:** Criar DTO para aceitação de convites com token, name e password.

**Prompt para o agente:**
> Criar o arquivo `src/dto/accept-invitation.dto.ts`. Implementar `AcceptInvitationDto`:
> - `@IsString() @IsNotEmpty() token: string`
> - `@IsString() @MinLength(2) name: string`
> - `@IsString() @MinLength(8) @MaxLength(72) password: string`
> O `@MaxLength(72)` previne bcrypt bombing.
> Critérios de aceitação: validação funciona para token vazio, name < 2, password < 8, password > 72.

---

### ⬜ NEST-116: InvitationService - invite()
- **Fase:** 5
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-114, NEST-010
- **Agente:** code-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implementar criação de convites com validação de role na hierarquia e armazenamento seguro no Redis.

**Prompt para o agente:**
> Criar o arquivo `src/services/invitation.service.ts`. Implementar `InvitationService` com método `invite(inviterId: string, email: string, role: string, tenantId: string, tenantName?: string)`:
> 1. Validar que o `role` existe na `roles.hierarchy` configurada. Se não existe, lançar `INSUFFICIENT_ROLE`.
> 2. Validação de autorização: buscar inviter via `userRepo.findById(inviterId)`, verificar que role do inviter >= role solicitado usando `hasRole()` de `src/utils/roles.util.ts`. Se não autorizado, lançar `INSUFFICIENT_ROLE`.
> 3. Gerar token seguro via `generateSecureToken(32)`.
> 4. Armazenar: `inv:{sha256(token)}` com valor `{ email, role, tenantId, inviterId }` e TTL = `tokenTtlSeconds` (da config invitations).
> 5. Buscar nome do inviter via `userRepo.findById(inviterId)` para incluir no email.
> 6. Se `tenantName` não fornecido, usar `tenantId` como fallback.
> 7. Enviar email via `emailProvider.sendInvitation({ email, token, inviterName, tenantName, role })`.
> 8. O raw token NUNCA é logado (apenas NoOpEmailProvider loga truncado).
> Injetar: IUserRepository, IEmailProvider, Redis, options do módulo.
> Critérios de aceitação: role validado contra hierarquia, autorização do inviter verificada, token armazenado com TTL, email enviado.

---

### ⬜ NEST-117: InvitationService - acceptInvitation()
- **Fase:** 5
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-116, NEST-115
- **Agente:** code-reviewer
- **Estimativa:** ~30min
- **Descricao:** Implementar aceitação de convites com criação de usuário e emissão de tokens.

**Prompt para o agente:**
> No arquivo `src/services/invitation.service.ts`, adicionar o método `acceptInvitation(dto: AcceptInvitationDto, ip: string, userAgent: string)`:
> 1. Buscar convite: GET `inv:{sha256(dto.token)}`. Se não encontrado, lançar `INVALID_INVITATION_TOKEN`.
> 2. Verificar se email já existe no tenant via `userRepo.findByEmail(invitation.email, invitation.tenantId)`. Se existe, lançar erro.
> 3. Hash da senha via `CryptoService.hashPassword(dto.password)`.
> 4. Criar usuário com: email do convite, nome do DTO, passwordHash, role do convite, tenantId do convite, `emailVerified: true` (convite implica verificação do email).
> 5. Consumir convite: DEL `inv:{sha256(dto.token)}`.
> 6. Emitir tokens via `tokenManager.issueTokens()`.
> 7. Executar `hooks.afterInvitationAccepted({ user, invitation })` se hook configurado.
> 8. Retornar `AuthResult`.
> Critérios de aceitação: convite consumido, usuário criado com emailVerified true, tokens emitidos, hook executado.

---

### ⬜ NEST-118: InvitationController
- **Fase:** 5
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-116, NEST-117
- **Agente:** code-reviewer
- **Estimativa:** ~30min
- **Descricao:** Criar controller com endpoints para criar e aceitar convites.

**Prompt para o agente:**
> Criar o arquivo `src/controllers/invitation.controller.ts`. Implementar `InvitationController`:
> 1. `POST /` — protegido com `@UseGuards(JwtAuthGuard, RolesGuard)`. Extrai `tenantId` do JWT (req.user.tenantId), NÃO do body. `tenantName` vem do body (`dto.tenantName`) ou usa `tenantId` como fallback. Chama `invitationService.invite(req.user.sub, dto.email, dto.role, tenantId, dto.tenantName)`.
> 2. `POST /accept` — público, com `@Throttle(AUTH_THROTTLE_CONFIGS.invitationAccept)`. Chama `invitationService.acceptInvitation(dto, ip, userAgent)`. Usa `TokenDeliveryService` para entregar tokens.
> DESVIO DA SPEC: DTO da spec não inclui `tenantName`, mas `IEmailProvider.sendInvitation()` o requer. Campo opcional adicionado.
> Critérios de aceitação: POST / extrai tenantId do JWT, POST /accept é público com throttle, TokenDeliveryService usado.

---

### ⬜ NEST-119: Invitation Unit Tests
- **Fase:** 5
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-118
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Escrever testes unitários para InvitationService cobrindo criação, aceitação, e validações.

**Prompt para o agente:**
> Criar os arquivos `src/services/__tests__/invitation.service.spec.ts` e `src/controllers/__tests__/invitation.controller.spec.ts`. Testes requeridos:
> 1. `invite()` com role válido e inviter autorizado: token gerado e email enviado.
> 2. `invite()` com role inexistente na hierarquia: lança INSUFFICIENT_ROLE.
> 3. `invite()` com inviter sem autorização (role inferior): lança INSUFFICIENT_ROLE.
> 4. `acceptInvitation()` com token válido: cria usuário com emailVerified true e retorna tokens.
> 5. `acceptInvitation()` com token inválido/expirado: lança INVALID_INVITATION_TOKEN.
> 6. `acceptInvitation()` com email já existente no tenant: lança erro.
> 7. Convite consumido após aceitação (segunda aceitação falha).
> 8. Controller POST / extrai tenantId do JWT, não do body.
> 9. `afterInvitationAccepted` hook é executado.
> Mockar: IUserRepository, IEmailProvider, Redis, TokenManagerService, CryptoService, hooks.
> Critérios de aceitação: todos os testes passam, cobertura >= 80%.

---

### ⬜ NEST-120: Phase 5 Dynamic Module Integration
- **Fase:** 5
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-107, NEST-109, NEST-118
- **Agente:** architect
- **Estimativa:** ~45min
- **Descricao:** Integrar PlatformAuth, OAuth e Invitations no módulo dinâmico principal com registro condicional.

**Prompt para o agente:**
> Atualizar o arquivo `src/bymax-auth.module.ts` (o módulo dinâmico principal) para:
> 1. Registrar `PlatformAuthService`, `PlatformAuthController`, `JwtPlatformStrategy`, `JwtPlatformGuard`, `PlatformRolesGuard` se `platformAdmin.enabled` é true na configuração.
> 2. Importar `OAuthModule` se `oauth` está presente e configurado.
> 3. Registrar `InvitationService` e `InvitationController` se `invitations.enabled` é true.
> 4. Garantir que controllers são adicionados ao array `controllers` dinamicamente (não hardcoded).
> 5. Garantir que não há ciclos de DI: `InvitationService` usa `hasRole()` de `utils/roles.util.ts`, NÃO injeta `RolesGuard`.
> Critérios de aceitação: cada feature só é registrada se habilitada na config, módulo compila com qualquer combinação de features.

---

### ⬜ NEST-121: Phase 5 Barrel Export Update
- **Fase:** 5
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-120
- **Agente:** architect
- **Estimativa:** ~15min
- **Descricao:** Atualizar barrel export com todos os exports da Fase 5.

**Prompt para o agente:**
> Atualizar o arquivo `src/index.ts` para adicionar os seguintes exports:
> - `export { JwtPlatformGuard } from './guards/jwt-platform.guard'`
> - `export { PlatformRolesGuard } from './guards/platform-roles.guard'`
> - `export { PlatformRoles } from './decorators/platform-roles.decorator'`
> - `export type { PlatformAuthResult }` — confirmar que já foi definido e exportado na Fase 1, se não, adicionar.
> - `export { PlatformLoginDto } from './dto/platform-login.dto'`
> - `export { AcceptInvitationDto } from './dto/accept-invitation.dto'`
> - `export { CreateInvitationDto } from './dto/create-invitation.dto'`
> IMPORTANTE: DTOs usam `export` (nunca `export type`) para preservar metadata de `class-validator` em runtime.
> Critérios de aceitação: todos os novos exports presentes no index.ts, DTOs com export regular (não type export).

---

## Fase 6 — Integracao, Polimento e Publicacao

### ⬜ NEST-122: WsJwtGuard
- **Fase:** 6
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-026
- **Agente:** code-reviewer
- **Estimativa:** ~30min
- **Descricao:** Criar guard WebSocket que extrai JWT do handshake e valida tipo dashboard.

**Prompt para o agente:**
> Criar o arquivo `src/guards/ws-jwt.guard.ts`. Implementar `WsJwtGuard`:
> 1. No `canActivate(context)`: verificar se `@nestjs/websockets` está disponível via try/catch em `require.resolve('@nestjs/websockets')`. Se não disponível, lançar erro descritivo: "WsJwtGuard requires @nestjs/websockets to be installed". Este check deve ser em runtime (canActivate), não apenas compile-time.
> 2. Extrair token de `client.handshake.headers.authorization` (formato `Bearer <token>`). NÃO extrair de query params (segurança).
> 3. Validar JWT usando o mesmo secret/options do módulo.
> 4. Verificar `payload.type === 'dashboard'`. Rejeitar tokens `platform` e `mfa_challenge`.
> 5. Verificar blacklist: `rv:{jti}`.
> 6. Popular `client.data.user` com o payload.
> 7. Retornar true se válido.
> Critérios de aceitação: token extraído do header (não query), tipo 'platform' rejeitado, tipo 'dashboard' aceito, peer dep check em runtime.

---

### ⬜ NEST-123: SelfOrAdminGuard
- **Fase:** 6
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-026
- **Agente:** code-reviewer
- **Estimativa:** ~30min
- **Descricao:** Criar guard que permite acesso se userId no param === JWT.sub ou se role é admin. Protecao contra IDOR.

**Prompt para o agente:**
> Criar o arquivo `src/guards/self-or-admin.guard.ts`. Implementar `SelfOrAdminGuard`:
> 1. Comparar `req.params.userId` (ou `req.params.id`) com `req.user.sub`.
> 2. Se match: permitir acesso.
> 3. Se não match: verificar se o role do usuário é admin na hierarquia usando `hasRole()` de `src/utils/roles.util.ts`.
> 4. Para session hashes em `DELETE /sessions/:id`: validar formato SHA-256 hex (64 caracteres, regex `[a-f0-9]{64}`). Se formato inválido, rejeitar.
> 5. Se não é self nem admin: lançar `ForbiddenException`.
> IMPORTANTE: Este guard NÃO valida que o recurso alvo pertence ao `tenantId` do JWT. Em contextos multi-tenant, o controller/service deve verificar ownership adicionalmente. Adicionar comentário JSDoc documentando esta limitação.
> Critérios de aceitação: self-access permitido, admin-access permitido, outro-user rejeitado, session hash validado contra regex.

---

### ⬜ NEST-124: OptionalAuthGuard
- **Fase:** 6
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-026
- **Agente:** code-reviewer
- **Estimativa:** ~30min
- **Descricao:** Criar guard que tenta autenticar via JWT mas nao falha se token ausente.

**Prompt para o agente:**
> Criar o arquivo `src/guards/optional-auth.guard.ts`. Implementar `OptionalAuthGuard`:
> 1. Extends `JwtAuthGuard` (da Fase 2).
> 2. Sobrescrever `handleRequest(err, user, info)`:
>    - Se token ausente (info indica 'No auth token'): retornar `null` (NÃO lançar exceção).
>    - Se token presente mas inválido: lançar exceção normalmente.
>    - Se token válido: retornar `user`.
> 3. `request.user` será `null` se sem token, ou o payload se autenticado.
> Critérios de aceitação: sem token -> user null (sem exceção), token inválido -> exceção, token válido -> user populado.

---

### ⬜ NEST-125: Additional Guards Unit Tests
- **Fase:** 6
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-122, NEST-123, NEST-124
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Escrever testes unitários para WsJwtGuard, SelfOrAdminGuard e OptionalAuthGuard.

**Prompt para o agente:**
> Criar arquivos de teste para os 3 guards:
> - `src/guards/__tests__/ws-jwt.guard.spec.ts`
> - `src/guards/__tests__/self-or-admin.guard.spec.ts`
> - `src/guards/__tests__/optional-auth.guard.spec.ts`
> Testes requeridos:
> WsJwtGuard:
> 1. Token com type 'platform' é rejeitado.
> 2. Token com type 'dashboard' é aceito e client.data.user populado.
> 3. Token com type 'mfa_challenge' é rejeitado.
> 4. Token na blacklist é rejeitado.
> 5. Sem @nestjs/websockets instalado: lança erro descritivo.
> 6. Token extraído do header, não do query param.
> SelfOrAdminGuard:
> 7. req.params.userId === req.user.sub: acesso permitido.
> 8. req.params.userId !== req.user.sub mas user é admin: acesso permitido.
> 9. req.params.userId !== req.user.sub e user não é admin: ForbiddenException.
> 10. Session hash com formato inválido (não SHA-256 hex): rejeitado.
> OptionalAuthGuard:
> 11. Sem token: request.user é null, sem exceção.
> 12. Token válido: request.user é o payload JWT.
> 13. Token inválido/expirado: lança exceção.
> Mockar: Redis, ExecutionContext, JWT verify.
> Critérios de aceitação: todos os 13 testes passam.

---

### ⬜ NEST-126: E2E Test - Full Auth Flow
- **Fase:** 6
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-035, NEST-080
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Teste E2E do fluxo completo: register, login, refresh, /me, logout em ambos os modos cookie e bearer.

**Prompt para o agente:**
> Criar o arquivo `test/e2e/auth-flow.e2e-spec.ts`. Implementar teste E2E usando `@nestjs/testing` com `Test.createTestingModule` e `supertest`:
> 1. Configurar módulo de teste com `BymaxAuthModule.registerAsync()`, mock de `IUserRepository` e `IEmailProvider`, Redis de teste (ou mock).
> 2. Cenário bearer mode:
>    - POST /auth/register -> 201, body contém accessToken e refreshToken.
>    - POST /auth/login -> 200, body contém tokens.
>    - POST /auth/refresh com refreshToken -> 200, novos tokens.
>    - GET /auth/me com Authorization header -> 200, dados do usuário.
>    - POST /auth/logout -> 200.
>    - GET /auth/me com token antigo -> 401 (blacklisted).
> 3. Cenário cookie mode:
>    - POST /auth/login -> 200, cookies Set-Cookie com HttpOnly.
>    - GET /auth/me (cookies enviados automaticamente) -> 200.
> Critérios de aceitação: fluxo completo funciona em ambos os modos, tokens são corretamente emitidos e invalidados.

---

### ⬜ NEST-127: E2E Test - MFA Flow
- **Fase:** 6
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-050, NEST-126
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Teste E2E do fluxo MFA completo incluindo setup, verify, challenge com TOTP e recovery code.

**Prompt para o agente:**
> Criar o arquivo `test/e2e/mfa-flow.e2e-spec.ts`. Implementar:
> 1. Register -> Login -> POST /auth/mfa/setup (retorna secret e QR) -> POST /auth/mfa/verify (com TOTP válido, retorna recovery codes) -> POST /auth/logout.
> 2. Login novamente -> resposta com mfaRequired: true e mfaTempToken -> POST /auth/mfa/challenge com TOTP -> tokens emitidos.
> 3. Login -> mfaTempToken -> POST /auth/mfa/challenge com recovery code -> tokens emitidos (recovery code consumido).
> Usar `otpauth` ou `totp-generator` para gerar códigos TOTP válidos no teste.
> Critérios de aceitação: setup + verify funciona, challenge com TOTP funciona, challenge com recovery code funciona e é consumido.

---

### ⬜ NEST-128: E2E Test - Sessions Flow
- **Fase:** 6
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-080, NEST-126
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Teste E2E do fluxo de sessoes: login em 3 dispositivos, listar, revogar uma, revogar todas exceto atual.

**Prompt para o agente:**
> Criar o arquivo `test/e2e/sessions-flow.e2e-spec.ts`. Implementar:
> 1. Login com 3 user-agents diferentes (simular 3 dispositivos).
> 2. GET /auth/sessions -> lista 3 sessões, uma com `isCurrent: true`.
> 3. DELETE /auth/sessions/:id (revogar sessão específica) -> sessão removida.
> 4. GET /auth/sessions -> lista 2 sessões.
> 5. DELETE /auth/sessions (revogar todas exceto atual) -> apenas sessão atual permanece.
> 6. GET /auth/sessions -> lista 1 sessão.
> Critérios de aceitação: sessões listadas corretamente, revogação individual e bulk funcionam, isCurrent correto.

---

### ⬜ NEST-129: E2E Test - Password Reset Flow
- **Fase:** 6
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-085, NEST-126
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Teste E2E dos dois métodos de password reset: token e OTP.

**Prompt para o agente:**
> Criar o arquivo `test/e2e/password-reset-flow.e2e-spec.ts`. Implementar:
> 1. Token method:
>    - POST /auth/password/forgot com email -> 200 (resposta genérica, não revela se email existe).
>    - Extrair token do mock de IEmailProvider.
>    - POST /auth/password/reset com token e nova senha -> 200.
>    - Login com nova senha -> sucesso.
> 2. OTP method:
>    - POST /auth/password/forgot com email -> 200.
>    - Extrair OTP do mock de IEmailProvider.
>    - POST /auth/password/verify-otp com OTP -> 200, retorna verifiedToken.
>    - POST /auth/password/reset com verifiedToken e nova senha -> 200.
>    - Login com nova senha -> sucesso.
> Critérios de aceitação: ambos os métodos funcionam end-to-end, senha efetivamente alterada.

---

### ⬜ NEST-130: E2E Test - Invitations Flow
- **Fase:** 6
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-118, NEST-126
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Teste E2E do fluxo de convites: admin cria convite, destinatário aceita, login.

**Prompt para o agente:**
> Criar o arquivo `test/e2e/invitations-flow.e2e-spec.ts`. Implementar:
> 1. Login como admin (com role suficiente).
> 2. POST /auth/invitations com email e role -> 201.
> 3. Extrair token do mock de IEmailProvider.
> 4. POST /auth/invitations/accept com token, name e password -> 200, tokens emitidos.
> 5. Login com email e senha do convite -> sucesso.
> 6. Usuário criado com emailVerified: true e role do convite.
> Critérios de aceitação: convite criado, aceito, usuário criado com role e emailVerified corretos.

---

### ⬜ NEST-131: E2E Test - OAuth Flow (Mock)
- **Fase:** 6
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-111, NEST-126
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Teste E2E do fluxo OAuth com provider mockado.

**Prompt para o agente:**
> Criar o arquivo `test/e2e/oauth-flow.e2e-spec.ts`. Implementar:
> 1. Mockar o OAuth provider (não fazer chamada real ao Google).
> 2. GET /auth/oauth/google?tenantId=xxx -> redirect 302 com state no URL.
> 3. Simular callback: GET /auth/oauth/google/callback com profile e state válido.
> 4. Hook onOAuthLogin retorna action 'create' -> usuário criado, tokens emitidos.
> 5. Segundo callback com mesmo providerId: hook retorna action 'link' -> usuário vinculado.
> 6. Callback com state inválido -> erro OAUTH_FAILED.
> Critérios de aceitação: fluxo create e link funcionam, state CSRF validado.

---

### ⬜ NEST-132: E2E Test - FIFO Session Eviction
- **Fase:** 6
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-080, NEST-126
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Teste E2E de eviction FIFO quando limite de sessoes é excedido.

**Prompt para o agente:**
> Criar o arquivo `test/e2e/session-eviction.e2e-spec.ts`. Implementar:
> 1. Configurar módulo com `sessions.maxPerUser: 5`.
> 2. Login com 6 user-agents diferentes (simular 6 dispositivos).
> 3. Verificar que a sessão mais antiga (primeiro login) foi removida automaticamente.
> 4. GET /auth/sessions -> retorna exatamente 5 sessões.
> 5. Verificar que `isCurrent` é true apenas para a última sessão usada.
> Critérios de aceitação: 6o login evicta 1a sessão, lista retorna 5 sessões, isCurrent correto.

---

### ⬜ NEST-133: E2E Test - Refresh Concurrency
- **Fase:** 6
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-035, NEST-126
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Teste E2E de duas requisicoes de refresh simultâneas com grace window.

**Prompt para o agente:**
> Criar o arquivo `test/e2e/refresh-concurrency.e2e-spec.ts`. Implementar:
> 1. Login e obter refreshToken.
> 2. Enviar duas requisições POST /auth/refresh simultaneamente (Promise.all) com o mesmo refreshToken.
> 3. Primeira requisição sucede com novos tokens.
> 4. Segunda requisição usa grace window e retorna o MESMO novo token (não gera um terceiro).
> 5. O refreshToken original não funciona mais após grace window expirar.
> Critérios de aceitação: ambas as requisições retornam sucesso, retornam mesmos tokens novos, token original invalidado.

---

### ⬜ NEST-134: E2E Test - Security Scenarios
- **Fase:** 6
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-126, NEST-127
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Teste E2E de cenários de segurança: brute-force, blacklist, cross-tenant, role, token sem jti, MFA cross-context, OTP cooldown.

**Prompt para o agente:**
> Criar o arquivo `test/e2e/security.e2e-spec.ts`. Implementar:
> 1. Brute-force: 10 tentativas de login com senha errada -> resposta com status 429 e header `Retry-After`.
> 2. Token blacklist: logout -> reutilizar access token -> 401.
> 3. Cross-tenant: login em tenant A -> acessar recurso com tenantId B no JWT -> 403.
> 4. Role insuficiente: login como MEMBER -> acessar endpoint @Roles('ADMIN') -> 403.
> 5. Token sem `jti`: craftar JWT sem jti -> 401 TOKEN_INVALID.
> 6. MFA temp token 'dashboard' usado no endpoint de plataforma -> rejeitado.
> 7. OTP cooldown: enviar forgot password -> imediatamente enviar novamente (< 60s) -> sucesso retornado mas novo OTP NÃO gerado.
> Critérios de aceitação: todos os 7 cenários de segurança verificados e passando.

---

### ⬜ NEST-135: Security Review - Password and Crypto
- **Fase:** 6
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-010
- **Agente:** security-reviewer
- **Estimativa:** ~45min
- **Descricao:** Revisar todas as operacoes de senha e criptografia contra checklist do Apendice B.

**Prompt para o agente:**
> Realizar revisão de segurança verificando os seguintes itens nos arquivos do projeto:
> 1. `src/services/crypto.service.ts`: senhas hasheadas com bcrypt (12 rounds). Verificar `saltRounds: 12`.
> 2. `src/services/crypto.service.ts`: comparação constant-time em senhas via `bcrypt.compare()` (inerentemente constant-time).
> 3. `src/services/crypto.service.ts`: secrets TOTP criptografados com AES-256-GCM. Verificar uso de `createCipheriv('aes-256-gcm')`.
> 4. MFA recovery codes hasheados com bcrypt (não armazenados em plain text).
> 5. Refresh tokens são opacos (UUID v4, não JWT).
> 6. Comparação de OTPs e recovery codes usa `timingSafeEqual` com buffers de mesmo comprimento.
> Produzir relatório com status (PASS/FAIL) para cada item e recomendações de correção se FAIL.
> Critérios de aceitação: todos os 6 itens verificados, relatório produzido com evidências (linhas de código).

---

### ⬜ NEST-136: Security Review - Token and Session
- **Fase:** 6
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-035, NEST-080
- **Agente:** security-reviewer
- **Estimativa:** ~45min
- **Descricao:** Revisar seguranca de tokens, refresh, blacklist e cookies.

**Prompt para o agente:**
> Realizar revisão de segurança verificando:
> 1. `src/services/token-manager.service.ts`: rotação de refresh com grace window implementada.
> 2. Blacklist de access tokens via `rv:{jti}` no Redis.
> 3. `src/services/token-delivery.service.ts`: HttpOnly cookies em modo cookie/both.
> 4. Refresh cookie com SameSite Strict.
> 5. Path restrito `/auth` (ou configurado) no refresh cookie.
> 6. Algorithm pinning no JWT Strategy: `algorithms: ['HS256']` em `src/strategies/jwt.strategy.ts` E `src/strategies/jwt-platform.strategy.ts`.
> 7. SHA-256 usado em todas as chaves Redis (refresh tokens, sessions, OTPs, etc.).
> Produzir relatório com status PASS/FAIL para cada item.
> Critérios de aceitação: todos os 7 itens verificados com evidências de código.

---

### ⬜ NEST-137: Security Review - Anti-Enumeration and Brute Force
- **Fase:** 6
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-026, NEST-085
- **Agente:** security-reviewer
- **Estimativa:** ~45min
- **Descricao:** Revisar proteções contra enumeração de usuários, brute-force e sanitização.

**Prompt para o agente:**
> Realizar revisão de segurança verificando:
> 1. `src/services/brute-force.service.ts`: brute-force por email scopado por tenant (identifier usa `sha256(tenantId + ':' + email)`).
> 2. Rate limiting por IP: verificar que `@Throttle()` com configs de `AUTH_THROTTLE_CONFIGS` está presente em todos os endpoints sensíveis (login, register, forgot-password, mfa/challenge, refresh, invitation/accept, platform/login).
> 3. Não revelação de existência de usuário: login com email inexistente retorna mesma mensagem que senha errada. forgot-password sempre retorna sucesso.
> 4. PII mascarado em logs: verificar que NestJS Logger não loga emails, senhas, tokens em plain text.
> 5. Anti-replay de código TOTP: verificar que códigos usados são armazenados e rejeitados se reutilizados.
> 6. OTP com limite de 5 tentativas.
> 7. Sanitização de headers no HookContext: verificar que headers sensíveis (Authorization, Cookie) são removidos antes de passar ao hook.
> Produzir relatório PASS/FAIL para cada item.
> Critérios de aceitação: todos os 7 itens verificados.

---

### ⬜ NEST-138: JSDoc Documentation - Services
- **Fase:** 6
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-107, NEST-118, NEST-122
- **Agente:** planner
- **Estimativa:** ~45min
- **Descricao:** Adicionar JSDoc em todos os métodos públicos de todos os services.

**Prompt para o agente:**
> Adicionar documentação JSDoc completa em todos os métodos públicos dos seguintes arquivos de serviço:
> - `src/services/auth.service.ts`
> - `src/services/token-manager.service.ts`
> - `src/services/token-delivery.service.ts`
> - `src/services/brute-force.service.ts`
> - `src/services/crypto.service.ts`
> - `src/services/mfa.service.ts`
> - `src/services/session.service.ts`
> - `src/services/password-reset.service.ts`
> - `src/services/otp.service.ts`
> - `src/services/platform-auth.service.ts`
> - `src/services/invitation.service.ts`
> - `src/oauth/oauth.service.ts`
> Cada JSDoc deve incluir: descrição do método, `@param` para cada parâmetro com tipo e descrição, `@returns` com tipo e descrição, `@throws` listando exceções possíveis.
> Critérios de aceitação: todos os métodos públicos de todos os services têm JSDoc completo.

---

### ⬜ NEST-139: JSDoc Documentation - Guards and Decorators
- **Fase:** 6
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-125
- **Agente:** planner
- **Estimativa:** ~20min
- **Descricao:** Adicionar JSDoc em todos os guards e decorators exportados.

**Prompt para o agente:**
> Adicionar documentação JSDoc completa nos seguintes arquivos:
> Guards: `jwt-auth.guard.ts`, `jwt-platform.guard.ts`, `roles.guard.ts`, `platform-roles.guard.ts`, `user-status.guard.ts`, `mfa-verified.guard.ts`, `ws-jwt.guard.ts`, `self-or-admin.guard.ts`, `optional-auth.guard.ts` (todos em `src/guards/`).
> Decorators: `current-user.decorator.ts`, `roles.decorator.ts`, `platform-roles.decorator.ts`, `public.decorator.ts` (todos em `src/decorators/`).
> Cada JSDoc deve incluir: descrição do guard/decorator, exemplos de uso, notas de segurança quando aplicável (ex: limitações cross-tenant do SelfOrAdminGuard, peer dep de WsJwtGuard).
> Critérios de aceitação: todos os guards e decorators públicos têm JSDoc com exemplos.

---

### ⬜ NEST-140: README.md - Quick Start and Configuration
- **Fase:** 6
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-120
- **Agente:** planner
- **Estimativa:** ~45min
- **Descricao:** Criar README com instalação, configuração mínima, registerAsync e implementação de IUserRepository.

**Prompt para o agente:**
> Criar o arquivo `README.md` na raiz do projeto com as seguintes seções:
> 1. **Instalação:** `npm install @bymax-one/nest-auth` com lista de peer dependencies.
> 2. **Configuração mínima:** exemplo completo de `BymaxAuthModule.registerAsync()` com `useFactory` mostrando options obrigatórias (jwt.secret, repositories).
> 3. **Exemplo de IUserRepository:** implementação completa de referência com todos os métodos requeridos, incluindo nota sobre tipagem.
> 4. **Exemplo de IEmailProvider:** implementação de referência com NOTA DE SEGURANÇA: todos os valores de usuário interpolados em HTML devem ser escapados (`escapeHtml(name)`) para prevenir XSS nas notificações.
> 5. **Tabela de endpoints:** todos os 14+ endpoints com método, path, auth, guard e descrição.
> 6. **Tabela de guards e decorators:** nome, tipo, descrição.
> 7. **Seção de segurança:** allowlist de domínios em `resolveDomains`, recovery sem TOTP requer intervenção admin, `@MaxLength(72)` em senhas.
> 8. **Nota sobre @nestjs/throttler:** >= 6.0.0 requerido para `AUTH_THROTTLE_CONFIGS`.
> Critérios de aceitação: README completo e funcional, exemplos de código corretos e testáveis.

---

### ⬜ NEST-141: CHANGELOG.md v1.0.0
- **Fase:** 6
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-140
- **Agente:** planner
- **Estimativa:** ~45min
- **Descricao:** Popular CHANGELOG.md com entrada v1.0.0 detalhando todas as features.

**Prompt para o agente:**
> Atualizar o arquivo `CHANGELOG.md` (criado na Fase 1) com a entrada v1.0.0. Incluir todas as features implementadas organizadas por categoria:
> - **Authentication:** register, login, logout, refresh, getMe, email verification
> - **MFA:** TOTP setup/verify, challenge, recovery codes, disable
> - **Sessions:** list, revoke, revoke all, FIFO eviction
> - **Password Reset:** token method, OTP method
> - **Platform Admin:** login, logout, refresh, getMe, revoke all sessions, MFA
> - **OAuth:** extensible plugin system, Google provider
> - **Invitations:** create, accept
> - **Guards:** JwtAuthGuard, JwtPlatformGuard, RolesGuard, PlatformRolesGuard, UserStatusGuard, MfaVerifiedGuard, WsJwtGuard, SelfOrAdminGuard, OptionalAuthGuard
> - **Security:** bcrypt, AES-256-GCM, brute-force protection, CSRF state, constant-time comparison, algorithm pinning
> Formato: Keep a Changelog (https://keepachangelog.com).
> Critérios de aceitação: entrada v1.0.0 completa com todas as features listadas.

---

### ⬜ NEST-142: Phase 6 Barrel Export Update
- **Fase:** 6
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-122, NEST-123, NEST-124
- **Agente:** architect
- **Estimativa:** ~15min
- **Descricao:** Adicionar WsJwtGuard, SelfOrAdminGuard e OptionalAuthGuard ao barrel export.

**Prompt para o agente:**
> Atualizar o arquivo `src/index.ts` para adicionar:
> - `export { WsJwtGuard } from './guards/ws-jwt.guard'`
> - `export { SelfOrAdminGuard } from './guards/self-or-admin.guard'`
> - `export { OptionalAuthGuard } from './guards/optional-auth.guard'`
> Verificar que `export type` é usado para types/interfaces e `export` regular para classes (preservar runtime metadata).
> Critérios de aceitação: 3 novos guards exportados no index.ts.

---

### ⬜ NEST-143: Final Barrel Export Review
- **Fase:** 6
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-142
- **Agente:** architect
- **Estimativa:** ~15min
- **Descricao:** Revisão completa do barrel export para garantir que tudo público está exportado e export type vs export está correto.

**Prompt para o agente:**
> Revisar o arquivo `src/index.ts` completamente:
> 1. Verificar que TODOS os itens públicos estão exportados: todos os services, controllers, guards, decorators, DTOs, interfaces, types, constantes.
> 2. Verificar que `export type` é usado para interfaces e types (ex: AuthUser, IUserRepository, IEmailProvider, AuthModuleOptions, PlatformAuthResult).
> 3. Verificar que `export` regular (sem `type`) é usado para: classes de DTOs (preservar metadata class-validator), guards, decorators, services, módulo.
> 4. Verificar que não há exports duplicados ou circulares.
> 5. Listar qualquer item público que esteja faltando.
> Critérios de aceitação: barrel export completo e correto, distinção type/regular export verificada.

---

### ⬜ NEST-144: Module Options Validation
- **Fase:** 6
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-120
- **Agente:** code-reviewer
- **Estimativa:** ~45min
- **Descricao:** Validar opções na inicialização do módulo com mensagens de erro claras.

**Prompt para o agente:**
> Revisar e melhorar a validação de opções em `src/bymax-auth.module.ts` (ou `src/utils/resolve-options.ts`):
> 1. Verificar que `jwt.secret` é obrigatório e não vazio. Mensagem: "BymaxAuthModule: jwt.secret is required".
> 2. Verificar que `userRepository` é fornecido. Mensagem: "BymaxAuthModule: userRepository is required".
> 3. Se `platformAdmin.enabled`, verificar que `platformUserRepository` é fornecido. Mensagem: "BymaxAuthModule: platformUserRepository is required when platformAdmin is enabled".
> 4. Se `oauth` configurado, verificar que pelo menos um provider tem `clientId` e `clientSecret`.
> 5. Se `mfa.enabled`, verificar que `mfa.encryptionKey` é fornecido e tem 32 bytes (256 bits).
> 6. Verificar que `resolveOptions` usa shallow merge por grupo (spread), NÃO `JSON.parse/stringify` (que strip funções/hooks).
> Todas as validações devem lançar `Error` descritivo no momento de inicialização do módulo.
> Critérios de aceitação: cada configuração inválida produz mensagem clara, funções/hooks sobrevivem ao merge.

---

### ⬜ NEST-145: Structured Logging Review
- **Fase:** 6
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-120
- **Agente:** code-reviewer
- **Estimativa:** ~45min
- **Descricao:** Garantir logs estruturados com NestJS Logger em todos os services, sem PII.

**Prompt para o agente:**
> Revisar todos os services para garantir:
> 1. Cada service usa `private readonly logger = new Logger(ServiceName.name)` do `@nestjs/common`.
> 2. Logs em operações importantes: login (sucesso/falha), register, logout, refresh, MFA setup/challenge, password reset, invitation create/accept, OAuth callback.
> 3. PII NUNCA logado em plain text: emails mascarados (ex: `m***@example.com`), tokens NUNCA logados, senhas NUNCA logadas.
> 4. Usar nível apropriado: `logger.log()` para operações normais, `logger.warn()` para tentativas suspeitas (brute-force, token inválido), `logger.error()` para erros inesperados.
> 5. Incluir contexto útil: userId (ok, não é PII sensível), tenantId, operação, IP (considerar se necessário).
> Services a revisar: auth, platform-auth, mfa, session, password-reset, otp, invitation, oauth, brute-force, token-manager.
> Critérios de aceitação: todos os services têm Logger, PII mascarado, níveis de log corretos.

---

### ⬜ NEST-146: Build and Package Verification
- **Fase:** 6
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-143
- **Agente:** code-reviewer
- **Estimativa:** ~45min
- **Descricao:** Verificar que o build produz dist/ limpo com types e sourcemaps, e package.json tem files correto.

**Prompt para o agente:**
> Verificar a configuração de build:
> 1. Executar `npm run build` e verificar que produz `dist/` sem erros ou warnings.
> 2. Verificar que `dist/` contém: `.js` files, `.d.ts` type declarations, `.js.map` sourcemaps.
> 3. Verificar `tsconfig.json` tem: `declaration: true`, `declarationMap: true`, `sourceMap: true`, `outDir: "dist"`.
> 4. Verificar `package.json`:
>    - `"main": "dist/index.js"`
>    - `"types": "dist/index.d.ts"`
>    - `"files": ["dist/"]` — apenas dist publicado (sem src, tests, docs).
> 5. Executar `npm pack` e verificar conteúdo do tarball — apenas dist/ e package.json/README/LICENSE/CHANGELOG.
> 6. Verificar que NÃO inclui: `src/`, `test/`, `node_modules/`, `.env`, `tsconfig.json`.
> Critérios de aceitação: build limpo, types e sourcemaps gerados, package.json correto, npm pack contém apenas o necessário.

---

### ⬜ NEST-147: Local Installation Test
- **Fase:** 6
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-146
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Testar instalacao local do pacote em um projeto NestJS de teste.

**Prompt para o agente:**
> Testar instalação local:
> 1. Criar um diretório temporário com um projeto NestJS mínimo (`nest new test-app` ou scaffold manual).
> 2. Instalar o pacote local: `npm install ../nest-auth` (path relativo ao tarball ou diretório).
> 3. Verificar que o import funciona: `import { BymaxAuthModule, JwtAuthGuard, AuthService } from '@bymax-one/nest-auth'`.
> 4. Verificar que types estão disponíveis: `import type { AuthUser, IUserRepository, AuthModuleOptions } from '@bymax-one/nest-auth'`.
> 5. Verificar que `BymaxAuthModule.registerAsync()` compila sem erros no app.module.ts.
> 6. Verificar que DTOs têm metadata de class-validator preservada (não foram exportados com `export type`).
> Critérios de aceitação: pacote instala, importa e compila corretamente em projeto externo.

---

### ⬜ NEST-148: Test Coverage Verification
- **Fase:** 6
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-134
- **Agente:** tester
- **Estimativa:** ~30min
- **Descricao:** Executar cobertura de testes e garantir >= 80% em branches, functions e lines.

**Prompt para o agente:**
> Executar `npm run test:cov` e analisar o relatório:
> 1. Verificar cobertura total >= 80% para: branches, functions, lines, statements.
> 2. Identificar arquivos com cobertura < 80%.
> 3. Para cada arquivo abaixo de 80%, listar os métodos/branches não cobertos.
> 4. Escrever testes adicionais para cobrir os gaps mais críticos (priorizar services e guards sobre controllers).
> 5. Re-executar coverage e confirmar >= 80%.
> Critérios de aceitação: cobertura total >= 80% em todas as métricas, relatório limpo.

---

### ⬜ NEST-149: Throttle Config Verification
- **Fase:** 6
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-107, NEST-118
- **Agente:** security-reviewer
- **Estimativa:** ~45min
- **Descricao:** Verificar que todos os 14 endpoints sensíveis têm @Throttle com AUTH_THROTTLE_CONFIGS.

**Prompt para o agente:**
> Verificar que `@Throttle()` com configurações de `AUTH_THROTTLE_CONFIGS` está presente em TODOS os endpoints sensíveis. Lista completa a verificar:
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
> Para cada endpoint, verificar que a config de throttle é apropriada (ex: login mais restritivo que /me).
> Critérios de aceitação: todos os 14 endpoints verificados com @Throttle, configs apropriadas.

---

### ⬜ NEST-150: npm Publish Preparation
- **Fase:** 6
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-146, NEST-148, NEST-141
- **Agente:** planner
- **Estimativa:** ~30min
- **Descricao:** Executar checklist final de publicação: build, coverage, pack, publish.

**Prompt para o agente:**
> Executar o checklist de publicação:
> 1. `npm run build` — verificar zero erros e zero warnings.
> 2. `npm run test:cov` — verificar cobertura >= 80%.
> 3. `npm pack` — verificar conteúdo do pacote (apenas dist, package.json, README, LICENSE, CHANGELOG).
> 4. Verificar `package.json`: name `@bymax-one/nest-auth`, version `1.0.0`, license, repository, keywords, peerDependencies corretas.
> 5. Verificar que `.npmignore` ou `files` em package.json exclui src/, test/, docs/, .github/.
> 6. Preparar comando de publicação: `npm publish --access public`.
> NÃO executar o publish automaticamente — apenas preparar e validar.
> Critérios de aceitação: build limpo, coverage OK, pack correto, package.json completo, pronto para publish.

---

### ⬜ NEST-151: Phase 6 Final Validation Checklist
- **Fase:** 6
- **Status:** TODO
- **Prioridade:** Media
- **Dependencias:** NEST-148, NEST-149, NEST-146, NEST-140, NEST-138, NEST-139, NEST-143
- **Agente:** planner
- **Estimativa:** ~45min
- **Descricao:** Executar checklist final de validação da Fase 6 verificando todos os critérios.

**Prompt para o agente:**
> Executar e verificar cada item do checklist de validação da Fase 6:
> 1. [ ] Todos os testes E2E passando (incluindo concorrência de refresh e FIFO eviction).
> 2. [ ] Cobertura total >= 80%.
> 3. [ ] Build sem erros ou warnings.
> 4. [ ] README completo e funcional com seções de segurança.
> 5. [ ] JSDoc em todos os exports públicos.
> 6. [ ] Todos os 14 endpoints têm `@Throttle()` com configs de `AUTH_THROTTLE_CONFIGS`.
> 7. [ ] Checklist de segurança 100% verificado (Apêndice B).
> 8. [ ] `WsJwtGuard` verifica `payload.type === 'dashboard'`.
> 9. [ ] Barrel export distingue `export type` de `export` corretamente.
> 10. [ ] Pacote pronto para publicação no npm.
> Para cada item, marcar PASS ou FAIL com evidência. Se algum FAIL, listar ação corretiva.
> Critérios de aceitação: todos os 10 itens PASS.

---

## Caminho Critico

O caminho critico determina a duracao minima do projeto. As cadeias de dependencia mais longas sao:

**Cadeia Principal (Fases 1-2):**
1. NEST-001 (scaffold) → NEST-005 (interfaces) → NEST-015 (defaults) → NEST-016 (resolveOptions) → NEST-041 (barrel Phase 1) → NEST-042 (Phase 1 validation)
2. NEST-042 → NEST-043 (JWT Strategy) → NEST-057 (AuthService) → NEST-059 (AuthController) → NEST-061 (BymaxAuthModule) → NEST-064 (Phase 2 validation)

**Cadeia MFA (Fase 3):**
3. NEST-064 → NEST-069 (MfaService skeleton) → NEST-070 (setup) → NEST-071 (verifyAndEnable) → NEST-072 (challenge) → NEST-073 (MfaController) → NEST-074 (module integration) → NEST-079 (Phase 3 validation)

**Cadeia Sessoes + Password Reset (Fase 4):**
4. NEST-064 → NEST-081 (SessionService create) → NEST-082 (list/revoke) → NEST-083 (rotate) → NEST-086 (integration) → NEST-096 (Phase 4 validation)
5. NEST-064 → NEST-085 (PasswordResetService initiate) → NEST-086 (resetPassword) → NEST-087 (verifyOtp/resendOtp) → NEST-088 (controller) → NEST-096 (Phase 4 validation)

**Cadeia Plataforma + OAuth + Convites (Fase 5):**
6. NEST-064 → NEST-097 (JWT Platform Strategy) → NEST-101 (PlatformAuthService login) → NEST-107 (controller) → NEST-119 (module integration) → NEST-120 (barrel)
7. NEST-064 → NEST-108 (OAuthModule) → NEST-109 (OAuthService initiate) → NEST-110 (callback) → NEST-119 (module integration)
8. NEST-064 → NEST-115 (InvitationService invite) → NEST-116 (accept) → NEST-117 (controller) → NEST-119 (module integration)

**Cadeia Integracao (Fase 6):**
9. NEST-120 → NEST-122 (WsJwtGuard) → NEST-141 (Test Coverage) → NEST-149 (npm Publish Prep) → NEST-151 (Final Validation)

**Duracao estimada do caminho critico:** ~6 semanas (1 desenvolvedor + agente IA)

## Tarefas Paralelizaveis

Grupos de tarefas que podem ser executados simultaneamente:

**Fase 1 — Paralelismo inicial:**
- NEST-002, NEST-003, NEST-004 (todos dependem apenas de NEST-001)
- NEST-005 a NEST-013 (interfaces, todos dependem de NEST-004)
- NEST-014, NEST-018, NEST-020, NEST-023 (constantes e utils, dependem de NEST-004)
- NEST-024, NEST-025 (crypto utils, dependem de NEST-004)
- NEST-027, NEST-030 (Redis e Password services, dependem de NEST-014)

**Fase 2 — Paralelismo:**
- NEST-049, NEST-050 (decorators, dependem de NEST-004)
- NEST-052, NEST-053 (DTOs, dependem de NEST-004)
- NEST-043, NEST-045, NEST-046, NEST-047 (strategy e guards, pos-Phase 1)

**Fase 3 + 4 — Podem rodar em paralelo:**
- Fase 3 (MFA: NEST-065..079) e Fase 4 (Sessoes + Password Reset: NEST-080..096) dependem ambas de Fase 2, mas sao independentes entre si ate a integracao

**Fase 5 — Tres trilhas paralelas:**
- Platform Auth (NEST-097..108)
- OAuth (NEST-108..113)
- Invitations (NEST-113..118)

**Fase 6 — Paralelismo em testes e revisoes:**
- E2E tests (NEST-125..132) podem rodar em paralelo entre si
- Security reviews (NEST-134..136) podem rodar em paralelo
- JSDoc (NEST-137..138) pode rodar em paralelo com testes