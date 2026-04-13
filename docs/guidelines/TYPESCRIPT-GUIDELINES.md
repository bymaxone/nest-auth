# TypeScript Guidelines — @bymax-one/nest-auth

> **Audience:** AI agents and developers working on this codebase.
> **Stack:** TypeScript 5.8+, strict mode, ES2022, experimental decorators, CommonJS output
> **Rule:** Follow these guidelines for all TypeScript code in this project.

---

## Table of Contents

1. [Strict Mode Configuration](#1-strict-mode-configuration)
2. [Type Design Principles](#2-type-design-principles)
3. [Zero `any` Policy](#3-zero-any-policy)
4. [Interface and Type Naming](#4-interface-and-type-naming)
5. [Generics](#5-generics)
6. [Type Guards and Narrowing](#6-type-guards-and-narrowing)
7. [Utility Types](#7-utility-types)
8. [Export Patterns for npm Libraries](#8-export-patterns-for-npm-libraries)
9. [Decorator Typing](#9-decorator-typing)
10. [Anti-Patterns](#10-anti-patterns)
11. [Quick Reference Checklist](#11-quick-reference-checklist)

---

## 1. Strict Mode Configuration

### 1.1 Required tsconfig.json Settings

This project uses the strictest possible TypeScript configuration. Every flag below is mandatory and must never be relaxed.

```jsonc
{
  "compilerOptions": {
    // --- Strict family (all enabled by "strict": true) ---
    "strict": true,
    // Individually, this enables:
    //   "strictNullChecks": true,        // null and undefined are distinct types
    //   "strictFunctionTypes": true,      // contravariant parameter checking
    //   "strictBindCallApply": true,      // type-check bind/call/apply arguments
    //   "strictPropertyInitialization": true, // class properties must be initialized
    //   "noImplicitAny": true,            // error on inferred 'any'
    //   "noImplicitThis": true,           // error when 'this' is implicitly 'any'
    //   "alwaysStrict": true,             // emit "use strict" in every file
    //   "useUnknownInCatchVariables": true // catch variables are 'unknown', not 'any'

    // --- Additional strictness beyond the "strict" flag ---
    "noUncheckedIndexedAccess": true,      // array/record indexing returns T | undefined
    "noImplicitOverride": true,            // require 'override' keyword on overridden methods
    "noImplicitReturns": true,             // every code path must return a value
    "noFallthroughCasesInSwitch": true,    // prevent fall-through in switch statements
    "noPropertyAccessFromIndexSignature": true, // require bracket notation for index signatures
    "exactOptionalPropertyTypes": true,    // distinguish between missing and undefined

    // --- Module and target ---
    "target": "ES2022",
    "module": "CommonJS",
    "moduleResolution": "node",
    "esModuleInterop": true,
    "resolveJsonModule": true,
    "isolatedModules": true,

    // --- Decorators ---
    "experimentalDecorators": true,
    "emitDecoratorMetadata": true,

    // --- Declarations for npm package ---
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,

    // --- Path and output ---
    "outDir": "./dist",
    "rootDir": "./src",
    "baseUrl": ".",
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true
  }
}
```

### 1.2 Why Each Flag Matters

| Flag | Purpose | Impact on this project |
|---|---|---|
| `strictNullChecks` | Prevents null/undefined from being assignable to every type | Critical for auth — a null `user` must be handled explicitly |
| `noImplicitAny` | Forces explicit typing of all parameters and variables | Enforces the zero-`any` policy |
| `strictFunctionTypes` | Enforces contravariant parameter checking on function types | Prevents unsafe callback assignments in hooks and guards |
| `strictPropertyInitialization` | Class properties must be set in constructor or declared with `!` | NestJS services use `@Inject()` — use definite assignment (`!`) only for injected dependencies |
| `noUncheckedIndexedAccess` | Indexing into arrays and records returns `T \| undefined` | Forces null checks when accessing user roles, claims, sessions by index |
| `exactOptionalPropertyTypes` | Differentiates `property?: T` from `property: T \| undefined` | Important for config objects where "not provided" and "explicitly undefined" have different meanings |
| `noImplicitOverride` | Requires `override` keyword | Prevents accidental overrides in guard and service subclasses |
| `emitDecoratorMetadata` | Emits design-time type metadata | Required by NestJS dependency injection and class-validator |
| `isolatedModules` | Ensures every file can be transpiled independently | Required by tsup bundler |

### 1.3 Flags That Must Never Be Added

```jsonc
// NEVER add these to tsconfig:
{
  "skipDefaultLibCheck": true,   // hides standard library type errors
  "suppressImplicitAnyIndexErrors": true, // suppresses index signature errors
  "noStrictGenericChecks": true  // weakens generic type checking
}
```

---

## 2. Type Design Principles

### 2.1 Interface vs Type — When to Use Each

This project uses a clear, consistent rule for choosing between `interface` and `type`.

| Use `interface` when... | Use `type` when... |
|---|---|
| Defining an object shape that may be implemented by a class | Defining union types, intersection types, or mapped types |
| Defining a repository contract (e.g., `IUserRepository`) | Defining function signatures as standalone types |
| Defining a service contract or plugin contract | Creating utility types or conditional types |
| Defining DTO shapes consumed by class-validator | Defining literal types or template literal types |
| You want declaration merging (rare, intentional cases only) | Defining tuples |

**Key principle:** Interfaces for contracts and object shapes. Types for everything else.

```typescript
// CORRECT: Interface for a repository contract (will be implemented by a class)
export interface IUserRepository {
  findByEmail(email: string): Promise<AuthUser | null>;
  findById(id: string): Promise<AuthUser | null>;
  create(data: CreateUserData): Promise<AuthUser>;
  update(id: string, data: Partial<AuthUser>): Promise<AuthUser>;
}

// CORRECT: Type for a union
export type TokenDeliveryMethod = 'cookie' | 'body' | 'both';

// CORRECT: Type for a function signature
export type PasswordHasher = (password: string, salt: string) => Promise<string>;

// CORRECT: Type for a mapped/conditional type
export type RequiredFields<T> = {
  [K in keyof T]-?: NonNullable<T[K]>;
};

// WRONG: Using type for an object shape that classes will implement
type IUserRepository = {  // Should be interface
  findByEmail(email: string): Promise<AuthUser | null>;
};

// WRONG: Using interface for a union
interface TokenDeliveryMethod {  // Cannot — interfaces don't support unions
  kind: 'cookie' | 'body' | 'both';
}
```

### 2.2 Prefer Readonly by Default

In a security library, immutability prevents accidental mutation of auth state.

```typescript
// CORRECT: Readonly JWT payload — tokens should never be mutated after creation
export interface DashboardJwtPayload {
  readonly sub: string;
  readonly email: string;
  readonly tenantId: string;
  readonly role: string;
  readonly sessionId: string;
  readonly type: 'dashboard';
  readonly iat: number;
  readonly exp: number;
}

// CORRECT: Readonly array for roles
export interface AuthUser {
  readonly id: string;
  readonly email: string;
  readonly roles: readonly string[];
}

// WRONG: Mutable JWT payload — risk of accidental mutation
export interface DashboardJwtPayload {
  sub: string;       // mutable — dangerous for auth tokens
  email: string;
  tenantId: string;
}
```

### 2.3 Discriminated Unions for State Machines

Auth flows are state machines. Use discriminated unions to model them.

```typescript
// CORRECT: Discriminated union for login result
export type LoginResult =
  | { readonly status: 'success'; readonly tokens: TokenPair; readonly user: AuthUserClient }
  | { readonly status: 'mfa_required'; readonly mfaChallengeId: string; readonly mfaMethod: 'totp' }
  | { readonly status: 'locked'; readonly retryAfterSeconds: number }
  | { readonly status: 'email_unverified'; readonly userId: string };

// Usage — TypeScript narrows the type automatically:
function handleLogin(result: LoginResult): void {
  switch (result.status) {
    case 'success':
      // result.tokens is accessible here
      setSession(result.tokens);
      break;
    case 'mfa_required':
      // result.mfaChallengeId is accessible here
      redirectToMfa(result.mfaChallengeId);
      break;
    case 'locked':
      // result.retryAfterSeconds is accessible here
      showLockMessage(result.retryAfterSeconds);
      break;
    case 'email_unverified':
      // result.userId is accessible here
      redirectToVerification(result.userId);
      break;
  }
}
```

### 2.4 Branded Types for Domain Safety

Use branded types to prevent mixing IDs and tokens that are structurally identical strings.

```typescript
// CORRECT: Branded types prevent mixing user IDs with tenant IDs
declare const __brand: unique symbol;
type Brand<T, B extends string> = T & { readonly [__brand]: B };

export type UserId = Brand<string, 'UserId'>;
export type TenantId = Brand<string, 'TenantId'>;
export type SessionId = Brand<string, 'SessionId'>;
export type RefreshTokenHash = Brand<string, 'RefreshTokenHash'>;

// Factory functions that validate and brand
export function toUserId(id: string): UserId {
  if (!id || id.length === 0) {
    throw new Error('Invalid user ID');
  }
  return id as UserId;
}

// CORRECT: The compiler catches accidental mixing
function revokeSession(userId: UserId, sessionId: SessionId): void { /* ... */ }

const uid = toUserId('user-123');
const sid = 'session-456' as SessionId;

revokeSession(uid, sid);      // OK
// revokeSession(sid, uid);   // Compile error — SessionId is not assignable to UserId
```

---

## 3. Zero `any` Policy

### 3.1 The Rule

**No `any` in source code, tests, or type declarations.** This is non-negotiable. The TypeScript `any` type disables type checking and propagates unsafety through the type system. In an authentication library, this creates security risks.

Enforcement:
- `noImplicitAny: true` in tsconfig catches implicit `any`
- ESLint rule `@typescript-eslint/no-explicit-any` set to `"error"` catches explicit `any`
- Code review must reject any PR containing `any`

### 3.2 Alternatives to `any`

For every situation where you might reach for `any`, there is a type-safe alternative.

#### 3.2.1 Use `unknown` for values of uncertain type

```typescript
// WRONG: Catch variable typed as any
try {
  await verifyToken(token);
} catch (err: any) {
  logger.error(err.message);  // No type safety — err could be anything
}

// CORRECT: Use unknown and narrow
try {
  await verifyToken(token);
} catch (err: unknown) {
  if (err instanceof AuthException) {
    logger.error(err.message);  // Safe — AuthException has .message
  } else if (err instanceof Error) {
    logger.error(err.message);
  } else {
    logger.error('Unknown error during token verification', { error: String(err) });
  }
}
```

#### 3.2.2 Use `Record<string, unknown>` for arbitrary objects

```typescript
// WRONG: Using 'any' for JSON payloads
function parseWebhookBody(body: any): void { /* ... */ }

// CORRECT: Use Record<string, unknown> and validate
function parseWebhookBody(body: Record<string, unknown>): WebhookEvent {
  if (typeof body['event'] !== 'string') {
    throw new Error('Missing event field');
  }
  if (typeof body['timestamp'] !== 'number') {
    throw new Error('Missing timestamp field');
  }
  return {
    event: body['event'],
    timestamp: body['timestamp'],
    payload: body['payload'] as Record<string, unknown> | undefined,
  };
}
```

#### 3.2.3 Use generics instead of `any`

```typescript
// WRONG: Generic function with any
function wrapResponse(data: any): { data: any; timestamp: number } {
  return { data, timestamp: Date.now() };
}

// CORRECT: Generic preserves the type
function wrapResponse<T>(data: T): { data: T; timestamp: number } {
  return { data, timestamp: Date.now() };
}

// The caller gets full type safety:
const response = wrapResponse({ userId: '123', email: 'a@b.com' });
// response.data.userId is typed as string
```

#### 3.2.4 Use type assertions with `unknown` as an intermediate step

```typescript
// WRONG: Casting through any
const payload = jwt.decode(token) as any as DashboardJwtPayload;

// CORRECT: Cast through unknown and validate
function decodeDashboardToken(token: string): DashboardJwtPayload {
  const raw: unknown = jwt.decode(token);
  if (!isDashboardPayload(raw)) {
    throw new AuthException('INVALID_TOKEN', 'Token payload does not match expected shape');
  }
  return raw;
}
```

#### 3.2.5 Use `never` for exhaustive checks

```typescript
// CORRECT: Exhaustive switch with never
function getTokenTtl(type: 'access' | 'refresh' | 'mfa_temp'): number {
  switch (type) {
    case 'access':
      return 900;       // 15 minutes
    case 'refresh':
      return 604800;    // 7 days
    case 'mfa_temp':
      return 300;       // 5 minutes
    default: {
      // If a new type is added but not handled, this line will produce a compile error
      const _exhaustive: never = type;
      throw new Error(`Unhandled token type: ${_exhaustive}`);
    }
  }
}
```

### 3.3 The Only Acceptable `any` Exception

The single place where `any` is tolerated is in **decorator return types** required by TypeScript's experimental decorator signature. This is a language limitation, not a code choice.

```typescript
// ACCEPTABLE: TypeScript decorator signatures require specific return types
// that sometimes mandate 'any' in the decorator factory type.
// Isolate these to decorator files and add a suppression comment:

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type ClassDecorator = <TFunction extends (...args: any[]) => unknown>(
  target: TFunction,
) => TFunction | void;
```

Even in this case, prefer `unknown` and `(...args: unknown[])` wherever the decorator signature allows it.

---

## 4. Interface and Type Naming

### 4.1 Naming Convention Table

| Category | Prefix | Suffix | Example | Rationale |
|---|---|---|---|---|
| Repository interface | `I` | `Repository` | `IUserRepository` | Distinguishes the contract from its implementation |
| Service interface | `I` | `Service` | `IEmailProvider` | Same — the app provides the implementation |
| Hook interface | `I` | `Hooks` | `IAuthHooks` | Contract for lifecycle hook implementations |
| Plugin interface | — | `Plugin` | `OAuthProviderPlugin` | Plugin contracts are already clearly abstractions |
| Data/model interface | — | — | `AuthUser`, `AuthPlatformUser` | No prefix — these are data shapes, not contracts |
| JWT payload interface | — | `Payload` | `DashboardJwtPayload` | Describes data carried in a token |
| DTO class | — | `Dto` | `RegisterDto`, `LoginDto` | Data Transfer Object for validation |
| Configuration interface | — | `Options` or `Config` | `BymaxAuthModuleOptions`, `AuthClientConfig` | Configuration containers |
| Response type | — | `Result` or `Response` | `LoginResult`, `AuthErrorResponse` | API response shapes |
| Guard class | — | `Guard` | `JwtAuthGuard`, `RolesGuard` | NestJS guard naming convention |
| Exception class | `Auth` | `Exception` | `AuthException` | Domain-specific error |
| Enum | — | — | `AuthErrorCode`, `TokenType` | PascalCase, descriptive name |
| Type alias (union) | — | — | `TokenDeliveryMethod`, `MfaMethod` | PascalCase, descriptive name |
| Generic type parameter | `T` | — | `T`, `TUser`, `TPayload` | Single letter or `T` + descriptor for clarity |

### 4.2 The I-Prefix Rule

Use the `I` prefix **only** for interfaces that define **contracts to be implemented by classes** (repository pattern, service provider pattern, plugin pattern). Never use the `I` prefix for data shape interfaces.

```typescript
// CORRECT: I-prefix for a contract the host app implements
export interface IUserRepository {
  findByEmail(email: string): Promise<AuthUser | null>;
  create(data: CreateUserData): Promise<AuthUser>;
}

// CORRECT: No I-prefix for a data shape
export interface AuthUser {
  id: string;
  email: string;
  tenantId: string;
  roles: string[];
}

// WRONG: I-prefix on a data shape
export interface IAuthUser {   // This is not a contract — remove the I prefix
  id: string;
  email: string;
}

// WRONG: Missing I-prefix on a repository contract
export interface UserRepository {  // Ambiguous — could be confused with a class name
  findByEmail(email: string): Promise<AuthUser | null>;
}
```

### 4.3 File Naming Conventions

| Category | File pattern | Example |
|---|---|---|
| Interface contracts | `*.interface.ts` | `user-repository.interface.ts` |
| Type definitions | `*.types.ts` | `jwt-payload.types.ts` |
| DTOs | `*.dto.ts` | `register.dto.ts` |
| Guards | `*.guard.ts` | `jwt-auth.guard.ts` |
| Services | `*.service.ts` | `auth.service.ts` |
| Constants | `*.constants.ts` | `auth-error-codes.constants.ts` |
| Enums | `*.enum.ts` | `token-type.enum.ts` |

---

## 5. Generics

### 5.1 Generic Patterns Used in This Project

#### 5.1.1 Constrained Generics

Always constrain generic type parameters to the narrowest type that satisfies the contract. Unconstrained generics allow callers to pass unexpected types.

```typescript
// WRONG: Unconstrained generic — any type could be passed
function createToken<T>(payload: T): string {
  return jwt.sign(payload, secret);  // T could be a number, string, null...
}

// CORRECT: Constrained to object types with required fields
function createToken<T extends Record<string, unknown> & { sub: string }>(
  payload: T,
): string {
  return jwt.sign(payload, secret);
}

// Even better — constrain to known payload types
function createToken<T extends DashboardJwtPayload | PlatformJwtPayload | MfaTempPayload>(
  payload: T,
): string {
  return jwt.sign(payload, secret);
}
```

#### 5.1.2 Generic Defaults

Provide default type parameters when a sensible default exists.

```typescript
// CORRECT: Default generic for common use case
export interface PaginatedResult<T = AuthUser> {
  readonly items: readonly T[];
  readonly total: number;
  readonly page: number;
  readonly pageSize: number;
  readonly hasNextPage: boolean;
}

// Caller can omit the generic for the common case:
const users: PaginatedResult = await userRepo.findAll(page, pageSize);

// Or specify a different type:
const sessions: PaginatedResult<SessionInfo> = await sessionService.listSessions(userId);
```

#### 5.1.3 Generic Factories

The NestJS dynamic module pattern relies on generic factories.

```typescript
// CORRECT: Generic module factory with constraints
export class BymaxAuthModule {
  static forRoot<
    TUser extends AuthUser = AuthUser,
    TPlatformUser extends AuthPlatformUser = AuthPlatformUser,
  >(options: BymaxAuthModuleOptions<TUser, TPlatformUser>): DynamicModule {
    const providers = buildProviders(options);
    return {
      module: BymaxAuthModule,
      global: true,
      providers,
      exports: providers,
    };
  }
}
```

#### 5.1.4 Generic Repository Pattern

```typescript
// CORRECT: Base repository interface with generic entity
export interface IBaseRepository<TEntity, TCreateData, TUpdateData = Partial<TEntity>> {
  findById(id: string): Promise<TEntity | null>;
  create(data: TCreateData): Promise<TEntity>;
  update(id: string, data: TUpdateData): Promise<TEntity>;
  delete(id: string): Promise<void>;
}

// Specific repository extends with concrete types:
export interface IUserRepository extends IBaseRepository<AuthUser, CreateUserData> {
  findByEmail(email: string): Promise<AuthUser | null>;
  findByTenantId(tenantId: string): Promise<readonly AuthUser[]>;
}
```

### 5.2 Conditional Types

Use conditional types to derive types based on configuration.

```typescript
// CORRECT: Response type changes based on MFA configuration
export type AuthResponse<TMfaEnabled extends boolean> = TMfaEnabled extends true
  ? LoginResult            // includes mfa_required variant
  : LoginSuccessResult;    // only success variant

// CORRECT: Extract the return type of an async function
export type AsyncReturnType<T extends (...args: never[]) => Promise<unknown>> =
  T extends (...args: never[]) => Promise<infer R> ? R : never;

// Usage:
type User = AsyncReturnType<typeof userRepo.findById>;
// User = AuthUser | null
```

### 5.3 Template Literal Types

Use template literal types for string patterns.

```typescript
// CORRECT: Auth error code pattern
export type AuthErrorCode = `AUTH_${Uppercase<string>}`;

// More specific:
export type AuthErrorCode =
  | 'AUTH_INVALID_CREDENTIALS'
  | 'AUTH_EMAIL_NOT_VERIFIED'
  | 'AUTH_ACCOUNT_LOCKED'
  | 'AUTH_TOKEN_EXPIRED'
  | 'AUTH_TOKEN_REVOKED'
  | 'AUTH_MFA_REQUIRED'
  | 'AUTH_MFA_INVALID_CODE'
  | 'AUTH_SESSION_EXPIRED'
  | 'AUTH_RATE_LIMITED';

// CORRECT: Redis key patterns
export type RedisKeyPattern =
  | `auth:blacklist:${string}`
  | `auth:refresh:${string}:${string}`
  | `auth:bruteforce:${string}`
  | `auth:session:${string}:${string}`
  | `auth:otp:${string}`;
```

### 5.4 Mapped Types

```typescript
// CORRECT: Make all hook methods optional for partial implementations
export type PartialHooks<T extends IAuthHooks> = {
  [K in keyof T]?: T[K];
};

// CORRECT: Extract only async methods from an interface
export type AsyncMethods<T> = {
  [K in keyof T as T[K] extends (...args: never[]) => Promise<unknown> ? K : never]: T[K];
};

// Usage:
type RepoAsyncMethods = AsyncMethods<IUserRepository>;
// Only includes findByEmail, findById, create, update — all return Promises
```

---

## 6. Type Guards and Narrowing

### 6.1 User-Defined Type Guards

User-defined type guards are functions that return `value is Type`. They are essential in an auth library for validating tokens, payloads, and user objects that arrive as `unknown`.

```typescript
// CORRECT: Type guard for JWT payload validation
export function isDashboardPayload(value: unknown): value is DashboardJwtPayload {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const obj = value as Record<string, unknown>;
  return (
    typeof obj['sub'] === 'string' &&
    typeof obj['email'] === 'string' &&
    typeof obj['tenantId'] === 'string' &&
    typeof obj['role'] === 'string' &&
    typeof obj['sessionId'] === 'string' &&
    obj['type'] === 'dashboard' &&
    typeof obj['iat'] === 'number' &&
    typeof obj['exp'] === 'number'
  );
}

// Usage:
function handleToken(decoded: unknown): DashboardJwtPayload {
  if (!isDashboardPayload(decoded)) {
    throw new AuthException('INVALID_TOKEN', 'Malformed dashboard token payload');
  }
  // decoded is now narrowed to DashboardJwtPayload
  return decoded;
}
```

#### Compound Type Guards

```typescript
// CORRECT: Type guard for discriminated union members
export function isMfaRequired(result: LoginResult): result is LoginResult & { status: 'mfa_required' } {
  return result.status === 'mfa_required';
}

// CORRECT: Type guard for non-null values (generic, reusable)
export function isNonNull<T>(value: T): value is NonNullable<T> {
  return value !== null && value !== undefined;
}

// Usage — filter with type safety:
const activeUsers = users.map(u => u.session).filter(isNonNull);
// activeUsers is Session[] — not (Session | null | undefined)[]
```

### 6.2 Assertion Functions

Assertion functions throw on failure instead of returning a boolean. They are useful for guard clauses at the top of functions.

```typescript
// CORRECT: Assertion function — narrows type or throws
export function assertDashboardPayload(
  value: unknown,
): asserts value is DashboardJwtPayload {
  if (!isDashboardPayload(value)) {
    throw new AuthException('INVALID_TOKEN', 'Expected a dashboard JWT payload');
  }
}

// Usage — simpler than if/throw:
function processToken(decoded: unknown): void {
  assertDashboardPayload(decoded);
  // decoded is narrowed to DashboardJwtPayload from this point
  console.log(decoded.tenantId);
}
```

#### Assertion for Non-Null

```typescript
// CORRECT: Generic non-null assertion
export function assertNonNull<T>(
  value: T,
  message: string,
): asserts value is NonNullable<T> {
  if (value === null || value === undefined) {
    throw new AuthException('INTERNAL_ERROR', message);
  }
}

// Usage:
const user = await userRepo.findById(userId);
assertNonNull(user, `User not found: ${userId}`);
// user is now AuthUser (not AuthUser | null)
user.email; // safe
```

### 6.3 `in` Operator Narrowing

```typescript
// CORRECT: Use 'in' to discriminate between response types
function handleAuthResponse(response: AuthClientResponse | AuthErrorResponse): void {
  if ('error' in response) {
    // response is narrowed to AuthErrorResponse
    console.error(response.error.code, response.error.message);
  } else {
    // response is narrowed to AuthClientResponse
    console.log(response.user.email);
  }
}
```

### 6.4 `satisfies` Operator (TypeScript 5.0+)

The `satisfies` operator validates that a value conforms to a type without widening it.

```typescript
// CORRECT: satisfies validates the shape while preserving literal types
const AUTH_ERRORS = {
  INVALID_CREDENTIALS: { status: 401, message: 'Invalid email or password' },
  ACCOUNT_LOCKED:      { status: 423, message: 'Account temporarily locked' },
  TOKEN_EXPIRED:       { status: 401, message: 'Token has expired' },
  MFA_REQUIRED:        { status: 403, message: 'MFA verification required' },
} satisfies Record<string, { status: number; message: string }>;

// The type is preserved as the literal object — not widened to Record<string, ...>
// AUTH_ERRORS.INVALID_CREDENTIALS.status is 401 (literal), not number
// AUTH_ERRORS.NONEXISTENT would be a compile error

// WRONG: Using 'as const' alone (no shape validation)
const AUTH_ERRORS = {
  INVALID_CREDENTIALS: { status: 401, mesage: 'typo here' }, // typo not caught!
} as const;

// WRONG: Using a type annotation (widens the type)
const AUTH_ERRORS: Record<string, { status: number; message: string }> = {
  INVALID_CREDENTIALS: { status: 401, message: 'Invalid email or password' },
};
// AUTH_ERRORS.ANYTHING is valid — no key safety
```

### 6.5 Control Flow Narrowing Patterns

```typescript
// CORRECT: Early return pattern for narrowing
async function getAuthenticatedUser(
  request: Request,
): Promise<AuthUser> {
  const token = extractToken(request);
  if (token === undefined) {
    throw new AuthException('AUTH_NO_TOKEN', 'No authentication token provided');
  }
  // token is narrowed to string

  const payload = verifyToken(token);
  if (!isDashboardPayload(payload)) {
    throw new AuthException('AUTH_INVALID_TOKEN', 'Invalid token payload');
  }
  // payload is narrowed to DashboardJwtPayload

  const user = await userRepo.findById(payload.sub);
  if (user === null) {
    throw new AuthException('AUTH_USER_NOT_FOUND', 'User no longer exists');
  }
  // user is narrowed to AuthUser

  return user;
}
```

---

## 7. Utility Types

### 7.1 Built-in Utility Types Used in This Project

#### `Partial<T>` — Make all properties optional

```typescript
// CORRECT: Partial for update operations
export interface IUserRepository {
  update(id: string, data: Partial<AuthUser>): Promise<AuthUser>;
}

// The caller can update any subset of fields:
await userRepo.update(userId, { email: newEmail });
await userRepo.update(userId, { roles: ['admin'], status: 'active' });
```

#### `Required<T>` — Make all properties required

```typescript
// CORRECT: Ensure all config fields are resolved after merging with defaults
type ResolvedAuthConfig = Required<BymaxAuthModuleOptions>;

function resolveConfig(
  partial: BymaxAuthModuleOptions,
  defaults: Required<BymaxAuthModuleOptions>,
): Required<BymaxAuthModuleOptions> {
  return { ...defaults, ...partial };
}
```

#### `Pick<T, K>` — Select specific properties

```typescript
// CORRECT: Pick only the fields needed for the client response
export type AuthUserClient = Pick<AuthUser, 'id' | 'email' | 'name' | 'roles' | 'tenantId'>;

// This ensures AuthUserClient stays in sync with AuthUser — if a field
// is renamed in AuthUser, TypeScript will error here.
```

#### `Omit<T, K>` — Remove specific properties

```typescript
// CORRECT: Omit sensitive fields before sending to client
export type SafeUser = Omit<AuthUser, 'passwordHash' | 'mfaSecret' | 'recoveryCodes'>;

// CORRECT: Omit auto-generated fields for create operations
export type CreateUserData = Omit<AuthUser, 'id' | 'createdAt' | 'updatedAt'>;
```

#### `Record<K, V>` — Dictionary/map type

```typescript
// CORRECT: Error code to message mapping
export type AuthErrorMap = Record<AuthErrorCode, { status: number; message: string }>;

// CORRECT: OAuth provider configuration map
export type OAuthProviderMap = Record<string, OAuthProviderPlugin>;
```

#### `Readonly<T>` — Deep immutability for shallow objects

```typescript
// CORRECT: Resolved config should never be mutated at runtime
export type FrozenConfig = Readonly<Required<BymaxAuthModuleOptions>>;
```

#### `Extract<T, U>` and `Exclude<T, U>` — Filter union members

```typescript
// CORRECT: Extract only error statuses from LoginResult
export type LoginErrorResult = Extract<LoginResult, { status: 'locked' | 'email_unverified' }>;

// CORRECT: Exclude the success case to get all error variants
export type LoginFailure = Exclude<LoginResult, { status: 'success' }>;
```

#### `ReturnType<T>` and `Parameters<T>`

```typescript
// CORRECT: Derive types from function signatures
export type HashResult = ReturnType<typeof PasswordService.prototype.hash>;
export type HashParams = Parameters<typeof PasswordService.prototype.hash>;
```

### 7.2 Custom Utility Types for This Project

```typescript
/**
 * Makes specific properties optional while keeping others required.
 * Useful for builder patterns and partial updates with required identifiers.
 */
export type PartialBy<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>;

/**
 * Makes specific properties required while keeping others as-is.
 * Useful for resolved configurations where certain fields must be present.
 */
export type RequiredBy<T, K extends keyof T> = T & Required<Pick<T, K>>;

/**
 * Deep readonly — makes all nested properties readonly recursively.
 * Use for configuration objects and JWT payloads.
 */
export type DeepReadonly<T> = T extends ReadonlyArray<infer U>
  ? ReadonlyArray<DeepReadonly<U>>
  : T extends object
    ? { readonly [K in keyof T]: DeepReadonly<T[K]> }
    : T;

/**
 * Deep partial — makes all nested properties optional recursively.
 * Use for partial configuration overrides.
 */
export type DeepPartial<T> = T extends object
  ? { [K in keyof T]?: DeepPartial<T[K]> }
  : T;

/**
 * Require at least one property from a set.
 * Useful for search parameters where at least one criterion must be provided.
 */
export type AtLeastOne<T, Keys extends keyof T = keyof T> = Pick<T, Exclude<keyof T, Keys>> &
  { [K in Keys]-?: Required<Pick<T, K>> & Partial<Pick<T, Exclude<Keys, K>>> }[Keys];

// Usage:
type UserSearchCriteria = AtLeastOne<{
  email: string;
  id: string;
  tenantId: string;
}>;
// Valid: { email: 'a@b.com' }
// Valid: { email: 'a@b.com', tenantId: 'tenant-1' }
// Invalid: {} — at least one field must be present
```

### 7.3 `NoInfer<T>` (TypeScript 5.4+)

Prevents a type parameter from being inferred from a specific argument position.

```typescript
// CORRECT: Prevent inference from the default value
function getConfigValue<T extends string>(
  key: string,
  defaultValue: NoInfer<T>,
): T {
  const value = process.env[key];
  return (value as T | undefined) ?? defaultValue;
}

// Without NoInfer, the default value would widen T:
const mode = getConfigValue<'strict' | 'lenient'>('AUTH_MODE', 'strict');
// mode is 'strict' | 'lenient', not string
```

---

## 8. Export Patterns for npm Libraries

### 8.1 The Three-Layer Export Strategy

This package uses subpath exports with three layers of type visibility.

```
Layer 1: Public API types    — exported in barrel files, consumed by host apps
Layer 2: Internal types      — shared between modules but NOT exported
Layer 3: Implementation types — local to a single file
```

#### Layer 1: Public API (barrel exports)

```typescript
// src/server/index.ts — Main barrel export for @bymax-one/nest-auth
// Use 'export type' for types that should only exist at compile time

export { BymaxAuthModule } from './bymax-auth.module';
export { AuthException } from './exceptions/auth.exception';
export { JwtAuthGuard } from './guards/jwt-auth.guard';
export { RolesGuard } from './guards/roles.guard';
export { Roles } from './decorators/roles.decorator';
export { CurrentUser } from './decorators/current-user.decorator';

// Type-only exports — erased at runtime, no impact on bundle size
export type { BymaxAuthModuleOptions } from './config/auth-module-options.interface';
export type { IUserRepository } from './repositories/user-repository.interface';
export type { IPlatformUserRepository } from './repositories/platform-user-repository.interface';
export type { IEmailProvider } from './providers/email-provider.interface';
export type { IAuthHooks, HookContext } from './hooks/auth-hooks.interface';
export type { AuthUser, AuthPlatformUser } from './entities/auth-user.interface';
export type { DashboardJwtPayload, PlatformJwtPayload, MfaTempPayload } from './types/jwt-payload.types';
export type { LoginResult, AuthUserClient } from './types/auth-result.types';
```

#### Layer 2: Internal shared types

```typescript
// src/server/internal/types.ts — NOT exported from barrel
// These types are shared between modules but not part of the public API

export interface InternalTokenMetadata {
  jti: string;
  issuedAt: Date;
  expiresAt: Date;
  fingerprint: string;
}

export interface RedisSessionData {
  userId: string;
  tenantId: string;
  deviceInfo: string;
  createdAt: number;
  lastActiveAt: number;
}
```

#### Layer 3: Implementation-local types

```typescript
// src/server/services/auth.service.ts — Types local to this file only
// No export keyword — these stay in the file

interface LoginAttemptContext {
  email: string;
  ip: string;
  userAgent: string;
  timestamp: number;
}
```

### 8.2 `export type` vs `export`

Always use `export type` for types and interfaces that should be erased at compile time. This is critical for tree-shaking and prevents runtime errors in consumer projects.

```typescript
// CORRECT: Type-only export — erased at compile time
export type { AuthUser } from './entities/auth-user.interface';
export type { IUserRepository } from './repositories/user-repository.interface';

// CORRECT: Value export — exists at runtime
export { BymaxAuthModule } from './bymax-auth.module';
export { AuthException } from './exceptions/auth.exception';

// CORRECT: Mixed — export the class and its type separately
export { JwtAuthGuard } from './guards/jwt-auth.guard';
export type { JwtAuthGuardOptions } from './guards/jwt-auth.guard';

// WRONG: Exporting a pure type without 'type' keyword
export { AuthUser } from './entities/auth-user.interface';
// This may cause runtime import of an empty module
```

### 8.3 Subpath Export Types

Each subpath export must have a corresponding `types` entry in `package.json` that points to the declaration file.

```jsonc
// package.json — exports map
{
  "exports": {
    ".": {
      "types": "./dist/server/index.d.ts",    // MUST come first
      "import": "./dist/server/index.mjs",
      "require": "./dist/server/index.cjs"
    },
    "./shared": {
      "types": "./dist/shared/index.d.ts",
      "import": "./dist/shared/index.mjs",
      "require": "./dist/shared/index.cjs"
    },
    "./client": {
      "types": "./dist/client/index.d.ts",
      "import": "./dist/client/index.mjs",
      "require": "./dist/client/index.cjs"
    },
    "./react": {
      "types": "./dist/react/index.d.ts",
      "import": "./dist/react/index.mjs",
      "require": "./dist/react/index.cjs"
    },
    "./nextjs": {
      "types": "./dist/nextjs/index.d.ts",
      "import": "./dist/nextjs/index.mjs",
      "require": "./dist/nextjs/index.cjs"
    }
  }
}
```

**Rule:** The `"types"` condition must always be the **first** entry in each export block. TypeScript resolves conditions in order and stops at the first match.

### 8.4 `typesVersions` Fallback

For older TypeScript versions and tools that do not support `exports`, provide a `typesVersions` fallback.

```jsonc
{
  "typesVersions": {
    "*": {
      "shared": ["./dist/shared/index.d.ts"],
      "client": ["./dist/client/index.d.ts"],
      "react":  ["./dist/react/index.d.ts"],
      "nextjs": ["./dist/nextjs/index.d.ts"]
    }
  }
}
```

### 8.5 Declaration File Best Practices

```typescript
// CORRECT: Ensure declaration files do not leak internal types
// In tsup.config.ts:
export default defineConfig([
  {
    entry: {
      'server/index': 'src/server/index.ts',
      'shared/index': 'src/shared/index.ts',
      'client/index': 'src/client/index.ts',
      'react/index':  'src/react/index.ts',
      'nextjs/index': 'src/nextjs/index.ts',
    },
    format: ['cjs', 'esm'],
    dts: true,           // Generate .d.ts files
    sourcemap: true,
    clean: true,
    splitting: false,    // Avoid chunk splitting for npm packages
    treeshake: true,
  },
]);
```

### 8.6 Shared Types Across Subpaths

The `./shared` subpath exports types and constants used by both server and client code. This is the single source of truth for cross-boundary types.

```typescript
// src/shared/index.ts
// These types are consumed by ALL subpaths — server, client, react, nextjs

export type { AuthUserClient } from './types/auth-user-client.types';
export type { AuthClientResponse, AuthErrorResponse } from './types/auth-response.types';
export type { TokenDeliveryMethod, MfaMethod } from './types/auth-enums.types';

export { AUTH_COOKIE_NAMES } from './constants/cookie-names.constants';
export { AUTH_HEADER_NAMES } from './constants/header-names.constants';
export { AUTH_ERROR_CODES } from './constants/error-codes.constants';
```

---

## 9. Decorator Typing

### 9.1 NestJS Decorator Context

This project uses experimental decorators (`experimentalDecorators: true`) as required by NestJS 11. The TC39 Stage 3 decorators are not yet supported by NestJS.

### 9.2 Custom Parameter Decorators

```typescript
import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import type { DashboardJwtPayload } from '../types/jwt-payload.types';

// CORRECT: Typed parameter decorator
export const CurrentUser = createParamDecorator(
  (data: keyof DashboardJwtPayload | undefined, ctx: ExecutionContext): DashboardJwtPayload | DashboardJwtPayload[keyof DashboardJwtPayload] => {
    const request = ctx.switchToHttp().getRequest<{ user: DashboardJwtPayload }>();
    const user = request.user;
    return data ? user[data] : user;
  },
);

// Usage in controller:
@Get('me')
getProfile(@CurrentUser() user: DashboardJwtPayload): AuthUserClient {
  return toClientUser(user);
}

@Get('tenant')
getTenant(@CurrentUser('tenantId') tenantId: string): string {
  return tenantId;
}
```

### 9.3 Custom Method Decorators

```typescript
import { SetMetadata } from '@nestjs/common';

// CORRECT: Typed metadata key and value
export const ROLES_KEY = 'roles' as const;

export const Roles = (...roles: string[]): MethodDecorator & ClassDecorator => {
  return SetMetadata(ROLES_KEY, roles);
};

// Usage:
@Roles('admin', 'owner')
@Get('admin/users')
listUsers(): Promise<AuthUserClient[]> {
  return this.adminService.listUsers();
}
```

### 9.4 Custom Class Decorators

```typescript
import { applyDecorators, UseGuards } from '@nestjs/common';

// CORRECT: Composed decorator with full typing
export function Authenticated(...roles: string[]): MethodDecorator & ClassDecorator {
  const decorators: Array<ClassDecorator | MethodDecorator> = [
    UseGuards(JwtAuthGuard, UserStatusGuard),
  ];
  if (roles.length > 0) {
    decorators.push(UseGuards(RolesGuard), Roles(...roles));
  }
  return applyDecorators(...decorators);
}

// Usage — single decorator replaces multiple:
@Authenticated('admin')
@Controller('admin')
export class AdminController {
  // All routes require JWT + active user + admin role
}
```

### 9.5 Metadata Reflection Types

When reading metadata at runtime, always validate the type.

```typescript
import { Reflector } from '@nestjs/core';

// CORRECT: Type-safe metadata retrieval
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<string[] | undefined>(
      ROLES_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (requiredRoles === undefined || requiredRoles.length === 0) {
      return true; // No roles required — allow access
    }

    const request = context.switchToHttp().getRequest<{ user: DashboardJwtPayload }>();
    const userRole = request.user.role;
    return requiredRoles.includes(userRole);
  }
}
```

### 9.6 class-validator and class-transformer Typing

DTOs use class-validator decorators. Ensure property types match the validator constraints.

```typescript
import { IsEmail, IsString, MinLength, MaxLength, Matches, IsOptional } from 'class-validator';

// CORRECT: DTO with validators that match the TypeScript types
export class RegisterDto {
  @IsEmail()
  readonly email!: string;

  @IsString()
  @MinLength(8)
  @MaxLength(128)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, {
    message: 'Password must contain at least one uppercase letter, one lowercase letter, and one digit',
  })
  readonly password!: string;

  @IsString()
  @MinLength(1)
  @MaxLength(100)
  readonly name!: string;

  @IsString()
  readonly tenantId!: string;

  @IsOptional()
  @IsString()
  readonly role?: string;
}
```

**Note on `!` (definite assignment assertion):** DTO properties use `!` because they are populated by class-transformer at runtime, not in the constructor. This is the one valid use of `!` in this project — NestJS pipes guarantee the properties are set before the DTO reaches the handler.

---

## 10. Anti-Patterns

### 10.1 Using `any` Instead of Proper Types

```typescript
// WRONG
function handleError(error: any): void {
  console.log(error.message);
}

// CORRECT
function handleError(error: unknown): void {
  const message = error instanceof Error ? error.message : String(error);
  console.log(message);
}
```

### 10.2 Type Assertions Without Validation

```typescript
// WRONG: Blind assertion — if the token is malformed, runtime crash
const payload = jwt.decode(token) as DashboardJwtPayload;
console.log(payload.tenantId);  // undefined if token has wrong shape

// CORRECT: Validate, then narrow
const raw: unknown = jwt.decode(token);
if (!isDashboardPayload(raw)) {
  throw new AuthException('AUTH_INVALID_TOKEN', 'Malformed token payload');
}
// raw is now DashboardJwtPayload — safe to access
console.log(raw.tenantId);
```

### 10.3 Overusing Non-Null Assertion (`!`)

```typescript
// WRONG: Assuming a value exists without checking
const user = await userRepo.findById(id);
return user!.email;  // Runtime crash if user is null

// CORRECT: Explicit null check
const user = await userRepo.findById(id);
if (user === null) {
  throw new AuthException('AUTH_USER_NOT_FOUND', `User ${id} not found`);
}
return user.email;  // Safe — narrowed by the if-check
```

**Valid uses of `!`:** Only for NestJS `@Inject()` properties that are guaranteed by the DI container:

```typescript
@Injectable()
export class AuthService {
  // These use ! because NestJS DI guarantees injection
  @Inject(USER_REPOSITORY)
  private readonly userRepo!: IUserRepository;

  @Inject(AUTH_HOOKS)
  private readonly hooks!: IAuthHooks;
}
```

### 10.4 Returning Naked Booleans for Validation

```typescript
// WRONG: Boolean return gives no information about what failed
function validatePassword(password: string): boolean {
  // Caller cannot distinguish between "too short" and "missing uppercase"
  return password.length >= 8 && /[A-Z]/.test(password);
}

// CORRECT: Return a discriminated union with error details
type PasswordValidationResult =
  | { valid: true }
  | { valid: false; reason: 'TOO_SHORT' | 'MISSING_UPPERCASE' | 'MISSING_DIGIT' | 'TOO_COMMON' };

function validatePassword(password: string): PasswordValidationResult {
  if (password.length < 8) return { valid: false, reason: 'TOO_SHORT' };
  if (!/[A-Z]/.test(password)) return { valid: false, reason: 'MISSING_UPPERCASE' };
  if (!/\d/.test(password)) return { valid: false, reason: 'MISSING_DIGIT' };
  return { valid: true };
}
```

### 10.5 Exporting Mutable Constants

```typescript
// WRONG: Mutable export — consumers can overwrite your defaults
export const DEFAULT_TOKEN_TTL = 900;
export const COOKIE_OPTIONS = { httpOnly: true, secure: true, sameSite: 'strict' };
// A consumer could do: COOKIE_OPTIONS.httpOnly = false;  // Security hole

// CORRECT: Use as const for immutable exports
export const DEFAULT_TOKEN_TTL = 900 as const;
export const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',
} as const;
// COOKIE_OPTIONS.httpOnly = false;  // Compile error — readonly
```

### 10.6 Using Enums Incorrectly

```typescript
// WRONG: Numeric enum — runtime value is a number, easy to misuse
enum TokenType {
  Access,    // 0
  Refresh,   // 1
  MfaTemp,   // 2
}

// CORRECT: String enum or union type — self-documenting, no numeric confusion
// Option A: String enum (when runtime value is needed)
enum TokenType {
  Access = 'access',
  Refresh = 'refresh',
  MfaTemp = 'mfa_temp',
}

// Option B: Union type (preferred for this project — simpler, no runtime overhead)
type TokenType = 'access' | 'refresh' | 'mfa_temp';
```

### 10.7 Implicit Index Signatures

```typescript
// WRONG: Accessing a property that may not exist without checking
const config: Record<string, string> = loadConfig();
const secret = config['JWT_SECRET'];
// With noUncheckedIndexedAccess, secret is string | undefined

// Still wrong — ignoring the possibility of undefined:
const secret = config['JWT_SECRET']!;  // Non-null assertion on possibly missing key

// CORRECT: Check before use
const secret = config['JWT_SECRET'];
if (secret === undefined) {
  throw new Error('JWT_SECRET is required but not configured');
}
// secret is now string
```

### 10.8 Leaking Internal Types

```typescript
// WRONG: Exporting implementation details that consumers should not depend on
export { RedisSessionData } from './internal/redis-session-data';
export { BruteForceEntry } from './internal/brute-force-entry';
// Consumers may depend on these, making them impossible to change

// CORRECT: Only export the public API surface
// Internal types are imported within the package but never re-exported
export type { AuthUser } from './entities/auth-user.interface';
export type { IUserRepository } from './repositories/user-repository.interface';
// RedisSessionData and BruteForceEntry stay internal
```

### 10.9 God Interfaces

```typescript
// WRONG: Single interface with too many unrelated responsibilities
export interface IAuthService {
  register(data: RegisterDto): Promise<AuthUser>;
  login(data: LoginDto): Promise<LoginResult>;
  verifyMfa(data: MfaVerifyDto): Promise<LoginResult>;
  sendPasswordResetEmail(email: string): Promise<void>;
  resetPassword(data: ResetPasswordDto): Promise<void>;
  createInvitation(data: CreateInvitationDto): Promise<void>;
  manageTenant(tenantId: string): Promise<void>;
  // 30 more methods...
}

// CORRECT: Separate interfaces by responsibility
export interface IAuthService {
  register(data: RegisterDto): Promise<AuthUser>;
  login(data: LoginDto): Promise<LoginResult>;
  logout(userId: string, sessionId: string): Promise<void>;
  refreshTokens(refreshToken: string): Promise<TokenPair>;
}

export interface IMfaService {
  enableMfa(userId: string): Promise<MfaSetupData>;
  verifyMfa(data: MfaVerifyDto): Promise<LoginResult>;
  disableMfa(userId: string, password: string): Promise<void>;
}

export interface IPasswordResetService {
  requestReset(email: string): Promise<void>;
  resetPassword(data: ResetPasswordDto): Promise<void>;
}
```

### 10.10 Using `Function` Type

```typescript
// WRONG: The Function type accepts any function with any arguments
function registerHook(name: string, handler: Function): void {
  // handler could be anything — no type safety
}

// CORRECT: Use a specific function signature
type HookHandler<TContext = HookContext> = (context: TContext) => Promise<void> | void;

function registerHook(name: string, handler: HookHandler): void {
  // handler is typed — must accept HookContext and return void or Promise<void>
}
```

---

## 11. Quick Reference Checklist

Use this checklist when writing or reviewing TypeScript code in this project.

### Before Writing Code

- [ ] Verify `strict: true` is in tsconfig — never relax it
- [ ] Confirm `noUncheckedIndexedAccess: true` is enabled
- [ ] Check that `experimentalDecorators` and `emitDecoratorMetadata` are enabled

### Type Design

- [ ] Use `interface` for object shapes and contracts, `type` for unions, mapped types, and utilities
- [ ] Use `I` prefix only for repository, service, and hook contracts (not for data types)
- [ ] Use `readonly` on properties that must not be mutated (JWT payloads, config objects)
- [ ] Use discriminated unions for state machines (login results, token types)
- [ ] Use branded types for domain IDs when type confusion is a risk

### Zero `any`

- [ ] No `any` in function parameters, return types, or variable declarations
- [ ] Use `unknown` for values of uncertain type and narrow with type guards
- [ ] Use `Record<string, unknown>` for arbitrary objects
- [ ] Use generics instead of `any` for reusable functions
- [ ] Catch variables are `unknown` — always narrow before accessing properties

### Type Safety

- [ ] Never use `as` assertions without prior validation
- [ ] Never use `!` (non-null assertion) except for NestJS `@Inject()` properties
- [ ] Write user-defined type guards (`value is Type`) for all runtime type checks
- [ ] Use assertion functions (`asserts value is Type`) for guard clauses
- [ ] Use `satisfies` to validate constant objects without widening
- [ ] Handle `null` and `undefined` explicitly — never ignore them

### Generics

- [ ] Always constrain generic parameters (`T extends SomeBase`)
- [ ] Provide default type parameters where a common case exists
- [ ] Use `NoInfer<T>` to prevent unwanted inference from default values

### Exports (npm Library)

- [ ] Use `export type` for interfaces and type aliases
- [ ] Use `export` (without `type`) for classes, functions, and enums with runtime presence
- [ ] Barrel exports in `index.ts` — every public symbol, nothing internal
- [ ] `"types"` condition is first in every `package.json` exports block
- [ ] Internal types are never re-exported from barrel files

### Decorators

- [ ] Custom decorators have explicit return types
- [ ] Metadata is retrieved with type parameters (`reflector.get<string[]>`)
- [ ] DTO properties use `!` (definite assignment) — class-transformer populates them
- [ ] DTO property types match their class-validator constraints

### Anti-Patterns to Avoid

- [ ] No `Function` type — use specific function signatures
- [ ] No numeric enums — use string enums or union types
- [ ] No mutable exported constants — use `as const`
- [ ] No god interfaces — separate concerns into focused interfaces
- [ ] No returning naked booleans from validation — return discriminated results
- [ ] No blind type assertions (`as Type`) without validation
- [ ] No implicit index access without undefined checks

---

*This document is the authoritative reference for TypeScript patterns in the `@bymax-one/nest-auth` project. When in doubt, prioritize type safety over convenience. Every `any` avoided is a potential bug prevented.*
