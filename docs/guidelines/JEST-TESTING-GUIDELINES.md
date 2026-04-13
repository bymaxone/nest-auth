# Jest Testing Guidelines — @bymax-one/nest-auth

> **Audience:** AI agents and developers working on this codebase.
> **Stack:** Jest 29, ts-jest 29, @nestjs/testing, @testing-library/react
> **Rule:** Follow these guidelines for all test code in this project.

---

## Table of Contents

1. [Test Structure and Organization](#1-test-structure-and-organization)
2. [Jest Configuration](#2-jest-configuration)
3. [Unit Testing Services](#3-unit-testing-services)
4. [Unit Testing Guards](#4-unit-testing-guards)
5. [Unit Testing Controllers](#5-unit-testing-controllers)
6. [Mocking Patterns](#6-mocking-patterns)
7. [Testing Async Code](#7-testing-async-code)
8. [Testing React Hooks](#8-testing-react-hooks)
9. [Coverage Requirements](#9-coverage-requirements)
10. [Anti-Patterns](#10-anti-patterns)
11. [Quick Reference Checklist](#quick-reference-checklist)

---

## 1. Test Structure and Organization

### 1.1 File Naming Convention

All test files use the `.spec.ts` (or `.spec.tsx` for React) suffix and are **co-located** next to the source file they test.

```
src/
  server/
    services/
      auth.service.ts
      auth.service.spec.ts
      password.service.ts
      password.service.spec.ts
    guards/
      jwt-auth.guard.ts
      jwt-auth.guard.spec.ts
    controllers/
      auth.controller.ts
      auth.controller.spec.ts
  react/
    hooks/
      use-session.ts
      use-session.spec.tsx
    providers/
      auth-provider.tsx
      auth-provider.spec.tsx
  shared/
    utils/
      cookie-parser.ts
      cookie-parser.spec.ts
```

**Rules:**

- Every `.ts` file containing logic MUST have a corresponding `.spec.ts` file.
- Test files MUST live in the same directory as their source file (co-location).
- Never create a top-level `__tests__/` or `test/` directory for unit tests.
- Integration or end-to-end tests (if any) go in a top-level `test/` directory with the suffix `.e2e-spec.ts`.

### 1.2 The AAA Pattern

Every test case MUST follow the **Arrange-Act-Assert** pattern. Separate each section with a blank line and an optional comment for complex tests.

```typescript
it('should hash a password using scrypt', async () => {
  // Arrange
  const plainPassword = 'SuperSecret123!';

  // Act
  const hash = await passwordService.hash(plainPassword);

  // Assert
  expect(hash).toBeDefined();
  expect(hash).not.toBe(plainPassword);
  expect(hash.split('.')).toHaveLength(2); // salt.hash format
});
```

For simple tests where Arrange is trivial, the comment may be omitted but the logical separation must remain clear.

### 1.3 describe/it Block Structure

Organize tests using nested `describe` blocks that mirror the class/function structure:

```typescript
describe('AuthService', () => {
  // Setup: module creation, dependency injection, mocks

  describe('register()', () => {
    it('should create a new user when email is unique', async () => { /* ... */ });
    it('should throw ConflictException when email exists', async () => { /* ... */ });
    it('should hash the password before saving', async () => { /* ... */ });
    it('should emit afterRegister hook', async () => { /* ... */ });
  });

  describe('login()', () => {
    it('should return tokens for valid credentials', async () => { /* ... */ });
    it('should throw UnauthorizedException for invalid password', async () => { /* ... */ });
    it('should enforce brute-force lockout after threshold', async () => { /* ... */ });
  });
});
```

**Rules:**

- Top-level `describe` matches the class or module name.
- Second-level `describe` matches the method or function name, including parentheses.
- `it` blocks start with `should` and describe the expected behavior, not the implementation.
- Keep `it` descriptions under 80 characters when possible.
- Never nest more than 3 levels of `describe`.

### 1.4 Test Isolation

Each test MUST be fully independent. No test should depend on the state produced by another test.

```typescript
describe('SessionService', () => {
  let service: SessionService;
  let mockRedis: jest.Mocked<Redis>;

  beforeEach(async () => {
    // Fresh module and mocks for every test
    const module = await Test.createTestingModule({
      providers: [
        SessionService,
        { provide: 'REDIS_CLIENT', useValue: createMockRedis() },
      ],
    }).compile();

    service = module.get(SessionService);
    mockRedis = module.get('REDIS_CLIENT');
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });
});
```

**Rules:**

- Use `beforeEach` (not `beforeAll`) for module setup so each test gets a fresh instance.
- Use `afterEach` to call `jest.restoreAllMocks()`.
- Never use shared mutable state between tests.
- Never rely on test execution order.

### 1.5 TDD Workflow

This project follows Test-Driven Development. The workflow is:

1. **Write the interface / type** first (in `shared/` or the relevant module).
2. **Write the test** that asserts the expected behavior against that interface.
3. **Run the test** and confirm it fails (red).
4. **Write the minimal implementation** to make the test pass (green).
5. **Refactor** while keeping all tests green.

When an AI agent generates code, it MUST produce the `.spec.ts` file before or alongside the implementation file, never after.

---

## 2. Jest Configuration

### 2.1 jest.config.ts

The project uses a TypeScript Jest config at the project root:

```typescript
// jest.config.ts
import type { Config } from 'jest';

const config: Config = {
  // Use ts-jest ESM preset for this ESM-first package
  preset: 'ts-jest/presets/default-esm',

  // The test environment
  testEnvironment: 'node',

  // File extensions to consider
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json'],

  // Test file pattern
  testRegex: '.*\\.spec\\.tsx?$',

  // Transform TypeScript files with ts-jest
  transform: {
    '^.+\\.tsx?$': [
      'ts-jest',
      {
        useESM: true,
        tsconfig: 'tsconfig.json',
      },
    ],
  },

  // Module name mapping for subpath imports
  moduleNameMapper: {
    '^@bymax-one/nest-auth$': '<rootDir>/src/server/index.ts',
    '^@bymax-one/nest-auth/shared$': '<rootDir>/src/shared/index.ts',
    '^@bymax-one/nest-auth/client$': '<rootDir>/src/client/index.ts',
    '^@bymax-one/nest-auth/react$': '<rootDir>/src/react/index.ts',
    '^@bymax-one/nest-auth/nextjs$': '<rootDir>/src/nextjs/index.ts',
  },

  // Coverage configuration
  collectCoverageFrom: [
    'src/**/*.ts',
    'src/**/*.tsx',
    '!src/**/index.ts',       // barrel files
    '!src/**/*.d.ts',         // type declarations
    '!src/**/*.interface.ts',  // pure interfaces
    '!src/**/*.types.ts',      // pure type files
  ],

  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'text-summary', 'lcov', 'json-summary'],

  // Enforce minimum coverage thresholds
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80,
    },
  },

  // Ignore patterns
  testPathIgnorePatterns: ['/node_modules/', '/dist/'],

  // Clear mocks between tests
  clearMocks: true,
  restoreMocks: true,
};

export default config;
```

### 2.2 Project-Specific Overrides for React Tests

For React hook tests that need `jsdom`, use a docblock directive at the top of the `.spec.tsx` file instead of a separate config:

```typescript
/**
 * @jest-environment jsdom
 */
import { renderHook, act } from '@testing-library/react';
import { useSession } from './use-session';
```

This avoids the need for multiple Jest config files. The `node` environment is the default; only React/DOM tests override it.

### 2.3 ts-jest Configuration Details

The project uses `ts-jest` 29 with the following considerations:

- **ESM mode** is enabled (`useESM: true`) because the package uses `"type": "module"` in `package.json`.
- The `tsconfig.json` used by ts-jest should have `"module": "ESNext"` and `"moduleResolution": "bundler"` or `"node16"`.
- If you encounter ESM import issues in tests, ensure the `NODE_OPTIONS` environment variable includes `--experimental-vm-modules`:

```jsonc
// package.json scripts
{
  "test": "NODE_OPTIONS='--experimental-vm-modules' jest",
  "test:cov": "NODE_OPTIONS='--experimental-vm-modules' jest --coverage"
}
```

### 2.4 Running Tests

| Command              | Purpose                                |
| -------------------- | -------------------------------------- |
| `npm test`           | Run all tests once                     |
| `npm run test:cov`   | Run all tests with coverage report     |
| `npm run test:watch` | Run tests in watch mode (development)  |
| `npx jest path/to/file.spec.ts` | Run a single test file      |
| `npx jest --testNamePattern="should hash"` | Run tests matching a pattern |

---

## 3. Unit Testing Services

### 3.1 NestJS Testing Module Setup

Every NestJS service test uses `@nestjs/testing`'s `Test.createTestingModule` to create an isolated DI container:

```typescript
import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { PasswordService } from '../password/password.service';
import { TokenManagerService } from '../token/token-manager.service';
import { AUTH_CONFIG } from '../../constants';

describe('AuthService', () => {
  let service: AuthService;
  let passwordService: jest.Mocked<PasswordService>;
  let tokenManager: jest.Mocked<TokenManagerService>;

  const mockConfig = {
    jwt: {
      accessSecret: 'test-access-secret',
      refreshSecret: 'test-refresh-secret',
      accessExpiresIn: '15m',
      refreshExpiresIn: '7d',
    },
    registration: {
      enabled: true,
      requireEmailVerification: false,
    },
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: PasswordService,
          useValue: {
            hash: jest.fn(),
            compare: jest.fn(),
          },
        },
        {
          provide: TokenManagerService,
          useValue: {
            generateAccessToken: jest.fn(),
            generateRefreshToken: jest.fn(),
            verifyRefreshToken: jest.fn(),
          },
        },
        {
          provide: AUTH_CONFIG,
          useValue: mockConfig,
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    passwordService = module.get(PasswordService);
    tokenManager = module.get(TokenManagerService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
```

### 3.2 Testing Service Methods

Test both the happy path and all error paths for each service method:

```typescript
describe('register()', () => {
  const registerDto = {
    email: 'user@example.com',
    password: 'StrongPass123!',
    name: 'Test User',
  };

  it('should create a user and return tokens', async () => {
    // Arrange
    const mockUser = { id: 'user-1', email: registerDto.email, name: registerDto.name };
    const mockUserRepo = {
      findByEmail: jest.fn().mockResolvedValue(null),
      create: jest.fn().mockResolvedValue(mockUser),
    };
    passwordService.hash.mockResolvedValue('hashed-password');
    tokenManager.generateAccessToken.mockReturnValue('access-token');
    tokenManager.generateRefreshToken.mockReturnValue('refresh-token');

    // Act
    const result = await service.register(registerDto, mockUserRepo);

    // Assert
    expect(mockUserRepo.findByEmail).toHaveBeenCalledWith(registerDto.email);
    expect(passwordService.hash).toHaveBeenCalledWith(registerDto.password);
    expect(mockUserRepo.create).toHaveBeenCalledWith(
      expect.objectContaining({
        email: registerDto.email,
        passwordHash: 'hashed-password',
      }),
    );
    expect(result).toEqual({
      user: mockUser,
      accessToken: 'access-token',
      refreshToken: 'refresh-token',
    });
  });

  it('should throw ConflictException when email already exists', async () => {
    // Arrange
    const existingUser = { id: 'existing-1', email: registerDto.email };
    const mockUserRepo = {
      findByEmail: jest.fn().mockResolvedValue(existingUser),
      create: jest.fn(),
    };

    // Act & Assert
    await expect(service.register(registerDto, mockUserRepo)).rejects.toThrow(
      ConflictException,
    );
    expect(mockUserRepo.create).not.toHaveBeenCalled();
  });
});
```

### 3.3 Testing Services with Repository Contracts

This package follows Inversion of Dependency: services accept repository interfaces, not concrete implementations. When testing, provide mock implementations of those interfaces:

```typescript
// Create a reusable factory for mock repositories
function createMockUserRepository(): jest.Mocked<UserRepository> {
  return {
    findById: jest.fn(),
    findByEmail: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
    findByTenantId: jest.fn(),
  };
}

// Use it in tests
describe('AuthService', () => {
  let userRepo: jest.Mocked<UserRepository>;

  beforeEach(() => {
    userRepo = createMockUserRepository();
  });
});
```

### 3.4 Testing Services That Use node:crypto

Several services in this package (PasswordService, TokenManagerService, MFA/TOTP) use `node:crypto`. Mock `crypto` at the module level:

```typescript
import * as crypto from 'node:crypto';

// Mock specific crypto functions
jest.spyOn(crypto, 'randomBytes').mockReturnValue(
  Buffer.from('0123456789abcdef0123456789abcdef', 'hex'),
);

jest.spyOn(crypto, 'scryptSync').mockReturnValue(
  Buffer.from('mocked-scrypt-output'),
);

// For async crypto operations
jest.spyOn(crypto, 'scrypt').mockImplementation(
  (password, salt, keylen, callback) => {
    (callback as Function)(null, Buffer.from('mocked-output'));
  },
);
```

Alternatively, for PasswordService tests where you want to test real hashing (integration-style):

```typescript
describe('PasswordService (integration)', () => {
  it('should hash and verify a password correctly', async () => {
    // Use real crypto — no mocks
    const service = new PasswordService();
    const password = 'MySecret123!';

    const hash = await service.hash(password);
    const isValid = await service.compare(password, hash);
    const isInvalid = await service.compare('wrong-password', hash);

    expect(isValid).toBe(true);
    expect(isInvalid).toBe(false);
  });
});
```

---

## 4. Unit Testing Guards

### 4.1 Testing CanActivate Guards

Guards are a critical security boundary. Every guard MUST be thoroughly tested for both allow and deny cases.

```typescript
import { Test, TestingModule } from '@nestjs/testing';
import { Reflector } from '@nestjs/core';
import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { JwtAuthGuard } from './jwt-auth.guard';
import { TokenManagerService } from '../services/token-manager.service';

describe('JwtAuthGuard', () => {
  let guard: JwtAuthGuard;
  let tokenManager: jest.Mocked<TokenManagerService>;
  let reflector: jest.Mocked<Reflector>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        JwtAuthGuard,
        {
          provide: TokenManagerService,
          useValue: {
            verifyAccessToken: jest.fn(),
          },
        },
        {
          provide: Reflector,
          useValue: {
            getAllAndOverride: jest.fn(),
          },
        },
      ],
    }).compile();

    guard = module.get<JwtAuthGuard>(JwtAuthGuard);
    tokenManager = module.get(TokenManagerService);
    reflector = module.get(Reflector);
  });

  it('should be defined', () => {
    expect(guard).toBeDefined();
  });
});
```

### 4.2 Mocking ExecutionContext

The `ExecutionContext` is the most important mock in guard tests. Create a reusable factory:

```typescript
function createMockExecutionContext(overrides: {
  headers?: Record<string, string>;
  cookies?: Record<string, string>;
  handler?: Function;
  classRef?: Function;
  user?: any;
} = {}): ExecutionContext {
  const request = {
    headers: overrides.headers ?? {},
    cookies: overrides.cookies ?? {},
    user: overrides.user ?? undefined,
  };

  const response = {
    setHeader: jest.fn(),
    cookie: jest.fn(),
  };

  const mockHandler = overrides.handler ?? jest.fn();
  const mockClass = overrides.classRef ?? class MockController {};

  return {
    switchToHttp: jest.fn().mockReturnValue({
      getRequest: jest.fn().mockReturnValue(request),
      getResponse: jest.fn().mockReturnValue(response),
    }),
    getHandler: jest.fn().mockReturnValue(mockHandler),
    getClass: jest.fn().mockReturnValue(mockClass),
    getType: jest.fn().mockReturnValue('http'),
    getArgs: jest.fn().mockReturnValue([request, response]),
    getArgByIndex: jest.fn(),
    switchToRpc: jest.fn(),
    switchToWs: jest.fn(),
  } as unknown as ExecutionContext;
}
```

### 4.3 Testing Guard Allow/Deny Logic

```typescript
describe('canActivate()', () => {
  it('should allow access with a valid JWT in Authorization header', async () => {
    // Arrange
    const context = createMockExecutionContext({
      headers: { authorization: 'Bearer valid-token' },
    });
    tokenManager.verifyAccessToken.mockReturnValue({
      sub: 'user-1',
      email: 'user@example.com',
      tenantId: 'tenant-1',
      roles: ['user'],
    });
    reflector.getAllAndOverride.mockReturnValue(false); // not public

    // Act
    const result = await guard.canActivate(context);

    // Assert
    expect(result).toBe(true);
    expect(tokenManager.verifyAccessToken).toHaveBeenCalledWith('valid-token');
  });

  it('should deny access when no token is present', async () => {
    // Arrange
    const context = createMockExecutionContext({ headers: {} });
    reflector.getAllAndOverride.mockReturnValue(false);

    // Act & Assert
    await expect(guard.canActivate(context)).rejects.toThrow(
      UnauthorizedException,
    );
  });

  it('should allow access to routes decorated with @Public()', async () => {
    // Arrange
    const context = createMockExecutionContext({ headers: {} });
    reflector.getAllAndOverride.mockReturnValue(true); // IS_PUBLIC_KEY

    // Act
    const result = await guard.canActivate(context);

    // Assert
    expect(result).toBe(true);
    expect(tokenManager.verifyAccessToken).not.toHaveBeenCalled();
  });

  it('should deny access when token is expired', async () => {
    // Arrange
    const context = createMockExecutionContext({
      headers: { authorization: 'Bearer expired-token' },
    });
    tokenManager.verifyAccessToken.mockImplementation(() => {
      throw new Error('jwt expired');
    });
    reflector.getAllAndOverride.mockReturnValue(false);

    // Act & Assert
    await expect(guard.canActivate(context)).rejects.toThrow(
      UnauthorizedException,
    );
  });
});
```

### 4.4 Testing Role-Based Guards

```typescript
describe('RolesGuard', () => {
  it('should allow access when user has required role', async () => {
    // Arrange
    const context = createMockExecutionContext({
      user: { id: 'user-1', roles: ['admin', 'user'] },
    });
    reflector.getAllAndOverride.mockReturnValue(['admin']); // required roles

    // Act
    const result = await guard.canActivate(context);

    // Assert
    expect(result).toBe(true);
  });

  it('should deny access when user lacks required role', async () => {
    // Arrange
    const context = createMockExecutionContext({
      user: { id: 'user-1', roles: ['user'] },
    });
    reflector.getAllAndOverride.mockReturnValue(['admin']);

    // Act & Assert
    await expect(guard.canActivate(context)).rejects.toThrow(
      ForbiddenException,
    );
  });

  it('should allow access when no roles are required', async () => {
    // Arrange
    const context = createMockExecutionContext({
      user: { id: 'user-1', roles: ['user'] },
    });
    reflector.getAllAndOverride.mockReturnValue(undefined);

    // Act
    const result = await guard.canActivate(context);

    // Assert
    expect(result).toBe(true);
  });
});
```

---

## 5. Unit Testing Controllers

### 5.1 Controller Test Setup

Controllers are thin layers that delegate to services. Tests focus on verifying correct delegation and HTTP-specific behavior:

```typescript
import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from '../services/auth.service';

describe('AuthController', () => {
  let controller: AuthController;
  let authService: jest.Mocked<AuthService>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        {
          provide: AuthService,
          useValue: {
            register: jest.fn(),
            login: jest.fn(),
            logout: jest.fn(),
            refreshToken: jest.fn(),
            me: jest.fn(),
          },
        },
      ],
    }).compile();

    controller = module.get<AuthController>(AuthController);
    authService = module.get(AuthService);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
```

### 5.2 Testing Controller Methods

```typescript
describe('register()', () => {
  it('should call authService.register and return the result', async () => {
    // Arrange
    const dto = { email: 'user@example.com', password: 'Pass123!', name: 'User' };
    const expectedResult = {
      user: { id: 'user-1', email: dto.email },
      accessToken: 'access-token',
      refreshToken: 'refresh-token',
    };
    authService.register.mockResolvedValue(expectedResult);

    // Act
    const result = await controller.register(dto);

    // Assert
    expect(authService.register).toHaveBeenCalledWith(dto);
    expect(result).toEqual(expectedResult);
  });

  it('should propagate service exceptions to the caller', async () => {
    // Arrange
    const dto = { email: 'existing@example.com', password: 'Pass123!', name: 'User' };
    authService.register.mockRejectedValue(new ConflictException('Email already exists'));

    // Act & Assert
    await expect(controller.register(dto)).rejects.toThrow(ConflictException);
  });
});
```

### 5.3 Testing Controllers with Request/Response Objects

When a controller method needs the raw Express `Request` or `Response` (e.g., to set cookies):

```typescript
describe('login()', () => {
  it('should set refresh token as HttpOnly cookie', async () => {
    // Arrange
    const dto = { email: 'user@example.com', password: 'Pass123!' };
    const mockResponse = {
      cookie: jest.fn(),
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    } as unknown as Response;

    authService.login.mockResolvedValue({
      user: { id: 'user-1' },
      accessToken: 'access-token',
      refreshToken: 'refresh-token',
    });

    // Act
    await controller.login(dto, mockResponse);

    // Assert
    expect(mockResponse.cookie).toHaveBeenCalledWith(
      'refresh_token',
      'refresh-token',
      expect.objectContaining({
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
      }),
    );
  });
});
```

### 5.4 Testing Decorated Controller Methods

If your controllers use custom decorators like `@CurrentUser()`, test that the controller correctly receives the injected value:

```typescript
describe('me()', () => {
  it('should return the current user profile', async () => {
    // Arrange
    const currentUser = { id: 'user-1', email: 'user@example.com', tenantId: 'tenant-1' };
    const fullProfile = { ...currentUser, name: 'Test User', createdAt: new Date() };
    authService.me.mockResolvedValue(fullProfile);

    // Act — the controller receives currentUser from the @CurrentUser() decorator
    const result = await controller.me(currentUser);

    // Assert
    expect(authService.me).toHaveBeenCalledWith(currentUser.id);
    expect(result).toEqual(fullProfile);
  });
});
```

---

## 6. Mocking Patterns

### 6.1 jest.fn() — Inline Mocks

Use `jest.fn()` for simple, one-off mocks within a test file:

```typescript
const mockCallback = jest.fn();
mockCallback.mockReturnValue(42);
mockCallback.mockResolvedValue({ success: true });
mockCallback.mockRejectedValue(new Error('fail'));
mockCallback.mockImplementation((x: number) => x * 2);
```

### 6.2 jest.Mocked<T> — Typed Mock Objects

Always type your mocks using `jest.Mocked<T>` to get IntelliSense and catch type errors:

```typescript
let service: jest.Mocked<AuthService>;

// When providing mocks in the module setup:
{
  provide: AuthService,
  useValue: {
    register: jest.fn(),
    login: jest.fn(),
  } as Partial<jest.Mocked<AuthService>>,
}

// After module.get(), the variable is fully typed:
service = module.get(AuthService);
service.register.mockResolvedValue(/* typed result */);
```

### 6.3 jest.mock() — Module-Level Mocking

Use `jest.mock()` to mock entire modules. This is hoisted to the top of the file automatically:

```typescript
// Mock the entire @nestjs/jwt module
jest.mock('@nestjs/jwt', () => ({
  JwtService: jest.fn().mockImplementation(() => ({
    sign: jest.fn().mockReturnValue('mocked-jwt-token'),
    verify: jest.fn().mockReturnValue({ sub: 'user-1' }),
    signAsync: jest.fn().mockResolvedValue('mocked-jwt-token'),
    verifyAsync: jest.fn().mockResolvedValue({ sub: 'user-1' }),
  })),
}));
```

### 6.4 jest.spyOn() — Spying on Existing Methods

Use `jest.spyOn()` when you want to observe calls to a real method or temporarily override it:

```typescript
// Spy without changing behavior
const spy = jest.spyOn(service, 'validateToken');
await service.someMethod();
expect(spy).toHaveBeenCalled();

// Spy and override
jest.spyOn(service, 'validateToken').mockResolvedValue({ valid: true });

// Spy on a prototype method
jest.spyOn(AuthService.prototype, 'validateToken').mockResolvedValue({ valid: true });
```

### 6.5 Mocking Redis (ioredis)

Redis is used for session management, token blacklisting, and rate limiting. Create a reusable mock factory:

```typescript
// test/mocks/redis.mock.ts (or inline in the test file)
type MockRedis = jest.Mocked<Pick<Redis, 'get' | 'set' | 'del' | 'expire' | 'exists' | 'keys' | 'ttl' | 'incr' | 'multi' | 'pipeline'>>;

function createMockRedis(): MockRedis {
  const mockMulti = {
    set: jest.fn().mockReturnThis(),
    expire: jest.fn().mockReturnThis(),
    del: jest.fn().mockReturnThis(),
    exec: jest.fn().mockResolvedValue([]),
  };

  return {
    get: jest.fn().mockResolvedValue(null),
    set: jest.fn().mockResolvedValue('OK'),
    del: jest.fn().mockResolvedValue(1),
    expire: jest.fn().mockResolvedValue(1),
    exists: jest.fn().mockResolvedValue(0),
    keys: jest.fn().mockResolvedValue([]),
    ttl: jest.fn().mockResolvedValue(-2),
    incr: jest.fn().mockResolvedValue(1),
    multi: jest.fn().mockReturnValue(mockMulti),
    pipeline: jest.fn().mockReturnValue(mockMulti),
  } as MockRedis;
}
```

Usage in a test:

```typescript
describe('SessionService', () => {
  let service: SessionService;
  let redis: MockRedis;

  beforeEach(async () => {
    redis = createMockRedis();

    const module = await Test.createTestingModule({
      providers: [
        SessionService,
        { provide: 'REDIS_CLIENT', useValue: redis },
      ],
    }).compile();

    service = module.get(SessionService);
  });

  it('should store session data in Redis with TTL', async () => {
    // Arrange
    const sessionId = 'session-abc';
    const sessionData = { userId: 'user-1', tenantId: 'tenant-1' };

    // Act
    await service.create(sessionId, sessionData, 3600);

    // Assert
    expect(redis.set).toHaveBeenCalledWith(
      `session:${sessionId}`,
      JSON.stringify(sessionData),
    );
    expect(redis.expire).toHaveBeenCalledWith(`session:${sessionId}`, 3600);
  });

  it('should return null for non-existent session', async () => {
    redis.get.mockResolvedValue(null);

    const result = await service.get('non-existent');

    expect(result).toBeNull();
  });
});
```

### 6.6 Mocking node:crypto

For services that use `node:crypto` for hashing, TOTP, or encryption:

```typescript
import * as crypto from 'node:crypto';

describe('TOTPService', () => {
  beforeEach(() => {
    // Deterministic random bytes for reproducible tests
    jest.spyOn(crypto, 'randomBytes').mockReturnValue(
      Buffer.from('a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8', 'hex') as any,
    );
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('should generate a TOTP secret of correct length', () => {
    const secret = service.generateSecret();
    expect(secret).toBeDefined();
    expect(typeof secret).toBe('string');
    expect(crypto.randomBytes).toHaveBeenCalledWith(20);
  });
});
```

For AES-256-GCM encryption testing:

```typescript
describe('EncryptionService', () => {
  it('should encrypt and decrypt data symmetrically', () => {
    // For encryption tests, avoid mocking crypto — test the real behavior
    const service = new EncryptionService('0123456789abcdef0123456789abcdef'); // 32-byte key
    const plaintext = 'sensitive-data-here';

    const encrypted = service.encrypt(plaintext);
    const decrypted = service.decrypt(encrypted);

    expect(encrypted).not.toBe(plaintext);
    expect(decrypted).toBe(plaintext);
  });

  it('should produce different ciphertexts for the same input (random IV)', () => {
    const service = new EncryptionService('0123456789abcdef0123456789abcdef');
    const plaintext = 'same-input';

    const encrypted1 = service.encrypt(plaintext);
    const encrypted2 = service.encrypt(plaintext);

    expect(encrypted1).not.toBe(encrypted2);
  });
});
```

### 6.7 Mocking NestJS @nestjs/jwt

The `@nestjs/jwt` JwtService is a peer dependency. Mock it in tests:

```typescript
{
  provide: JwtService,
  useValue: {
    sign: jest.fn().mockReturnValue('mocked-access-token'),
    signAsync: jest.fn().mockResolvedValue('mocked-access-token'),
    verify: jest.fn().mockReturnValue({
      sub: 'user-1',
      email: 'user@example.com',
      tenantId: 'tenant-1',
      iat: 1700000000,
      exp: 1700000900,
    }),
    verifyAsync: jest.fn().mockResolvedValue({
      sub: 'user-1',
      email: 'user@example.com',
      tenantId: 'tenant-1',
      iat: 1700000000,
      exp: 1700000900,
    }),
  },
}
```

### 6.8 Mocking External HTTP Calls (OAuth)

For OAuth provider tests, mock the global `fetch`:

```typescript
describe('OAuthService', () => {
  beforeEach(() => {
    global.fetch = jest.fn();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('should exchange authorization code for tokens', async () => {
    // Arrange
    const mockTokenResponse = {
      access_token: 'oauth-access-token',
      refresh_token: 'oauth-refresh-token',
      expires_in: 3600,
      token_type: 'Bearer',
    };

    (global.fetch as jest.Mock).mockResolvedValue({
      ok: true,
      json: jest.fn().mockResolvedValue(mockTokenResponse),
    });

    // Act
    const result = await service.exchangeCode('auth-code-123', 'google');

    // Assert
    expect(global.fetch).toHaveBeenCalledWith(
      'https://oauth2.googleapis.com/token',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          'Content-Type': 'application/x-www-form-urlencoded',
        }),
      }),
    );
    expect(result.access_token).toBe('oauth-access-token');
  });

  it('should throw when OAuth provider returns an error', async () => {
    (global.fetch as jest.Mock).mockResolvedValue({
      ok: false,
      status: 400,
      json: jest.fn().mockResolvedValue({ error: 'invalid_grant' }),
    });

    await expect(service.exchangeCode('bad-code', 'google')).rejects.toThrow();
  });
});
```

### 6.9 Mock Factory Organization

For shared mock factories across test files, place them in a `test/mocks/` directory at the project root:

```
test/
  mocks/
    redis.mock.ts
    execution-context.mock.ts
    user-repository.mock.ts
    config.mock.ts
```

Import them in test files:

```typescript
import { createMockRedis } from '../../../test/mocks/redis.mock';
import { createMockExecutionContext } from '../../../test/mocks/execution-context.mock';
```

Configure the path alias in `jest.config.ts`:

```typescript
moduleNameMapper: {
  // ... other mappings
  '^@test/(.*)$': '<rootDir>/test/$1',
},
```

Then import as:

```typescript
import { createMockRedis } from '@test/mocks/redis.mock';
```

---

## 7. Testing Async Code

### 7.1 async/await Pattern (Preferred)

Always use `async/await` for testing asynchronous code. Never use the `done` callback pattern.

```typescript
// CORRECT
it('should refresh the token', async () => {
  tokenManager.verifyRefreshToken.mockResolvedValue({ sub: 'user-1' });
  tokenManager.generateAccessToken.mockReturnValue('new-access-token');

  const result = await service.refreshToken('old-refresh-token');

  expect(result.accessToken).toBe('new-access-token');
});

// WRONG — never use done callback
it('should refresh the token', (done) => {
  service.refreshToken('old-refresh-token').then((result) => {
    expect(result.accessToken).toBe('new-access-token');
    done();
  });
});
```

### 7.2 Testing Rejected Promises

Use `rejects` matcher for testing promise rejections:

```typescript
it('should throw when refresh token is blacklisted', async () => {
  tokenManager.verifyRefreshToken.mockImplementation(() => {
    throw new UnauthorizedException('Token has been revoked');
  });

  await expect(service.refreshToken('blacklisted-token')).rejects.toThrow(
    UnauthorizedException,
  );
});

// Test specific error message
it('should include error code in the exception', async () => {
  await expect(service.refreshToken('bad-token')).rejects.toThrow(
    expect.objectContaining({
      message: expect.stringContaining('revoked'),
    }),
  );
});

// Test specific error properties
it('should throw with AUTH_TOKEN_EXPIRED error code', async () => {
  try {
    await service.refreshToken('expired-token');
    fail('Expected an error to be thrown');
  } catch (error) {
    expect(error).toBeInstanceOf(UnauthorizedException);
    expect(error.response.errorCode).toBe('AUTH_TOKEN_EXPIRED');
  }
});
```

### 7.3 Testing with Fake Timers

Use `jest.useFakeTimers()` for testing time-dependent logic such as token expiration, lockout durations, and session TTLs:

```typescript
describe('BruteForceService', () => {
  beforeEach(() => {
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('should lock account after 5 failed attempts', async () => {
    for (let i = 0; i < 5; i++) {
      await service.recordFailedAttempt('user@example.com');
    }

    const isLocked = await service.isLocked('user@example.com');
    expect(isLocked).toBe(true);
  });

  it('should unlock account after lockout duration expires', async () => {
    // Lock the account
    for (let i = 0; i < 5; i++) {
      await service.recordFailedAttempt('user@example.com');
    }
    expect(await service.isLocked('user@example.com')).toBe(true);

    // Advance time past the lockout window (e.g., 15 minutes)
    jest.advanceTimersByTime(15 * 60 * 1000);

    expect(await service.isLocked('user@example.com')).toBe(false);
  });
});
```

### 7.4 Testing setTimeout / setInterval

```typescript
it('should schedule a session cleanup after the configured interval', () => {
  jest.useFakeTimers();
  const cleanupSpy = jest.spyOn(service, 'cleanExpiredSessions');

  service.startCleanupScheduler(60_000); // every 60 seconds

  // No cleanup yet
  expect(cleanupSpy).not.toHaveBeenCalled();

  // Advance 60 seconds
  jest.advanceTimersByTime(60_000);
  expect(cleanupSpy).toHaveBeenCalledTimes(1);

  // Advance another 60 seconds
  jest.advanceTimersByTime(60_000);
  expect(cleanupSpy).toHaveBeenCalledTimes(2);

  jest.useRealTimers();
});
```

### 7.5 Testing Promise.all and Concurrent Operations

```typescript
it('should revoke all sessions concurrently', async () => {
  const sessionIds = ['session-1', 'session-2', 'session-3'];
  redis.del.mockResolvedValue(1);

  await service.revokeAllSessions('user-1', sessionIds);

  expect(redis.del).toHaveBeenCalledTimes(3);
  sessionIds.forEach((id) => {
    expect(redis.del).toHaveBeenCalledWith(`session:${id}`);
  });
});
```

---

## 8. Testing React Hooks

### 8.1 Environment Setup

React hook tests run in the `jsdom` environment. Add the docblock at the top of every `.spec.tsx` file:

```typescript
/**
 * @jest-environment jsdom
 */
```

Required imports:

```typescript
import { renderHook, act, waitFor } from '@testing-library/react';
import { type ReactNode } from 'react';
```

### 8.2 Testing a Simple Hook

```typescript
/**
 * @jest-environment jsdom
 */
import { renderHook, act } from '@testing-library/react';
import { useAuth } from './use-auth';

describe('useAuth', () => {
  beforeEach(() => {
    global.fetch = jest.fn();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('should return initial unauthenticated state', () => {
    const { result } = renderHook(() => useAuth());

    expect(result.current.isAuthenticated).toBe(false);
    expect(result.current.user).toBeNull();
    expect(result.current.isLoading).toBe(true);
  });
});
```

### 8.3 Testing Hooks with Context Providers

When hooks depend on context (e.g., `AuthProvider`), create a wrapper:

```typescript
import { AuthProvider } from '../providers/auth-provider';

function createWrapper(config?: Partial<AuthConfig>) {
  const defaultConfig: AuthConfig = {
    apiUrl: 'http://localhost:3000',
    refreshInterval: 0, // disable auto-refresh in tests
    ...config,
  };

  return function Wrapper({ children }: { children: ReactNode }) {
    return <AuthProvider config={defaultConfig}>{children}</AuthProvider>;
  };
}

describe('useSession', () => {
  it('should fetch session on mount', async () => {
    // Arrange
    const mockSession = {
      user: { id: 'user-1', email: 'user@example.com' },
      expiresAt: Date.now() + 3600_000,
    };

    (global.fetch as jest.Mock).mockResolvedValue({
      ok: true,
      json: jest.fn().mockResolvedValue(mockSession),
    });

    // Act
    const { result } = renderHook(() => useSession(), {
      wrapper: createWrapper(),
    });

    // Assert — wait for the async fetch to complete
    await waitFor(() => {
      expect(result.current.isLoading).toBe(false);
    });

    expect(result.current.session).toEqual(mockSession);
    expect(result.current.isAuthenticated).toBe(true);
  });
});
```

### 8.4 Testing Hook State Updates with act()

Any operation that triggers a state update MUST be wrapped in `act()`:

```typescript
it('should update state after login', async () => {
  (global.fetch as jest.Mock)
    .mockResolvedValueOnce({
      ok: true,
      json: jest.fn().mockResolvedValue(null), // initial session check
    })
    .mockResolvedValueOnce({
      ok: true,
      json: jest.fn().mockResolvedValue({
        user: { id: 'user-1', email: 'user@example.com' },
        accessToken: 'token-123',
      }),
    });

  const { result } = renderHook(() => useAuth(), {
    wrapper: createWrapper(),
  });

  // Wait for initial load
  await waitFor(() => {
    expect(result.current.isLoading).toBe(false);
  });

  // Perform login
  await act(async () => {
    await result.current.login({ email: 'user@example.com', password: 'Pass123!' });
  });

  expect(result.current.isAuthenticated).toBe(true);
  expect(result.current.user?.email).toBe('user@example.com');
});
```

### 8.5 Testing Hook Cleanup and Unmount

```typescript
it('should clear refresh interval on unmount', () => {
  jest.useFakeTimers();

  const { unmount } = renderHook(() => useSession(), {
    wrapper: createWrapper({ refreshInterval: 60_000 }),
  });

  // Verify interval is set
  expect(jest.getTimerCount()).toBeGreaterThan(0);

  // Unmount the hook
  unmount();

  // Verify interval is cleared
  expect(jest.getTimerCount()).toBe(0);

  jest.useRealTimers();
});
```

### 8.6 Testing Error States in Hooks

```typescript
it('should set error state when session fetch fails', async () => {
  (global.fetch as jest.Mock).mockRejectedValue(new Error('Network error'));

  const { result } = renderHook(() => useSession(), {
    wrapper: createWrapper(),
  });

  await waitFor(() => {
    expect(result.current.isLoading).toBe(false);
  });

  expect(result.current.error).toBeDefined();
  expect(result.current.error?.message).toBe('Network error');
  expect(result.current.isAuthenticated).toBe(false);
});
```

### 8.7 Testing Custom Hook Return Values

Verify the complete return type contract:

```typescript
it('should return the full hook API', () => {
  const { result } = renderHook(() => useAuth(), {
    wrapper: createWrapper(),
  });

  // Verify the shape of the returned object
  expect(result.current).toEqual(
    expect.objectContaining({
      user: expect.any(Object).nullable,
      isAuthenticated: expect.any(Boolean),
      isLoading: expect.any(Boolean),
      error: null,
      login: expect.any(Function),
      logout: expect.any(Function),
      register: expect.any(Function),
      refreshSession: expect.any(Function),
    }),
  );
});
```

---

## 9. Coverage Requirements

### 9.1 Minimum Coverage Thresholds

This project enforces the following **global** coverage thresholds. A test run will **fail** if any metric drops below its threshold:

| Metric       | Minimum | Description                                                |
| ------------ | ------- | ---------------------------------------------------------- |
| **Branches** | 80%     | All `if/else`, ternary, `switch`, `??`, `?.` paths tested  |
| **Functions**| 80%     | All exported and private functions invoked during tests     |
| **Lines**    | 80%     | Physical lines of code executed during tests                |
| **Statements** | 80%  | All statements (may differ from lines for multi-statement lines) |

### 9.2 How to Check Coverage

Run coverage locally:

```bash
npm run test:cov
```

This generates:

- **Terminal output** with a summary table.
- **`coverage/lcov-report/index.html`** — open in a browser for a detailed, file-by-file, line-by-line report.
- **`coverage/coverage-summary.json`** — machine-readable summary for CI pipelines.

### 9.3 What to Cover

Focus coverage efforts on code with business logic and security implications:

| Priority | What                                | Why                                     |
| -------- | ----------------------------------- | --------------------------------------- |
| Critical | Guards (JWT, roles, MFA, tenant)    | Security boundary — must be airtight    |
| Critical | PasswordService (hash, compare)     | Credential handling                     |
| Critical | TokenManagerService                 | JWT issuance and verification           |
| Critical | SessionService (create, revoke)     | Session lifecycle                       |
| High     | AuthService (register, login, etc.) | Core business logic                     |
| High     | BruteForceService                   | Rate limiting correctness               |
| High     | OAuth code exchange and user fetch  | Third-party integration                 |
| High     | React hooks (useSession, useAuth)   | Frontend authentication state           |
| Medium   | Controllers                         | Thin delegation layer — fewer edge cases|
| Medium   | Decorators                          | Metadata extraction                     |
| Low      | Pure type files, interfaces         | No runtime behavior to test             |

### 9.4 What to Exclude from Coverage

These files are excluded from coverage collection via the `collectCoverageFrom` config:

- `src/**/index.ts` — Barrel files that only re-export.
- `src/**/*.d.ts` — TypeScript declaration files.
- `src/**/*.interface.ts` — Pure interface definitions (no runtime code).
- `src/**/*.types.ts` — Pure type definitions (no runtime code).

If a file must be excluded for other reasons, add it to the `collectCoverageFrom` exclusion list:

```typescript
collectCoverageFrom: [
  'src/**/*.ts',
  '!src/**/index.ts',
  '!src/**/*.d.ts',
  '!src/**/*.interface.ts',
  '!src/**/*.types.ts',
  '!src/**/some-generated-file.ts', // Add specific exclusions here
],
```

### 9.5 Per-File Coverage Goals

While the global threshold is 80%, aim for higher coverage on security-critical code:

| Module Category     | Target Coverage |
| ------------------- | --------------- |
| Guards              | 95%+            |
| Crypto/Password     | 95%+            |
| Token Management    | 90%+            |
| Core Auth Service   | 90%+            |
| Session Management  | 90%+            |
| Controllers         | 85%+            |
| React Hooks         | 85%+            |
| Utility Functions   | 80%+            |

---

## 10. Anti-Patterns

### 10.1 Testing Implementation Details Instead of Behavior

```typescript
// WRONG — tests internal method call count and order
it('should call validateEmail then hashPassword then createUser', async () => {
  await service.register(dto);
  expect(service['validateEmail']).toHaveBeenCalledBefore(service['hashPassword']);
  expect(service['hashPassword']).toHaveBeenCalledBefore(userRepo.create);
});

// CORRECT — tests observable behavior
it('should create a user with a hashed password', async () => {
  const result = await service.register(dto);
  expect(result.user.email).toBe(dto.email);
  expect(passwordService.hash).toHaveBeenCalledWith(dto.password);
  expect(userRepo.create).toHaveBeenCalledWith(
    expect.objectContaining({ passwordHash: expect.any(String) }),
  );
});
```

### 10.2 Snapshot Overuse

```typescript
// WRONG — snapshot of an entire response object; brittle, hides intent
it('should return user data', async () => {
  const result = await service.me('user-1');
  expect(result).toMatchSnapshot();
});

// CORRECT — explicit assertions on important fields
it('should return user data without sensitive fields', async () => {
  const result = await service.me('user-1');
  expect(result).toHaveProperty('id', 'user-1');
  expect(result).toHaveProperty('email', 'user@example.com');
  expect(result).not.toHaveProperty('passwordHash');
  expect(result).not.toHaveProperty('mfaSecret');
});
```

### 10.3 Not Cleaning Up Mocks

```typescript
// WRONG — leaked mock state across tests
jest.mock('./some-module'); // persists across all tests in the file

it('test one', () => {
  someMock.mockReturnValue('value-a');
  // ...
});

it('test two', () => {
  // someMock still returns 'value-a' if clearMocks is not configured!
  // This test depends on test one's mock setup
});

// CORRECT — configure clearMocks: true in jest.config.ts (already done)
// AND use jest.restoreAllMocks() in afterEach
afterEach(() => {
  jest.restoreAllMocks();
});
```

### 10.4 Using Real External Services

```typescript
// WRONG — test depends on a running Redis instance
it('should store session', async () => {
  const redis = new Redis('localhost:6379');
  const service = new SessionService(redis);
  await service.create('session-1', { userId: 'user-1' });
  const session = await service.get('session-1');
  expect(session).toBeDefined();
});

// CORRECT — mock Redis
it('should store session', async () => {
  const redis = createMockRedis();
  redis.get.mockResolvedValue(JSON.stringify({ userId: 'user-1' }));
  const service = new SessionService(redis);

  const session = await service.get('session-1');

  expect(redis.get).toHaveBeenCalledWith('session:session-1');
  expect(session).toEqual({ userId: 'user-1' });
});
```

### 10.5 Overly Broad Exception Tests

```typescript
// WRONG — only checks that something was thrown, not what
it('should throw for invalid token', async () => {
  await expect(service.verifyToken('bad')).rejects.toThrow();
});

// CORRECT — asserts the specific exception type and message
it('should throw UnauthorizedException for invalid token', async () => {
  await expect(service.verifyToken('bad')).rejects.toThrow(UnauthorizedException);
  await expect(service.verifyToken('bad')).rejects.toThrow(
    expect.objectContaining({
      message: expect.stringContaining('invalid'),
    }),
  );
});
```

### 10.6 Test Interdependence

```typescript
// WRONG — test two depends on test one
let createdUserId: string;

it('should create a user', async () => {
  const result = await service.register(dto);
  createdUserId = result.user.id; // saved for the next test
  expect(result.user).toBeDefined();
});

it('should fetch the created user', async () => {
  const user = await service.me(createdUserId); // depends on previous test!
  expect(user.email).toBe(dto.email);
});

// CORRECT — each test is self-contained
it('should create a user', async () => {
  userRepo.create.mockResolvedValue({ id: 'user-1', email: 'test@example.com' });
  const result = await service.register(dto);
  expect(result.user).toBeDefined();
});

it('should fetch a user by ID', async () => {
  userRepo.findById.mockResolvedValue({ id: 'user-1', email: 'test@example.com' });
  const user = await service.me('user-1');
  expect(user.email).toBe('test@example.com');
});
```

### 10.7 Testing Private Methods Directly

```typescript
// WRONG — accessing private methods bypasses encapsulation
it('should validate email format', () => {
  const result = (service as any)['validateEmailFormat']('user@example.com');
  expect(result).toBe(true);
});

// CORRECT — test via the public API that uses the private method
it('should reject registration with invalid email', async () => {
  const dto = { email: 'not-an-email', password: 'Pass123!' };
  await expect(service.register(dto)).rejects.toThrow(BadRequestException);
});
```

### 10.8 Ignoring Error Paths

```typescript
// WRONG — only tests the happy path
describe('login()', () => {
  it('should return tokens for valid credentials', async () => {
    // ... happy path test
  });
  // No error case tests!
});

// CORRECT — tests happy path AND all error paths
describe('login()', () => {
  it('should return tokens for valid credentials', async () => { /* ... */ });
  it('should throw UnauthorizedException for wrong password', async () => { /* ... */ });
  it('should throw UnauthorizedException for non-existent user', async () => { /* ... */ });
  it('should throw ForbiddenException when account is locked', async () => { /* ... */ });
  it('should throw ForbiddenException when MFA is required but not provided', async () => { /* ... */ });
  it('should throw UnauthorizedException for invalid MFA code', async () => { /* ... */ });
});
```

### 10.9 Redundant expect(true).toBe(true)

```typescript
// WRONG — asserts nothing meaningful
it('should not throw during registration', async () => {
  await service.register(dto);
  expect(true).toBe(true); // this always passes
});

// CORRECT — assert on the actual return value or side effects
it('should register successfully and return user data', async () => {
  const result = await service.register(dto);
  expect(result.user).toBeDefined();
  expect(result.accessToken).toBeDefined();
});
```

### 10.10 Hardcoded Magic Values Without Context

```typescript
// WRONG — what does 900000 mean?
jest.advanceTimersByTime(900000);
expect(redis.del).toHaveBeenCalled();

// CORRECT — use named constants
const FIFTEEN_MINUTES_MS = 15 * 60 * 1000;
jest.advanceTimersByTime(FIFTEEN_MINUTES_MS);
expect(redis.del).toHaveBeenCalled();
```

---

## Quick Reference Checklist

Use this checklist before submitting any test code:

### File and Structure

- [ ] Test file is named `*.spec.ts` (or `*.spec.tsx` for React).
- [ ] Test file is co-located next to the source file.
- [ ] Top-level `describe` matches the class/module name.
- [ ] Method-level `describe` blocks include parentheses (e.g., `register()`).
- [ ] All `it` blocks start with `should`.
- [ ] Nesting does not exceed 3 levels of `describe`.

### Test Quality

- [ ] Every test follows the AAA pattern (Arrange, Act, Assert).
- [ ] Each test is independent and does not rely on other tests.
- [ ] Both happy path and error paths are tested for every public method.
- [ ] `async/await` is used (never the `done` callback).
- [ ] `act()` wraps all state-triggering operations in React hook tests.
- [ ] Specific exception types and messages are asserted (not just `toThrow()`).
- [ ] No snapshots are used for large objects or API responses.

### Mocking

- [ ] Mocks are typed with `jest.Mocked<T>`.
- [ ] `beforeEach` creates fresh module and mock instances.
- [ ] `afterEach` calls `jest.restoreAllMocks()`.
- [ ] Redis, crypto, and external services are properly mocked.
- [ ] No test depends on a running external service (Redis, HTTP, database).
- [ ] `jest.useFakeTimers()` is cleaned up with `jest.useRealTimers()` in `afterEach`.

### Coverage

- [ ] Running `npm run test:cov` shows all four metrics at 80% or above.
- [ ] Security-critical modules (guards, password, tokens) are at 90%+ coverage.
- [ ] Barrel files, `.d.ts` files, and pure interface/type files are excluded.

### TDD Compliance

- [ ] The `.spec.ts` file was written before or alongside the implementation.
- [ ] Tests fail before the implementation is written (red).
- [ ] Tests pass after the minimal implementation (green).
- [ ] Code is refactored while tests remain green.

---

> **Last updated:** 2026-04-13
> **Maintainer:** Bymax Digital Engineering
