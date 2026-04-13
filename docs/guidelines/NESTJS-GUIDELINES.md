# NestJS 11 Guidelines — @bymax-one/nest-auth

> **Audience:** AI agents and developers working on this codebase.
> **Stack:** NestJS 11, TypeScript 5.8+, Node.js 24+
> **Package type:** Public npm library (`@bymax-one/nest-auth`) — NOT an application.
> **Rule:** Follow these guidelines for all NestJS code in this project.

---

## Table of Contents

1. [Dynamic Module Pattern](#1-dynamic-module-pattern)
2. [Dependency Injection](#2-dependency-injection)
3. [Guards (Without Passport)](#3-guards-without-passport)
4. [Decorators](#4-decorators)
5. [Services Architecture](#5-services-architecture)
6. [Controllers](#6-controllers)
7. [Error Handling](#7-error-handling)
8. [Module Organization](#8-module-organization)
9. [Testing Patterns](#9-testing-patterns)
10. [Anti-Patterns](#10-anti-patterns)
11. [Quick Reference Checklist](#quick-reference-checklist)

---

## 1. Dynamic Module Pattern

This package is a **dynamic NestJS module**. It is not an application — it is imported into host applications via `BymaxAuthModule.registerAsync()`. Every design decision must support this model.

### 1.1 Core Concepts

A dynamic module is a module whose providers, controllers, and exports are determined at runtime based on configuration supplied by the consuming application. NestJS 11 provides the `ConfigurableModuleBuilder` utility, but this project uses the **manual pattern** for maximum control over conditional registration.

### 1.2 The `registerAsync` Pattern

The primary entry point for consumers is `registerAsync`. This allows the host application to inject its own `ConfigService` or factory to supply configuration asynchronously.

```typescript
// bymax-one-nest-auth.module.ts

import { DynamicModule, Module, Provider, Type } from '@nestjs/common';
import {
  AUTH_MODULE_OPTIONS,
  USER_REPOSITORY,
  EMAIL_PROVIDER,
  AUTH_REDIS_CLIENT,
  AUTH_HOOKS,
} from './bymax-one-nest-auth.constants';
import type { AuthModuleAsyncOptions } from './interfaces/auth-module-options.interface';

@Module({})
export class BymaxAuthModule {
  /**
   * Register the auth module with async configuration.
   * This is the ONLY public registration method.
   */
  static registerAsync(options: AuthModuleAsyncOptions): DynamicModule {
    const asyncProviders = this.createAsyncProviders(options);
    const conditionalProviders = this.createConditionalProviders();
    const conditionalControllers = this.createConditionalControllers();

    return {
      module: BymaxAuthModule,
      global: options.isGlobal ?? false,
      imports: [...(options.imports ?? [])],
      providers: [
        ...asyncProviders,
        ...conditionalProviders,
        // Core services always registered
        AuthService,
        PasswordService,
        TokenManagerService,
        BruteForceService,
      ],
      controllers: [...conditionalControllers],
      exports: [
        AuthService,
        TokenManagerService,
        AUTH_MODULE_OPTIONS,
      ],
    };
  }

  // No static register() — async-only for this package
}
```

### 1.3 Async Options Interface

```typescript
// interfaces/auth-module-options.interface.ts

import { ModuleMetadata, Type } from '@nestjs/common';

export interface AuthModuleOptions {
  jwt: {
    accessSecret: string;
    refreshSecret: string;
    accessExpiresIn: string;   // e.g., '15m'
    refreshExpiresIn: string;  // e.g., '7d'
  };
  tokenDelivery: 'cookie' | 'body' | 'both';
  mfa?: { issuer: string };
  sessions?: { enabled: boolean; maxPerUser?: number };
  oauth?: { google?: GoogleOAuthConfig };
  platformAdmin?: { enabled: boolean };
  invitations?: { enabled: boolean };
  controllers?: {
    auth?: boolean;
    mfa?: boolean;
    passwordReset?: boolean;
    sessions?: boolean;
    platform?: boolean;
    invitations?: boolean;
  };
}

export interface AuthModuleAsyncOptions extends Pick<ModuleMetadata, 'imports'> {
  isGlobal?: boolean;
  useFactory: (...args: unknown[]) => Promise<AuthModuleOptions> | AuthModuleOptions;
  inject?: (Type | string | symbol)[];
}
```

### 1.4 Creating Async Providers

The factory function creates providers that resolve the configuration at runtime:

```typescript
private static createAsyncProviders(options: AuthModuleAsyncOptions): Provider[] {
  return [
    {
      provide: AUTH_MODULE_OPTIONS,
      useFactory: options.useFactory,
      inject: options.inject ?? [],
    },
  ];
}
```

### 1.5 Consumer Usage Example

This is how a host application imports the module:

```typescript
// In the host application's AppModule
import { BymaxAuthModule } from '@bymax-one/nest-auth';
import { ConfigService } from '@nestjs/config';

@Module({
  imports: [
    BymaxAuthModule.registerAsync({
      isGlobal: true,
      imports: [ConfigModule],
      useFactory: (config: ConfigService) => ({
        jwt: {
          accessSecret: config.getOrThrow('JWT_ACCESS_SECRET'),
          refreshSecret: config.getOrThrow('JWT_REFRESH_SECRET'),
          accessExpiresIn: '15m',
          refreshExpiresIn: '7d',
        },
        tokenDelivery: 'cookie',
        mfa: { issuer: 'MyApp' },
        sessions: { enabled: true, maxPerUser: 5 },
      }),
      inject: [ConfigService],
    }),
  ],
})
export class AppModule {}
```

### 1.6 Rules for Dynamic Modules in This Project

| Rule | Description |
|------|-------------|
| **Async only** | Only expose `registerAsync()`. Never expose a synchronous `register()` — all real-world configs depend on environment variables. |
| **No `forRoot` / `forFeature` split** | This package is a single cohesive module, not an ORM-style multi-instance module. Use `registerAsync` exclusively. |
| **Conditional registration** | Controllers and optional services (MFA, sessions, OAuth) are registered only when their configuration section is present. |
| **`global` is opt-in** | The `isGlobal` option defaults to `false`. The host decides whether the module is global. |
| **No hard dependencies** | The module must never import concrete implementations. All external dependencies (user repository, email provider, Redis client) are injected via tokens. |

### 1.7 Conditional Controller Registration

Controllers are registered dynamically based on configuration. Use a factory method:

```typescript
private static createConditionalControllers(): Type[] {
  // This method is called during registerAsync.
  // At this point, options are not yet resolved (they come from a factory).
  // Instead, use a provider-based approach to conditionally bind routes,
  // or register all controllers and use guards/metadata to disable them.
  //
  // Preferred approach: register all controllers, but use a module-level
  // factory that reads resolved options and filters the controller list.

  // For this package, we use the following approach:
  // 1. Pass a resolved options reference
  // 2. Use the DiscoveryService or a simple flag check
  return [];
}
```

A better approach for this package -- since options are resolved via async factory -- is to compute the controller list inside `registerAsync` using a helper:

```typescript
static registerAsync(options: AuthModuleAsyncOptions): DynamicModule {
  // Controllers cannot be determined before the factory runs.
  // Strategy: register all controllers, each controller checks
  // at runtime whether its feature is enabled via the injected options.
  // If disabled, routes return 404 or the controller is not bound.
  //
  // Alternative (used in this package): use a two-phase approach
  // where the consumer specifies which controllers to enable
  // in the options, and we use a conditional module factory.

  return {
    module: BymaxAuthModule,
    // ... providers, exports
  };
}
```

> **Important:** Since `registerAsync` uses a factory (resolved at runtime), you cannot conditionally include controllers at module definition time. The recommended pattern for this package is to register all controllers and have each controller inject `AUTH_MODULE_OPTIONS` to check if its feature is enabled. Controllers for disabled features should throw a `NotFoundException` or simply not bind routes using a custom decorator.

---

## 2. Dependency Injection

### 2.1 Injection Tokens

This package uses `Symbol()` for all injection tokens to avoid naming collisions with host application providers.

```typescript
// bymax-one-nest-auth.constants.ts

/**
 * Injection token for the resolved auth module options.
 * Provided by the async factory in registerAsync().
 */
export const AUTH_MODULE_OPTIONS = Symbol('AUTH_MODULE_OPTIONS');

/**
 * Injection token for the user repository implementation.
 * The host application must provide a class implementing IUserRepository.
 */
export const USER_REPOSITORY = Symbol('USER_REPOSITORY');

/**
 * Injection token for the email provider implementation.
 * The host application must provide a class implementing IEmailProvider.
 */
export const EMAIL_PROVIDER = Symbol('EMAIL_PROVIDER');

/**
 * Injection token for the ioredis client instance.
 * The host application must provide a configured Redis client.
 */
export const AUTH_REDIS_CLIENT = Symbol('AUTH_REDIS_CLIENT');

/**
 * Injection token for auth lifecycle hooks.
 * Optional — falls back to NoOpAuthHooks if not provided.
 */
export const AUTH_HOOKS = Symbol('AUTH_HOOKS');
```

### 2.2 Why `Symbol()` Instead of Strings

```typescript
// WRONG: String tokens can collide with host application tokens
export const USER_REPOSITORY = 'USER_REPOSITORY';

// CORRECT: Symbol tokens are unique by identity
export const USER_REPOSITORY = Symbol('USER_REPOSITORY');
```

String tokens like `'USER_REPOSITORY'` can collide if the host application or another package uses the same string. `Symbol()` guarantees uniqueness because each call creates a distinct identity. The string argument is purely a debug label.

### 2.3 Using `@Inject()` with Symbol Tokens

When a token is not a class (i.e., it is a Symbol, string, or abstract class), you must use the `@Inject()` decorator explicitly:

```typescript
import { Injectable, Inject } from '@nestjs/common';
import { AUTH_MODULE_OPTIONS, USER_REPOSITORY } from '../bymax-one-nest-auth.constants';
import type { AuthModuleOptions } from '../interfaces/auth-module-options.interface';
import type { IUserRepository } from '../interfaces/user-repository.interface';

@Injectable()
export class AuthService {
  constructor(
    @Inject(AUTH_MODULE_OPTIONS)
    private readonly options: AuthModuleOptions,

    @Inject(USER_REPOSITORY)
    private readonly userRepository: IUserRepository,

    // Class-based tokens do NOT need @Inject()
    private readonly tokenManager: TokenManagerService,
  ) {}
}
```

### 2.4 Custom Provider Patterns

This package uses all four provider types. Here is when and how to use each:

#### `useClass` — Swap Implementation

```typescript
// Provide a default implementation that can be overridden
{
  provide: AUTH_HOOKS,
  useClass: NoOpAuthHooks,
}
```

#### `useFactory` — Compute at Runtime

```typescript
// Configuration factory — the most common pattern in this package
{
  provide: AUTH_MODULE_OPTIONS,
  useFactory: async (config: ConfigService): Promise<AuthModuleOptions> => ({
    jwt: {
      accessSecret: config.getOrThrow<string>('JWT_ACCESS_SECRET'),
      refreshSecret: config.getOrThrow<string>('JWT_REFRESH_SECRET'),
      accessExpiresIn: '15m',
      refreshExpiresIn: '7d',
    },
    tokenDelivery: 'cookie',
  }),
  inject: [ConfigService],
}
```

#### `useValue` — Static Values

```typescript
// Useful for testing or constant values
{
  provide: AUTH_MODULE_OPTIONS,
  useValue: {
    jwt: {
      accessSecret: 'test-secret',
      refreshSecret: 'test-refresh-secret',
      accessExpiresIn: '15m',
      refreshExpiresIn: '7d',
    },
    tokenDelivery: 'body',
  },
}
```

#### `useExisting` — Alias a Provider

```typescript
// Alias an existing provider under a different token
{
  provide: LEGACY_USER_REPO,
  useExisting: USER_REPOSITORY,
}
```

### 2.5 Interface-Based Injection Pattern

This package defines TypeScript interfaces for all external contracts. Since TypeScript interfaces are erased at runtime, you must use injection tokens:

```typescript
// WRONG: Interfaces do not exist at runtime — this fails
@Injectable()
export class AuthService {
  constructor(private readonly userRepo: IUserRepository) {} // Error!
}

// CORRECT: Use the Symbol token
@Injectable()
export class AuthService {
  constructor(
    @Inject(USER_REPOSITORY)
    private readonly userRepo: IUserRepository,
  ) {}
}
```

### 2.6 Factory Providers for Conditional Services

When a service should only exist if its feature is enabled:

```typescript
// Provide MfaService only when MFA is configured
const mfaProvider: Provider = {
  provide: MfaService,
  useFactory: (options: AuthModuleOptions) => {
    if (!options.mfa) {
      return null; // Or a no-op stub
    }
    return new MfaService(options.mfa);
  },
  inject: [AUTH_MODULE_OPTIONS],
};
```

### 2.7 Provider Scope

All providers in this package use the **default scope** (`Scope.DEFAULT` — singleton). Do not use `Scope.REQUEST` or `Scope.TRANSIENT` unless absolutely necessary, as they introduce performance overhead and complicate testing.

```typescript
// WRONG: Request-scoped provider in a library — forces the entire
// dependency chain to become request-scoped
@Injectable({ scope: Scope.REQUEST })
export class AuthService { ... }

// CORRECT: Default singleton scope
@Injectable()
export class AuthService { ... }
```

### 2.8 Rules for Dependency Injection in This Project

| Rule | Description |
|------|-------------|
| **Symbol tokens only** | All injection tokens use `Symbol()`. Never use string tokens. |
| **Explicit `@Inject()`** | Always use `@Inject(TOKEN)` for non-class tokens. Never rely on type inference for interfaces. |
| **No `Scope.REQUEST`** | All services are singletons. If you need request data, pass it as a method parameter. |
| **No circular references** | Design service boundaries to avoid circular DI. If unavoidable, use `forwardRef()` (see Section 5.5). |
| **Validate injected deps** | The module should validate that required external dependencies (user repo, Redis, email provider) are provided at initialization, not at first use. |

---

## 3. Guards (Without Passport)

This package does **not** use Passport.js. All authentication and authorization guards are implemented natively using the NestJS `CanActivate` interface and `@nestjs/jwt` for token verification.

### 3.1 The `CanActivate` Interface

Every guard implements `CanActivate`, which requires a single method:

```typescript
import { CanActivate, ExecutionContext } from '@nestjs/common';

export interface CanActivate {
  canActivate(context: ExecutionContext): boolean | Promise<boolean> | Observable<boolean>;
}
```

The `ExecutionContext` extends `ArgumentsHost` and provides methods to determine the handler class and method being invoked, enabling metadata-based decisions.

### 3.2 JWT Auth Guard (Core)

The primary guard — extracts and validates JWT tokens from cookies or the `Authorization` header:

```typescript
// guards/jwt-auth.guard.ts

import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Inject,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { AUTH_MODULE_OPTIONS } from '../bymax-one-nest-auth.constants';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';
import type { AuthModuleOptions } from '../interfaces/auth-module-options.interface';
import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface';
import type { Request } from 'express';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private readonly jwtService: JwtService,
    private readonly reflector: Reflector,
    @Inject(AUTH_MODULE_OPTIONS)
    private readonly options: AuthModuleOptions,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Check if the route is marked as public
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) {
      return true;
    }

    const request = context.switchToHttp().getRequest<Request>();
    const token = this.extractToken(request);

    if (!token) {
      throw new UnauthorizedException('Missing authentication token');
    }

    try {
      const payload = await this.jwtService.verifyAsync<DashboardJwtPayload>(
        token,
        { secret: this.options.jwt.accessSecret },
      );

      // Attach the validated payload to the request for downstream use
      request['user'] = payload;
    } catch {
      throw new UnauthorizedException('Invalid or expired token');
    }

    return true;
  }

  /**
   * Extract JWT from cookie first, then fall back to Authorization header.
   * Cookie takes precedence because it is HttpOnly and more secure.
   */
  private extractToken(request: Request): string | undefined {
    // 1. Try cookie
    const cookieToken = request.cookies?.['access_token'];
    if (cookieToken) {
      return cookieToken;
    }

    // 2. Fall back to Authorization: Bearer <token>
    const authHeader = request.headers.authorization;
    if (authHeader?.startsWith('Bearer ')) {
      return authHeader.slice(7);
    }

    return undefined;
  }
}
```

### 3.3 Roles Guard

Checks that the authenticated user has the required role(s) based on a hierarchical role system:

```typescript
// guards/roles.guard.ts

import {
  CanActivate,
  ExecutionContext,
  Injectable,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../decorators/roles.decorator';
import { hasRole } from '../utils/roles.util';
import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<string[]>(
      ROLES_KEY,
      [context.getHandler(), context.getClass()],
    );

    // If no roles are specified, the route is accessible to any authenticated user
    if (!requiredRoles || requiredRoles.length === 0) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const user = request['user'] as DashboardJwtPayload;

    if (!user) {
      throw new ForbiddenException('Authentication required');
    }

    const authorized = requiredRoles.some((role) => hasRole(user.role, role));

    if (!authorized) {
      throw new ForbiddenException('Insufficient permissions');
    }

    return true;
  }
}
```

### 3.4 User Status Guard

Prevents banned or inactive users from accessing resources:

```typescript
// guards/user-status.guard.ts

import {
  CanActivate,
  ExecutionContext,
  Injectable,
  ForbiddenException,
} from '@nestjs/common';
import { AuthRedisService } from '../redis/auth-redis.service';
import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface';

@Injectable()
export class UserStatusGuard implements CanActivate {
  constructor(private readonly redisService: AuthRedisService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const user = request['user'] as DashboardJwtPayload | undefined;

    if (!user) {
      // If no user is attached, this guard should not block (let JwtAuthGuard handle it)
      return true;
    }

    const isBlocked = await this.redisService.isUserBlocked(user.sub);

    if (isBlocked) {
      throw new ForbiddenException('Account is suspended');
    }

    return true;
  }
}
```

### 3.5 MFA Required Guard

Ensures that MFA-enabled users have completed the MFA challenge:

```typescript
// guards/mfa-required.guard.ts

import {
  CanActivate,
  ExecutionContext,
  Injectable,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { SKIP_MFA_KEY } from '../decorators/skip-mfa.decorator';
import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface';

@Injectable()
export class MfaRequiredGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const skipMfa = this.reflector.getAllAndOverride<boolean>(SKIP_MFA_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (skipMfa) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const user = request['user'] as DashboardJwtPayload | undefined;

    if (!user) {
      return true; // Let JwtAuthGuard handle missing user
    }

    // If the user has MFA enabled but has not completed the challenge
    if (user.mfaEnabled && !user.mfaVerified) {
      throw new ForbiddenException('MFA verification required');
    }

    return true;
  }
}
```

### 3.6 Optional Auth Guard

Attaches user data if a valid token is present, but does not reject unauthenticated requests:

```typescript
// guards/optional-auth.guard.ts

import { CanActivate, ExecutionContext, Injectable, Inject } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { AUTH_MODULE_OPTIONS } from '../bymax-one-nest-auth.constants';
import type { AuthModuleOptions } from '../interfaces/auth-module-options.interface';
import type { Request } from 'express';

@Injectable()
export class OptionalAuthGuard implements CanActivate {
  constructor(
    private readonly jwtService: JwtService,
    @Inject(AUTH_MODULE_OPTIONS)
    private readonly options: AuthModuleOptions,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const token = this.extractToken(request);

    if (token) {
      try {
        const payload = await this.jwtService.verifyAsync(token, {
          secret: this.options.jwt.accessSecret,
        });
        request['user'] = payload;
      } catch {
        // Token is invalid — proceed without user (do not throw)
      }
    }

    // Always return true — this guard never blocks
    return true;
  }

  private extractToken(request: Request): string | undefined {
    return (
      request.cookies?.['access_token'] ??
      request.headers.authorization?.replace('Bearer ', '') ??
      undefined
    );
  }
}
```

### 3.7 WebSocket JWT Guard

For WebSocket gateways, extract the token from the handshake:

```typescript
// guards/ws-jwt.guard.ts

import { CanActivate, ExecutionContext, Injectable, Inject } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { WsException } from '@nestjs/websockets';
import { AUTH_MODULE_OPTIONS } from '../bymax-one-nest-auth.constants';
import type { AuthModuleOptions } from '../interfaces/auth-module-options.interface';

@Injectable()
export class WsJwtGuard implements CanActivate {
  constructor(
    private readonly jwtService: JwtService,
    @Inject(AUTH_MODULE_OPTIONS)
    private readonly options: AuthModuleOptions,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const client = context.switchToWs().getClient();
    const token =
      client.handshake?.auth?.token ??
      client.handshake?.headers?.authorization?.replace('Bearer ', '');

    if (!token) {
      throw new WsException('Missing authentication token');
    }

    try {
      const payload = await this.jwtService.verifyAsync(token, {
        secret: this.options.jwt.accessSecret,
      });
      client.data = { user: payload };
    } catch {
      throw new WsException('Invalid or expired token');
    }

    return true;
  }
}
```

### 3.8 Guard Execution Order

Guards execute in the order they are bound. For this package, the standard execution order is:

```
JwtAuthGuard → UserStatusGuard → MfaRequiredGuard → RolesGuard
```

Bind them at the controller level using `@UseGuards()`:

```typescript
@Controller('auth')
@UseGuards(JwtAuthGuard, UserStatusGuard, MfaRequiredGuard, RolesGuard)
export class ProtectedController {
  // All routes in this controller pass through the guard chain
}
```

Or at the method level for granular control:

```typescript
@Controller('auth')
export class AuthController {
  @Post('login')
  @Public() // Skips JwtAuthGuard
  async login(@Body() dto: LoginDto) { ... }

  @Get('me')
  @UseGuards(JwtAuthGuard, UserStatusGuard)
  async me(@CurrentUser() user: DashboardJwtPayload) { ... }
}
```

### 3.9 Global Guards in This Package

This package does **not** register global guards via `APP_GUARD`. Global guard registration is the responsibility of the host application. The package only exports the guard classes.

```typescript
// WRONG: Library should NOT register global guards
// This would force every route in the host app through our guard
@Module({
  providers: [
    { provide: APP_GUARD, useClass: JwtAuthGuard },
  ],
})
export class BymaxAuthModule {}

// CORRECT: Export guards for the host to use or register globally
@Module({
  providers: [JwtAuthGuard, RolesGuard, UserStatusGuard],
  exports: [JwtAuthGuard, RolesGuard, UserStatusGuard],
})
export class BymaxAuthModule {}
```

The host application can then register them globally if desired:

```typescript
// In the HOST application (not in this package)
@Module({
  providers: [
    { provide: APP_GUARD, useClass: JwtAuthGuard },
    { provide: APP_GUARD, useClass: RolesGuard },
  ],
})
export class AppModule {}
```

### 3.10 Rules for Guards in This Project

| Rule | Description |
|------|-------------|
| **No Passport** | All guards implement `CanActivate` directly. Never import `@nestjs/passport`. |
| **No `APP_GUARD`** | The library never registers global guards. It exports them for the host to use. |
| **Reflector for metadata** | Use `Reflector.getAllAndOverride()` to read decorator metadata. |
| **Throw specific exceptions** | Guards throw `UnauthorizedException` (401) or `ForbiddenException` (403) — never generic errors. |
| **Attach payload to request** | After successful validation, assign `request['user'] = payload`. Use bracket notation for type safety. |
| **Token extraction order** | Cookie first, then `Authorization: Bearer` header. Cookie is preferred for security (HttpOnly). |

---

## 4. Decorators

### 4.1 Custom Parameter Decorators

Use `createParamDecorator` to extract data from the request in a clean, reusable way:

```typescript
// decorators/current-user.decorator.ts

import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface';

/**
 * Extracts the authenticated user payload from the request.
 * Must be used on routes protected by JwtAuthGuard.
 *
 * @example
 * @Get('me')
 * @UseGuards(JwtAuthGuard)
 * async getProfile(@CurrentUser() user: DashboardJwtPayload) {
 *   return user;
 * }
 *
 * @example
 * // Extract a specific property
 * @Get('me')
 * @UseGuards(JwtAuthGuard)
 * async getProfile(@CurrentUser('sub') userId: string) {
 *   return { userId };
 * }
 */
export const CurrentUser = createParamDecorator(
  (data: keyof DashboardJwtPayload | undefined, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    const user = request['user'] as DashboardJwtPayload;

    if (!user) {
      return undefined;
    }

    return data ? user[data] : user;
  },
);
```

### 4.2 Metadata Decorators with `SetMetadata`

Use `SetMetadata` to attach metadata to route handlers, then read it in guards with `Reflector`:

```typescript
// decorators/public.decorator.ts

import { SetMetadata } from '@nestjs/common';

export const IS_PUBLIC_KEY = Symbol('isPublic');

/**
 * Marks a route as public — bypasses JwtAuthGuard.
 *
 * @example
 * @Public()
 * @Post('login')
 * async login(@Body() dto: LoginDto) { ... }
 */
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
```

```typescript
// decorators/roles.decorator.ts

import { SetMetadata } from '@nestjs/common';

export const ROLES_KEY = Symbol('roles');

/**
 * Specifies which roles can access a route.
 * Used in conjunction with RolesGuard.
 *
 * @example
 * @Roles('admin', 'owner')
 * @Get('admin/users')
 * async listUsers() { ... }
 */
export const Roles = (...roles: string[]) => SetMetadata(ROLES_KEY, roles);
```

```typescript
// decorators/skip-mfa.decorator.ts

import { SetMetadata } from '@nestjs/common';

export const SKIP_MFA_KEY = Symbol('skipMfa');

/**
 * Skips MFA verification for a specific route.
 * Use on the MFA verification endpoint itself to avoid circular requirement.
 *
 * @example
 * @SkipMfa()
 * @Post('mfa/verify')
 * async verifyMfa(@Body() dto: MfaVerifyDto) { ... }
 */
export const SkipMfa = () => SetMetadata(SKIP_MFA_KEY, true);
```

```typescript
// decorators/platform-roles.decorator.ts

import { SetMetadata } from '@nestjs/common';

export const PLATFORM_ROLES_KEY = Symbol('platformRoles');

/**
 * Specifies required platform-level roles for admin routes.
 * Used with PlatformRolesGuard.
 */
export const PlatformRoles = (...roles: string[]) =>
  SetMetadata(PLATFORM_ROLES_KEY, roles);
```

### 4.3 Composing Decorators with `applyDecorators`

When multiple decorators are frequently used together, compose them:

```typescript
import { applyDecorators, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { RolesGuard } from '../guards/roles.guard';
import { Roles } from './roles.decorator';

/**
 * Composite decorator: requires authentication + specific roles.
 *
 * @example
 * @Auth('admin')
 * @Get('admin/dashboard')
 * async dashboard() { ... }
 */
export function Auth(...roles: string[]) {
  return applyDecorators(
    Roles(...roles),
    UseGuards(JwtAuthGuard, RolesGuard),
  );
}
```

### 4.4 Using Symbol Keys for Metadata

```typescript
// WRONG: String metadata keys can collide across packages
export const ROLES_KEY = 'roles';

// CORRECT: Symbol keys are collision-proof
export const ROLES_KEY = Symbol('roles');
```

This is critical for a library — the host application may have its own `'roles'` metadata key. Symbol keys prevent collisions.

### 4.5 Rules for Decorators in This Project

| Rule | Description |
|------|-------------|
| **Symbol metadata keys** | All `SetMetadata` keys use `Symbol()`, not strings. |
| **Export the key** | Always export the metadata key constant so guards can import it. |
| **JSDoc every decorator** | Each decorator must have JSDoc with at least one `@example`. |
| **Type the `data` parameter** | In `createParamDecorator`, type the `data` parameter to the expected shape (e.g., `keyof DashboardJwtPayload`). |
| **No side effects** | Decorators must not perform async operations, I/O, or throw errors. They only attach metadata. |

---

## 5. Services Architecture

### 5.1 Service Design Principles

Services in this package follow these principles:

1. **Single Responsibility** — Each service handles one domain (auth, password, tokens, MFA, etc.)
2. **Constructor Injection** — All dependencies are injected via the constructor
3. **Stateless** — Services do not hold request-scoped state; all state comes from method parameters
4. **Interface-Driven** — External dependencies are typed by interfaces, not implementations

### 5.2 Service Structure Template

```typescript
// services/example.service.ts

import { Injectable, Inject } from '@nestjs/common';
import { AUTH_MODULE_OPTIONS, USER_REPOSITORY } from '../bymax-one-nest-auth.constants';
import type { AuthModuleOptions } from '../interfaces/auth-module-options.interface';
import type { IUserRepository } from '../interfaces/user-repository.interface';

@Injectable()
export class ExampleService {
  constructor(
    @Inject(AUTH_MODULE_OPTIONS)
    private readonly options: AuthModuleOptions,

    @Inject(USER_REPOSITORY)
    private readonly userRepository: IUserRepository,
  ) {}

  /**
   * Public methods represent the service API.
   * They should validate inputs, orchestrate private methods,
   * and return typed results.
   */
  async doSomething(input: SomeDto): Promise<SomeResult> {
    this.validateInput(input);
    const data = await this.fetchData(input.id);
    return this.transformResult(data);
  }

  /**
   * Private methods handle internal logic.
   * They should be pure functions when possible.
   */
  private validateInput(input: SomeDto): void {
    // Validation logic
  }

  private async fetchData(id: string): Promise<RawData> {
    return this.userRepository.findById(id);
  }

  private transformResult(data: RawData): SomeResult {
    return { /* ... */ };
  }
}
```

### 5.3 Core Service Catalog

| Service | Responsibility | Always Active |
|---------|---------------|:---:|
| `AuthService` | Register, login, logout, refresh, profile | Yes |
| `PasswordService` | Hash and compare passwords (scrypt via `node:crypto`) | Yes |
| `TokenManagerService` | Issue and verify JWT tokens via `@nestjs/jwt` | Yes |
| `TokenDeliveryService` | Deliver tokens via cookies, body, or both | Yes |
| `BruteForceService` | Track failed login attempts, lockout by email | Yes |
| `AuthRedisService` | Redis operations: token blacklist, refresh sessions | Yes |
| `PasswordResetService` | Forgot/reset password flow | Yes |
| `MfaService` | TOTP setup, verify, recovery codes | Opt-in |
| `SessionService` | Active session tracking, FIFO eviction | Opt-in |
| `OtpService` | Email OTP codes for password reset / verification | Opt-in |
| `PlatformAuthService` | Platform admin authentication | Opt-in |
| `InvitationService` | User invitations via email | Opt-in |

### 5.4 Service-to-Service Communication

Services may depend on other services within this package. Keep the dependency graph acyclic:

```typescript
// AuthService depends on PasswordService and TokenManagerService — this is fine
@Injectable()
export class AuthService {
  constructor(
    private readonly passwordService: PasswordService,
    private readonly tokenManager: TokenManagerService,
    private readonly tokenDelivery: TokenDeliveryService,
    private readonly bruteForce: BruteForceService,
    @Inject(USER_REPOSITORY)
    private readonly userRepository: IUserRepository,
    @Inject(AUTH_HOOKS)
    private readonly hooks: IAuthHooks,
  ) {}
}
```

Dependency flow:

```
AuthService → PasswordService (no further deps)
AuthService → TokenManagerService → JwtService (@nestjs/jwt)
AuthService → BruteForceService → AuthRedisService
AuthService → TokenDeliveryService
MfaService → AuthRedisService
SessionService → AuthRedisService
```

### 5.5 Handling Circular Dependencies

Circular dependencies should be avoided by design. If two services depend on each other, extract the shared logic into a third service. As a last resort, use `forwardRef()`:

```typescript
// WRONG: Direct circular dependency
@Injectable()
export class ServiceA {
  constructor(private readonly serviceB: ServiceB) {} // ServiceB also depends on ServiceA
}

// CORRECT: Use forwardRef() if unavoidable
import { forwardRef, Inject } from '@nestjs/common';

@Injectable()
export class ServiceA {
  constructor(
    @Inject(forwardRef(() => ServiceB))
    private readonly serviceB: ServiceB,
  ) {}
}

// BEST: Extract shared logic into a third service
@Injectable()
export class SharedService { /* common logic */ }

@Injectable()
export class ServiceA {
  constructor(private readonly shared: SharedService) {}
}

@Injectable()
export class ServiceB {
  constructor(private readonly shared: SharedService) {}
}
```

### 5.6 Async Initialization

If a service needs async setup (e.g., verifying Redis connection), implement `OnModuleInit`:

```typescript
import { Injectable, OnModuleInit, Logger } from '@nestjs/common';

@Injectable()
export class AuthRedisService implements OnModuleInit {
  private readonly logger = new Logger(AuthRedisService.name);

  constructor(
    @Inject(AUTH_REDIS_CLIENT)
    private readonly redis: Redis,
  ) {}

  async onModuleInit(): Promise<void> {
    try {
      await this.redis.ping();
      this.logger.log('Redis connection verified');
    } catch (error) {
      this.logger.error('Redis connection failed', error);
      throw error; // Fail fast — do not start with broken Redis
    }
  }
}
```

### 5.7 Timing-Safe Operations

For authentication services, use constant-time comparisons and normalize execution time to prevent timing attacks:

```typescript
import { timingSafeEqual, randomBytes } from 'node:crypto';

/**
 * Constant-time string comparison to prevent timing attacks.
 */
function safeCompare(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');

  if (bufA.length !== bufB.length) {
    // Compare against random bytes to maintain constant time
    timingSafeEqual(bufA, randomBytes(bufA.length));
    return false;
  }

  return timingSafeEqual(bufA, bufB);
}

/**
 * Sleep utility for timing normalization.
 * Ensures login attempts take a consistent amount of time
 * regardless of whether the user exists.
 */
async function normalizeLoginTime(
  startTime: bigint,
  targetMs: number,
): Promise<void> {
  const elapsed = Number(process.hrtime.bigint() - startTime) / 1_000_000;
  const remaining = targetMs - elapsed;
  if (remaining > 0) {
    await new Promise((resolve) => setTimeout(resolve, remaining));
  }
}
```

### 5.8 Rules for Services in This Project

| Rule | Description |
|------|-------------|
| **Singleton scope only** | All services use default scope. No `Scope.REQUEST`. |
| **No direct DB access** | Services interact with the database exclusively through injected repository interfaces. |
| **No `node:fs` or `node:net`** | Services must not perform file I/O or raw network calls. |
| **All crypto via `node:crypto`** | Hashing, TOTP, encryption — all use native Node.js crypto. Zero external crypto dependencies. |
| **Timing-safe comparisons** | All token/password comparisons use `timingSafeEqual`. |
| **Structured logging** | Use `Logger` from `@nestjs/common`. Never use `console.log`. |
| **Type method signatures** | Every public method must have explicit return types. |

---

## 6. Controllers

### 6.1 Controller Design in a Library

Controllers in this package are **optional** and **conditionally registered**. The host application decides which controllers to enable via configuration. Controllers should be thin — they validate input, call the appropriate service, and return a response.

### 6.2 Controller Structure Template

```typescript
// controllers/auth.controller.ts

import {
  Controller,
  Post,
  Get,
  Body,
  Res,
  HttpCode,
  HttpStatus,
  UseGuards,
} from '@nestjs/common';
import type { Response } from 'express';
import { AuthService } from '../services/auth.service';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { Public } from '../decorators/public.decorator';
import { CurrentUser } from '../decorators/current-user.decorator';
import { RegisterDto } from '../dto/register.dto';
import { LoginDto } from '../dto/login.dto';
import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() dto: RegisterDto, @Res({ passthrough: true }) res: Response) {
    return this.authService.register(dto, res);
  }

  @Public()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(@Body() dto: LoginDto, @Res({ passthrough: true }) res: Response) {
    return this.authService.login(dto, res);
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  async logout(
    @CurrentUser() user: DashboardJwtPayload,
    @Res({ passthrough: true }) res: Response,
  ) {
    return this.authService.logout(user, res);
  }

  @UseGuards(JwtAuthGuard)
  @Get('me')
  async me(@CurrentUser() user: DashboardJwtPayload) {
    return this.authService.getProfile(user.sub);
  }
}
```

### 6.3 Response Patterns

Use `@Res({ passthrough: true })` when you need to set cookies but still want NestJS to handle serialization:

```typescript
// WRONG: Using @Res() alone disables NestJS response handling
@Post('login')
async login(@Body() dto: LoginDto, @Res() res: Response) {
  const result = await this.authService.login(dto, res);
  res.json(result); // You must manually send the response
}

// CORRECT: Using passthrough mode
@Post('login')
async login(@Body() dto: LoginDto, @Res({ passthrough: true }) res: Response) {
  return this.authService.login(dto, res);
  // NestJS handles serialization; service can still call res.cookie()
}
```

### 6.4 DTO Validation with Pipes

Use `class-validator` and `class-transformer` for input validation. The host application must register the `ValidationPipe` globally:

```typescript
// dto/register.dto.ts

import { IsEmail, IsString, MinLength, MaxLength, Matches } from 'class-validator';

export class RegisterDto {
  @IsEmail({}, { message: 'Invalid email format' })
  email!: string;

  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters' })
  @MaxLength(128, { message: 'Password must not exceed 128 characters' })
  @Matches(/[A-Z]/, { message: 'Password must contain at least one uppercase letter' })
  @Matches(/[a-z]/, { message: 'Password must contain at least one lowercase letter' })
  @Matches(/\d/, { message: 'Password must contain at least one number' })
  password!: string;

  @IsString()
  @MinLength(1)
  @MaxLength(100)
  name!: string;
}
```

```typescript
// dto/login.dto.ts

import { IsEmail, IsString, MinLength } from 'class-validator';

export class LoginDto {
  @IsEmail({}, { message: 'Invalid email format' })
  email!: string;

  @IsString()
  @MinLength(1, { message: 'Password is required' })
  password!: string;
}
```

> **Important:** This package does NOT register `ValidationPipe` globally. That is the host application's responsibility. Document this requirement for consumers.

### 6.5 HTTP Status Codes

Use explicit status codes for every route:

```typescript
@Post('register')
@HttpCode(HttpStatus.CREATED) // 201

@Post('login')
@HttpCode(HttpStatus.OK) // 200 (not 201 — login does not create a resource)

@Post('logout')
@HttpCode(HttpStatus.OK) // 200

@Delete('sessions/:id')
@HttpCode(HttpStatus.NO_CONTENT) // 204
```

### 6.6 Conditional Controller Registration

Since this package is a library, controllers should be registerable selectively. The pattern:

```typescript
static registerAsync(options: AuthModuleAsyncOptions): DynamicModule {
  // All controllers are registered. Each controller internally checks
  // whether its feature is enabled. Alternatively, use a wrapper module:
  const controllers: Type[] = [];

  // The consumer tells us which controllers to activate via options.
  // However, since options are async, we use a different strategy:
  // Register all controllers, and have a feature-gate guard.
  return {
    module: BymaxAuthModule,
    controllers: [
      AuthController,       // Always available
      // Optional controllers added based on a sync flag
      // or all registered with runtime gating
    ],
    // ...
  };
}
```

### 6.7 Route Prefix Configuration

The package does not hardcode route prefixes. The host application can wrap the module in a `RouterModule` or use a global prefix:

```typescript
// Host application can namespace all auth routes
import { RouterModule } from '@nestjs/core';

@Module({
  imports: [
    BymaxAuthModule.registerAsync({ /* ... */ }),
    RouterModule.register([
      { path: 'api/v1', module: BymaxAuthModule },
    ]),
  ],
})
export class AppModule {}
```

### 6.8 Rules for Controllers in This Project

| Rule | Description |
|------|-------------|
| **Thin controllers** | Controllers only validate, call services, and return. No business logic in controllers. |
| **Explicit `@HttpCode()`** | Every route handler must have an explicit HTTP status code. |
| **`passthrough: true`** | Always use `@Res({ passthrough: true })` when injecting the response object. |
| **No global `ValidationPipe`** | The package does not register global pipes. Document this for consumers. |
| **No hardcoded route prefixes** | Do not use `@Controller('api/v1/auth')`. Use `@Controller('auth')` and let the host configure prefixes. |
| **Type all return values** | Every handler method must have an explicit return type annotation. |

---

## 7. Error Handling

### 7.1 Custom Exception Class

The package defines a custom exception for auth-specific errors. This extends `HttpException` to maintain compatibility with NestJS exception filters:

```typescript
// errors/auth-exception.ts

import { HttpException, HttpStatus } from '@nestjs/common';

export interface AuthErrorPayload {
  /** Machine-readable error code (e.g., 'AUTH_INVALID_CREDENTIALS') */
  code: string;
  /** Human-readable error message */
  message: string;
  /** HTTP status code */
  statusCode: number;
}

export class AuthException extends HttpException {
  public readonly code: string;

  constructor(code: string, message: string, status: HttpStatus) {
    const payload: AuthErrorPayload = {
      code,
      message,
      statusCode: status,
    };
    super(payload, status);
    this.code = code;
  }
}
```

### 7.2 Error Codes Catalog

Define all error codes as constants to ensure consistency:

```typescript
// errors/auth-error-codes.ts

export const AUTH_ERROR_CODES = {
  // Authentication
  INVALID_CREDENTIALS: 'AUTH_INVALID_CREDENTIALS',
  ACCOUNT_LOCKED: 'AUTH_ACCOUNT_LOCKED',
  ACCOUNT_SUSPENDED: 'AUTH_ACCOUNT_SUSPENDED',
  EMAIL_NOT_VERIFIED: 'AUTH_EMAIL_NOT_VERIFIED',
  TOKEN_EXPIRED: 'AUTH_TOKEN_EXPIRED',
  TOKEN_INVALID: 'AUTH_TOKEN_INVALID',
  REFRESH_TOKEN_REVOKED: 'AUTH_REFRESH_TOKEN_REVOKED',

  // Registration
  EMAIL_ALREADY_EXISTS: 'AUTH_EMAIL_ALREADY_EXISTS',
  REGISTRATION_DISABLED: 'AUTH_REGISTRATION_DISABLED',

  // MFA
  MFA_REQUIRED: 'AUTH_MFA_REQUIRED',
  MFA_INVALID_CODE: 'AUTH_MFA_INVALID_CODE',
  MFA_ALREADY_ENABLED: 'AUTH_MFA_ALREADY_ENABLED',
  MFA_NOT_ENABLED: 'AUTH_MFA_NOT_ENABLED',

  // Password Reset
  RESET_TOKEN_INVALID: 'AUTH_RESET_TOKEN_INVALID',
  RESET_TOKEN_EXPIRED: 'AUTH_RESET_TOKEN_EXPIRED',
  PASSWORD_TOO_WEAK: 'AUTH_PASSWORD_TOO_WEAK',

  // Sessions
  SESSION_NOT_FOUND: 'AUTH_SESSION_NOT_FOUND',
  MAX_SESSIONS_REACHED: 'AUTH_MAX_SESSIONS_REACHED',

  // Authorization
  INSUFFICIENT_PERMISSIONS: 'AUTH_INSUFFICIENT_PERMISSIONS',
  FORBIDDEN: 'AUTH_FORBIDDEN',

  // Rate Limiting
  TOO_MANY_ATTEMPTS: 'AUTH_TOO_MANY_ATTEMPTS',

  // Platform
  PLATFORM_ACCESS_DENIED: 'AUTH_PLATFORM_ACCESS_DENIED',

  // Invitations
  INVITATION_EXPIRED: 'AUTH_INVITATION_EXPIRED',
  INVITATION_ALREADY_ACCEPTED: 'AUTH_INVITATION_ALREADY_ACCEPTED',
} as const;

export type AuthErrorCode = (typeof AUTH_ERROR_CODES)[keyof typeof AUTH_ERROR_CODES];
```

### 7.3 Using AuthException in Services

```typescript
import { HttpStatus } from '@nestjs/common';
import { AuthException } from '../errors/auth-exception';
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes';

@Injectable()
export class AuthService {
  async login(dto: LoginDto, res: Response): Promise<AuthResult> {
    const user = await this.userRepository.findByEmail(dto.email);

    if (!user) {
      // Use constant-time flow — do not reveal if the email exists
      await this.passwordService.fakeCompare();
      throw new AuthException(
        AUTH_ERROR_CODES.INVALID_CREDENTIALS,
        'Invalid email or password',
        HttpStatus.UNAUTHORIZED,
      );
    }

    const isLocked = await this.bruteForce.isLocked(dto.email);
    if (isLocked) {
      throw new AuthException(
        AUTH_ERROR_CODES.ACCOUNT_LOCKED,
        'Account temporarily locked due to too many failed attempts',
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    const passwordValid = await this.passwordService.compare(
      dto.password,
      user.passwordHash,
    );

    if (!passwordValid) {
      await this.bruteForce.recordFailure(dto.email);
      throw new AuthException(
        AUTH_ERROR_CODES.INVALID_CREDENTIALS,
        'Invalid email or password',
        HttpStatus.UNAUTHORIZED,
      );
    }

    // ... continue with token generation
  }
}
```

### 7.4 Exception Filter (Optional Export)

The package optionally exports an exception filter that formats `AuthException` responses consistently:

```typescript
// filters/auth-exception.filter.ts

import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
} from '@nestjs/common';
import { AuthException } from '../errors/auth-exception';
import type { Response } from 'express';

@Catch(AuthException)
export class AuthExceptionFilter implements ExceptionFilter {
  catch(exception: AuthException, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const status = exception.getStatus();

    response.status(status).json({
      success: false,
      error: {
        code: exception.code,
        message: exception.message,
        statusCode: status,
      },
      timestamp: new Date().toISOString(),
    });
  }
}
```

### 7.5 Standard Error Response Format

All error responses from this package follow a consistent shape:

```json
{
  "success": false,
  "error": {
    "code": "AUTH_INVALID_CREDENTIALS",
    "message": "Invalid email or password",
    "statusCode": 401
  },
  "timestamp": "2026-04-13T12:00:00.000Z"
}
```

### 7.6 Never Leak Implementation Details

```typescript
// WRONG: Leaking internal details to the client
throw new AuthException(
  AUTH_ERROR_CODES.INVALID_CREDENTIALS,
  `User with email ${dto.email} not found in PostgreSQL users table`,
  HttpStatus.UNAUTHORIZED,
);

// CORRECT: Generic, safe error message
throw new AuthException(
  AUTH_ERROR_CODES.INVALID_CREDENTIALS,
  'Invalid email or password',
  HttpStatus.UNAUTHORIZED,
);
```

### 7.7 Rules for Error Handling in This Project

| Rule | Description |
|------|-------------|
| **Use `AuthException`** | All auth-related errors throw `AuthException`, not generic `HttpException`. |
| **Use error code constants** | Always reference `AUTH_ERROR_CODES.*`, never hardcode error code strings. |
| **No stack traces to client** | Never include stack traces or internal details in error responses. |
| **Consistent response shape** | All errors follow the `{ success, error: { code, message, statusCode }, timestamp }` format. |
| **No generic `Error`** | Never `throw new Error('...')`. Always throw NestJS exceptions or `AuthException`. |
| **Log internally, respond generically** | Use `Logger.error()` for internal details, send generic messages to clients. |

---

## 8. Module Organization

### 8.1 Package Entry Points

This package uses subpath exports in `package.json`:

```
@bymax-one/nest-auth          → src/server/index.ts     (NestJS backend)
@bymax-one/nest-auth/shared   → src/shared/index.ts     (types and constants, zero deps)
@bymax-one/nest-auth/client   → src/client/index.ts     (fetch-based client)
@bymax-one/nest-auth/react    → src/react/index.ts      (React hooks)
@bymax-one/nest-auth/nextjs   → src/nextjs/index.ts     (Next.js integration)
```

### 8.2 Barrel Export Rules

Each entry point has a barrel `index.ts` that controls the public API surface:

```typescript
// src/server/index.ts — Server barrel export

// Module
export { BymaxAuthModule } from './bymax-one-nest-auth.module';

// Services (export class, not type)
export { AuthService } from './services/auth.service';
export { TokenManagerService } from './services/token-manager.service';
export { PasswordService } from './services/password.service';
export { MfaService } from './services/mfa.service';
export { SessionService } from './services/session.service';

// Guards
export { JwtAuthGuard } from './guards/jwt-auth.guard';
export { RolesGuard } from './guards/roles.guard';
export { UserStatusGuard } from './guards/user-status.guard';
export { MfaRequiredGuard } from './guards/mfa-required.guard';
export { OptionalAuthGuard } from './guards/optional-auth.guard';
export { WsJwtGuard } from './guards/ws-jwt.guard';

// Decorators
export { CurrentUser } from './decorators/current-user.decorator';
export { Public } from './decorators/public.decorator';
export { Roles } from './decorators/roles.decorator';
export { SkipMfa } from './decorators/skip-mfa.decorator';
export { PlatformRoles } from './decorators/platform-roles.decorator';

// Constants (injection tokens)
export {
  AUTH_MODULE_OPTIONS,
  USER_REPOSITORY,
  EMAIL_PROVIDER,
  AUTH_REDIS_CLIENT,
  AUTH_HOOKS,
} from './bymax-one-nest-auth.constants';

// Interfaces (export type, not class)
export type { AuthModuleOptions, AuthModuleAsyncOptions } from './interfaces/auth-module-options.interface';
export type { IUserRepository } from './interfaces/user-repository.interface';
export type { IEmailProvider } from './interfaces/email-provider.interface';
export type { IAuthHooks } from './interfaces/auth-hooks.interface';
export type { DashboardJwtPayload, PlatformJwtPayload } from './interfaces/jwt-payload.interface';
export type { AuthResult } from './interfaces/auth-result.interface';
export type { AuthenticatedRequest } from './interfaces/authenticated-request.interface';

// Error handling
export { AuthException } from './errors/auth-exception';
export { AUTH_ERROR_CODES } from './errors/auth-error-codes';
export type { AuthErrorCode, AuthErrorPayload } from './errors/auth-error-codes';
export { AuthExceptionFilter } from './filters/auth-exception.filter';
```

### 8.3 Distinguishing `export` vs `export type`

```typescript
// WRONG: Exporting an interface as a value — may cause issues with bundlers
export { IUserRepository } from './interfaces/user-repository.interface';

// CORRECT: Use 'export type' for types and interfaces
export type { IUserRepository } from './interfaces/user-repository.interface';

// CORRECT: Use 'export' (no 'type') for classes, functions, constants, decorators
export { AuthService } from './services/auth.service';
export { AUTH_MODULE_OPTIONS } from './bymax-one-nest-auth.constants';
export { Public } from './decorators/public.decorator';
```

TypeScript's `isolatedModules` and bundlers like `tsup` require this distinction. Use `export type` for:
- Interfaces
- Type aliases
- Any export that does not exist at runtime

Use `export` (without `type`) for:
- Classes (services, guards, filters, modules)
- Functions (decorators, utilities)
- Constants (injection tokens, error codes)
- Enums

### 8.4 Provider Registration in the Module

Register providers in the correct order and group them by purpose:

```typescript
@Module({})
export class BymaxAuthModule {
  static registerAsync(options: AuthModuleAsyncOptions): DynamicModule {
    return {
      module: BymaxAuthModule,
      imports: [...(options.imports ?? [])],
      providers: [
        // 1. Configuration providers
        ...this.createAsyncProviders(options),

        // 2. Core infrastructure services (always active)
        AuthRedisService,
        PasswordService,
        TokenManagerService,
        TokenDeliveryService,
        BruteForceService,

        // 3. Core business services (always active)
        AuthService,
        PasswordResetService,

        // 4. Guards (always registered, metadata controls behavior)
        JwtAuthGuard,
        RolesGuard,
        UserStatusGuard,
        MfaRequiredGuard,

        // 5. Conditional services (opt-in features)
        ...this.createConditionalProviders(),
      ],
      exports: [
        // Export tokens and services that consumers need
        AUTH_MODULE_OPTIONS,
        AuthService,
        TokenManagerService,
        JwtAuthGuard,
        RolesGuard,
      ],
    };
  }
}
```

### 8.5 Conditional Providers

```typescript
private static createConditionalProviders(): Provider[] {
  // Note: since options are resolved asynchronously, conditional
  // providers must use factory patterns that read the resolved options.
  return [
    {
      provide: MfaService,
      useFactory: (options: AuthModuleOptions) => {
        if (!options.mfa) return null;
        // MfaService dependencies would also be injected here
        return new MfaService(options.mfa);
      },
      inject: [AUTH_MODULE_OPTIONS],
    },
    {
      provide: SessionService,
      useFactory: (options: AuthModuleOptions, redis: AuthRedisService) => {
        if (!options.sessions?.enabled) return null;
        return new SessionService(options.sessions, redis);
      },
      inject: [AUTH_MODULE_OPTIONS, AuthRedisService],
    },
  ];
}
```

### 8.6 Module Composition

If the package grows, split into sub-modules:

```typescript
// oauth/oauth.module.ts
@Module({})
export class OAuthModule {
  static register(oauthConfig: OAuthConfig): DynamicModule {
    const providers: Provider[] = [OAuthService];

    if (oauthConfig.google) {
      providers.push({
        provide: 'GOOGLE_OAUTH_PLUGIN',
        useFactory: () => new GoogleOAuthPlugin(oauthConfig.google!),
      });
    }

    return {
      module: OAuthModule,
      providers,
      exports: [OAuthService],
    };
  }
}
```

Then import the sub-module from the main module:

```typescript
static registerAsync(options: AuthModuleAsyncOptions): DynamicModule {
  return {
    module: BymaxAuthModule,
    imports: [
      ...(options.imports ?? []),
      // Sub-modules imported conditionally
      // (requires resolving options first via a factory module)
    ],
    // ...
  };
}
```

### 8.7 Rules for Module Organization in This Project

| Rule | Description |
|------|-------------|
| **`export type` for interfaces** | Always use `export type` in barrel files for types, interfaces, and type aliases. |
| **Single barrel per entry point** | Each subpath has exactly one `index.ts` barrel file. |
| **No deep imports** | Consumers must only import from barrel files (`@bymax-one/nest-auth`, `@bymax-one/nest-auth/shared`, etc.). Never expose internal paths. |
| **Group providers by purpose** | In the module definition, group providers as: config, infrastructure, business, guards, conditional. |
| **No circular module imports** | Sub-modules must not import the root module. |
| **Explicit exports** | Only export what consumers need. Internal services stay internal. |

---

## 9. Testing Patterns

### 9.1 Unit Testing with `Test.createTestingModule`

Every service, guard, and controller must have unit tests. Use the NestJS testing utilities:

```typescript
// services/auth.service.spec.ts

import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { PasswordService } from './password.service';
import { TokenManagerService } from './token-manager.service';
import { BruteForceService } from './brute-force.service';
import { TokenDeliveryService } from './token-delivery.service';
import {
  AUTH_MODULE_OPTIONS,
  USER_REPOSITORY,
  AUTH_HOOKS,
} from '../bymax-one-nest-auth.constants';

describe('AuthService', () => {
  let service: AuthService;
  let userRepository: jest.Mocked<IUserRepository>;
  let passwordService: jest.Mocked<PasswordService>;
  let tokenManager: jest.Mocked<TokenManagerService>;

  const mockOptions: AuthModuleOptions = {
    jwt: {
      accessSecret: 'test-access-secret',
      refreshSecret: 'test-refresh-secret',
      accessExpiresIn: '15m',
      refreshExpiresIn: '7d',
    },
    tokenDelivery: 'body',
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: AUTH_MODULE_OPTIONS,
          useValue: mockOptions,
        },
        {
          provide: USER_REPOSITORY,
          useValue: {
            findByEmail: jest.fn(),
            findById: jest.fn(),
            create: jest.fn(),
            update: jest.fn(),
          },
        },
        {
          provide: AUTH_HOOKS,
          useValue: {
            afterRegister: jest.fn(),
            afterLogin: jest.fn(),
            afterLogout: jest.fn(),
          },
        },
        {
          provide: PasswordService,
          useValue: {
            hash: jest.fn(),
            compare: jest.fn(),
            fakeCompare: jest.fn(),
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
          provide: BruteForceService,
          useValue: {
            isLocked: jest.fn().mockResolvedValue(false),
            recordFailure: jest.fn(),
            clearFailures: jest.fn(),
          },
        },
        {
          provide: TokenDeliveryService,
          useValue: {
            deliver: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    userRepository = module.get(USER_REPOSITORY);
    passwordService = module.get(PasswordService);
    tokenManager = module.get(TokenManagerService);
  });

  describe('login', () => {
    it('should return tokens for valid credentials', async () => {
      const mockUser = {
        id: 'user-1',
        email: 'test@example.com',
        passwordHash: 'hashed-password',
        role: 'member',
        status: 'active',
      };

      userRepository.findByEmail.mockResolvedValue(mockUser);
      passwordService.compare.mockResolvedValue(true);
      tokenManager.generateAccessToken.mockResolvedValue('access-token');
      tokenManager.generateRefreshToken.mockResolvedValue('refresh-token');

      const result = await service.login(
        { email: 'test@example.com', password: 'Password1' },
        {} as Response,
      );

      expect(result.accessToken).toBe('access-token');
      expect(userRepository.findByEmail).toHaveBeenCalledWith('test@example.com');
      expect(passwordService.compare).toHaveBeenCalledWith('Password1', 'hashed-password');
    });

    it('should throw AuthException for invalid credentials', async () => {
      userRepository.findByEmail.mockResolvedValue(null);

      await expect(
        service.login(
          { email: 'wrong@example.com', password: 'Password1' },
          {} as Response,
        ),
      ).rejects.toThrow(AuthException);
    });

    it('should throw AuthException when account is locked', async () => {
      const bruteForce = module.get(BruteForceService);
      bruteForce.isLocked.mockResolvedValue(true);

      await expect(
        service.login(
          { email: 'test@example.com', password: 'Password1' },
          {} as Response,
        ),
      ).rejects.toThrow(AuthException);
    });
  });
});
```

### 9.2 Testing Guards

```typescript
// guards/jwt-auth.guard.spec.ts

import { Test, TestingModule } from '@nestjs/testing';
import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { JwtAuthGuard } from './jwt-auth.guard';
import { AUTH_MODULE_OPTIONS } from '../bymax-one-nest-auth.constants';

describe('JwtAuthGuard', () => {
  let guard: JwtAuthGuard;
  let jwtService: jest.Mocked<JwtService>;
  let reflector: Reflector;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        JwtAuthGuard,
        {
          provide: JwtService,
          useValue: {
            verifyAsync: jest.fn(),
          },
        },
        {
          provide: AUTH_MODULE_OPTIONS,
          useValue: {
            jwt: { accessSecret: 'test-secret' },
          },
        },
        Reflector,
      ],
    }).compile();

    guard = module.get<JwtAuthGuard>(JwtAuthGuard);
    jwtService = module.get(JwtService);
    reflector = module.get(Reflector);
  });

  it('should allow access for public routes', async () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(true);

    const context = createMockExecutionContext();
    const result = await guard.canActivate(context);

    expect(result).toBe(true);
  });

  it('should throw UnauthorizedException when no token is present', async () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);

    const context = createMockExecutionContext({ cookies: {}, headers: {} });

    await expect(guard.canActivate(context)).rejects.toThrow(
      UnauthorizedException,
    );
  });

  it('should attach user payload to request on valid token', async () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);
    const mockPayload = { sub: 'user-1', role: 'member' };
    jwtService.verifyAsync.mockResolvedValue(mockPayload);

    const request = {
      cookies: { access_token: 'valid-token' },
      headers: {},
    };
    const context = createMockExecutionContext(request);

    await guard.canActivate(context);

    expect(request['user']).toEqual(mockPayload);
  });
});

/**
 * Helper to create a mock ExecutionContext.
 */
function createMockExecutionContext(request?: Partial<Request>): ExecutionContext {
  return {
    switchToHttp: () => ({
      getRequest: () => request ?? { cookies: {}, headers: {} },
      getResponse: () => ({}),
    }),
    getHandler: () => jest.fn(),
    getClass: () => jest.fn(),
  } as unknown as ExecutionContext;
}
```

### 9.3 Mocking Patterns

#### Mock Symbol-Token Providers

```typescript
// Always use the actual Symbol token when mocking
{
  provide: USER_REPOSITORY,   // The Symbol from constants
  useValue: {
    findByEmail: jest.fn(),
    findById: jest.fn(),
    create: jest.fn(),
  },
}
```

#### Override Providers in an Existing Module

```typescript
const module = await Test.createTestingModule({
  imports: [BymaxAuthModule.registerAsync({ /* ... */ })],
})
  .overrideProvider(USER_REPOSITORY)
  .useValue(mockUserRepository)
  .overrideProvider(AUTH_REDIS_CLIENT)
  .useValue(mockRedisClient)
  .compile();
```

#### Mock `Reflector`

```typescript
const reflector = module.get(Reflector);
jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(['admin']);
```

### 9.4 Integration (e2e) Testing

Use `@nestjs/testing` with a real NestJS application to test the full request lifecycle:

```typescript
// test/auth.e2e-spec.ts

import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { BymaxAuthModule } from '../src/server';

describe('AuthController (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [
        BymaxAuthModule.registerAsync({
          useFactory: () => ({
            jwt: {
              accessSecret: 'e2e-access-secret',
              refreshSecret: 'e2e-refresh-secret',
              accessExpiresIn: '15m',
              refreshExpiresIn: '7d',
            },
            tokenDelivery: 'body',
          }),
        }),
      ],
    })
      .overrideProvider(USER_REPOSITORY)
      .useValue(createInMemoryUserRepository())
      .overrideProvider(EMAIL_PROVIDER)
      .useValue(createNoOpEmailProvider())
      .overrideProvider(AUTH_REDIS_CLIENT)
      .useValue(createMockRedisClient())
      .compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ whitelist: true }));
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('POST /auth/register', () => {
    it('should register a new user', () => {
      return request(app.getHttpServer())
        .post('/auth/register')
        .send({
          email: 'test@example.com',
          password: 'SecurePass1',
          name: 'Test User',
        })
        .expect(201)
        .expect((res) => {
          expect(res.body).toHaveProperty('accessToken');
          expect(res.body).toHaveProperty('refreshToken');
        });
    });

    it('should reject invalid email', () => {
      return request(app.getHttpServer())
        .post('/auth/register')
        .send({
          email: 'not-an-email',
          password: 'SecurePass1',
          name: 'Test User',
        })
        .expect(400);
    });
  });
});
```

### 9.5 Test Utilities

Create reusable test helpers:

```typescript
// test/helpers/mock-execution-context.ts

import { ExecutionContext } from '@nestjs/common';

export function createMockExecutionContext(
  overrides: {
    request?: Partial<Request>;
    handler?: () => void;
    classRef?: () => void;
  } = {},
): ExecutionContext {
  return {
    switchToHttp: () => ({
      getRequest: () => overrides.request ?? { cookies: {}, headers: {} },
      getResponse: () => ({}),
      getNext: () => jest.fn(),
    }),
    switchToWs: () => ({
      getClient: () => ({ handshake: { auth: {}, headers: {} }, data: {} }),
      getData: () => ({}),
    }),
    getHandler: () => overrides.handler ?? jest.fn(),
    getClass: () => overrides.classRef ?? jest.fn(),
    getType: () => 'http',
    getArgs: () => [],
    getArgByIndex: () => undefined,
    switchToRpc: () => ({}),
  } as unknown as ExecutionContext;
}
```

### 9.6 Coverage Requirements

| Metric | Minimum |
|--------|---------|
| Line coverage | 80% |
| Branch coverage | 75% |
| Function coverage | 80% |
| Statement coverage | 80% |

Configure in `jest.config.ts`:

```typescript
export default {
  // ...
  coverageThreshold: {
    global: {
      branches: 75,
      functions: 80,
      lines: 80,
      statements: 80,
    },
  },
};
```

### 9.7 Rules for Testing in This Project

| Rule | Description |
|------|-------------|
| **Test file collocation** | Test files live next to source files as `*.spec.ts`. |
| **Use `Test.createTestingModule`** | Always use NestJS testing utilities, not manual instantiation. |
| **Mock via injection tokens** | Mock dependencies using their Symbol tokens, not by class reference. |
| **No real Redis in unit tests** | Always mock `AUTH_REDIS_CLIENT`. Use testcontainers for integration tests if needed. |
| **No real JWT secrets** | Use deterministic test secrets like `'test-access-secret'`. |
| **Test error paths** | Every service test must cover the error/exception paths, not just happy paths. |
| **80% coverage minimum** | The CI pipeline must enforce the coverage threshold. |

---

## 10. Anti-Patterns

This section documents common mistakes and their corrections. Every pattern below is a real risk in this project.

### 10.1 Importing Concrete Implementations

```typescript
// WRONG: Library depends on a specific ORM — breaks the abstraction
import { PrismaService } from '@prisma/client';

@Injectable()
export class AuthService {
  constructor(private readonly prisma: PrismaService) {
    // This couples the library to Prisma
  }
}

// CORRECT: Depend on an interface via injection token
@Injectable()
export class AuthService {
  constructor(
    @Inject(USER_REPOSITORY)
    private readonly userRepository: IUserRepository,
  ) {}
}
```

### 10.2 Registering Global Guards in a Library

```typescript
// WRONG: Forces global guard on the host application
@Module({
  providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }],
})
export class BymaxAuthModule {}

// CORRECT: Export the guard; let the host decide
@Module({
  providers: [JwtAuthGuard],
  exports: [JwtAuthGuard],
})
export class BymaxAuthModule {}
```

### 10.3 Using String Injection Tokens

```typescript
// WRONG: String tokens collide across packages
export const USER_REPO = 'USER_REPO';

// CORRECT: Symbol tokens are unique
export const USER_REPO = Symbol('USER_REPO');
```

### 10.4 Using `console.log` Instead of `Logger`

```typescript
// WRONG: No structured logging, no log level control
console.log('User logged in:', user.email);

// CORRECT: NestJS Logger with context
import { Logger } from '@nestjs/common';

private readonly logger = new Logger(AuthService.name);

this.logger.log(`User logged in: ${user.id}`);
this.logger.warn(`Failed login attempt for: ${dto.email}`);
this.logger.error(`Token verification failed`, error.stack);
```

### 10.5 Leaking Sensitive Data in Logs

```typescript
// WRONG: Logging passwords, tokens, or secrets
this.logger.debug(`Login attempt with password: ${dto.password}`);
this.logger.log(`Generated token: ${accessToken}`);

// CORRECT: Log only identifiers and actions
this.logger.log(`Login successful for user: ${user.id}`);
this.logger.warn(`Failed login attempt for email: ${dto.email}`);
```

### 10.6 Using `any` Type

```typescript
// WRONG: Bypasses TypeScript safety
async login(dto: any): Promise<any> {
  const user = await this.userRepository.findByEmail(dto.email) as any;
  return { token: user.token };
}

// CORRECT: Explicit types everywhere
async login(dto: LoginDto): Promise<AuthResult> {
  const user = await this.userRepository.findByEmail(dto.email);
  if (!user) {
    throw new AuthException(
      AUTH_ERROR_CODES.INVALID_CREDENTIALS,
      'Invalid email or password',
      HttpStatus.UNAUTHORIZED,
    );
  }
  // ...
}
```

### 10.7 Synchronous `register()` for a Library Module

```typescript
// WRONG: Secrets cannot be hardcoded — config always comes from env
static register(options: AuthModuleOptions): DynamicModule {
  return {
    module: BymaxAuthModule,
    providers: [{ provide: AUTH_MODULE_OPTIONS, useValue: options }],
  };
}

// CORRECT: Async factory for runtime configuration
static registerAsync(options: AuthModuleAsyncOptions): DynamicModule {
  return {
    module: BymaxAuthModule,
    providers: [{
      provide: AUTH_MODULE_OPTIONS,
      useFactory: options.useFactory,
      inject: options.inject ?? [],
    }],
  };
}
```

### 10.8 Mutating Injected Options

```typescript
// WRONG: Mutating the shared options object
@Injectable()
export class AuthService {
  constructor(
    @Inject(AUTH_MODULE_OPTIONS)
    private readonly options: AuthModuleOptions,
  ) {
    // This mutates the singleton options for all consumers
    this.options.jwt.accessExpiresIn = '30m';
  }
}

// CORRECT: Treat options as readonly
@Injectable()
export class AuthService {
  private readonly accessExpiresIn: string;

  constructor(
    @Inject(AUTH_MODULE_OPTIONS)
    private readonly options: Readonly<AuthModuleOptions>,
  ) {
    this.accessExpiresIn = options.jwt.accessExpiresIn;
  }
}
```

### 10.9 Non-Constant-Time Password Comparison

```typescript
// WRONG: Simple equality is vulnerable to timing attacks
if (hash === providedHash) {
  return true;
}

// CORRECT: Use timingSafeEqual from node:crypto
import { timingSafeEqual } from 'node:crypto';

const a = Buffer.from(hash, 'hex');
const b = Buffer.from(providedHash, 'hex');
if (a.length !== b.length) {
  return false;
}
return timingSafeEqual(a, b);
```

### 10.10 Using `@Res()` Without Passthrough

```typescript
// WRONG: Disables NestJS response handling — interceptors and serialization break
@Post('login')
async login(@Body() dto: LoginDto, @Res() res: Response) {
  const result = await this.authService.login(dto, res);
  return res.json(result); // Must manually send response
}

// CORRECT: Use passthrough to let NestJS handle serialization
@Post('login')
async login(@Body() dto: LoginDto, @Res({ passthrough: true }) res: Response) {
  return this.authService.login(dto, res); // NestJS serializes the return value
}
```

### 10.11 Request-Scoped Providers in a Library

```typescript
// WRONG: Request scope propagates to the entire dependency tree
@Injectable({ scope: Scope.REQUEST })
export class AuthService {
  constructor(
    @Inject(REQUEST) private readonly request: Request,
  ) {}
}

// CORRECT: Pass request data as method arguments
@Injectable()
export class AuthService {
  async login(dto: LoginDto, res: Response): Promise<AuthResult> {
    // Request/Response passed as parameters, not injected
  }
}
```

### 10.12 Hardcoding Cookie Names or Paths

```typescript
// WRONG: Hardcoded values that cannot be customized
res.cookie('access_token', token, { httpOnly: true, path: '/' });

// CORRECT: Read from configuration or shared constants
import { COOKIE_DEFAULTS } from '../../shared/constants/cookie-defaults';

res.cookie(
  this.options.cookies?.accessTokenName ?? COOKIE_DEFAULTS.ACCESS_TOKEN_NAME,
  token,
  {
    httpOnly: true,
    secure: this.options.cookies?.secure ?? true,
    sameSite: this.options.cookies?.sameSite ?? 'lax',
    path: this.options.cookies?.path ?? '/',
  },
);
```

### 10.13 Using External Crypto Libraries

```typescript
// WRONG: External dependency for crypto operations
import bcrypt from 'bcrypt';        // C++ binding, supply chain risk
import speakeasy from 'speakeasy';  // Unmaintained, bloated

// CORRECT: Native node:crypto
import { scrypt, randomBytes, timingSafeEqual, createHmac } from 'node:crypto';
```

### 10.14 Not Validating Required Dependencies at Module Init

```typescript
// WRONG: Fail at first use — confusing error message
@Injectable()
export class AuthService {
  async login(dto: LoginDto) {
    // This will throw a cryptic NestJS error if USER_REPOSITORY was never provided
    const user = await this.userRepository.findByEmail(dto.email);
  }
}

// CORRECT: Validate at module initialization
@Injectable()
export class AuthService implements OnModuleInit {
  constructor(
    @Inject(USER_REPOSITORY)
    private readonly userRepository: IUserRepository,
  ) {}

  onModuleInit() {
    if (!this.userRepository) {
      throw new Error(
        '@bymax-one/nest-auth: USER_REPOSITORY provider is required. ' +
        'Please provide an implementation of IUserRepository in your module configuration.',
      );
    }
  }
}
```

---

## Quick Reference Checklist

Use this checklist when writing or reviewing NestJS code in this project:

### Module & DI

- [ ] Module uses `registerAsync()` only (no synchronous `register()`)
- [ ] All injection tokens use `Symbol()`, not strings
- [ ] All non-class tokens use `@Inject(TOKEN)` explicitly
- [ ] All providers use default scope (no `Scope.REQUEST`)
- [ ] External dependencies are injected via interfaces, never concrete classes
- [ ] Required dependencies are validated in `onModuleInit()`
- [ ] Options are treated as `Readonly` — never mutated

### Guards

- [ ] No Passport — all guards implement `CanActivate` directly
- [ ] No `APP_GUARD` registered by the library
- [ ] Guards use `Reflector.getAllAndOverride()` for metadata
- [ ] Guards throw `UnauthorizedException` (401) or `ForbiddenException` (403)
- [ ] JWT extracted from cookie first, then `Authorization` header
- [ ] Validated payload attached to `request['user']`

### Decorators

- [ ] Metadata keys use `Symbol()`, not strings
- [ ] Metadata key constants are exported alongside the decorator
- [ ] Parameter decorators type the `data` parameter
- [ ] Every decorator has JSDoc with `@example`

### Controllers

- [ ] Controllers are thin — no business logic
- [ ] Every route has explicit `@HttpCode()`
- [ ] `@Res()` always uses `{ passthrough: true }`
- [ ] No global `ValidationPipe` registered by the library
- [ ] No hardcoded route prefixes (use `@Controller('auth')`, not `@Controller('api/v1/auth')`)

### Services

- [ ] Constructor injection for all dependencies
- [ ] All public methods have explicit return type annotations
- [ ] No `console.log` — use `Logger` from `@nestjs/common`
- [ ] All crypto uses `node:crypto` (no external packages)
- [ ] Password/token comparisons use `timingSafeEqual`
- [ ] No sensitive data in logs (passwords, tokens, secrets)

### Barrel Exports

- [ ] `export type` for interfaces and type aliases
- [ ] `export` (no `type`) for classes, functions, constants, decorators
- [ ] Barrel file only re-exports — no logic or side effects
- [ ] Internal implementation details are not exported

### Error Handling

- [ ] Auth errors use `AuthException` with a code from `AUTH_ERROR_CODES`
- [ ] Error messages are generic — no internal details leaked to client
- [ ] All errors follow the standard response shape
- [ ] Internal details logged via `Logger.error()`, not sent to client

### Testing

- [ ] Tests use `Test.createTestingModule`, not manual instantiation
- [ ] Dependencies mocked via their Symbol tokens
- [ ] Error paths are tested, not just happy paths
- [ ] No real Redis or JWT secrets in unit tests
- [ ] 80% minimum coverage enforced
- [ ] Test files are colocated with source as `*.spec.ts`

### Security

- [ ] Zero external crypto dependencies — `node:crypto` only
- [ ] Timing-safe comparisons for all secret comparisons
- [ ] HttpOnly, Secure, SameSite cookies by default
- [ ] No sensitive data in error responses or logs
- [ ] Brute-force protection on login endpoints
- [ ] Token blacklisting via Redis for logout/revocation
