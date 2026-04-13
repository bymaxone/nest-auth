import { DynamicModule, Module } from '@nestjs/common'
import type { Provider } from '@nestjs/common'
import { JwtModule } from '@nestjs/jwt'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS
} from './bymax-one-nest-auth.constants'
import { resolveOptions } from './config/resolved-options'
import type { ResolvedOptions } from './config/resolved-options'
import { AuthController } from './controllers/auth.controller'
import { JwtAuthGuard } from './guards/jwt-auth.guard'
import { RolesGuard } from './guards/roles.guard'
import { UserStatusGuard } from './guards/user-status.guard'
import { NoOpAuthHooks } from './hooks/no-op-auth.hooks'
import type { AuthModuleAsyncOptions } from './interfaces/auth-module-options.interface'
import { NoOpEmailProvider } from './providers/no-op-email.provider'
import { AuthRedisService } from './redis/auth-redis.service'
import { AuthService } from './services/auth.service'
import { BruteForceService } from './services/brute-force.service'
import { OtpService } from './services/otp.service'
import { PasswordService } from './services/password.service'
import { TokenDeliveryService } from './services/token-delivery.service'
import { TokenManagerService } from './services/token-manager.service'

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Checks whether a given injection token is already declared in a providers array.
 *
 * Used to determine whether NoOp fallback providers should be registered.
 * Only checks object-form providers with an explicit `provide` field — class
 * shorthand providers do not carry an injection token and are skipped.
 */
function hasProviderToken(providers: Provider[], token: symbol): boolean {
  return providers.some((p) => {
    if (typeof p === 'function') return false
    return 'provide' in p && p.provide === token
  })
}

// ---------------------------------------------------------------------------
// BymaxAuthModule
// ---------------------------------------------------------------------------

/**
 * Root authentication module for the @bymax-one/nest-auth library.
 *
 * Registers all services, guards, and (optionally) controllers required for
 * the dashboard authentication flow. Consumed via `registerAsync()` — sync
 * registration is not supported because `resolveOptions()` may need to await
 * async configuration sources (e.g. `ConfigService`).
 *
 * @example
 * ```typescript
 * BymaxAuthModule.registerAsync({
 *   imports: [ConfigModule],
 *   useFactory: (config: ConfigService) => ({
 *     jwt: { secret: config.get('JWT_SECRET') },
 *     roles: { hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] } },
 *   }),
 *   inject: [ConfigService],
 *   extraProviders: [
 *     { provide: BYMAX_AUTH_USER_REPOSITORY, useClass: PrismaUserRepository },
 *     { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: redisClient },
 *   ],
 * })
 * ```
 *
 * @remarks
 * - Route prefix (`routePrefix` option) is applied by the consuming app via
 *   `RouterModule.register()` — the library's controller uses no path prefix.
 * - Guards (`JwtAuthGuard`, `RolesGuard`, `UserStatusGuard`) are registered as
 *   providers and must be applied per-controller or per-route via `@UseGuards()`.
 *   They are NOT registered as `APP_GUARD` to avoid polluting the host application.
 * - `NoOpEmailProvider` and `NoOpAuthHooks` are registered as fallbacks when the
 *   consumer does not supply those tokens in `extraProviders`.
 */
@Module({})
export class BymaxAuthModule {
  /**
   * Registers the auth module asynchronously.
   *
   * @param options - Async registration options including a `useFactory` that
   *   returns `BymaxAuthModuleOptions`. Optionally supply `extraProviders` with
   *   the user repository and Redis client tokens.
   * @returns A fully configured `DynamicModule`.
   */
  static registerAsync(options: AuthModuleAsyncOptions): DynamicModule {
    const extraProviders = options.extraProviders ?? []

    // Resolved options provider — wraps the consumer's factory with resolveOptions().
    const resolvedOptionsProvider: Provider = {
      provide: BYMAX_AUTH_OPTIONS,
      useFactory: async (...args: unknown[]): Promise<ResolvedOptions> => {
        const userOptions = await options.useFactory(...args)
        return resolveOptions(userOptions)
      },
      inject: options.inject ?? []
    }

    // Fallback email provider — only registered when the consumer has not supplied one.
    const emailProviders: Provider[] = hasProviderToken(extraProviders, BYMAX_AUTH_EMAIL_PROVIDER)
      ? []
      : [{ provide: BYMAX_AUTH_EMAIL_PROVIDER, useClass: NoOpEmailProvider }]

    // Fallback hooks provider — only registered when the consumer has not supplied one.
    const hooksProviders: Provider[] = hasProviderToken(extraProviders, BYMAX_AUTH_HOOKS)
      ? []
      : [{ provide: BYMAX_AUTH_HOOKS, useClass: NoOpAuthHooks }]

    // Conditionally register AuthController (synchronous option, defaults to true).
    const includeAuth = options.controllers?.auth !== false
    const controllers = includeAuth ? [AuthController] : []

    return {
      module: BymaxAuthModule,
      imports: [
        ...(options.imports ?? []),
        // JwtModule reads the secret directly from the consumer factory (without re-running
        // resolveOptions) to avoid double-validation on startup. Full validation happens once
        // in the BYMAX_AUTH_OPTIONS provider above.
        // expiresIn is omitted — TokenManagerService sets it per-call via accessSignOptions().
        JwtModule.registerAsync({
          useFactory: async (...args: unknown[]) => {
            const userOptions = await options.useFactory(...args)
            return {
              secret: userOptions.jwt.secret,
              signOptions: { algorithm: 'HS256' }
            }
          },
          inject: options.inject ?? []
        })
      ],
      providers: [
        // Consumer-supplied providers first so they can override internal ones.
        ...extraProviders,
        // Resolved options (depends on consumer's inject tokens).
        resolvedOptionsProvider,
        // Fallback NoOp providers (skipped if consumer already supplied them).
        ...emailProviders,
        ...hooksProviders,
        // Core services.
        // AuthRedisService is registered directly (not via AuthRedisModule) so that
        // BYMAX_AUTH_REDIS_CLIENT and BYMAX_AUTH_OPTIONS provided via extraProviders
        // are visible in the same module scope.
        AuthRedisService,
        PasswordService,
        TokenManagerService,
        TokenDeliveryService,
        BruteForceService,
        OtpService,
        AuthService,
        // Guards — registered as providers so they can be applied via @UseGuards().
        JwtAuthGuard,
        RolesGuard,
        UserStatusGuard
      ],
      controllers,
      exports: [
        // Export resolved options so host-app modules can inspect configuration.
        BYMAX_AUTH_OPTIONS,
        // Export core service for host-app controllers that extend auth flows.
        AuthService,
        // Export guards so host-app modules can apply them without reimporting.
        JwtAuthGuard,
        RolesGuard,
        UserStatusGuard,
        // Export TokenDeliveryService for host-app refresh endpoints.
        TokenDeliveryService
      ]
    }
  }
}
