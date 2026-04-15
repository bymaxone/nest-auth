import { DynamicModule, Module, type Provider } from '@nestjs/common'
import { JwtModule } from '@nestjs/jwt'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS
} from './bymax-one-nest-auth.constants'
import { resolveOptions, type ResolvedOptions } from './config/resolved-options'
import { AuthController } from './controllers/auth.controller'
import { MfaController } from './controllers/mfa.controller'
import { PasswordResetController } from './controllers/password-reset.controller'
import { SessionController } from './controllers/session.controller'
import { JwtAuthGuard } from './guards/jwt-auth.guard'
import { MfaRequiredGuard } from './guards/mfa-required.guard'
import { RolesGuard } from './guards/roles.guard'
import { UserStatusGuard } from './guards/user-status.guard'
import { NoOpAuthHooks } from './hooks/no-op-auth.hooks'
import type { AuthModuleAsyncOptions } from './interfaces/auth-module-options.interface'
import { NoOpEmailProvider } from './providers/no-op-email.provider'
import { AuthRedisService } from './redis/auth-redis.service'
import { AuthService } from './services/auth.service'
import { BruteForceService } from './services/brute-force.service'
import { MfaService } from './services/mfa.service'
import { OtpService } from './services/otp.service'
import { PasswordResetService } from './services/password-reset.service'
import { PasswordService } from './services/password.service'
import { SessionService } from './services/session.service'
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
 *     mfa: {
 *       encryptionKey: config.get('MFA_ENCRYPTION_KEY'),
 *       issuer: 'My App',
 *     },
 *   }),
 *   inject: [ConfigService],
 *   controllers: { mfa: true },
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
 *   consumer does not supply those tokens in `extraProviders`. When `NoOpEmailProvider`
 *   is active, password-reset and OTP endpoints return `200 OK` but no email is sent —
 *   this is intentional for testing environments. Supply a real `BYMAX_AUTH_EMAIL_PROVIDER`
 *   in production to ensure reset emails are delivered.
 * - **MFA is opt-in.** Set `controllers: { mfa: true }` **on the `registerAsync()`
 *   call** (not inside `useFactory`) **and** supply `mfa.encryptionKey` + `mfa.issuer`
 *   in the factory return value. Omitting either leaves `MfaService` and
 *   `MfaRequiredGuard` completely unregistered. Setting `controllers.mfa: true`
 *   without the `mfa` configuration group causes a startup error.
 * - **Platform MFA.** When `controllers.mfa: true` and `platformAdmin.enabled: true`,
 *   supply `BYMAX_AUTH_PLATFORM_USER_REPOSITORY` in `extraProviders` so that platform
 *   admin MFA challenges can resolve the admin identity. Omitting the token causes an
 *   `AUTH_ERROR_CODES.TOKEN_INVALID` response on the first platform MFA challenge.
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

    // MfaController — opt-in only. The consumer must set controllers.mfa: true when
    // they configure the `mfa` group. This prevents MfaService from being registered
    // without a valid mfa.encryptionKey/issuer in the resolved options.
    const includeMfa = options.controllers?.mfa === true

    // PasswordResetController — opt-out. Enabled by default unless explicitly disabled.
    const includePasswordReset = options.controllers?.passwordReset !== false

    // SessionController — opt-in. Requires controllers.sessions: true AND sessions.enabled: true
    // in the factory return value. Enabling the controller without session tracking active would
    // register endpoints that return stale/empty data.
    const includeSessions = options.controllers?.sessions === true

    // Resolved options provider — wraps the consumer's factory with resolveOptions().
    const resolvedOptionsProvider: Provider = {
      provide: BYMAX_AUTH_OPTIONS,
      useFactory: async (...args: unknown[]): Promise<ResolvedOptions> => {
        const userOptions = await options.useFactory(...args)
        const resolved = resolveOptions(userOptions)

        // Cross-validate: controllers.mfa: true without the mfa config group would
        // register MfaService with a null mfa getter and throw a TypeError at the first
        // MFA request. Catch this at startup where the error is actionable.
        if (includeMfa && resolved.mfa === undefined) {
          throw new Error(
            '[BymaxAuthModule] controllers.mfa: true requires the mfa group ' +
              '(encryptionKey and issuer) to be configured in the useFactory return value.'
          )
        }

        // Cross-validate: controllers.sessions: true without sessions.enabled: true registers
        // session endpoints that silently return empty data because SessionService.createSession()
        // is never called from the auth flow unless sessions are active. Catch misconfiguration
        // at startup rather than letting consumers debug empty session lists.
        if (includeSessions && resolved.sessions.enabled !== true) {
          throw new Error(
            '[BymaxAuthModule] controllers.sessions: true requires sessions.enabled: true ' +
              'in the useFactory return value.'
          )
        }

        return resolved
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

    // ---------------------------------------------------------------------------
    // Conditional controller registration (all evaluated synchronously).
    // ---------------------------------------------------------------------------

    // AuthController — enabled by default, opt-out via controllers.auth: false.
    const includeAuth = options.controllers?.auth !== false

    const controllers = [
      ...(includeAuth ? [AuthController] : []),
      ...(includeMfa ? [MfaController] : []),
      ...(includePasswordReset ? [PasswordResetController] : []),
      ...(includeSessions ? [SessionController] : [])
    ]

    // MfaService and MfaRequiredGuard are only registered when MFA is enabled so
    // that modules without MFA configuration have zero overhead from this feature.
    // Using a shared array prevents providers/exports from diverging when new MFA
    // components are added in the future.
    const mfaProviders: Provider[] = includeMfa ? [MfaService, MfaRequiredGuard] : []

    // PasswordResetService is registered as a named provider array so providers/exports
    // stay in sync (same pattern as mfaProviders).
    const passwordResetProviders: Provider[] = includePasswordReset ? [PasswordResetService] : []

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
        // SessionService is always registered (not gated on includeSessions) because
        // AuthService.login() and AuthService.refresh() call session methods. Registering
        // it unconditionally avoids an injection error when sessions.enabled: true is set
        // but controllers.sessions: false (session tracking active, session UI disabled).
        SessionService,
        AuthService,
        // Guards — registered as providers so they can be applied via @UseGuards().
        JwtAuthGuard,
        RolesGuard,
        UserStatusGuard,
        // MFA services and guard — only registered when controllers.mfa: true.
        ...mfaProviders,
        // Password reset service — only registered when controllers.passwordReset !== false.
        ...passwordResetProviders
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
        TokenDeliveryService,
        // Export SessionService unconditionally — mirrors provider registration above.
        // Host-app modules that extend the auth flow (e.g. custom logout logic) can
        // inject SessionService without re-registering it.
        SessionService,
        // Export MFA components when enabled — allows host-app modules to inject
        // MfaService and apply MfaRequiredGuard without re-registering them.
        // Spreads mfaProviders directly so providers and exports always stay in sync.
        ...mfaProviders,
        // Export PasswordResetService when enabled — allows host-app modules to call
        // service methods (e.g. initiateReset) from custom controllers.
        ...passwordResetProviders
      ]
    }
  }
}
