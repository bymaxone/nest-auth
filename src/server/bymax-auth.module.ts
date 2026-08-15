/**
 * @fileoverview Root NestJS dynamic module for `@bymax-one/nest-auth`.
 *
 * Exposes `BymaxAuthModule.forRoot()` and `BymaxAuthModule.registerAsync()`
 * as the sole entry points for library configuration.
 *
 * @layer Module
 */
import { DynamicModule, Module, type Provider, type Type } from '@nestjs/common'
import { JwtModule } from '@nestjs/jwt'

import {
  BYMAX_AUTH_REGISTERED_CONTROLLERS,
  BYMAX_AUTH_BREACH_CHECKER,
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_PLATFORM_USER_REPOSITORY,
  BYMAX_AUTH_REDIS_CLIENT,
  BYMAX_AUTH_USER_REPOSITORY
} from './bymax-auth.constants'
import { resolveOptions, type ResolvedOptions } from './config/resolved-options'
import { AuthController } from './controllers/auth.controller'
import { EmailChangeController } from './controllers/email-change.controller'
import { InvitationController } from './controllers/invitation.controller'
import { MfaController } from './controllers/mfa.controller'
import { PasswordResetController } from './controllers/password-reset.controller'
import { PlatformAuthController } from './controllers/platform-auth.controller'
import { PlatformMfaController } from './controllers/platform-mfa.controller'
import { SessionController } from './controllers/session.controller'
import { AuthRateLimitGuard } from './guards/auth-rate-limit.guard'
import { JwtAuthGuard } from './guards/jwt-auth.guard'
import { JwtPlatformGuard } from './guards/jwt-platform.guard'
import { MfaRequiredGuard } from './guards/mfa-required.guard'
import { PlatformRolesGuard } from './guards/platform-roles.guard'
import { RolesGuard } from './guards/roles.guard'
import { TrustedOriginGuard } from './guards/trusted-origin.guard'
import { UserStatusGuard } from './guards/user-status.guard'
import { NoOpAuthHooks } from './hooks/no-op-auth.hooks'
import { NoStoreInterceptor } from './interceptors/no-store.interceptor'
import type { AuthModuleAsyncOptions } from './interfaces/auth-module-options.interface'
import { OAUTH_PLUGINS } from './oauth/oauth.constants'
import { OAuthController } from './oauth/oauth.controller'
import { buildOAuthPlugins } from './oauth/oauth.module'
import { OAuthService } from './oauth/oauth.service'
import type { RegisteredControllers } from './openapi/auth-openapi-fragment'
import { AuthOpenApiContributor } from './openapi/auth-openapi.contributor'
import { CommonPasswordChecker } from './providers/common-password-checker.provider'
import { NoOpEmailProvider } from './providers/no-op-email.provider'
import { AuthRedisService } from './redis/auth-redis.service'
import { AuthRevocationService } from './services/auth-revocation.service'
import { AuthService } from './services/auth.service'
import { BruteForceService } from './services/brute-force.service'
import { EmailChangeService } from './services/email-change.service'
import { InvitationService } from './services/invitation.service'
import { MfaService } from './services/mfa.service'
import { OtpService } from './services/otp.service'
import { PasswordResetService } from './services/password-reset.service'
import { PasswordService } from './services/password.service'
import { PlatformAuthService } from './services/platform-auth.service'
import { SessionService } from './services/session.service'
import { TokenDeliveryService } from './services/token-delivery.service'
import { TokenManagerService } from './services/token-manager.service'
import { WsTicketService } from './services/ws-ticket.service'

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
 * Every controller this module can mount, whatever the feature flags say.
 *
 * The list the suites read when they have to reason about the whole surface — the route-constant
 * completeness gate, and the check that no contributed request body lands on a method without
 * payload semantics. Both of those pass by knowing less if their view of "every controller" is a
 * copy that fell behind, so neither keeps one.
 *
 * It is **not** the array `registerAsync` builds: that one names the same classes again, each
 * behind its own feature flag, because which controllers exist and which a given deployment
 * mounts are different questions. The two are held together by an e2e that boots with every
 * switch on and asserts the container registered exactly these classes — so a controller added
 * to one and not the other is a red test rather than a gate that silently skips a family.
 *
 * Internal: exported for those tests, and deliberately absent from the package barrel.
 */
export const AUTH_CONTROLLERS: readonly Type<object>[] = [
  AuthController,
  MfaController,
  PasswordResetController,
  SessionController,
  PlatformAuthController,
  PlatformMfaController,
  OAuthController,
  InvitationController,
  EmailChangeController
]

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
 *   call** (not inside `useFactory`, which throws at startup if you do) **and** supply `mfa.encryptionKey` + `mfa.issuer`
 *   in the factory return value. Omitting either leaves `MfaService` and
 *   `MfaRequiredGuard` completely unregistered. Setting `controllers.mfa: true`
 *   without the `mfa` configuration group causes a startup error.
 * - **Platform MFA.** When `controllers.mfa: true` and `platform.enabled: true`,
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

    // BYMAX_AUTH_USER_REPOSITORY is required by AuthService, UserStatusGuard, SessionService,
    // MfaService, OAuthService, InvitationService, and PasswordResetService. Without it every
    // request that touches user data fails with a NestJS injection error at runtime. Catching
    // the omission here — at synchronous module-build time — gives a clear startup error
    // instead of a cryptic "No provider for BYMAX_AUTH_USER_REPOSITORY" from NestJS internals.
    if (!hasProviderToken(extraProviders, BYMAX_AUTH_USER_REPOSITORY)) {
      throw new Error(
        '[BymaxAuthModule] BYMAX_AUTH_USER_REPOSITORY is required in extraProviders. ' +
          'Provide your IUserRepository implementation: ' +
          '{ provide: BYMAX_AUTH_USER_REPOSITORY, useClass: YourUserRepository }.'
      )
    }

    // BYMAX_AUTH_REDIS_CLIENT is required by AuthRedisService and therefore by every
    // downstream service (token rotation, brute-force, OTP, sessions, MFA setup). The
    // same synchronous check as above gives a clear startup error instead of a cryptic
    // NestJS DI failure at the first request.
    if (!hasProviderToken(extraProviders, BYMAX_AUTH_REDIS_CLIENT)) {
      throw new Error(
        '[BymaxAuthModule] BYMAX_AUTH_REDIS_CLIENT is required in extraProviders. ' +
          'Provide your ioredis client instance: ' +
          '{ provide: BYMAX_AUTH_REDIS_CLIENT, useValue: new Redis(url) }.'
      )
    }

    // ---------------------------------------------------------------------------
    // Feature flags — evaluated synchronously from the registerAsync() call options.
    // These control which providers and controllers are registered at module build time.
    // Cross-validation (checking that the required config groups are present) happens
    // inside the async factory below, after resolveOptions() has run.
    // ---------------------------------------------------------------------------

    // AuthController — opt-out. Enabled by default, disable via controllers.auth: false.
    const includeAuth = options.controllers?.auth !== false

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

    // PlatformAuthController — opt-in. Requires platform.enabled: true in the resolved
    // options. MfaService is also required (platform MFA challenge endpoint) so the mfa group
    // must be configured as well.
    const includePlatform = options.controllers?.platform === true

    // OAuthController — opt-in. Requires the oauth group to be configured in the factory.
    // OAUTH_PLUGINS is built lazily via a factory provider so that buildOAuthPlugins()
    // runs after BYMAX_AUTH_OPTIONS is resolved rather than at module build time.
    const includeOAuth = options.controllers?.oauth === true

    // InvitationController — opt-in. Requires invitations.enabled: true in the resolved options.
    const includeInvitations = options.controllers?.invitations === true

    // EmailChangeController — opt-in. The service refuses to boot when the configured email
    // provider cannot deliver the verification token, so a deployment that enables the flow
    // without wiring the message fails at startup rather than at a user's first attempt.
    const includeEmailChange = options.controllers?.emailChange === true

    // Resolved options provider — wraps the consumer's factory with resolveOptions().
    const resolvedOptionsProvider: Provider = {
      provide: BYMAX_AUTH_OPTIONS,
      useFactory: async (...args: unknown[]): Promise<ResolvedOptions> => {
        const userOptions = await options.useFactory(...args)

        // `controllers` belongs on the `registerAsync()` call, never in the factory's return
        // value. Nest decides a module's shape before any factory runs, so a `controllers` key
        // here is read by nothing: the flags are silently dropped and the endpoints they were
        // meant to enable are simply absent — a 404 whose cause is in a different object from
        // the one the developer edited. It was documented; documentation is not a control.
        if ('controllers' in (userOptions as unknown as Record<string, unknown>)) {
          throw new Error(
            '[BymaxAuthModule] `controllers` must be passed to registerAsync() itself, not ' +
              'returned from useFactory — the module is assembled before the factory runs, so ' +
              'flags returned here are ignored and the endpoints are never registered.'
          )
        }

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

        // Cross-validate: controllers.platform: true requires platform.enabled: true
        // in the resolved options and the mfa group (MfaService backs the platform MFA challenge
        // endpoint). Also requires BYMAX_AUTH_PLATFORM_USER_REPOSITORY in extraProviders —
        // without it, all platform auth requests fail at runtime rather than at startup.
        // Stryker disable next-line OptionalChaining: resolveOptions always sets `platform`, so `resolved.platform?.enabled` and `.enabled` are identical
        if (includePlatform && !resolved.platform?.enabled) {
          throw new Error(
            '[BymaxAuthModule] controllers.platform: true requires ' +
              'platform.enabled: true in the useFactory return value.'
          )
        }
        if (includePlatform && resolved.mfa === undefined) {
          throw new Error(
            '[BymaxAuthModule] controllers.platform: true requires the mfa group ' +
              '(encryptionKey and issuer) to be configured — MfaService is used for ' +
              'platform admin MFA challenges.'
          )
        }
        if (
          includePlatform &&
          !hasProviderToken(extraProviders, BYMAX_AUTH_PLATFORM_USER_REPOSITORY)
        ) {
          throw new Error(
            // Stryker disable next-line StringLiteral: developer-facing startup error message text; consumers act on the thrown error, not its wording
            '[BymaxAuthModule] controllers.platform: true requires ' +
              'BYMAX_AUTH_PLATFORM_USER_REPOSITORY in extraProviders. ' +
              'Omitting it will cause TOKEN_INVALID on all platform auth requests.'
          )
        }

        // Cross-validate: controllers.oauth: true without the oauth group would register
        // OAuthService without any plugins, causing all OAuth requests to throw OAUTH_FAILED.
        if (includeOAuth && !resolved.oauth) {
          throw new Error(
            '[BymaxAuthModule] controllers.oauth: true requires the oauth group ' +
              'to be configured in the useFactory return value.'
          )
        }

        // Cross-validate: controllers.invitations: true requires invitations.enabled: true.
        // Stryker disable next-line OptionalChaining: resolveOptions always sets `invitations`, so `resolved.invitations?.enabled` and `.enabled` are identical
        if (includeInvitations && !resolved.invitations?.enabled) {
          throw new Error(
            '[BymaxAuthModule] controllers.invitations: true requires ' +
              'invitations.enabled: true in the useFactory return value.'
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

    // Fallback breach checker — approves every password, so the credential path never reaches
    // the network unless the consumer wires a real checker (e.g. HibpBreachChecker).
    const breachCheckerProviders: Provider[] = hasProviderToken(
      extraProviders,
      BYMAX_AUTH_BREACH_CHECKER
    )
      ? []
      : [{ provide: BYMAX_AUTH_BREACH_CHECKER, useClass: CommonPasswordChecker }]

    // Fallback hooks provider — only registered when the consumer has not supplied one.
    const hooksProviders: Provider[] = hasProviderToken(extraProviders, BYMAX_AUTH_HOOKS)
      ? []
      : [{ provide: BYMAX_AUTH_HOOKS, useClass: NoOpAuthHooks }]

    // ---------------------------------------------------------------------------
    // Controllers and provider arrays — built from the feature flags above.
    // ---------------------------------------------------------------------------

    const controllers = [
      ...(includeAuth ? [AuthController] : []),
      ...(includeMfa ? [MfaController] : []),
      ...(includePasswordReset ? [PasswordResetController] : []),
      ...(includeSessions ? [SessionController] : []),
      ...(includePlatform ? [PlatformAuthController, PlatformMfaController] : []),
      ...(includeOAuth ? [OAuthController] : []),
      ...(includeInvitations ? [InvitationController] : []),
      ...(includeEmailChange ? [EmailChangeController] : [])
    ]

    // MfaService and MfaRequiredGuard are only registered when MFA is enabled so
    // that modules without MFA configuration have zero overhead from this feature.
    // Using a shared array prevents providers/exports from diverging when new MFA
    // components are added in the future.
    const mfaProviders: Provider[] = includeMfa ? [MfaService, MfaRequiredGuard] : []

    // MfaService is also required by PlatformAuthController for the MFA challenge endpoint.
    // Only register it here when MFA controllers are disabled — avoids duplicate registration
    // when both controllers.mfa and controllers.platform are true.
    const platformMfaProvider: Provider[] = includePlatform && !includeMfa ? [MfaService] : []

    // PasswordResetService is registered as a named provider array so providers/exports
    // stay in sync (same pattern as mfaProviders).
    const passwordResetProviders: Provider[] = includePasswordReset ? [PasswordResetService] : []

    // PlatformAuthService, JwtPlatformGuard, and PlatformRolesGuard — only when
    // controllers.platform: true.
    const platformProviders: Provider[] = includePlatform
      ? [PlatformAuthService, JwtPlatformGuard, PlatformRolesGuard]
      : []

    // OAuth providers — OAUTH_PLUGINS is built lazily from BYMAX_AUTH_OPTIONS so that
    // buildOAuthPlugins() runs after the resolved options are available. OAuthService
    // is registered as a class provider alongside it.
    const oauthProviders: Provider[] = includeOAuth
      ? [
          {
            provide: OAUTH_PLUGINS,
            useFactory: (opts: ResolvedOptions) => buildOAuthPlugins(opts),
            inject: [BYMAX_AUTH_OPTIONS]
          },
          OAuthService
        ]
      : []

    // InvitationService — only when controllers.invitations: true.
    const invitationProviders: Provider[] = includeInvitations ? [InvitationService] : []

    // EmailChangeService — only when controllers.emailChange: true.
    const emailChangeProviders: Provider[] = includeEmailChange ? [EmailChangeService] : []

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
              // Stryker disable next-line ObjectLiteral: jsonwebtoken defaults to HS256 and TokenManagerService overrides signOptions per call, so the emptied `signOptions` produces identical signing
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
        // Which controllers this registration mounted, and the contributor that reads it.
        //
        // The flags are computed above from the `controllers` argument, which Nest reads
        // synchronously — before any factory runs — so they cannot travel inside the resolved
        // options. The contributor needs them because a fragment naming a handler the document
        // does not contain FAILS a consumer's document build: a library that described its
        // platform routes on a deployment that never mounted them would break the build it was
        // supposed to describe.
        {
          provide: BYMAX_AUTH_REGISTERED_CONTROLLERS,
          useValue: {
            auth: includeAuth,
            passwordReset: includePasswordReset,
            mfa: includeMfa,
            sessions: includeSessions,
            platform: includePlatform,
            // One switch mounts both platform controllers, so they cannot disagree.
            platformMfa: includePlatform,
            invitations: includeInvitations,
            emailChange: includeEmailChange,
            oauth: includeOAuth
          } satisfies RegisteredControllers
        },
        AuthOpenApiContributor,
        // Fallback NoOp providers (skipped if consumer already supplied them).
        ...emailProviders,
        ...breachCheckerProviders,
        ...hooksProviders,
        // Core services.
        // AuthRedisService is registered directly (not via AuthRedisModule) so that
        // BYMAX_AUTH_REDIS_CLIENT and BYMAX_AUTH_OPTIONS provided via extraProviders
        // are visible in the same module scope.
        AuthRedisService,
        AuthRevocationService,
        PasswordService,
        TokenManagerService,
        TokenDeliveryService,
        WsTicketService,
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
        TrustedOriginGuard,
        AuthRateLimitGuard,
        // Response-header interceptor — every library controller applies it, so it must be
        // resolvable in this module's injector.
        NoStoreInterceptor,
        RolesGuard,
        UserStatusGuard,
        // MFA services and guard — only registered when controllers.mfa: true.
        ...mfaProviders,
        // MfaService for platform admin MFA challenges (when controllers.mfa is disabled).
        ...platformMfaProvider,
        // Password reset service — only registered when controllers.passwordReset !== false.
        ...passwordResetProviders,
        // Platform admin components — only when controllers.platform: true.
        ...platformProviders,
        // OAuth providers — only when controllers.oauth: true.
        ...oauthProviders,
        // Invitation service — only when controllers.invitations: true.
        ...invitationProviders,
        // Address-change service — only when controllers.emailChange: true.
        ...emailChangeProviders
      ],
      controllers,
      exports: [
        // Export resolved options so host-app modules can inspect configuration.
        BYMAX_AUTH_OPTIONS,
        // Export core service for host-app controllers that extend auth flows.
        AuthService,
        // Export guards so host-app modules can apply them without reimporting.
        JwtAuthGuard,
        TrustedOriginGuard,
        AuthRateLimitGuard,
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
        // MfaService exported for platform admin use when MFA controllers are disabled.
        ...platformMfaProvider,
        // Export PasswordResetService when enabled — allows host-app modules to call
        // service methods (e.g. initiateReset) from custom controllers.
        ...passwordResetProviders,
        // Export platform admin components — allows host-app modules to apply
        // JwtPlatformGuard and PlatformRolesGuard without re-registering them.
        ...platformProviders,
        // Export OAuthService — allows host-app modules to extend OAuth flows.
        // NOTE: oauthProviders is NOT spread here because OAUTH_PLUGINS is an internal
        // injection token — host-app modules have no reason to inject the plugin array
        // directly. Only OAuthService is part of the public integration surface.
        ...(includeOAuth ? [OAuthService] : []),
        // Export email provider — allows host-app modules (e.g. custom invitation flows)
        // to inject the configured IEmailProvider without re-registering it.
        BYMAX_AUTH_EMAIL_PROVIDER,
        BYMAX_AUTH_BREACH_CHECKER,
        // Export InvitationService — allows host-app modules to send or manage invitations.
        ...invitationProviders,
        // Export EmailChangeService — a host app may want to drive the flow from its own
        // profile screen rather than through the shipped controller.
        ...emailChangeProviders,
        // Export AuthRedisService so host-app modules that apply JwtPlatformGuard,
        // WsJwtGuard, or other guards via @UseGuards() have AuthRedisService in scope.
        // NestJS auto-registers @UseGuards() guards as local providers in the controller's
        // module; all constructor deps must be resolvable from that module's context.
        AuthRedisService,
        // Export AuthRevocationService for the same @UseGuards() reason — the exported guards now
        // depend on it — and so a host bridging a realtime transport can inject it and consult
        // both revocation channels rather than granting a stream that outlives a logout.
        AuthRevocationService,
        // Same reason, for the two exported guards whose remaining constructor deps are not
        // covered by the entries above. Exporting the guard class is necessary but not
        // sufficient: because @UseGuards() re-instantiates the guard in the *consumer's*
        // injector, a dep missing here fails the consumer's boot with
        // UnknownDependenciesException even though the guard itself is exported.
        //
        //   UserStatusGuard -> BYMAX_AUTH_USER_REPOSITORY
        //   WsJwtGuard      -> WsTicketService
        //
        // Re-exporting the token (rather than asking the consumer to register the repository
        // again) is what keeps the guard bound to the SAME instance the auth module uses; a
        // second registration would resolve the guard against a different object.
        BYMAX_AUTH_USER_REPOSITORY,
        // WsTicketService also stands on its own as public surface: single-use ticket
        // handshakes are the credential a realtime transport is meant to use, and a consumer
        // cannot mint one without injecting this service.
        WsTicketService,
        // Export JwtModule so host-app modules that apply JWT-dependent guards via
        // @UseGuards() have JwtService in scope.
        JwtModule
      ]
    }
  }
}
