/**
 * Dynamic OAuth module for @bymax-one/nest-auth.
 *
 * Registers `OAuthService`, `OAuthController`, and the configured provider plugins
 * (e.g. `GoogleOAuthPlugin`) based on the resolved options. Imported conditionally
 * by `BymaxAuthModule` when the `oauth` configuration block is present.
 *
 * @remarks
 * **Dependency sharing:** `OAuthService` depends on `AuthRedisService`,
 * `TokenManagerService`, `SessionService`, and the injection tokens
 * `BYMAX_AUTH_OPTIONS`, `BYMAX_AUTH_USER_REPOSITORY`, and `BYMAX_AUTH_HOOKS`.
 * These are resolved from the importing module's (`BymaxAuthModule`) scope — they
 * must be exported by `BymaxAuthModule` and available in the DI container when
 * `OAuthModule` providers are resolved.
 *
 * **Integration pattern:** `BymaxAuthModule` registers `OAuthController` and `OAuthService`
 * in its own `controllers`/`providers` arrays, and builds the provider plugins through
 * {@link buildOAuthPlugins} — the seam that actually carries the wiring. Everything stays in
 * one DI scope, which avoids the circular-dependency problem a sub-module hits when it tries
 * to import providers that only exist in the parent.
 *
 * `OAuthModule` below is NOT on that path: it exists for standalone use and testing, where
 * the consumer supplies every external dependency (`AuthRedisService`, `TokenManagerService`,
 * `SessionService`, and the injection tokens) themselves.
 *
 * @layer Module
 */

import { Module, type DynamicModule, type Provider } from '@nestjs/common'

import { GoogleOAuthPlugin } from './google/google-oauth.plugin'
import { OAUTH_PLUGINS } from './oauth.constants'
import { OAuthController } from './oauth.controller'
import { OAuthService } from './oauth.service'
import type { ResolvedOptions } from '../config/resolved-options'
import type { OAuthProviderPlugin } from '../interfaces/oauth-provider.interface'

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Builds the list of {@link OAuthProviderPlugin} instances from the resolved options.
 *
 * Extracted as a pure function so the plugin construction logic is unit-testable
 * and reusable by both `register()` and `getOAuthProviders()`.
 *
 * @param options - Fully resolved module options.
 * @returns Array of configured provider plugin instances (empty when `oauth` is absent).
 */
export function buildOAuthPlugins(options: ResolvedOptions): OAuthProviderPlugin[] {
  const plugins: OAuthProviderPlugin[] = []

  if (options.oauth?.google) {
    const googleCfg = options.oauth.google
    plugins.push(
      new GoogleOAuthPlugin({
        clientId: googleCfg.clientId,
        clientSecret: googleCfg.clientSecret,
        callbackUrl: googleCfg.callbackUrl,
        // Forward custom scopes when specified; plugin defaults to ['openid', 'email', 'profile'].
        ...(googleCfg.scope ? { scope: googleCfg.scope } : {})
      })
    )
  }

  return plugins
}

// ---------------------------------------------------------------------------
// OAuthModule
// ---------------------------------------------------------------------------

/**
 * Dynamic OAuth feature module.
 *
 * For **standalone or test** assembly only. `BymaxAuthModule` does not use this class: it
 * registers `OAuthController` and `OAuthService` directly and builds the plugins through
 * {@link buildOAuthPlugins}. Reach for this when you are wiring OAuth into a module of your
 * own and supplying every external dependency yourself.
 *
 * @example
 * ```typescript
 * // Standalone assembly:
 * imports: [OAuthModule.register(resolvedOptions)]
 *
 * // …or spread the pieces into a module you already have:
 * providers: [...OAuthModule.getOAuthProviders(resolvedOptions), ...otherProviders],
 * controllers: [...OAuthModule.getOAuthControllers(), ...otherControllers]
 * ```
 */
@Module({})
export class OAuthModule {
  /**
   * Returns the provider array for inline inclusion in `BymaxAuthModule`.
   *
   * Includes `OAUTH_PLUGINS` (value provider) and `OAuthService`. All other
   * dependencies (`AuthRedisService`, etc.) are expected to be present in
   * `BymaxAuthModule`'s own providers array.
   *
   * @param options - Fully resolved options from `resolveOptions()`.
   * @returns Provider array ready to be spread into a parent module's `providers`.
   */
  static getOAuthProviders(options: ResolvedOptions): Provider[] {
    return [{ provide: OAUTH_PLUGINS, useValue: buildOAuthPlugins(options) }, OAuthService]
  }

  /**
   * Returns the controller array for inline inclusion in `BymaxAuthModule`.
   *
   * @returns Controller array containing `OAuthController`.
   */
  static getOAuthControllers(): (typeof OAuthController)[] {
    return [OAuthController]
  }

  /**
   * Standalone registration for testing or direct module import scenarios.
   *
   * The caller must provide all external dependencies (see module remarks).
   *
   * @param options - Fully resolved options from `resolveOptions()`.
   * @returns A fully configured `DynamicModule`.
   */
  static register(options: ResolvedOptions): DynamicModule {
    return {
      module: OAuthModule,
      providers: OAuthModule.getOAuthProviders(options),
      controllers: OAuthModule.getOAuthControllers(),
      exports: [OAuthService]
    }
  }
}
