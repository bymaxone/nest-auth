/**
 * Tests for OAuthModule — buildOAuthPlugins() and static module helpers.
 *
 * Strategy: pure unit tests — no NestJS DI compilation needed.
 * buildOAuthPlugins() is a pure function; the static OAuthModule helpers return plain
 * arrays/objects that can be verified without spinning up a container.
 *
 * Special setup: none — GoogleOAuthPlugin is instantiated directly via buildOAuthPlugins.
 * Its authorizeUrl() is used to inspect internal scope state through the public API.
 */

import type { ResolvedOptions } from '../config/resolved-options'
import { GoogleOAuthPlugin } from './google/google-oauth.plugin'
import { OAUTH_PLUGINS } from './oauth.constants'
import { OAuthController } from './oauth.controller'
import { buildOAuthPlugins, OAuthModule } from './oauth.module'
import { OAuthService } from './oauth.service'

// ---------------------------------------------------------------------------
// Shared helper — minimal options cast (only `oauth` is read by buildOAuthPlugins)
// ---------------------------------------------------------------------------

type GoogleConfig = {
  clientId: string
  clientSecret: string
  callbackUrl: string
  scope?: string[]
}

function makeOptions(googleConfig?: GoogleConfig): ResolvedOptions {
  return (googleConfig ? { oauth: { google: googleConfig } } : {}) as unknown as ResolvedOptions
}

// ---------------------------------------------------------------------------
// buildOAuthPlugins
// ---------------------------------------------------------------------------

describe('buildOAuthPlugins', () => {
  // Verifies that an empty array is returned when the oauth config group is absent —
  // prevents null-dereference when the module is compiled without any provider configured.
  it('should return an empty array when the oauth config group is absent', () => {
    expect(buildOAuthPlugins(makeOptions())).toEqual([])
  })

  // Verifies that a GoogleOAuthPlugin is instantiated when oauth.google is configured,
  // confirming the factory wires the correct plugin class for the 'google' provider name.
  it('should return a GoogleOAuthPlugin with name "google" when oauth.google is configured', () => {
    const plugins = buildOAuthPlugins(
      makeOptions({
        clientId: 'cid',
        clientSecret: 'csec',
        callbackUrl: 'https://app.example.com/cb'
      })
    )

    expect(plugins).toHaveLength(1)
    expect(plugins[0]).toBeInstanceOf(GoogleOAuthPlugin)
    expect((plugins[0] as GoogleOAuthPlugin).name).toBe('google')
  })

  // Verifies that a custom scope array from oauth.google.scope is forwarded to the plugin.
  // Without forwarding, all OAuth requests would use the default scope regardless of consumer config.
  it('should forward a custom scope array to the GoogleOAuthPlugin', () => {
    const plugins = buildOAuthPlugins(
      makeOptions({
        clientId: 'cid',
        clientSecret: 'csec',
        callbackUrl: 'https://app.example.com/cb',
        scope: ['openid', 'email']
      })
    )

    // authorizeUrl exposes the stored scope via the URL query param — the only public accessor.
    const url = (plugins[0] as GoogleOAuthPlugin).authorizeUrl('st')
    expect(new URL(url).searchParams.get('scope')).toBe('openid email')
  })

  // Verifies that the plugin uses the default scope 'openid email profile' when no custom
  // scope is specified — confirming the GoogleOAuthPlugin default is preserved end-to-end.
  it('should use the default scope when oauth.google.scope is absent', () => {
    const plugins = buildOAuthPlugins(
      makeOptions({
        clientId: 'cid',
        clientSecret: 'csec',
        callbackUrl: 'https://app.example.com/cb'
      })
    )

    const url = (plugins[0] as GoogleOAuthPlugin).authorizeUrl('st')
    expect(new URL(url).searchParams.get('scope')).toBe('openid email profile')
  })
})

// ---------------------------------------------------------------------------
// OAuthModule.getOAuthProviders
// ---------------------------------------------------------------------------

describe('OAuthModule.getOAuthProviders', () => {
  // Verifies that exactly two providers are returned: the OAUTH_PLUGINS value provider and
  // OAuthService. Any deviation would cause injection errors when BymaxAuthModule spreads them.
  it('should return an OAUTH_PLUGINS value provider and OAuthService as the two providers', () => {
    const providers = OAuthModule.getOAuthProviders(makeOptions())

    expect(providers).toHaveLength(2)

    // First element must be the OAUTH_PLUGINS value provider.
    const first = providers[0] as { provide: symbol; useValue: unknown }
    expect(first.provide).toBe(OAUTH_PLUGINS)
    expect(Array.isArray(first.useValue)).toBe(true)

    // Second element must be the OAuthService class (constructor shorthand).
    expect(providers[1]).toBe(OAuthService)
  })

  // Verifies that the OAUTH_PLUGINS.useValue contains a GoogleOAuthPlugin when google is configured,
  // confirming that getOAuthProviders calls buildOAuthPlugins correctly with the provided options.
  it('should populate OAUTH_PLUGINS.useValue with a GoogleOAuthPlugin when google is configured', () => {
    const providers = OAuthModule.getOAuthProviders(
      makeOptions({
        clientId: 'cid',
        clientSecret: 'csec',
        callbackUrl: 'https://app.example.com/cb'
      })
    )

    const first = providers[0] as { provide: symbol; useValue: unknown[] }
    expect(first.useValue).toHaveLength(1)
    expect(first.useValue[0]).toBeInstanceOf(GoogleOAuthPlugin)
  })
})

// ---------------------------------------------------------------------------
// OAuthModule.getOAuthControllers
// ---------------------------------------------------------------------------

describe('OAuthModule.getOAuthControllers', () => {
  // Verifies that the array contains exactly OAuthController — BymaxAuthModule spreads this
  // into its controllers array, so any deviation breaks OAuth route registration.
  it('should return an array containing only OAuthController', () => {
    const controllers = OAuthModule.getOAuthControllers()

    expect(controllers).toHaveLength(1)
    expect(controllers[0]).toBe(OAuthController)
  })
})

// ---------------------------------------------------------------------------
// OAuthModule.register
// ---------------------------------------------------------------------------

describe('OAuthModule.register', () => {
  // Verifies the module class reference — NestJS uses this to identify the module
  // in the dependency graph when OAuthModule is imported standalone.
  it('should return a DynamicModule with module: OAuthModule', () => {
    const dm = OAuthModule.register(makeOptions())

    expect(dm.module).toBe(OAuthModule)
  })

  // Verifies that OAuthService is included in exports so standalone consumers can inject it
  // after importing OAuthModule.register().
  it('should export OAuthService', () => {
    const dm = OAuthModule.register(makeOptions())

    expect(dm.exports).toContain(OAuthService)
  })

  // Verifies that OAuthController is in the controllers array — required for OAuth
  // route handlers to be registered when the module is used standalone.
  it('should include OAuthController in the controllers array', () => {
    const dm = OAuthModule.register(makeOptions())

    expect(dm.controllers).toContain(OAuthController)
  })

  // Verifies that the providers array includes the OAUTH_PLUGINS value provider
  // so OAuthService can inject the plugin array on DI resolution.
  it('should include the OAUTH_PLUGINS value provider in the providers array', () => {
    const dm = OAuthModule.register(makeOptions())

    const hasPluginsProvider = (dm.providers ?? []).some(
      (p) =>
        typeof p === 'object' &&
        p !== null &&
        'provide' in p &&
        (p as { provide: unknown }).provide === OAUTH_PLUGINS
    )
    expect(hasPluginsProvider).toBe(true)
  })
})
