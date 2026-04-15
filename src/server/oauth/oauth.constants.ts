/**
 * NestJS injection token for the registered OAuth provider plugin array.
 *
 * Injected into {@link OAuthService} to resolve the correct plugin at runtime.
 * The value is an `OAuthProviderPlugin[]` built by the OAuthModule factory based
 * on the consumer's `oauth` configuration block.
 */
export const OAUTH_PLUGINS = Symbol('OAUTH_PLUGINS')
