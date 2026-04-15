/**
 * NestJS injection tokens for @bymax-one/nest-auth.
 *
 * All tokens are `Symbol`-based to avoid collisions with string tokens used
 * by the host application or other libraries. Never substitute these with
 * string literals — Symbol tokens provide guaranteed uniqueness.
 *
 * @example
 * ```typescript
 * // Host application — provide the user repository
 * {
 *   provide: BYMAX_AUTH_USER_REPOSITORY,
 *   useClass: PrismaUserRepository,
 * }
 * ```
 */

/**
 * Token for the resolved `BymaxAuthModuleOptions` object.
 * Injected into every service that needs access to the module configuration.
 */
export const BYMAX_AUTH_OPTIONS = Symbol('BYMAX_AUTH_OPTIONS')

/**
 * Token for the `IUserRepository` implementation.
 * **Required** — must be provided by the host application.
 * Bound to a class that implements `IUserRepository`.
 */
export const BYMAX_AUTH_USER_REPOSITORY = Symbol('BYMAX_AUTH_USER_REPOSITORY')

/**
 * Token for the `IPlatformUserRepository` implementation.
 * **Conditional** — required when `platform.enabled = true`.
 * Bound to a class that implements `IPlatformUserRepository`.
 */
export const BYMAX_AUTH_PLATFORM_USER_REPOSITORY = Symbol('BYMAX_AUTH_PLATFORM_USER_REPOSITORY')

/**
 * Token for the `IEmailProvider` implementation.
 * **Required** — must be provided by the host application.
 * Bound to a class that implements `IEmailProvider`.
 */
export const BYMAX_AUTH_EMAIL_PROVIDER = Symbol('BYMAX_AUTH_EMAIL_PROVIDER')

/**
 * Token for the `IAuthHooks` implementation.
 * **Optional** — when not provided, all hooks are silently skipped.
 * Bound to a class that implements `IAuthHooks`.
 */
export const BYMAX_AUTH_HOOKS = Symbol('BYMAX_AUTH_HOOKS')

/**
 * Token for the `ioredis` Redis client instance.
 * **Required** — must be provided by the host application.
 * Bound to an `ioredis` `Redis` instance configured for the host environment.
 */
export const BYMAX_AUTH_REDIS_CLIENT = Symbol('BYMAX_AUTH_REDIS_CLIENT')
