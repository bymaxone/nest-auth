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
 *
 * @layer Constants
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
 * Injection token for the password breach checker (`IPasswordBreachChecker`).
 *
 * Optional. When the consumer supplies none, the module registers a checker that approves
 * every password, so the credential path never reaches the network unless asked to.
 */
export const BYMAX_AUTH_BREACH_CHECKER = Symbol('BYMAX_AUTH_BREACH_CHECKER')

/**
 * Token for the `ioredis` Redis client instance.
 * **Required** — must be provided by the host application.
 * Bound to an `ioredis` `Redis` instance configured for the host environment.
 */
export const BYMAX_AUTH_REDIS_CLIENT = Symbol('BYMAX_AUTH_REDIS_CLIENT')

/**
 * Token carrying which of this library's controllers the module actually registered.
 *
 * Internal, and it exists for one reader: the OpenAPI contributor. Registration is decided
 * synchronously, from the `controllers` argument to `registerAsync()`, before any factory runs —
 * `BymaxAuthModule` refuses a `controllers` key inside the factory's return value for exactly
 * that reason. So the resolved options cannot carry it, and a contributor that guessed would
 * name handlers the document does not contain, which fails a consumer's document build rather
 * than degrading.
 */
export const BYMAX_AUTH_REGISTERED_CONTROLLERS = Symbol('BYMAX_AUTH_REGISTERED_CONTROLLERS')
