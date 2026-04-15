import { SetMetadata } from '@nestjs/common'

/**
 * Metadata key (Symbol) used by {@link PlatformRolesGuard} to read the required platform
 * roles for a route.
 *
 * Read via `Reflector.getAllAndOverride(PLATFORM_ROLES_KEY, [handler, class])`.
 */
export const PLATFORM_ROLES_KEY: unique symbol = Symbol('platformRoles')

/**
 * Declares the platform role(s) required to access a platform admin route.
 *
 * The {@link PlatformRolesGuard} will deny access if the authenticated platform
 * admin's role does not match at least one of the specified roles (including
 * hierarchical descendants configured in `roles.platformHierarchy`).
 *
 * @param roles - One or more platform role strings that grant access. An
 *   authenticated admin with any of the listed roles (or a role that includes
 *   them in the denormalized platform hierarchy) will be allowed through.
 *
 * @example
 * ```typescript
 * @PlatformRoles('super_admin', 'support')
 * @Get('/platform/users')
 * listUsers() { ... }
 * ```
 */
export const PlatformRoles = (...roles: string[]): MethodDecorator & ClassDecorator =>
  SetMetadata(PLATFORM_ROLES_KEY, roles)
