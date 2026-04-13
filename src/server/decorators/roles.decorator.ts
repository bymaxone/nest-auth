import { SetMetadata } from '@nestjs/common'

/**
 * Metadata key used by {@link RolesGuard} to read the required roles for a route.
 *
 * Read via `Reflector.getAllAndOverride(ROLES_KEY, [handler, class])`.
 */
export const ROLES_KEY = 'roles'

/**
 * Declares the role(s) required to access a route.
 *
 * The {@link RolesGuard} will deny access if the authenticated user's role
 * does not match at least one of the specified roles (including hierarchical
 * descendants configured in `roles.hierarchy`).
 *
 * @param roles - One or more role strings that grant access. An authenticated
 *   user with any of the listed roles (or a role that includes them in the
 *   denormalized hierarchy) will be allowed through.
 *
 * @example
 * ```typescript
 * @Roles('admin', 'owner')
 * @Get('/admin-panel')
 * adminPanel() { ... }
 * ```
 */
export const Roles = (...roles: string[]): MethodDecorator & ClassDecorator =>
  SetMetadata(ROLES_KEY, roles)
