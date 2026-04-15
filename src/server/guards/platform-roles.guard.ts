import { HttpStatus, Inject, Injectable } from '@nestjs/common'
import type { CanActivate, ExecutionContext } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import type { Request } from 'express'

import { BYMAX_AUTH_OPTIONS } from '../bymax-one-nest-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import { PLATFORM_ROLES_KEY } from '../decorators/platform-roles.decorator'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { PlatformJwtPayload } from '../interfaces/jwt-payload.interface'
import { hasRole } from '../utils/roles.util'

/**
 * Enforces role-based access control on platform admin routes using a
 * denormalized platform role hierarchy.
 *
 * Reads required roles from `@PlatformRoles(...)` metadata set on the handler
 * or controller class. If no roles are required the guard allows all
 * authenticated platform admin requests through.
 *
 * @remarks
 * **The platform hierarchy must be fully denormalized.** Each role must
 * explicitly list ALL transitive descendants — not just immediate children.
 * Example:
 * ```
 * { SUPER_ADMIN: ['ADMIN', 'SUPPORT'], ADMIN: ['SUPPORT'], SUPPORT: [] }
 * ```
 * A single-level lookup is performed in {@link hasRole}. Recursive traversal
 * is intentionally absent; a misconfigured hierarchy fails securely (deny).
 *
 * If `roles.platformHierarchy` is not configured in module options, all
 * role-protected routes are denied regardless of the user's role.
 *
 * @example
 * ```typescript
 * @UseGuards(PlatformJwtAuthGuard, PlatformRolesGuard)
 * @PlatformRoles('super_admin')
 * @Delete('/platform/users/:id')
 * deleteUser(@Param('id') id: string) { ... }
 * ```
 */
@Injectable()
export class PlatformRolesGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions
  ) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<string[] | undefined>(
      PLATFORM_ROLES_KEY,
      [context.getHandler(), context.getClass()]
    )

    // No role metadata → all authenticated platform admins may proceed.
    if (!requiredRoles || requiredRoles.length === 0) return true

    const request = context.switchToHttp().getRequest<Request & { user?: PlatformJwtPayload }>()
    const user = request.user

    // Ensure the request was authenticated by JwtPlatformGuard before role evaluation.
    // A missing user or non-platform token type means authentication failed, not authorization.
    if (!user || user.type !== 'platform') {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    const userRole = user.role

    const hierarchy = this.options.roles.platformHierarchy

    if (!hierarchy) {
      throw new AuthException(AUTH_ERROR_CODES.INSUFFICIENT_ROLE, HttpStatus.FORBIDDEN)
    }

    const allowed = requiredRoles.some((required) => hasRole(userRole, required, hierarchy))

    if (!allowed) {
      throw new AuthException(AUTH_ERROR_CODES.INSUFFICIENT_ROLE, HttpStatus.FORBIDDEN)
    }

    return true
  }
}
