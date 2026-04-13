import { HttpStatus, Inject, Injectable } from '@nestjs/common'
import type { CanActivate, ExecutionContext } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import type { Request } from 'express'

import { BYMAX_AUTH_OPTIONS } from '../bymax-one-nest-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import { ROLES_KEY } from '../decorators/roles.decorator'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface'
import { hasRole } from '../utils/roles.util'

/**
 * Enforces role-based access control using a denormalized role hierarchy.
 *
 * Reads required roles from `@Roles(...)` metadata set on the handler or
 * controller class. If no roles are required the guard allows all authenticated
 * requests through.
 *
 * @remarks
 * **The hierarchy must be fully denormalized.** Each role must explicitly list
 * ALL transitive descendants — not just immediate children. Example:
 * ```
 * { OWNER: ['ADMIN', 'MEMBER', 'VIEWER'], ADMIN: ['MEMBER', 'VIEWER'], ... }
 * ```
 * A single-level lookup is performed in {@link hasRole}. Recursive traversal
 * is intentionally absent; a misconfigured hierarchy fails securely (deny).
 *
 * @example
 * ```typescript
 * @UseGuards(JwtAuthGuard, RolesGuard)
 * @Roles('admin')
 * @Delete('/users/:id')
 * deleteUser(@Param('id') id: string) { ... }
 * ```
 */
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions
  ) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<string[] | undefined>(ROLES_KEY, [
      context.getHandler(),
      context.getClass()
    ])

    // No role metadata → all authenticated users may proceed.
    if (!requiredRoles || requiredRoles.length === 0) return true

    const request = context.switchToHttp().getRequest<Request & { user?: DashboardJwtPayload }>()
    const userRole = request.user?.role

    if (!userRole) {
      throw new AuthException(AUTH_ERROR_CODES.INSUFFICIENT_ROLE, HttpStatus.FORBIDDEN)
    }

    const hierarchy = this.options.roles.hierarchy
    const allowed = requiredRoles.some((required) => hasRole(userRole, required, hierarchy))

    if (!allowed) {
      throw new AuthException(AUTH_ERROR_CODES.INSUFFICIENT_ROLE, HttpStatus.FORBIDDEN)
    }

    return true
  }
}
