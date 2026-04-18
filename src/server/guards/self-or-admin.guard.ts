import { HttpStatus, Inject, Injectable } from '@nestjs/common'
import type { CanActivate, ExecutionContext } from '@nestjs/common'
import type { Request } from 'express'

import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface'
import { hasRole } from '../utils/roles.util'

/**
 * Guard that grants access when the authenticated user is either the resource
 * owner (self-access) or holds the `'admin'` role in the configured hierarchy.
 *
 * Intended to be composed after {@link JwtAuthGuard}, which must populate
 * `req.user` before this guard runs.
 *
 * @remarks
 * **Multi-tenant ownership limitation:** This guard does NOT verify that the
 * target resource belongs to the same `tenantId` as the JWT. In multi-tenant
 * deployments the controller or service MUST additionally enforce ownership
 * against `req.user.tenantId` to prevent cross-tenant IDOR. This guard only
 * enforces the *identity* boundary (self vs. other), not the *tenant* boundary.
 *
 * **Admin role convention:** The literal `'admin'` role is checked against the
 * configured hierarchy. If the consuming application uses a different convention
 * (e.g. `'OWNER'`, `'SUPER_ADMIN'`), it must include `'admin'` as a synonym in
 * the hierarchy or wrap this guard with custom logic.
 *
 * **Session-hash validation:** When the route param value has exactly 64
 * characters and consists entirely of hex digits (`[a-fA-F0-9]`), it is treated
 * as a SHA-256 session hash. In that case, strict lowercase format
 * (`/^[a-f0-9]{64}$/`) is enforced. A value that looks like a hash but uses
 * uppercase hex digits is rejected with `TOKEN_INVALID / BAD_REQUEST` before any
 * comparison occurs.
 *
 * @example
 * ```typescript
 * // Protect a self-or-admin endpoint — JwtAuthGuard must run first.
 * @UseGuards(JwtAuthGuard, SelfOrAdminGuard)
 * @Delete('/users/:userId')
 * deleteUser(@Param('userId') id: string) { ... }
 *
 * // Session revocation — param is a SHA-256 hash; guard enforces lowercase hex.
 * @UseGuards(JwtAuthGuard, SelfOrAdminGuard)
 * @Delete('/sessions/:id')
 * revokeSession(@Param('id') sessionHash: string) { ... }
 * ```
 */
@Injectable()
export class SelfOrAdminGuard implements CanActivate {
  constructor(@Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<Request & { user?: DashboardJwtPayload }>()

    // Defensive — JwtAuthGuard should always run before this guard.
    if (request.user == null) {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID, HttpStatus.UNAUTHORIZED)
    }

    const rawParam = request.params['userId'] ?? request.params['id']

    if (rawParam === undefined) {
      throw new AuthException(AUTH_ERROR_CODES.INSUFFICIENT_ROLE, HttpStatus.FORBIDDEN)
    }

    // Express types params as string | string[]. Route params are always plain strings;
    // only query-string multi-value entries produce arrays. Reject the unexpected case
    // rather than silently picking an element, since arrays here indicate a routing anomaly.
    const paramValue = resolveParamString(rawParam)

    if (paramValue === undefined) {
      throw new AuthException(AUTH_ERROR_CODES.INSUFFICIENT_ROLE, HttpStatus.FORBIDDEN)
    }

    // When the value is 64 hex-looking characters, treat it as a SHA-256 session
    // hash and require strictly lowercase format. Uppercase hex is an unexpected
    // source — reject it early to prevent silent normalization masking comparison errors.
    if (isHexLooking(paramValue) && !STRICT_SHA256_RE.test(paramValue)) {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID, HttpStatus.BAD_REQUEST)
    }

    if (request.user.sub === paramValue) return true

    if (hasRole(request.user.role, 'admin', this.options.roles.hierarchy)) return true

    throw new AuthException(AUTH_ERROR_CODES.INSUFFICIENT_ROLE, HttpStatus.FORBIDDEN)
  }
}

/** Matches a valid SHA-256 hash — 64 strictly lowercase hex characters. */
const STRICT_SHA256_RE = /^[a-f0-9]{64}$/

/**
 * Returns the param string when it is a plain string, or `undefined` when the
 * value is an array (which should never occur for route params in Express).
 */
function resolveParamString(param: string | string[]): string | undefined {
  return typeof param === 'string' ? param : undefined
}

/**
 * Returns true when the value is exactly 64 characters long and every character
 * is a hex digit (upper or lower case). This is the gate condition that triggers
 * the strict-lowercase format check without misidentifying UUIDs, ULIDs, or other
 * user-ID formats that happen to be shorter or contain non-hex characters.
 */
function isHexLooking(value: string): boolean {
  return value.length === 64 && /^[a-fA-F0-9]{64}$/.test(value)
}
