import { Inject, Injectable } from '@nestjs/common'
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
 * **Tenant boundary:** when the route captures the tenant under `tenantId`, `tenant_id` or
 * `tenant`, every capture present must equal the token's `tenantId`; otherwise the request is
 * refused with `INSUFFICIENT_ROLE` before the self-or-admin decision is made. An id is only
 * unique within a tenant, and the `admin` role is held inside one, so neither identity nor role
 * reaches across the boundary. Captures that disagree with one another, are empty, or are arrays
 * name no tenant the token can equal and are refused; a wildcard capture arrives as an array of
 * the segments it matched, so it is refused even for an admin.
 *
 * **What the tenant check cannot see:** only those three capture names are read. A route that
 * names the tenant any other way, `{org}` for instance, is decided by identity and role alone, and
 * the handler must bind that capture to the token's tenant itself, as must a route with no tenant
 * capture. Where Express resolves a capture name used at two nesting levels, the inner value wins
 * (measured on Express 5, with or without `mergeParams`), and a capture on a parent router
 * mounted without `mergeParams` is not visible to the inner route, so the guard sees none.
 * Nest controllers compose the full path on one route and are not affected by the second.
 *
 * **The id:** the `userId` or `id` capture must be one non-empty path segment. An empty value or
 * one carrying a slash (a decoded `%2F`) is refused with `INSUFFICIENT_ROLE`, for an admin too and
 * for an owner whose own id contains a slash.
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
 *
 * @layer Guard
 */
@Injectable()
export class SelfOrAdminGuard implements CanActivate {
  constructor(@Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<Request & { user?: DashboardJwtPayload }>()

    // Defensive — JwtAuthGuard should always run before this guard.
    if (request.user == null) {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    // The tenant comes before the id: a request for another tenant never reaches the decision
    // below, and what it is refused for does not depend on the rest of the route.
    if (!capturesOnlyTokenTenant(request.params, request.user.tenantId)) {
      throw new AuthException(AUTH_ERROR_CODES.INSUFFICIENT_ROLE)
    }

    const rawParam = request.params['userId'] ?? request.params['id']

    if (rawParam === undefined) {
      throw new AuthException(AUTH_ERROR_CODES.INSUFFICIENT_ROLE)
    }

    // Express types params as string | string[]. Route params are always plain strings;
    // only query-string multi-value entries produce arrays. Reject the unexpected case
    // rather than silently picking an element, since arrays here indicate a routing anomaly.
    const paramValue = resolveParamString(rawParam)

    if (paramValue === undefined) {
      throw new AuthException(AUTH_ERROR_CODES.INSUFFICIENT_ROLE)
    }

    // The id names one resource, so it is one non-empty path segment. An empty value, or a decoded
    // `%2F` that carries a slash, spans segments the route never matched, and not even an admin is
    // admitted on it.
    if (paramValue === '' || paramValue.includes('/')) {
      throw new AuthException(AUTH_ERROR_CODES.INSUFFICIENT_ROLE)
    }

    // When the value is 64 hex-looking characters, treat it as a SHA-256 session
    // hash and require strictly lowercase format. Uppercase hex is an unexpected
    // source — reject it early to prevent silent normalization masking comparison errors.
    if (isHexLooking(paramValue) && !STRICT_SHA256_RE.test(paramValue)) {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    if (request.user.sub === paramValue) return true

    if (hasRole(request.user.role, 'admin', this.options.roles.hierarchy)) return true

    throw new AuthException(AUTH_ERROR_CODES.INSUFFICIENT_ROLE)
  }
}

/**
 * Whether every tenant capture on the route (`tenantId`, `tenant_id` or `tenant`) equals the
 * token's tenant. A route with none passes. A capture that is empty, or that differs from the
 * token's tenant, fails; an array or any other non-string always differs, and a token with no
 * tenant cannot equal any capture.
 */
function capturesOnlyTokenTenant(
  params: Request['params'],
  tokenTenant: string | undefined
): boolean {
  const captures: unknown[] = [params.tenantId, params.tenant_id, params.tenant]
  return captures.every(
    (captured) => captured === undefined || (captured !== '' && captured === tokenTenant)
  )
}

/** Matches a valid SHA-256 hash — 64 strictly lowercase hex characters. */
// Stryker disable next-line Regex: this pattern is only ever tested against a value that already passed isHexLooking() (exactly 64 chars), so the `^` and `$` anchors are redundant — on a 64-char input "all 64 are lowercase hex" is identical to "starts/ends with 64 lowercase hex"
const STRICT_SHA256_RE = /^[a-f0-9]{64}$/

/**
 * Returns the param string when it is a plain string, or `undefined` when the value is an array.
 *
 * **An array is not the impossible case it looks like.** Express 5 (path-to-regexp 8) fills a
 * NAMED WILDCARD's param with an array of path segments — `['abc']` for one segment, measured,
 * and `['a','b','c']` for three. So any consumer who writes `@Get('files/*path')` behind this
 * guard reaches this arm on every request, including the single-segment URLs that look exactly
 * like a plain param.
 *
 * Refusing is deliberate, not defensive. The alternative is picking an element — comparing an
 * identity against one segment of a path the caller chose, which is not the check this guard
 * claims to be, and which would ADMIT a request whose remaining segments nobody looked at.
 * Driven over both shapes in `test/e2e/host-mounted-guards.e2e-spec.ts`.
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
  // Stryker disable next-line ConditionalExpression,Regex: the length check and the anchored {64} regex are mutually-redundant guards — each independently forces "exactly 64 hex chars", so mutating either one alone (dropping the length test, or removing an anchor) cannot change the result
  return value.length === 64 && /^[a-fA-F0-9]{64}$/.test(value)
}
