/**
 * @fileoverview The hook context a dashboard route hands to a service that reports an event.
 *
 * @layer Util
 */

import type { Request } from 'express'

import { resolveClientAddress } from './client-address'
import { sanitizeHeaders } from './sanitize-headers'
import type { HookContext } from '../interfaces/auth-hooks.interface'

/**
 * Builds the context for an event a dashboard caller caused.
 *
 * @param request - The incoming request.
 * @param caller - The verified token's subject and tenant.
 * @returns The context, with the headers sanitized.
 */
export function dashboardHookContext(
  request: Request,
  caller: { sub: string; tenantId: string }
): HookContext {
  return {
    plane: 'dashboard',
    userId: caller.sub,
    tenantId: caller.tenantId,
    ip: resolveClientAddress(request),
    userAgent: request.headers['user-agent'] ?? '',
    sanitizedHeaders: sanitizeHeaders(request.headers)
  }
}
