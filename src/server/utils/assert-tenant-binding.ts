/**
 * @fileoverview Tenant binding for credentials presented on a transport that has no Express request.
 *
 * @layer Utility
 */

import { handshakeRequest } from './handshake-request'
import type { HandshakeLike } from './handshake-request'
import type { ResolvedOptions } from '../config/resolved-options'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'

/**
 * Whether `enforceTenantBinding` is in force: exactly `true`, with a resolver to compare against.
 *
 * `resolveOptions` refuses the flag without a resolver at startup, so the second half is the
 * defensive twin of that check rather than a reachable state.
 *
 * @param options - Resolved module options.
 */
export function tenantBindingEnforced(
  options: Pick<ResolvedOptions, 'enforceTenantBinding' | 'tenantIdResolver'>
): boolean {
  return options.enforceTenantBinding === true && options.tenantIdResolver !== undefined
}

/**
 * Refuses a credential whose tenant is not the one the non-HTTP request resolves to — the twin of
 * the binding in {@link JwtAuthGuard} for a transport that has no Express request.
 *
 * The resolver is handed {@link handshakeRequest}, which carries only `headers`, `url` and
 * `hostname`. Anything it cannot answer from those (it throws, or returns something other than
 * `tenantId`, including nothing) is a refusal: a binding that cannot be evaluated must not admit.
 * Surfaced as `TOKEN_INVALID`, as on HTTP, to open no oracle.
 *
 * A no-op when {@link tenantBindingEnforced} is false.
 *
 * @param options - Resolved module options.
 * @param handshake - The connecting request: a handshake, or any object with `headers` and `url`.
 * @param tenantId - The tenant the credential was issued for.
 * @throws AuthException `TOKEN_INVALID` on a mismatch or a resolver that cannot answer.
 */
export async function assertTenantBinding(
  options: Pick<ResolvedOptions, 'enforceTenantBinding' | 'tenantIdResolver' | 'isTrustedProxy'>,
  handshake: HandshakeLike,
  tenantId: string
): Promise<void> {
  const resolver = options.tenantIdResolver
  if (options.enforceTenantBinding !== true || !resolver) return
  let requestTenant: string
  try {
    requestTenant = await resolver(handshakeRequest(handshake, options.isTrustedProxy))
  } catch {
    throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
  }
  if (requestTenant !== tenantId) {
    throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
  }
}
