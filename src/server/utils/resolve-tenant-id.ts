import type { Request } from 'express'

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'

/**
 * Resolves the tenant a request belongs to, preferring the configured resolver over the value
 * the caller supplied in the body.
 *
 * When `cookies`-style multi-tenancy is driven by the request itself — a subdomain, a header,
 * a mapped hostname — the deployment configures `tenantIdResolver` and the option promises
 * that the resolved value wins and the body's `tenantId` is ignored. That promise is what
 * prevents tenant spoofing: without it, any caller can name any tenant and every tenant-scoped
 * lookup below runs against a scope they chose.
 *
 * Because a configured resolver makes the body's value dead weight, the DTOs mark `tenantId`
 * optional and a caller may omit it. The two states the request can arrive in therefore differ:
 * with a resolver the field must be absent, and without one it is the only thing that can name a
 * tenant, so its absence is a request that cannot be scoped. That case is refused rather than
 * defaulted, because inventing a tenant name would silently gather into one scope every account
 * a misconfigured deployment created.
 *
 * **A body that names a tenant under a configured resolver is refused, not ignored.** It used to
 * be accepted and discarded, which is the worst of the three available answers: the caller
 * believes it chose a tenant, the server put the account somewhere else, and nothing in the
 * response says so. The divergence sits on the tenancy boundary the resolver exists to defend —
 * a registration answering `201` for `tenantId: "victim-tenant"` while creating the account in
 * `default` is misdirection, even though no privilege crossed. Whitelist validation already
 * refuses `role` and `status` on the principle that a property which does not participate should
 * not exist; under a resolver, `tenantId` does not participate, and this makes the principle
 * config-aware rather than making an exception to it.
 *
 * The asymmetry is deliberate and is why the refusal is conditional: refusing the field outright
 * would break every deployment without a resolver, where it is the participation mechanism.
 *
 * `null` counts as absent, and the distinction is not academic: `@IsOptional()` skips validation
 * for `null` as well as for `undefined`, so a caller may send `tenantId: null` and reach here past
 * every DTO constraint. Treating it as a value would carry `null` into the tenant-scoped lookups
 * and into the Redis and HMAC keys built from it.
 *
 * This lives as a shared helper rather than a method on one service because the promise has to
 * hold for **every** tenant-scoped flow. It previously lived inside `AuthService`, so only
 * login and register honoured it while password reset and email verification read the body
 * value verbatim — one rule with two implementations is how the gap opened in the first place.
 *
 * @param dtoTenantId - The tenant the caller named in the request body, if any. `null` and
 *   `undefined` both mean the body named none.
 * @param req - The request, handed to the configured resolver.
 * @param resolver - The configured `tenantIdResolver`, if any.
 * @returns The resolved tenant when a resolver is configured, otherwise the body's value.
 * @throws {@link AuthException} with `VALIDATION` when no resolver is configured and the body
 *   named no tenant, so nothing in the request can scope it — or when a resolver IS configured
 *   and the body named one anyway, which the deployment does not honour.
 */
export async function resolveTenantId(
  dtoTenantId: string | null | undefined,
  req: Request,
  resolver?: (req: Request) => string | Promise<string>
): Promise<string> {
  if (resolver) {
    // `null` and `undefined` both mean the body named no tenant, and neither is refused: the
    // caller asserted nothing, so there is nothing to contradict. Only a value the caller chose
    // reaches the refusal.
    if (dtoTenantId !== undefined && dtoTenantId !== null) {
      throw new AuthException(AUTH_ERROR_CODES.VALIDATION, [
        {
          field: 'tenantId',
          message: 'tenantId is decided by this deployment and must not be sent'
        }
      ])
    }

    return await resolver(req)
  }
  if (dtoTenantId === undefined || dtoTenantId === null) {
    throw new AuthException(AUTH_ERROR_CODES.VALIDATION, [
      {
        field: 'tenantId',
        message: 'tenantId is required unless the deployment configures tenantIdResolver'
      }
    ])
  }
  return dtoTenantId
}
