import type { Request } from 'express'

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
 * This lives as a shared helper rather than a method on one service because the promise has to
 * hold for **every** tenant-scoped flow. It previously lived inside `AuthService`, so only
 * login and register honoured it while password reset and email verification read the body
 * value verbatim — one rule with two implementations is how the gap opened in the first place.
 *
 * @param dtoTenantId - The tenant the caller named in the request body.
 * @param req - The request, handed to the configured resolver.
 * @param resolver - The configured `tenantIdResolver`, if any.
 * @returns The resolved tenant when a resolver is configured, otherwise the body's value.
 */
export async function resolveTenantId(
  dtoTenantId: string,
  req: Request,
  resolver?: (req: Request) => string | Promise<string>
): Promise<string> {
  if (resolver) {
    return await resolver(req)
  }
  return dtoTenantId
}
