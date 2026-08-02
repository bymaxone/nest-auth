/**
 * Enforces that a repository answered within the tenant it was asked about.
 *
 * @layer Utility
 */

/**
 * Returns `user` only when it belongs to `tenantId`, and `null` otherwise.
 *
 * `IUserRepository.findByEmail` takes a `tenantId` and its contract says to scope by it — but
 * the repository is the host's and an interface can only ask. A single-tenant host writing
 * `findByEmail(email)` that ignores its second argument is the shape nobody notices, and under
 * one every distinct `tenantId` in a request body resolves the same account while deriving a
 * *different* HMAC-keyed identifier. That turns the brute-force lockout and the resend cooldown
 * — both keyed on `hmac(tenantId:email)` — into per-value budgets an attacker refills by
 * rotating a field they control, so the 5-attempt ceiling and the 60-second cooldown never
 * engage.
 *
 * Collapsing a cross-tenant answer to `null` puts those callers on the path they already have
 * for "no such account": the same generic error, the same dummy-KDF timing, the same silent
 * `Ok`. Nothing new is disclosed, and the account in tenant A stops being reachable through a
 * request naming tenant B whatever the repository returns.
 *
 * @param user - Whatever the repository answered, possibly `null`.
 * @param tenantId - The tenant the lookup was scoped to.
 * @returns The user when its tenant matches, else `null`.
 */
export function tenantScoped<T extends { tenantId: string }>(
  user: T | null,
  tenantId: string
): T | null {
  if (user === null) return null
  return user.tenantId === tenantId ? user : null
}
