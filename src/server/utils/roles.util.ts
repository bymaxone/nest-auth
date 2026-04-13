/**
 * Checks whether a user role satisfies a required role in a denormalized hierarchy.
 *
 * @param userRole - The role currently held by the user (e.g. `'ADMIN'`).
 * @param requiredRole - The minimum role required to access the resource (e.g. `'MEMBER'`).
 * @param hierarchy - A flat map of role → all roles it inherits (transitively).
 *   **IMPORTANT:** The hierarchy must be fully denormalized — each key must list every
 *   descendant role it can act as, not just its direct children. This function performs a
 *   single-level lookup (`hierarchy[userRole].includes(requiredRole)`), NOT recursive
 *   traversal. Pre-compute the denormalized hierarchy at startup (e.g. in `resolveOptions`)
 *   and inject it into guards.
 * @returns `true` if the user has the required role or inherits it; `false` otherwise.
 *
 * @example
 * ```typescript
 * // Denormalized hierarchy where OWNER > ADMIN > MEMBER > VIEWER
 * const hierarchy = {
 *   OWNER: ['ADMIN', 'MEMBER', 'VIEWER'],
 *   ADMIN: ['MEMBER', 'VIEWER'],
 *   MEMBER: ['VIEWER'],
 *   VIEWER: [],
 * }
 *
 * hasRole('ADMIN', 'MEMBER', hierarchy)  // true  — ADMIN inherits MEMBER
 * hasRole('ADMIN', 'OWNER', hierarchy)   // false — ADMIN does not inherit OWNER
 * hasRole('OWNER', 'OWNER', hierarchy)   // true  — exact match
 * ```
 */
export function hasRole(
  userRole: string,
  requiredRole: string,
  hierarchy: Record<string, string[]>
): boolean {
  if (userRole === requiredRole) return true
  if (!Object.hasOwn(hierarchy, userRole)) return false
  // eslint-disable-next-line security/detect-object-injection -- guarded by Object.hasOwn above; userRole comes from a verified JWT claim
  const inherited = hierarchy[userRole]
  // noUncheckedIndexedAccess makes `inherited` typed as `string[] | undefined`;
  // the Object.hasOwn guard above ensures it is defined at runtime.
  return inherited !== undefined && inherited.includes(requiredRole)
}
