/**
 * @fileoverview The tenant rule of the MFA flows: a dashboard call carries a non-empty tenant, a
 * platform call carries none.
 *
 * @layer Utility
 */

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'

/**
 * The `VALIDATION` detail both plane-tenant guards answer with.
 *
 * One string, because the two halves are one rule read from opposite sides — a dashboard call
 * without a tenant and a platform call with one are the same mistake, made on the wrong plane.
 * A caller that starts seeing this needs to know both halves whichever half it tripped, and two
 * copies drift the moment one is reworded.
 */
const PLANE_TENANT_MESSAGE =
  'tenantId must be a non-empty value on the dashboard plane and absent on the platform plane'

/**
 * Asserts a dashboard-plane call carries a tenant, narrowing it to `string` for the caller.
 *
 * This is the dashboard half of {@link assertPlaneTenant}, separate because an assertion
 * signature is the only way to state "past this point the tenant is present" to the type system.
 * `IUserRepository.findById` requires the tenant, and the account read behind the MFA flows sits
 * under a `context === 'dashboard'` branch where a `void` guard run earlier in the caller has
 * narrowed nothing. Without this the branch would pass `string | undefined` into a `string`
 * parameter, which is the tenant-blind read the guard exists to stop.
 *
 * @param tenantId - The tenant supplied by the caller, if any.
 * @throws {@link AuthException} `VALIDATION` (400) when it is missing or blank.
 */
export function assertDashboardTenant(tenantId: string | undefined): asserts tenantId is string {
  if (tenantId === undefined || tenantId === '') {
    // A dashboard call needs a non-EMPTY tenant, not merely a present one: a blank tenant builds
    // `dashboard:0::{userId}`, a third keyspace distinct from every real tenant's — and an empty
    // string is exactly what an unset environment variable becomes by the time it reaches this
    // call site.
    throw new AuthException(AUTH_ERROR_CODES.VALIDATION, [
      {
        field: 'tenantId',
        message: PLANE_TENANT_MESSAGE
      }
    ])
  }
}

/**
 * A dashboard MFA flow MUST carry the tenant it was authenticated in; a platform flow MUST NOT.
 *
 * The controller sources the tenant from the verified JWT, which always carries a validated
 * `tenantId`, so this never trips through the HTTP surface. It guards the OTHER caller:
 * `MfaService` is a public API, and a host wiring it directly — or a future SSO path — could hand
 * a dashboard `userId` with no tenant, which would silently reach the tenant-blind account read
 * and key derivation. Refuse it here, naming the field, rather than let it degrade to a
 * tenant-less lookup, which is exactly the fallback an attacker would aim for.
 *
 * @param context - The identity plane the call is on.
 * @param tenantId - The tenant supplied by the caller, if any.
 * @throws {@link AuthException} `VALIDATION` (400) when a dashboard call omits the tenant, or a
 *   platform call supplies one.
 */
export function assertPlaneTenant(context: 'dashboard' | 'platform', tenantId?: string): void {
  if (context === 'dashboard') {
    // Stryker disable CallExpression: equivalent on every reachable path. All five callers of
    // this helper follow it with `MfaRecordService.loadAccount`, which repeats
    // `assertDashboardTenant` before its read, and nothing observable happens in between (the
    // only statement there is a platform-arm guard). Deleting this call refuses the same
    // dashboard flows with the same code, one frame later. Kept rather than removed because the
    // alternative is a helper named `assertPlaneTenant` whose dashboard arm asserts nothing; the
    // duplicate in `loadAccount` cannot go instead, since its `asserts tenantId is string`
    // narrowing is what lets the repository read typecheck. Block form because the reason does
    // not fit on one line, and a wrapped `next-line` binds to its own continuation.
    assertDashboardTenant(tenantId)
    // Stryker restore CallExpression
    return
  }
  if (tenantId !== undefined) {
    // The platform plane refuses any tenant at all, blank included: a platform admin is not
    // scoped to one, so a supplied tenant means the caller is on the wrong plane.
    throw new AuthException(AUTH_ERROR_CODES.VALIDATION, [
      {
        field: 'tenantId',
        message: PLANE_TENANT_MESSAGE
      }
    ])
  }
}
