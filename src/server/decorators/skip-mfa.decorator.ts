import { SetMetadata } from '@nestjs/common'

/**
 * Metadata key used by {@link MfaRequiredGuard} to identify routes that
 * should bypass MFA verification, even when the user has MFA enabled.
 *
 * A `Symbol` key prevents namespace collisions with other libraries or
 * consuming application code that may use `SetMetadata` for unrelated purposes.
 *
 * Read via `Reflector.getAllAndOverride(SKIP_MFA_KEY, [handler, class])`.
 *
 * @remarks
 * **Duplicate-bundle caveat:** `Symbol()` instances are unique per module
 * evaluation. If `@bymax-one/nest-auth` is accidentally bundled twice (e.g.
 * conflicting versions in a monorepo), the two `Symbol('skipMfa')` instances
 * are not equal. A custom guard that imports `SKIP_MFA_KEY` from a different
 * bundle copy than the one that ran `@SkipMfa()` will fail to find the metadata
 * and silently skip the bypass. Ensure only a single version of the library is
 * installed (use `pnpm why @bymax-one/nest-auth` to verify).
 */
export const SKIP_MFA_KEY = Symbol('skipMfa')

/**
 * Marks a route as exempt from the `MfaRequiredGuard` check.
 *
 * Apply to endpoints that must be accessible to users who have MFA enabled
 * but have not yet completed the MFA challenge for the current session
 * (e.g. the MFA challenge endpoint itself, or an account-recovery flow).
 *
 * @remarks
 * This decorator only takes effect when `MfaRequiredGuard` is active on the
 * route (via `@UseGuards(MfaRequiredGuard)` or a global guard registration).
 * Without the guard, applying `@SkipMfa()` is a no-op — other routes do not
 * automatically gain MFA enforcement simply because this decorator is present
 * on some routes.
 *
 * @example
 * ```typescript
 * @SkipMfa()
 * @Post('/mfa/challenge')
 * challenge(@Body() dto: MfaChallengeDto) { ... }
 * ```
 */
export const SkipMfa = (): MethodDecorator & ClassDecorator => SetMetadata(SKIP_MFA_KEY, true)
