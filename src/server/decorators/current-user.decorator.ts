import { createParamDecorator } from '@nestjs/common'
import type { ExecutionContext } from '@nestjs/common'

import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface'

/**
 * Extracts the authenticated user payload from the request, or a specific
 * field from that payload.
 *
 * Must be used on routes protected by {@link JwtAuthGuard} (or
 * {@link JwtPlatformGuard} for platform admin routes). On unprotected routes
 * `request.user` is undefined.
 *
 * The consumer is responsible for providing an explicit type annotation:
 *
 * @example
 * ```typescript
 * // Full payload
 * @CurrentUser() user: DashboardJwtPayload
 *
 * // Single field
 * @CurrentUser('sub') userId: string
 * @CurrentUser('tenantId') tenantId: string
 * ```
 *
 * @param property - Optional key to extract from the payload. When omitted the
 *   entire payload object is returned.
 */
export const CurrentUser = createParamDecorator(
  (property: keyof DashboardJwtPayload | undefined, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest<{ user?: DashboardJwtPayload }>()
    const user = request.user
    if (property !== undefined) {
      // eslint-disable-next-line security/detect-object-injection -- property is keyof DashboardJwtPayload, not user input
      return user?.[property]
    }
    return user
  }
)
