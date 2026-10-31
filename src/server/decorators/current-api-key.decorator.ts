/**
 * @fileoverview `@CurrentApiKey()` — injects the verified service key into a handler.
 *
 * @layer Decorator
 */

import { createParamDecorator } from '@nestjs/common'
import type { ExecutionContext } from '@nestjs/common'

import type { ApiKeyPrincipal } from '../interfaces/api-key-repository.interface'

/**
 * Injects the {@link ApiKeyPrincipal} `ApiKeyGuard` attached to the request.
 *
 * Only meaningful after the guard ran; `undefined` on a route the guard did not admit.
 *
 * @example
 * ```typescript
 * @ServiceKey('read')
 * @Get('videos')
 * list(@CurrentApiKey() key: ApiKeyPrincipal) { return this.videos.forKey(key.id) }
 * ```
 */
export const CurrentApiKey = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): ApiKeyPrincipal | undefined =>
    ctx.switchToHttp().getRequest<{ apiKey?: ApiKeyPrincipal }>().apiKey
)
