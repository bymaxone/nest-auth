/**
 * @fileoverview `@ApiKeyScopes()` — declares the scopes a service-key route requires.
 *
 * @layer Decorator
 */

import { SetMetadata } from '@nestjs/common'

/** Metadata key under which a route's required scopes are stored. */
export const API_KEY_SCOPES_KEY = Symbol('bymax:apiKeyScopes')

/**
 * Declares the scopes a route requires. A key must hold ALL of them.
 *
 * The low-level declaration, for a host that binds `ApiKeyGuard` at controller level or
 * globally. Most routes want {@link ServiceKey}, which also lets the route past the user JWT
 * guards and binds the guard, so the three cannot be separated by mistake.
 *
 * The most specific declaration wins (handler over class). An empty list counts as no
 * declaration, and a route with no declaration is refused.
 *
 * @param scopes - The required scopes, each from `apiKeys.scopes`.
 *
 * @example
 * ```typescript
 * @UseGuards(ApiKeyGuard)
 * @ApiKeyScopes('read')
 * @Get('videos')
 * list() { ... }
 * ```
 */
export const ApiKeyScopes = (...scopes: string[]): MethodDecorator & ClassDecorator =>
  SetMetadata(API_KEY_SCOPES_KEY, scopes)
