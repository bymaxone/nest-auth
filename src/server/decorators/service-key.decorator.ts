/**
 * @fileoverview `@ServiceKey()` — authenticates a route by service API key.
 *
 * @layer Decorator
 */

import { SetMetadata, UseGuards, applyDecorators } from '@nestjs/common'

import { ApiKeyScopes } from './api-key-scopes.decorator'
import { IS_PUBLIC_KEY } from './public.decorator'
import { ApiKeyGuard } from '../guards/api-key.guard'

/**
 * Makes a route reachable by a machine caller holding a service key with the given scopes.
 *
 * Three things in one decorator, so they cannot be separated by mistake:
 *
 * 1. the scopes the key must hold ({@link ApiKeyScopes});
 * 2. the route stops asking for a user JWT — `JwtAuthGuard` and `JwtPlatformGuard` skip a route
 *    carrying the public marker, so a global JWT guard does not refuse the machine caller;
 * 3. `ApiKeyGuard` is bound to the route and is the ONLY authenticator in front of it.
 *
 * "Public" here means "not a user route", never "unauthenticated": the key guard refuses a
 * missing or invalid key on every request.
 *
 * @param scopes - The required scopes. At least one, each from `apiKeys.scopes`.
 *
 * @example
 * ```typescript
 * @ServiceKey('read')
 * @Get('videos')
 * list(@CurrentApiKey() key: ApiKeyPrincipal) { ... }
 * ```
 */
export const ServiceKey = (...scopes: string[]): MethodDecorator & ClassDecorator =>
  applyDecorators(SetMetadata(IS_PUBLIC_KEY, true), ApiKeyScopes(...scopes), UseGuards(ApiKeyGuard))
