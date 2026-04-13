import { SetMetadata } from '@nestjs/common'

/**
 * Metadata key used by {@link JwtAuthGuard} to identify public (unauthenticated) routes.
 *
 * Read via `Reflector.getAllAndOverride(IS_PUBLIC_KEY, [handler, class])`.
 */
export const IS_PUBLIC_KEY = 'isPublic'

/**
 * Marks a route as public — JwtAuthGuard skips token validation entirely.
 *
 * Apply at the controller class level to make all routes public, or at the
 * individual handler level to make a single route public.
 *
 * @example
 * ```typescript
 * @Public()
 * @Post('/register')
 * register(@Body() dto: RegisterDto) { ... }
 * ```
 */
export const Public = (): MethodDecorator & ClassDecorator => SetMetadata(IS_PUBLIC_KEY, true)
