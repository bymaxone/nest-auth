import { SetMetadata } from '@nestjs/common'

/**
 * Metadata key used by {@link JwtAuthGuard} to identify public (unauthenticated) routes.
 *
 * Read via `Reflector.getAllAndOverride(IS_PUBLIC_KEY, [handler, class])`.
 *
 * A `Symbol` rather than the string `'isPublic'`, matching `SKIP_MFA_KEY` and the project's
 * injection-token rule. The literal is the one the canonical NestJS documentation uses in its
 * `@Public()` example, so a host that writes its own following those docs wrote the SAME
 * metadata key — and every route it marked public for its own guard was then also public to
 * `JwtAuthGuard` wherever the host mounts it. Both decorators mean "skip auth", so the
 * collision did not invert anyone's intent, but a key that gates authentication should not be
 * a value the ecosystem hands out by convention.
 */
export const IS_PUBLIC_KEY = Symbol('bymax:isPublic')

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
