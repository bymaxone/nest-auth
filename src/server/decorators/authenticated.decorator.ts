import { SetMetadata } from '@nestjs/common'

import { IS_PUBLIC_KEY } from './public.decorator'

/**
 * Marks a single handler as requiring authentication, overriding a class-level
 * {@link Public} on the controller it belongs to.
 *
 * `@Public()` sets its metadata to `true`, and the guards resolve it with
 * `getAllAndOverride([handler, class])` — handler first. Without a decorator that writes
 * `false`, a controller marked public at the class level could never carry an authenticated
 * route: adding `@UseGuards(JwtAuthGuard)` to the method changes nothing, because the guard
 * reads the public flag and returns before it looks at anything else. That is a silent
 * failure — the route mounts, the guard runs, and it lets everyone through.
 *
 * Pair it with the guards the route actually needs; this decorator only undoes the exemption.
 *
 * @example
 * ```typescript
 * \@Public()
 * \@Controller('password')
 * export class PasswordResetController {
 *   // …the public recovery endpoints…
 *
 *   \@Authenticated()
 *   \@UseGuards(JwtAuthGuard, UserStatusGuard)
 *   \@Post('change')
 *   async changePassword() {}
 * }
 * ```
 */
export const Authenticated = (): MethodDecorator & ClassDecorator =>
  SetMetadata(IS_PUBLIC_KEY, false)
