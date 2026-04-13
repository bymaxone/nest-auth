/**
 * Augmented Express Request types for authenticated routes in @bymax-one/nest-auth.
 *
 * Guards attach the decoded and validated JWT payload to `request.user` after
 * successful token verification. Controllers and downstream decorators should
 * use these types instead of the plain `Request` to get typed access to the
 * authenticated identity.
 */

import type { Request } from 'express'

import type { DashboardJwtPayload, PlatformJwtPayload } from './jwt-payload.interface'

/**
 * Express request augmented with a verified dashboard user JWT payload.
 *
 * @remarks
 * Uses `interface extends Request` (not an intersection type) to give nominal
 * protection against Passport.js declaration merging, which can override
 * `Request.user` with `any` when `@types/passport` is installed.
 *
 * The `user` property is populated by the dashboard authentication guard
 * (`DashboardAuthGuard`) after it verifies and decodes the Bearer token.
 * Accessing `request.user` before the guard runs yields `undefined` at runtime;
 * controllers should never be reached without the guard in place.
 */
export interface AuthenticatedRequest extends Request {
  /**
   * Decoded and validated dashboard JWT payload.
   * Set by `DashboardAuthGuard` — guaranteed to be present inside guarded routes.
   */
  user: DashboardJwtPayload
}

/**
 * Express request augmented with a verified platform administrator JWT payload.
 *
 * @remarks
 * Uses `interface extends Request` for the same reason as {@link AuthenticatedRequest}.
 * Only routes protected by `PlatformAuthGuard` should use this type.
 */
export interface PlatformAuthenticatedRequest extends Request {
  /**
   * Decoded and validated platform JWT payload.
   * Set by `PlatformAuthGuard` — guaranteed to be present inside guarded routes.
   */
  user: PlatformJwtPayload
}
