import {
  Inject,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Req,
  UseGuards,
  UsePipes,
  UseInterceptors
} from '@nestjs/common'
import { Throttle } from '@nestjs/throttler'
import type { Request } from 'express'

import { AUTH_THROTTLE_CONFIGS } from '../constants/throttle-configs'
import { sha256 } from '../crypto/secure-token'
import { AuthRateLimit } from '../decorators/auth-rate-limit.decorator'
import { CurrentUser } from '../decorators/current-user.decorator'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRateLimitGuard } from '../guards/auth-rate-limit.guard'
import { JwtAuthGuard } from '../guards/jwt-auth.guard'
import { TrustedOriginGuard } from '../guards/trusted-origin.guard'
import { UserStatusGuard } from '../guards/user-status.guard'
import { NoStoreInterceptor } from '../interceptors/no-store.interceptor'
import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface'
import { createAuthValidationPipe } from '../pipes/auth-validation.pipe'
import type { SessionInfo } from '../services/session.service'
import { SessionService } from '../services/session.service'
import { TokenDeliveryService } from '../services/token-delivery.service'

// ---------------------------------------------------------------------------
// SessionController
// ---------------------------------------------------------------------------

/**
 * Session management controller for dashboard users.
 *
 * Exposes three endpoints for the authenticated user to inspect and revoke
 * their own active sessions:
 *
 * - `GET  /sessions`     — list all sessions, with the caller's session marked
 * - `DELETE /sessions/all` — revoke all sessions except the caller's current session
 * - `DELETE /sessions/:id` — revoke a single session by its hash prefix (display id)
 *   or full 64-character SHA-256 session hash
 *
 * All endpoints require a valid JWT access token enforced by {@link JwtAuthGuard}.
 * Route prefix (`/sessions`) is relative — the consuming application applies
 * a global prefix (e.g. `/auth`) via `RouterModule` or `setGlobalPrefix`.
 *
 * @remarks
 * `DELETE /all` is declared before `DELETE /:id` in this class body as a
 * readability convention. NestJS resolves the ambiguity by scoring static
 * segments higher than parametric ones, so `all` is matched before `:id`
 * regardless of declaration order. The explicit ordering still communicates
 * intent to future maintainers.
 *
 * @layer Controller
 */
@UseInterceptors(NoStoreInterceptor)
@Controller('sessions')
// One decorator, in the order every other controller uses. Two stacked `@UseGuards` append
// via `extendArrayMetadata` and TypeScript applies decorators bottom-up, so the split form
// ran `[JwtAuthGuard, UserStatusGuard, TrustedOriginGuard, AuthRateLimitGuard]` — the inverse
// of the intent. `JwtAuthGuard` rejecting first meant a garbage `Authorization` header 401'd
// before `AuthRateLimitGuard` ever ran, so bad tokens were never metered: the route's limiter
// sat permanently at zero while every request still paid `verifyWithRotation` (one HMAC per
// configured secret, including every `previousSecrets` entry) and a Redis round trip.
@UseGuards(TrustedOriginGuard, AuthRateLimitGuard, JwtAuthGuard, UserStatusGuard)
@UsePipes(createAuthValidationPipe())
export class SessionController {
  constructor(
    @Inject(SessionService) private readonly sessionService: SessionService,
    @Inject(TokenDeliveryService) private readonly tokenDelivery: TokenDeliveryService
  ) {}

  // ---------------------------------------------------------------------------
  // GET /sessions
  // ---------------------------------------------------------------------------

  /**
   * Lists all active sessions for the authenticated user.
   *
   * Reads the `sess:{userId}` SET, fetches detail records for each session, and
   * marks the caller's session as `isCurrent: true` if a valid refresh token is
   * present in the request. Sessions with missing or stale detail records are
   * silently excluded and cleaned up asynchronously.
   *
   * @param user - Verified JWT payload from the access token.
   * @param req - Incoming request (used to extract the refresh token for `isCurrent` detection).
   * @returns Array of {@link SessionInfo} sorted newest-first.
   */
  @Throttle(AUTH_THROTTLE_CONFIGS.listSessions)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.listSessions)
  @Get()
  async listSessions(
    @CurrentUser() user: DashboardJwtPayload,
    @Req() req: Request
  ): Promise<SessionInfo[]> {
    const rawRefresh = this.tokenDelivery.extractRefreshToken(req)
    // When no refresh token is present (e.g. access-token-only requests),
    // isCurrent will be false for all sessions — this is the correct behaviour.
    const currentHash = rawRefresh ? sha256(rawRefresh) : undefined
    return this.sessionService.listSessions(user.sub, currentHash)
  }

  // ---------------------------------------------------------------------------
  // DELETE /sessions/all
  // ---------------------------------------------------------------------------

  /**
   * Revokes all sessions for the authenticated user except the current one.
   *
   * Uses the refresh token from the request to determine which session to preserve.
   * Throws `REFRESH_TOKEN_INVALID` if no refresh token is found — the current
   * session cannot be determined without it, and revoking all sessions (including
   * the caller's own) would force an immediate logout.
   *
   * @param user - Verified JWT payload from the access token.
   * @param req - Incoming request (used to extract the current session's refresh token).
   * @throws {@link AuthException} `SESSION_NOT_FOUND` when no refresh token is present in
   *   the request (current session cannot be determined without it).
   */
  @Throttle(AUTH_THROTTLE_CONFIGS.revokeAllSessions)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.revokeAllSessions)
  @HttpCode(HttpStatus.NO_CONTENT)
  @Delete('all')
  async revokeAllSessions(
    @CurrentUser() user: DashboardJwtPayload,
    @Req() req: Request
  ): Promise<void> {
    const rawRefresh = this.tokenDelivery.extractRefreshToken(req)

    if (!rawRefresh) {
      // Cannot determine the current session without a refresh token.
      // Refuse with SESSION_NOT_FOUND rather than REFRESH_TOKEN_INVALID to avoid
      // misleading clients into attempting a token refresh — this is a missing-cookie
      // condition, not a revoked/expired token condition.
      throw new AuthException(AUTH_ERROR_CODES.SESSION_NOT_FOUND)
    }

    const currentHash = sha256(rawRefresh)
    await this.sessionService.revokeAllExceptCurrent(user.sub, currentHash)
  }

  // ---------------------------------------------------------------------------
  // DELETE /sessions/:id
  // ---------------------------------------------------------------------------

  /**
   * Revokes a single session belonging to the authenticated user.
   *
   * The `:id` path parameter must be the full 64-character SHA-256 hex hash of
   * the session's refresh token (as returned in `sessionHash` by `GET /sessions`).
   * Ownership is enforced inside `SessionService.revokeSession` — a user cannot
   * revoke another user's session.
   *
   * @param user - Verified JWT payload from the access token.
   * @param id - Full SHA-256 session hash from the `sessionHash` field of `SessionInfo`.
   * @throws {@link AuthException} `SESSION_NOT_FOUND` when the session does not belong
   *   to the user or the hash format is invalid.
   * @returns 204 No Content on success.
   */
  @Throttle(AUTH_THROTTLE_CONFIGS.revokeSession)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.revokeSession)
  @HttpCode(HttpStatus.NO_CONTENT)
  @Delete(':id')
  async revokeSession(
    @CurrentUser() user: DashboardJwtPayload,
    @Param('id') id: string
  ): Promise<void> {
    await this.sessionService.revokeOtherSession(user.sub, id)
  }
}
