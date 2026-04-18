/**
 * OAuth 2.0 controller for @bymax-one/nest-auth.
 *
 * Exposes two endpoints per provider:
 *  - `GET /oauth/:provider?tenantId=xxx` — initiates the flow (302 redirect to provider).
 *  - `GET /oauth/:provider/callback?code=xxx&state=xxx` — handles the provider callback.
 *
 * Route prefix (`oauth`) is relative — the consuming application applies a global prefix
 * (e.g. `/auth`) via `RouterModule` or `setGlobalPrefix`, producing final routes such as
 * `/auth/oauth/google` and `/auth/oauth/google/callback`.
 *
 * Both endpoints are `@Public()` — the OAuth flow is unauthenticated by design.
 * `@SkipMfa()` prevents `MfaRequiredGuard` from blocking the callback route when
 * it is applied globally.
 */

import {
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Query,
  Req,
  Res,
  UsePipes,
  ValidationPipe
} from '@nestjs/common'
import { Throttle } from '@nestjs/throttler'
import type { Request, Response } from 'express'

import { OAuthService } from './oauth.service'
import { AUTH_THROTTLE_CONFIGS } from '../constants/throttle-configs'
import { Public } from '../decorators/public.decorator'
import { SkipMfa } from '../decorators/skip-mfa.decorator'
import { OAuthCallbackQueryDto } from '../dto/oauth-callback-query.dto'
import { OAuthInitiateQueryDto } from '../dto/oauth-initiate-query.dto'
import type {
  BearerAuthResponse,
  BothAuthResponse,
  CookieAuthResponse
} from '../services/token-delivery.service'
import { TokenDeliveryService } from '../services/token-delivery.service'

/**
 * Handles the provider-agnostic OAuth 2.0 Authorization Code flow.
 *
 * Both routes delegate all business logic to {@link OAuthService}. This controller
 * is thin — it validates query parameters, extracts request metadata (IP, UA), and
 * delivers the auth response via {@link TokenDeliveryService}.
 */
@Public()
@SkipMfa()
@Controller('oauth')
@UsePipes(
  new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, forbidUnknownValues: true })
)
export class OAuthController {
  constructor(
    private readonly oauthService: OAuthService,
    private readonly tokenDelivery: TokenDeliveryService
  ) {}

  // ---------------------------------------------------------------------------
  // GET /oauth/:provider
  // ---------------------------------------------------------------------------

  /**
   * Initiates the OAuth 2.0 flow for the given provider.
   *
   * Generates a CSRF state nonce, stores it in Redis, and redirects the user to
   * the provider's authorization URL. The `tenantId` query parameter is validated
   * via {@link OAuthInitiateQueryDto} — an empty or oversized value is rejected
   * before reaching the service layer.
   *
   * @param provider - Provider name (e.g. `'google'`). Must match a registered plugin.
   * @param query - Validated query parameters (contains `tenantId`).
   * @param res - Express response object (used to issue the 302 redirect).
   */
  @Throttle(AUTH_THROTTLE_CONFIGS.oauthInitiate)
  @Get(':provider')
  async initiate(
    @Param('provider') provider: string,
    @Query() query: OAuthInitiateQueryDto,
    @Res({ passthrough: true }) res: Response
  ): Promise<void> {
    await this.oauthService.initiateOAuth(provider, query.tenantId, res)
  }

  // ---------------------------------------------------------------------------
  // GET /oauth/:provider/callback
  // ---------------------------------------------------------------------------

  /**
   * Handles the OAuth provider callback and issues auth tokens.
   *
   * Validates the CSRF `state` nonce, exchanges the `code` for an access token,
   * fetches the user profile, runs the `onOAuthLogin` hook, and delivers the
   * auth response using the configured token delivery mode (cookie or bearer).
   *
   * Both `code` and `state` are validated via {@link OAuthCallbackQueryDto} — empty
   * or oversized values are rejected before reaching the service layer or the
   * token-exchange HTTP call.
   *
   * @param provider - Provider name from the URL path (e.g. `'google'`).
   * @param query - Validated query parameters (contains `code` and `state`).
   * @param req - Incoming request (IP, User-Agent, and cookie context for token delivery).
   * @param res - Express response in passthrough mode (used for cookie delivery).
   * @returns Auth response shaped by the configured `tokenDelivery` mode.
   */
  @Throttle(AUTH_THROTTLE_CONFIGS.oauthCallback)
  @HttpCode(HttpStatus.OK)
  @Get(':provider/callback')
  async callback(
    @Param('provider') provider: string,
    @Query() query: OAuthCallbackQueryDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<CookieAuthResponse | BearerAuthResponse | BothAuthResponse> {
    // Truncate to match the limits applied in all other auth controllers:
    // 64 chars for IP (longest IPv6 address is 39 chars; 64 gives ample headroom).
    // 512 chars for User-Agent (stored in the Redis session record; prevents key bloat).
    const ip = (req.ip ?? '').slice(0, 64)
    const userAgent = String(req.headers['user-agent'] ?? '').slice(0, 512)

    const result = await this.oauthService.handleCallback(
      provider,
      query.code,
      query.state,
      ip,
      userAgent,
      req.headers as Record<string, string | string[] | undefined>
    )
    return this.tokenDelivery.deliverAuthResponse(res, result, req)
  }
}
