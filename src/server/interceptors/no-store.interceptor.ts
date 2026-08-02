import { Injectable } from '@nestjs/common'
import type { CallHandler, ExecutionContext, NestInterceptor } from '@nestjs/common'
import type { Response } from 'express'

/**
 * Stamps `Cache-Control: no-store` (plus `Pragma: no-cache` for HTTP/1.0
 * intermediaries) on every response of the controllers it is applied to.
 *
 * RFC 6749 §5.1 requires it on any response carrying a token, and every route
 * this library registers either carries one, sets an auth cookie, or answers a
 * question about an authenticated identity — all of which a shared cache must
 * never replay to the next caller. A CDN or corporate proxy that caches a login
 * response serves one user's tokens to another; a cached `GET /auth/me` serves
 * one user's identity as another's. Applying the header per-route invites the
 * one forgotten endpoint to be the leak, so it is applied per-controller and
 * before the handler runs — an exception thrown later still leaves the header
 * on the error response.
 *
 * The Next.js proxy layer sets the same header on its own responses; this
 * covers consumers that reach the NestJS API directly, where nothing upstream
 * would add it. `rust-auth` stamps the identical header via router middleware.
 *
 * @layer Interceptor
 */
@Injectable()
export class NoStoreInterceptor implements NestInterceptor {
  // Typed via CallHandler's own return type: naming rxjs's Observable here would need an
  // rxjs import, and this package declares zero direct dependencies — rxjs is only present
  // transitively through the NestJS peers.
  intercept(context: ExecutionContext, next: CallHandler): ReturnType<CallHandler['handle']> {
    const response = context.switchToHttp().getResponse<Response>()
    // Set before the handler runs, so error responses carry it too — an
    // AuthException thrown mid-handler skips anything scheduled after next().
    response.setHeader('Cache-Control', 'no-store')
    response.setHeader('Pragma', 'no-cache')
    return next.handle()
  }
}
