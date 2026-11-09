/**
 * @fileoverview The refresh-token request body, declared so the request-schema artifact states the
 * bound both libraries enforce.
 *
 * @layer DTO
 */

import { IsOptional, IsString, MaxLength, MinLength } from 'class-validator'

/**
 * The body the dashboard and platform token routes read when the refresh token is not a cookie
 * (`POST refresh`, `POST logout`, and their platform counterparts).
 *
 * Declared so the request-schema artifact states the bound both libraries enforce. The routes read
 * the raw body through `TokenDeliveryService` and never validate against this class, because a
 * request with no body is legitimate there (the cookie carries the token) and the refusal of a
 * malformed value is the service's own `400 auth.validation`.
 *
 * @layer DTO
 */
export class RefreshTokenBodyDto {
  /** The refresh token, 1 to 2048 characters; the cookie carries it instead when this is absent. */
  @IsOptional()
  @IsString()
  @MinLength(1)
  @MaxLength(2048)
  refreshToken?: string
}
