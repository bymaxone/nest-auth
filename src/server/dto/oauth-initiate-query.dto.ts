import { IsNotEmpty, IsOptional, IsString, Matches, MaxLength } from 'class-validator'

import { NO_CONTROL_CHARACTERS } from './no-control-characters'

/**
 * Query parameters for the OAuth initiation endpoint (`GET /oauth/:provider`).
 *
 * The `tenantId` is stored in the Redis CSRF state and recovered on the callback
 * to associate the incoming user with the correct tenant. Validated here so that
 * an empty or oversized value cannot be stored in Redis or reach the database.
 *
 * @layer DTO
 */
export class OAuthInitiateQueryDto {
  /**
   * Tenant ID that scopes the OAuth login.
   *
   * Stored in the Redis CSRF state during the flow and used in `handleCallback()`
   * to create or link the user within the correct tenant. Must be a non-empty
   * string; the `onOAuthLogin` hook is responsible for validating that the tenant
   * actually exists (the library does not query the database here).
   *
   * `@MaxLength(128)` prevents oversized values from being stored in Redis.
   */
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  @MaxLength(128)
  @Matches(NO_CONTROL_CHARACTERS, { message: 'tenantId must not contain control characters' })
  tenantId?: string
}
