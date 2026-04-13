import { Module } from '@nestjs/common'

import { AuthRedisService } from './auth-redis.service'

/**
 * Internal NestJS module that registers {@link AuthRedisService}.
 *
 * Imported by `BymaxAuthModule` to make `AuthRedisService` available for
 * injection into the library's services (BruteForceService, TokenManagerService,
 * etc.). This module is **not** exported from the public barrel.
 */
@Module({
  providers: [AuthRedisService],
  exports: [AuthRedisService]
})
export class AuthRedisModule {}
