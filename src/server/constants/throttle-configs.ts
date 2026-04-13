/**
 * Rate limiting configurations for @bymax-one/nest-auth endpoints.
 *
 * Exported as named throttler configurations compatible with the
 * `@Throttle()` decorator from `@nestjs/throttler` >= 6.0.0.
 *
 * @remarks
 * These are **recommendations** — the consuming application applies them via
 * `@Throttle(AUTH_THROTTLE_CONFIGS.login)` on controller methods. The host
 * application must configure `ThrottlerModule` globally for these to take effect.
 *
 * This layer provides IP-based rate limiting. Email-based brute-force protection
 * (tracking failed login attempts per email) is always active independently via
 * `BruteForceService` and does not depend on `ThrottlerModule`.
 *
 * @example
 * ```typescript
 * // Host application setup
 * ThrottlerModule.forRoot([{ ttl: 60_000, limit: 100 }])
 *
 * // In a controller
 * @Throttle(AUTH_THROTTLE_CONFIGS.login)
 * @Post('login')
 * async login(@Body() dto: LoginDto) { ... }
 * ```
 */
export const AUTH_THROTTLE_CONFIGS = {
  /** POST /auth/login — 5 requests per minute per IP. Protects against brute-force by IP. */
  login: { default: { limit: 5, ttl: 60_000 } },

  /** POST /auth/register — 10 requests per hour per IP. Protects against mass account creation. */
  register: { default: { limit: 10, ttl: 3_600_000 } },

  /** POST /auth/refresh — 10 requests per minute per IP. */
  refresh: { default: { limit: 10, ttl: 60_000 } },

  /** POST /auth/password/forgot-password — 3 requests per 5 minutes per IP. */
  forgotPassword: { default: { limit: 3, ttl: 300_000 } },

  /** POST /auth/password/reset-password — 3 requests per 5 minutes per IP. */
  resetPassword: { default: { limit: 3, ttl: 300_000 } },

  /**
   * POST /auth/password/verify-otp — 3 requests per 5 minutes per IP.
   * More restrictive than the internal 5-attempt-per-OTP application limit,
   * providing an earlier IP-level block before the app-level lockout triggers.
   */
  verifyOtp: { default: { limit: 3, ttl: 300_000 } },

  /** POST /auth/mfa/setup — 5 requests per minute per IP. */
  mfaSetup: { default: { limit: 5, ttl: 60_000 } },

  /** POST /auth/mfa/challenge — 10 requests per minute per IP. */
  mfaChallenge: { default: { limit: 10, ttl: 60_000 } },

  /** POST /auth/mfa/disable — 3 requests per 5 minutes per IP. */
  mfaDisable: { default: { limit: 3, ttl: 300_000 } },

  /** POST /auth/platform/login — 5 requests per minute per IP. */
  platformLogin: { default: { limit: 5, ttl: 60_000 } },

  /** POST /auth/verify-email — 5 requests per minute per IP. */
  verifyEmail: { default: { limit: 5, ttl: 60_000 } },

  /** POST /auth/resend-verification — 3 requests per 5 minutes per IP. */
  resendVerification: { default: { limit: 3, ttl: 300_000 } },

  /** POST /auth/password/resend-otp — 3 requests per 5 minutes per IP. */
  resendPasswordOtp: { default: { limit: 3, ttl: 300_000 } },

  /** POST /auth/invitations/accept — 5 requests per minute per IP. */
  invitationAccept: { default: { limit: 5, ttl: 60_000 } }
} as const
