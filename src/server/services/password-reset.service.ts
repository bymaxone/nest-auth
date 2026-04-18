import { Inject, Injectable, Logger, Optional } from '@nestjs/common'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-auth.constants'
import { OtpService } from './otp.service'
import { PasswordService } from './password.service'
import type { ResolvedOptions } from '../config/resolved-options'
import { generateSecureToken, hmacSha256, sha256, timingSafeCompare } from '../crypto/secure-token'
import type { ForgotPasswordDto } from '../dto/forgot-password.dto'
import type { ResendOtpDto } from '../dto/resend-otp.dto'
import type { ResetPasswordDto } from '../dto/reset-password.dto'
import type { VerifyOtpDto } from '../dto/verify-otp.dto'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { IAuthHooks } from '../interfaces/auth-hooks.interface'
import type { IEmailProvider } from '../interfaces/email-provider.interface'
import type {
  AuthUser,
  IUserRepository,
  SafeAuthUser
} from '../interfaces/user-repository.interface'
import { AuthRedisService } from '../redis/auth-redis.service'
import { createEmptyHookContext } from '../utils/sanitize-headers'
import { sleep } from '../utils/sleep'

// ---------------------------------------------------------------------------
// Module-level constants
// ---------------------------------------------------------------------------

/** Minimum response time in milliseconds for anti-enumeration endpoints. */
const ANTI_ENUM_MIN_MS = 300

/**
 * TTL in seconds for the `verifiedToken` issued after OTP verification.
 * 5 minutes is enough to complete the password reset form.
 */
const VERIFIED_TOKEN_TTL_SECONDS = 300

/**
 * OTP purpose string used as the namespace segment in Redis keys.
 * Matches the format `otp:password_reset:{identifier}` inside OtpService.
 */
const PASSWORD_RESET_PURPOSE = 'password_reset'

// ---------------------------------------------------------------------------
// Private types
// ---------------------------------------------------------------------------

/** Stored context for a password-reset token or verifiedToken. */
interface ResetContext {
  userId: string
  email: string
  tenantId: string
}

// ---------------------------------------------------------------------------
// PasswordResetService
// ---------------------------------------------------------------------------

/**
 * Manages the password-reset lifecycle for dashboard users.
 *
 * Supports two reset flows, configured via `BymaxAuthModuleOptions.passwordReset.method`:
 *
 * - **Token** (`method: 'token'`): A high-entropy random token is emailed to the user.
 *   The client submits it via `POST /password/reset-password` with `{ token }`.
 *
 * - **OTP** (`method: 'otp'`): A short numeric OTP is emailed to the user. The client
 *   can either:
 *   1. Submit OTP directly: `POST /password/reset-password` with `{ otp }`.
 *   2. Pre-verify the OTP: `POST /password/verify-otp` → receive a `verifiedToken`
 *      (5-minute single-use token) → `POST /password/reset-password` with `{ verifiedToken }`.
 *
 * All public endpoints (`initiateReset`, `resendOtp`) apply timing normalization
 * ({@link ANTI_ENUM_MIN_MS}) to prevent email-existence enumeration via response time.
 *
 * @remarks
 * Anti-enumeration design: `initiateReset` and `resendOtp` always respond with the
 * same result regardless of whether the email exists or the user is eligible.
 * Error codes and error shapes are intentionally identical for "not found" and
 * "wrong input" to avoid leaking the existence of an account.
 */
@Injectable()
export class PasswordResetService {
  private readonly logger = new Logger(PasswordResetService.name)

  constructor(
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions,
    @Inject(BYMAX_AUTH_USER_REPOSITORY) private readonly userRepo: IUserRepository,
    @Inject(BYMAX_AUTH_EMAIL_PROVIDER)
    @Optional()
    private readonly emailProvider: IEmailProvider | null,
    @Inject(BYMAX_AUTH_HOOKS) @Optional() private readonly hooks: IAuthHooks | null,
    private readonly otpService: OtpService,
    private readonly passwordService: PasswordService,
    private readonly redis: AuthRedisService
  ) {}

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  /**
   * Initiates a password reset for the given email address.
   *
   * Looks up the user by `email + tenantId`. If found and eligible (not banned,
   * inactive, or suspended), issues a reset token or OTP (depending on
   * `options.passwordReset.method`) and sends it via the email provider.
   *
   * **Always returns without throwing**, even when:
   * - The email does not exist in the tenant.
   * - The account is blocked.
   * - The email provider fails.
   *
   * This anti-enumeration design ensures the response cannot be used to probe
   * whether an email address is registered.
   *
   * Timing normalization: the method always takes at least {@link ANTI_ENUM_MIN_MS}
   * milliseconds to respond, regardless of whether the user was found.
   *
   * @param dto - Validated DTO containing `email` and `tenantId`.
   */
  async initiateReset(dto: ForgotPasswordDto): Promise<void> {
    const start = Date.now()

    try {
      const user = await this.userRepo.findByEmail(dto.email, dto.tenantId)

      if (user && !this.isBlocked(user.status)) {
        const { method } = this.options.passwordReset

        if (method === 'otp') {
          await this.sendOtp(dto.email, dto.tenantId, user.id)
        } else {
          await this.sendToken(dto.email, dto.tenantId, user.id)
        }
      }
    } catch (err: unknown) {
      this.logger.error('initiateReset: unexpected error', err)
    } finally {
      await sleep(Math.max(0, ANTI_ENUM_MIN_MS - (Date.now() - start)))
    }
  }

  /**
   * Resets the user's password using a verified proof (token, OTP, or verifiedToken).
   *
   * Exactly one of `dto.token`, `dto.otp`, or `dto.verifiedToken` must be present:
   *
   * - `token` — consumed atomically from Redis (`pw_reset:{sha256(token)}`).
   * - `otp` — verified by {@link OtpService} and consumed on success.
   * - `verifiedToken` — consumed atomically from Redis (`pw_vtok:{sha256(verifiedToken)}`).
   *
   * On success the user's password is updated and all sessions are invalidated.
   * The method throws an {@link AuthException} on any failure — no timing
   * normalization is applied here since the error reveals only that the proof
   * was invalid, not whether the account exists.
   *
   * @param dto - Validated DTO with `email`, `newPassword`, `tenantId`, and one proof field.
   * @throws {@link AuthException} `PASSWORD_RESET_TOKEN_INVALID` when the proof is absent,
   *   consumed, expired, or method-mismatch detected.
   * @throws {@link AuthException} `OTP_INVALID` / `OTP_EXPIRED` / `OTP_MAX_ATTEMPTS` for
   *   OTP-path failures.
   */
  async resetPassword(dto: ResetPasswordDto): Promise<void> {
    const { method } = this.options.passwordReset

    // Mutual exclusivity: exactly one proof field must be present.
    // Count the number of defined proof fields to reject ambiguous requests.
    const proofCount = [dto.token, dto.otp, dto.verifiedToken].filter(
      (v): v is string => typeof v === 'string'
    ).length

    if (proofCount > 1) {
      throw new AuthException(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    }

    if (method === 'token') {
      if (!dto.token) {
        throw new AuthException(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
      }
      await this.resetWithToken(dto.email, dto.tenantId, dto.token, dto.newPassword)
      return
    }

    // method === 'otp'
    if (dto.token) {
      // Token-based proof submitted for an OTP-configured module — explicit method mismatch.
      throw new AuthException(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    }

    if (dto.verifiedToken) {
      await this.resetWithVerifiedToken(dto.email, dto.tenantId, dto.verifiedToken, dto.newPassword)
      return
    }

    if (dto.otp) {
      await this.resetWithOtp(dto.email, dto.tenantId, dto.otp, dto.newPassword)
      return
    }

    throw new AuthException(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
  }

  /**
   * Verifies a password-reset OTP and exchanges it for a short-lived `verifiedToken`.
   *
   * The `verifiedToken` is a 64-character hex string stored in Redis under
   * `pw_vtok:{sha256(token)}` with a {@link VERIFIED_TOKEN_TTL_SECONDS} TTL.
   * It can be submitted via `dto.verifiedToken` in `resetPassword` within 5 minutes.
   *
   * The OTP is consumed on success (single-use). Timing normalization is applied
   * by {@link OtpService.verify} — all failure paths take at least 100 ms.
   *
   * @param dto - Validated DTO with `email`, `tenantId`, and `otp`.
   * @returns The raw `verifiedToken` string (64-char hex) to forward to the client.
   * @throws {@link AuthException} `OTP_EXPIRED` when the OTP is not in Redis.
   * @throws {@link AuthException} `OTP_MAX_ATTEMPTS` when the attempt limit is reached.
   * @throws {@link AuthException} `OTP_INVALID` when the OTP does not match.
   * @throws {@link AuthException} `PASSWORD_RESET_TOKEN_INVALID` when the user is not
   *   found after OTP verification (prevents issuing tokens for non-existent accounts).
   */
  async verifyOtp(dto: VerifyOtpDto): Promise<string> {
    const identifier = this.otpIdentifier(dto.tenantId, dto.email)
    await this.otpService.verify(PASSWORD_RESET_PURPOSE, identifier, dto.otp)

    // After successful OTP verification, ensure the account still exists before
    // issuing the verifiedToken. Use PASSWORD_RESET_TOKEN_INVALID to prevent
    // distinguishing "OTP consumed for a deleted account" from other failures.
    const user = await this.userRepo.findByEmail(dto.email, dto.tenantId)
    if (!user) {
      throw new AuthException(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    }

    const rawVerifiedToken = generateSecureToken()
    const context: ResetContext = { userId: user.id, email: dto.email, tenantId: dto.tenantId }
    await this.redis.set(
      `pw_vtok:${sha256(rawVerifiedToken)}`,
      JSON.stringify(context),
      VERIFIED_TOKEN_TTL_SECONDS
    )

    return rawVerifiedToken
  }

  /**
   * Requests a new password-reset OTP for the given email address.
   *
   * Subject to an atomic 60-second cooldown enforced via a Redis NX key to
   * prevent OTP flooding. Always returns success regardless of whether the
   * user exists — anti-enumeration principle.
   *
   * Timing normalization: always takes at least {@link ANTI_ENUM_MIN_MS} ms.
   *
   * @param dto - Validated DTO with `email` and `tenantId`.
   */
  async resendOtp(dto: ResendOtpDto): Promise<void> {
    const start = Date.now()

    const identifier = this.otpIdentifier(dto.tenantId, dto.email)
    const cooldownKey = `resend:${PASSWORD_RESET_PURPOSE}:${identifier}`

    // Atomic NX: only one send allowed per 60 seconds.
    const wasSet = await this.redis.setnx(cooldownKey, 60)
    if (!wasSet) {
      await sleep(Math.max(0, ANTI_ENUM_MIN_MS - (Date.now() - start)))
      return // Cooldown active — silently succeed.
    }

    try {
      const user = await this.userRepo.findByEmail(dto.email, dto.tenantId)
      if (user && !this.isBlocked(user.status)) {
        // `sendOtp` stores the OTP in Redis synchronously, then fires the email
        // provider call as fire-and-forget (void). Timing normalization in the
        // `finally` block below is correct only because the email send is NOT
        // awaited here. If this is changed to `await`, the email RTT will be
        // added to the synchronous path, potentially creating a timing difference
        // between "user found" and "user not found" responses.
        await this.sendOtp(dto.email, dto.tenantId, user.id)
      }
    } catch (err: unknown) {
      this.logger.error('resendOtp: unexpected error', err)
    } finally {
      await sleep(Math.max(0, ANTI_ENUM_MIN_MS - (Date.now() - start)))
    }
  }

  // ---------------------------------------------------------------------------
  // Private helpers — reset paths
  // ---------------------------------------------------------------------------

  /**
   * Token-based reset path: atomically consumes the token from Redis and updates
   * the password.
   *
   * Uses {@link AuthRedisService.getdel} to atomically read and delete the token
   * in a single round-trip, preventing TOCTOU races where two concurrent requests
   * with the same token both succeed.
   */
  private async resetWithToken(
    email: string,
    tenantId: string,
    rawToken: string,
    newPassword: string
  ): Promise<void> {
    const contextJson = await this.redis.getdel(`pw_reset:${sha256(rawToken)}`)

    if (contextJson === null) {
      throw new AuthException(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    }

    const context = this.parseResetContext(contextJson)

    // Defence-in-depth: verify email and tenantId match the stored context.
    // Compare SHA-256 digests rather than the raw variable-length strings — the
    // underlying `timingSafeCompare` returns `false` on length mismatch, which
    // would leak whether the submitted email is the same length as the stored
    // one. Hashing to a fixed 64-char digest removes that length oracle.
    if (
      !timingSafeCompare(sha256(context.email), sha256(email)) ||
      !timingSafeCompare(sha256(context.tenantId), sha256(tenantId))
    ) {
      throw new AuthException(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    }

    await this.applyPasswordReset(context.userId, newPassword)
  }

  /**
   * Direct OTP reset path: verifies and consumes the OTP, then updates the password.
   */
  private async resetWithOtp(
    email: string,
    tenantId: string,
    otp: string,
    newPassword: string
  ): Promise<void> {
    const identifier = this.otpIdentifier(tenantId, email)
    await this.otpService.verify(PASSWORD_RESET_PURPOSE, identifier, otp)

    const user = await this.userRepo.findByEmail(email, tenantId)
    if (!user) {
      // OTP was consumed but user disappeared — treat as token invalid.
      throw new AuthException(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    }

    await this.applyPasswordReset(user.id, newPassword)
  }

  /**
   * VerifiedToken reset path: atomically consumes the verifiedToken from Redis
   * and updates the password.
   */
  private async resetWithVerifiedToken(
    email: string,
    tenantId: string,
    rawVerifiedToken: string,
    newPassword: string
  ): Promise<void> {
    const contextJson = await this.redis.getdel(`pw_vtok:${sha256(rawVerifiedToken)}`)

    if (contextJson === null) {
      throw new AuthException(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    }

    const context = this.parseResetContext(contextJson)

    // Compare SHA-256 digests to eliminate the variable-length oracle in
    // `timingSafeCompare`. See `resetWithToken` for the full rationale.
    if (
      !timingSafeCompare(sha256(context.email), sha256(email)) ||
      !timingSafeCompare(sha256(context.tenantId), sha256(tenantId))
    ) {
      throw new AuthException(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    }

    await this.applyPasswordReset(context.userId, newPassword)
  }

  /**
   * Hashes the new password and updates it in the user repository.
   * Then invalidates all active sessions via the Redis SET so the user
   * must re-authenticate with the new credentials.
   *
   * @remarks
   * **Operation order is intentional.** Password is updated BEFORE sessions are
   * invalidated. If the process crashes between the two operations:
   *
   * - Stale refresh tokens may survive until their TTL expires, but the old
   *   password is no longer valid for new logins — an attacker with a stolen
   *   password cannot issue new sessions.
   *
   * The reverse order (invalidate sessions first) is more dangerous: if
   * `updatePassword` fails after `invalidateUserSessions`, the old password
   * remains valid and the attacker can still authenticate with it.
   *
   * Cross-store atomicity between the DB and Redis is inherently unavailable.
   * The current ordering minimises the security impact of a partial failure.
   */
  private async applyPasswordReset(userId: string, newPassword: string): Promise<void> {
    const passwordHash = await this.passwordService.hash(newPassword)
    await this.userRepo.updatePassword(userId, passwordHash)
    // Invalidate all refresh sessions atomically via Lua script — no race
    // between a concurrent login adding a new session and the SET deletion.
    await this.redis.invalidateUserSessions(userId)

    // afterPasswordReset — fire-and-forget; errors must not propagate.
    if (this.hooks?.afterPasswordReset) {
      const user = await this.userRepo.findById(userId)
      if (user) {
        void Promise.resolve(
          this.hooks.afterPasswordReset(toSafeUser(user), createEmptyHookContext())
        ).catch((err: unknown) => {
          this.logger.error('afterPasswordReset hook threw', err)
        })
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Private helpers — email sending
  // ---------------------------------------------------------------------------

  /**
   * Generates and stores a password-reset token, then sends it to the user's email.
   * Errors are caught and logged — they must not propagate to `initiateReset`.
   */
  private async sendToken(email: string, tenantId: string, userId: string): Promise<void> {
    if (!this.emailProvider) {
      this.logger.warn('sendToken: no email provider configured — password reset token not sent')
      return
    }

    const rawToken = generateSecureToken()
    const context: ResetContext = { userId, email, tenantId }
    await this.redis.set(
      `pw_reset:${sha256(rawToken)}`,
      JSON.stringify(context),
      this.options.passwordReset.tokenTtlSeconds
    )

    void Promise.resolve(this.emailProvider.sendPasswordResetToken(email, rawToken)).catch(
      (err: unknown) => {
        this.logger.error(`sendPasswordResetToken failed for user ${userId}`, err)
      }
    )
  }

  /**
   * Generates and stores a password-reset OTP, then sends it to the user's email.
   * Errors are caught and logged — they must not propagate to `initiateReset`.
   */
  private async sendOtp(email: string, tenantId: string, userId: string): Promise<void> {
    if (!this.emailProvider) {
      this.logger.warn('sendOtp: no email provider configured — password reset OTP not sent')
      return
    }

    const { otpLength, otpTtlSeconds } = this.options.passwordReset
    const identifier = this.otpIdentifier(tenantId, email)
    const otp = this.otpService.generate(otpLength)
    await this.otpService.store(PASSWORD_RESET_PURPOSE, identifier, otp, otpTtlSeconds)

    void Promise.resolve(this.emailProvider.sendPasswordResetOtp(email, otp)).catch(
      (err: unknown) => {
        this.logger.error(`sendPasswordResetOtp failed for user ${userId}`, err)
      }
    )
  }

  // ---------------------------------------------------------------------------
  // Private helpers — misc
  // ---------------------------------------------------------------------------

  /**
   * Derives the HMAC-SHA-256 OTP identifier for a `tenantId + email` pair.
   *
   * HMAC is used (not bare SHA-256) because `email` is low-entropy — a bare
   * SHA-256 hash could be reversed by dictionary or rainbow-table lookup if
   * the Redis keyspace were ever exposed. The derived `hmacKey` (distinct
   * from `jwt.secret`) is used as the HMAC key so that a JWT-secret
   * compromise does not directly reveal Redis identifiers.
   */
  private otpIdentifier(tenantId: string, email: string): string {
    return hmacSha256(`${tenantId}:${email}`, this.options.hmacKey)
  }

  /**
   * Returns `true` when the user's account status prevents password reset.
   *
   * Uses the `options.blockedStatuses` list (case-insensitive) to check if
   * the status is in the consumer-configured blocked set.
   */
  private isBlocked(status: string): boolean {
    const lower = status.toLowerCase()
    return this.options.blockedStatuses.some((s) => s.toLowerCase() === lower)
  }

  /**
   * Parses a {@link ResetContext} from a Redis JSON string.
   *
   * @throws {@link AuthException} `PASSWORD_RESET_TOKEN_INVALID` if the JSON is
   *   malformed or missing required fields.
   */
  private parseResetContext(json: string): ResetContext {
    // Narrow try scope to JSON.parse only — so that future logic added after
    // parsing is not accidentally swallowed and re-wrapped as TOKEN_INVALID.
    let parsed: unknown
    try {
      parsed = JSON.parse(json)
    } catch {
      throw new AuthException(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    }

    if (
      parsed === null ||
      typeof parsed !== 'object' ||
      !('userId' in parsed) ||
      !('email' in parsed) ||
      !('tenantId' in parsed) ||
      typeof (parsed as Record<string, unknown>)['userId'] !== 'string' ||
      typeof (parsed as Record<string, unknown>)['email'] !== 'string' ||
      typeof (parsed as Record<string, unknown>)['tenantId'] !== 'string'
    ) {
      throw new AuthException(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    }

    return parsed as ResetContext
  }
}

// ---------------------------------------------------------------------------
// Projection helper
// ---------------------------------------------------------------------------

/**
 * Projects a full {@link AuthUser} to a {@link SafeAuthUser} by excluding
 * credential and secret fields that must never leave the service layer.
 */
function toSafeUser(user: AuthUser): SafeAuthUser {
  const {
    passwordHash: _passwordHash,
    mfaSecret: _mfaSecret,
    mfaRecoveryCodes: _mfaRecoveryCodes,
    ...safe
  } = user
  return safe
}
