import { Inject, Injectable, Logger, Optional } from '@nestjs/common'
import type { Request } from 'express'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-auth.constants'
import { OtpService } from './otp.service'
import { PasswordService } from './password.service'
import { SessionService } from './session.service'
import type { ResolvedOptions } from '../config/resolved-options'
import { generateSecureToken, hmacSha256, sha256, timingSafeCompare } from '../crypto/secure-token'
import type { ChangePasswordDto } from '../dto/change-password.dto'
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
import { resolveTenantId } from '../utils/resolve-tenant-id'
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

/**
 * Seconds one account must wait between reset sends, shared by `initiateReset` and
 * `resendOtp`.
 *
 * It is not only about mail volume. Every issuance rewrites the OTP record with `attempts: 0`,
 * so an entry point that can be called freely converts the 5-attempt ceiling into 5 attempts
 * *per call*, and a six-digit code stops being a secret. Both doors therefore draw on one
 * budget under one key.
 */
const RESEND_COOLDOWN_SECONDS = 60

// ---------------------------------------------------------------------------
// Private types
// ---------------------------------------------------------------------------

/** Stored context for a password-reset token or verifiedToken. */
interface ResetContext {
  userId: string
  email: string
  tenantId: string
  /**
   * A digest of the password hash this token was issued against, binding it to that password.
   *
   * Each `forgot-password` writes its own `pw_reset:` key, so several can be alive at once —
   * the 60-second cooldown against a 600-second TTL allows up to ten. Completing a reset with
   * one used to leave the others valid, which is the wrong end state precisely when it matters:
   * a victim who resets because an attacker read a link from their mailbox has not closed the
   * link the attacker read. Binding each token to the password in force when it was minted
   * means the first completed reset — or an authenticated change — invalidates every one of
   * them at once, with no per-user index to keep in step.
   *
   * Empty for an account that had no password (OAuth-only) at issue time.
   */
  passwordFingerprint: string
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
 *
 * @layer Service
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
    private readonly redis: AuthRedisService,
    private readonly sessionService: SessionService
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
  async initiateReset(dto: ForgotPasswordDto, req: Request): Promise<void> {
    // The configured resolver is authoritative, exactly as it is for login and register: a
    // deployment that derives the tenant from the request has stated that the body's value is
    // not to be trusted. Without this a caller on one tenant could drive reset mail at accounts
    // in another, and a reset started under the resolved tenant could never be completed —
    // the stored context and this step would disagree about which tenant it belonged to.
    const tenantId = await resolveTenantId(dto.tenantId, req, this.options.tenantIdResolver)
    dto = { ...dto, tenantId }
    const start = Date.now()

    // The SAME cooldown key `resendOtp` uses, so the two entry points share one budget rather
    // than one throttling itself while the other hands out fresh sends for free. Two things
    // depended on that: every issuance re-writes the OTP record with `attempts: 0`, so an
    // untimed initiate turns the 5-attempt ceiling into 5 attempts *per call* — an unbounded
    // supply of guesses at a six-digit code — and each call also mails the victim, which is a
    // mail bomb aimed at an address the caller merely has to know. Silent success on a
    // cooldown hit, with the same anti-enumeration floor as every other exit, so the throttle
    // does not itself answer whether the account exists.
    const cooldownKey = `resend:${PASSWORD_RESET_PURPOSE}:${this.otpIdentifier(dto.tenantId, dto.email)}`
    const wasSet = await this.redis.setnx(cooldownKey, RESEND_COOLDOWN_SECONDS)
    if (!wasSet) {
      await sleep(Math.max(0, ANTI_ENUM_MIN_MS - (Date.now() - start)))
      return
    }

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
  async resetPassword(dto: ResetPasswordDto, req: Request): Promise<void> {
    // The configured resolver is authoritative, exactly as it is for login and register: a
    // deployment that derives the tenant from the request has stated that the body's value is
    // not to be trusted. Without this a caller on one tenant could drive reset mail at accounts
    // in another, and a reset started under the resolved tenant could never be completed —
    // the stored context and this step would disagree about which tenant it belonged to.
    const tenantId = await resolveTenantId(dto.tenantId, req, this.options.tenantIdResolver)
    dto = { ...dto, tenantId }
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
    // Stryker disable next-line ConditionalExpression,BlockStatement: the only input that reaches here (token present, proofCount <= 1) falls through to the identical throw at the end of the function
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
  async verifyOtp(dto: VerifyOtpDto, req: Request): Promise<string> {
    // The configured resolver is authoritative, exactly as it is for login and register: a
    // deployment that derives the tenant from the request has stated that the body's value is
    // not to be trusted. Without this a caller on one tenant could drive reset mail at accounts
    // in another, and a reset started under the resolved tenant could never be completed —
    // the stored context and this step would disagree about which tenant it belonged to.
    const tenantId = await resolveTenantId(dto.tenantId, req, this.options.tenantIdResolver)
    dto = { ...dto, tenantId }
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
    const context: ResetContext = {
      userId: user.id,
      email: dto.email,
      tenantId: dto.tenantId,
      passwordFingerprint: await this.passwordFingerprintOf(user.id)
    }
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
  async resendOtp(dto: ResendOtpDto, req: Request): Promise<void> {
    // The configured resolver is authoritative, exactly as it is for login and register: a
    // deployment that derives the tenant from the request has stated that the body's value is
    // not to be trusted. Without this a caller on one tenant could drive reset mail at accounts
    // in another, and a reset started under the resolved tenant could never be completed —
    // the stored context and this step would disagree about which tenant it belonged to.
    const tenantId = await resolveTenantId(dto.tenantId, req, this.options.tenantIdResolver)
    dto = { ...dto, tenantId }
    const start = Date.now()

    const identifier = this.otpIdentifier(dto.tenantId, dto.email)
    const cooldownKey = `resend:${PASSWORD_RESET_PURPOSE}:${identifier}`

    // Atomic NX: one send per cooldown window, shared with `initiateReset` — see the note
    // there for why both doors have to draw on the same budget.
    const wasSet = await this.redis.setnx(cooldownKey, RESEND_COOLDOWN_SECONDS)
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

    await this.assertResetTokenStillBound(context)
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

    await this.assertResetTokenStillBound(context)
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
  /**
   * Changes the password of an already-authenticated account, proving identity with the
   * current password rather than an emailed token.
   *
   * This is the flow ASVS v5 §6.2.2 and §6.2.3 require at Level 1 — "users can change their
   * password", and "password change functionality requires the user's current and new
   * password" — and it was the one credential operation this library did not own. Without it a
   * consumer either sends their users through the *unauthenticated* recovery flow to rotate a
   * password they already know, or rebuilds the operation themselves against a hash format the
   * README forbids them to touch.
   *
   * The current password is what makes it safe. A session alone is not proof of identity: a
   * token lifted by XSS or from a shared machine would otherwise be enough to rotate the
   * credential, lock the real owner out of an account they still know the password to, and
   * keep the attacker in.
   *
   * Every other session is ended on success (ASVS v5 §7.4.3), and the token epoch is bumped so
   * already-issued access tokens die with them. The caller's own refresh session survives when
   * it can be identified, so the device that just changed the password stays signed in —
   * silently re-minting its access token on the next rotation. When it cannot be identified,
   * every session goes, including this one: a change that leaves an unknown session alive is
   * the failure this control exists to prevent.
   *
   * @param userId - The authenticated account, taken from the verified token — never the body.
   * @param dto - Validated current and new password.
   * @param currentRefreshToken - The caller's raw refresh token, when the request carried one.
   * @throws {@link AuthException} `INVALID_CREDENTIALS` when the current password does not
   *   match, or the account has no local password (an OAuth-only account has nothing to
   *   change; its credential belongs to the provider).
   * @throws {@link AuthException} `PASSWORD_COMPROMISED` when the new password is refused by
   *   the configured breach checker.
   */
  async changePassword(
    userId: string,
    dto: ChangePasswordDto,
    currentRefreshToken?: string
  ): Promise<void> {
    const user = await this.userRepo.findById(userId)
    // A verified token whose subject no longer exists, and an account with no local password,
    // answer identically: the caller cannot prove a credential this account does not have.
    if (!user?.passwordHash) {
      throw new AuthException(AUTH_ERROR_CODES.INVALID_CREDENTIALS)
    }

    const matches = await this.passwordService.compare(dto.currentPassword, user.passwordHash)
    if (!matches) {
      this.logger.warn(`changePassword: current password rejected userId=${userId}`)
      throw new AuthException(AUTH_ERROR_CODES.INVALID_CREDENTIALS)
    }

    await this.passwordService.assertNotCompromised(dto.newPassword)
    const passwordHash = await this.passwordService.hash(dto.newPassword)
    await this.userRepo.updatePassword(userId, passwordHash)

    // End every other session, and the access tokens with them. `revokeAllExceptCurrent`
    // bumps the epoch itself, which is what reaches the stateless access tokens — the ones a
    // session sweep alone leaves valid until they expire.
    if (currentRefreshToken !== undefined && currentRefreshToken.length > 0) {
      await this.sessionService.revokeAllExceptCurrent(userId, sha256(currentRefreshToken))
    } else {
      await this.redis.invalidateUserSessions(userId)
      await this.redis.bumpUserTokenEpoch(userId)
    }

    await this.notifyPasswordChanged(user)
  }

  /**
   * Sends the "your password changed" notice, fire-and-forget.
   *
   * NIST SP 800-63B §4.6 asks for a notification through a channel independent of the
   * transaction that bound the new credential. The classic takeover starts with a compromised
   * mailbox — trigger a reset, complete it, delete the mail — so this notice is what turns
   * "the victim finds out days later, at a failed login" into "the victim finds out now".
   *
   * Never awaited and never allowed to throw: a delivery failure must not undo a password that
   * has already been written, nor answer differently to the caller.
   */
  private async notifyPasswordChanged(user: AuthUser): Promise<void> {
    const send = this.emailProvider?.sendPasswordChangedNotification
    if (send === undefined) return
    void Promise.resolve(send.call(this.emailProvider, user.email)).catch((err: unknown) => {
      this.logger.error('notifyPasswordChanged: delivery failed', err)
    })
  }

  /**
   * A digest of the account's current password hash, used to bind a reset token to it.
   *
   * The hash itself never leaves the repository — only this digest goes into Redis, so a leaked
   * snapshot of the reset keyspace reveals nothing about the credential. An account with no
   * local password yields the empty string, which is a value like any other: a token minted
   * then is invalidated as soon as one is set.
   */
  private async passwordFingerprintOf(userId: string): Promise<string> {
    const user = await this.userRepo.findById(userId)
    return user?.passwordHash ? sha256(user.passwordHash) : ''
  }

  /**
   * Refuses a reset token whose binding no longer matches the account's current password.
   *
   * Several `pw_reset:` keys can be alive at once, and completing a reset with one used to
   * leave the others valid — the wrong end state precisely when it matters, since a victim
   * resetting because an attacker read a link from their mailbox had not closed the link the
   * attacker read. The binding makes the first completed reset, or an authenticated change,
   * invalidate all of them.
   *
   * An empty stored fingerprint means the token predates the binding (a rolling deploy, or a
   * sibling implementation that has not taken this change), and is accepted: refusing those
   * would break every reset in flight for a window this narrow.
   */
  private async assertResetTokenStillBound(context: ResetContext): Promise<void> {
    if (context.passwordFingerprint === '') return
    if (context.passwordFingerprint === (await this.passwordFingerprintOf(context.userId))) return

    this.logger.warn(
      `reset: refusing a token issued against a password that has since changed ` +
        `userId=${context.userId}`
    )
    throw new AuthException(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
  }

  private async applyPasswordReset(userId: string, newPassword: string): Promise<void> {
    await this.passwordService.assertNotCompromised(newPassword)
    const passwordHash = await this.passwordService.hash(newPassword)
    await this.userRepo.updatePassword(userId, passwordHash)
    // Revoke every session AND invalidate already-issued access tokens. This is two Redis
    // operations (a Lua session-invalidation followed by the epoch bump), not a single atomic
    // transaction — the bump simply must land before the reset returns. Deleting the refresh
    // sessions alone would leave stateless access tokens valid until their exp (they are not
    // tracked per-jti), so a stolen access token would survive a reset-after-compromise for
    // the full access-token TTL. The Lua-backed session deletion is itself atomic, avoiding
    // the race where a concurrent login adds a session between the SMEMBERS read and the DEL.
    await this.redis.invalidateUserSessions(userId)
    await this.redis.bumpUserTokenEpoch(userId)

    // afterPasswordReset — fire-and-forget; errors must not propagate. The same repository read
    // serves the notification, which a reset needs at least as much as a change does: the
    // classic takeover completes a reset from a compromised mailbox and deletes the mail.
    const user = await this.userRepo.findById(userId)
    if (user) {
      await this.notifyPasswordChanged(user)
      if (this.hooks?.afterPasswordReset) {
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
    const tokenKey = `pw_reset:${sha256(rawToken)}`
    const context: ResetContext = {
      userId,
      email,
      tenantId,
      passwordFingerprint: await this.passwordFingerprintOf(userId)
    }
    await this.redis.set(
      tokenKey,
      JSON.stringify(context),
      this.options.passwordReset.tokenTtlSeconds
    )

    // Rollback the Redis key if email delivery fails so an undeliverable token
    // does not linger in Redis until natural TTL expiry. A leaked Redis snapshot
    // could otherwise expose unconsumed reset tokens for accounts that never
    // received the email.
    void Promise.resolve(this.emailProvider.sendPasswordResetToken(email, rawToken)).catch(
      (err: unknown) => {
        this.logger.error(`sendPasswordResetToken failed for user ${userId}`, err)
        void this.redis.del(tokenKey).catch((delErr: unknown) => {
          this.logger.error(`pw_reset rollback delete failed for user ${userId}`, delErr)
        })
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
      // Corrupted storage, not an expired or replayed token: indistinguishable to the caller
      // by design, and distinguishable to an operator only here.
      this.logger.warn('reset: stored reset context is not parseable JSON')
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

    const record = parsed as Record<string, unknown>
    const fingerprint = record['passwordFingerprint']
    return {
      userId: record['userId'] as string,
      email: record['email'] as string,
      tenantId: record['tenantId'] as string,
      // Absent on a record written by an older build, or by a sibling that has not taken this
      // change yet. Treated as "no binding" rather than as a mismatch: refusing every such
      // token would break every reset in flight during a rolling deploy, which is a worse
      // outcome than the narrow window this closes.
      passwordFingerprint: typeof fingerprint === 'string' ? fingerprint : ''
    }
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
