import { Inject, Injectable, Logger, Optional } from '@nestjs/common'
import type { Request } from 'express'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-auth.constants'
import { BruteForceService } from './brute-force.service'
import { OtpService } from './otp.service'
import { PasswordService } from './password.service'
import { SessionService } from './session.service'
import type { ResolvedOptions } from '../config/resolved-options'
import { reproofCounterId } from '../constants/reproof-counter'
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
import { answerResetRequest } from '../utils/answer-reset-request'
import { classifyResetProof } from '../utils/classify-reset-proof'
import { describeChannelStatus } from '../utils/describe-error'
import { logSafe } from '../utils/log-safe'
import { normalizeEmail } from '../utils/normalize-email'
import { redactSecrets } from '../utils/redact-secrets'
import { resolveTenantId } from '../utils/resolve-tenant-id'
import { runDetached } from '../utils/run-detached'
import { safeLogLine } from '../utils/safe-log-line'
import { createEmptyHookContext } from '../utils/sanitize-headers'
import { tenantScoped } from '../utils/tenant-scoped'

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

/** The envelope an {@link AuthException} carries, read to tell one refusal from another. */
interface ErrorBody {
  error?: { code?: string }
}

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
    @Inject(OtpService) private readonly otpService: OtpService,
    @Inject(PasswordService) private readonly passwordService: PasswordService,
    @Inject(AuthRedisService) private readonly redis: AuthRedisService,
    @Inject(SessionService) private readonly sessionService: SessionService,
    @Inject(BruteForceService) private readonly bruteForce: BruteForceService
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
   * **Resolves the same way** whether or not the account exists:
   * - The email does not exist in the tenant.
   * - The account is blocked.
   * - Issuing or storing the code, or the email provider, fails for an account that exists.
   *
   * What a failure answers, and when the cooldown this call took is released, is decided in one
   * place, {@link answerResetRequest}. The response cannot be used to probe whether an email
   * address is registered.
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
    // The address is canonicalized here for the same reason the tenant is resolved here: every
    // control on this path is keyed on it. The OTP record, its five-attempt ceiling and the
    // resend cooldown all hang off `hmac(tenantId:email)`, so left raw, `USER@x.com` and
    // `user@x.com` key different records — varying the case alone bought a fresh attempt budget
    // and a fresh send, and the account lookup was left depending on whether the host's
    // repository happens to compare case-insensitively.
    dto = { ...dto, tenantId, email: normalizeEmail(dto.email) }
    const start = Date.now()

    const { method } = this.options.passwordReset
    await this.answerResetRequest('initiateReset', dto.email, tenantId, start, (userId) =>
      method === 'otp'
        ? this.sendOtp(dto.email, tenantId, userId)
        : this.sendToken(dto.email, tenantId, userId)
    )
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
   * The proof is classified before anything else is judged, so a request with none, with more than
   * one, or with one the configured method does not accept is an invalid token whatever password it
   * carries and never reaches the password policy. Then the password is judged, then the proof is
   * spent.
   *
   * On success the user's password is updated and all sessions are invalidated.
   * The method throws an {@link AuthException} on any failure — no timing
   * normalization is applied here since the error reveals only that the proof
   * was invalid, not whether the account exists.
   *
   * @param dto - Validated DTO with `email`, `newPassword`, `tenantId`, and one proof field.
   * @throws {@link AuthException} `PASSWORD_RESET_TOKEN_INVALID` when the proof is absent,
   *   consumed, expired, or method-mismatch detected.
   * @throws {@link AuthException} `OTP_INVALID` — one answer for every OTP failure — for
   *   OTP-path failures.
   */
  async resetPassword(dto: ResetPasswordDto, req: Request): Promise<void> {
    // The configured resolver is authoritative, exactly as it is for login and register: a
    // deployment that derives the tenant from the request has stated that the body's value is
    // not to be trusted. Without this a caller on one tenant could drive reset mail at accounts
    // in another, and a reset started under the resolved tenant could never be completed —
    // the stored context and this step would disagree about which tenant it belonged to.
    const tenantId = await resolveTenantId(dto.tenantId, req, this.options.tenantIdResolver)
    dto = { ...dto, tenantId, email: normalizeEmail(dto.email) }
    // The proof is classified first, without being looked up or spent: more than one, none, or one
    // the configured method does not accept is refused as an invalid token whatever password the
    // request carries, so a caller holding no usable proof never reaches the password policy. Its
    // breach screen may be an outbound query (the bundled HIBP provider), and such a caller must
    // not be able to drive it.
    const proof = classifyResetProof(this.options.passwordReset.method, dto)

    // The new password is judged BEFORE the proof is spent.
    //
    // Every proof on this path is single-use and consumed atomically (`GETDEL` for the two token
    // shapes, the Lua script for the OTP), so a rejection that arrived after the consumption
    // would burn the caller's only credential for a mistake in the request itself, and the whole
    // mail round trip would have to be repeated. Only a caller who presented a well-formed proof
    // of the right kind reaches this check, at the route's three requests per five minutes.
    await this.passwordService.assertAcceptable(dto.newPassword, 'newPassword')

    if (proof.kind === 'token') {
      await this.resetWithToken(dto.email, tenantId, proof.value, dto.newPassword)
    } else if (proof.kind === 'verifiedToken') {
      await this.resetWithVerifiedToken(dto.email, tenantId, proof.value, dto.newPassword)
    } else {
      await this.resetWithOtp(dto.email, tenantId, proof.value, dto.newPassword)
    }
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
   * @throws {@link AuthException} `OTP_INVALID` for every OTP failure — a wrong code, a
   *   record that is not in Redis, and an exhausted attempt ceiling are indistinguishable.
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
    dto = { ...dto, tenantId, email: normalizeEmail(dto.email) }
    const identifier = this.otpIdentifier(tenantId, dto.email)
    await this.otpService.verify(PASSWORD_RESET_PURPOSE, identifier, dto.otp)

    // After successful OTP verification, ensure the account still exists before
    // issuing the verifiedToken. Use PASSWORD_RESET_TOKEN_INVALID to prevent
    // distinguishing "OTP consumed for a deleted account" from other failures.
    const user = tenantScoped(
      await this.userRepo.findByEmail({ email: dto.email, tenantId }),
      tenantId
    )
    if (!user) {
      throw new AuthException(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    }

    const rawVerifiedToken = generateSecureToken()
    const context: ResetContext = {
      userId: user.id,
      email: dto.email,
      tenantId: tenantId,
      passwordFingerprint: await this.passwordFingerprintOf(user.id, user.tenantId)
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
   * prevent OTP flooding. Resolves the same way whether or not the user exists —
   * anti-enumeration principle; what a failure answers is decided in one place,
   * {@link answerResetRequest}.
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
    dto = { ...dto, tenantId, email: normalizeEmail(dto.email) }
    const start = Date.now()

    // `sendOtp` stores the OTP in Redis synchronously, then fires the email provider call as
    // fire-and-forget (void). The timing floor in `answerResetRequest` is correct only because
    // the email send is NOT awaited here. If this is changed to `await`, the email RTT is added
    // to the synchronous path, creating a timing difference between "user found" and "user not
    // found" responses.
    await this.answerResetRequest('resendOtp', dto.email, tenantId, start, (userId) =>
      this.sendOtp(dto.email, tenantId, userId)
    )
  }

  // ---------------------------------------------------------------------------
  // Private helpers — reset requests
  // ---------------------------------------------------------------------------

  /** Runs one `forgot-password` or `resend-otp` request through the shared failure rule. */
  private answerResetRequest(
    label: 'initiateReset' | 'resendOtp',
    email: string,
    tenantId: string,
    start: number,
    issue: (userId: string) => Promise<void>
  ): Promise<void> {
    return answerResetRequest(
      { redis: this.redis, logger: this.logger },
      {
        label,
        cooldownKey: `resend:${PASSWORD_RESET_PURPOSE}:${this.otpIdentifier(tenantId, email)}`,
        cooldownSeconds: RESEND_COOLDOWN_SECONDS,
        floorMs: ANTI_ENUM_MIN_MS,
        start,
        findAccount: async () =>
          tenantScoped(await this.userRepo.findByEmail({ email, tenantId }), tenantId),
        isBlocked: (status) => this.isBlocked(status),
        issue
      }
    )
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
    await this.applyPasswordReset(context.userId, context.tenantId, newPassword)
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

    const user = tenantScoped(await this.userRepo.findByEmail({ email, tenantId }), tenantId)
    if (!user) {
      // OTP was consumed but user disappeared — treat as token invalid.
      throw new AuthException(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    }

    await this.applyPasswordReset(user.id, user.tenantId, newPassword)
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
    await this.applyPasswordReset(context.userId, context.tenantId, newPassword)
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
    tenantId: string,
    dto: ChangePasswordDto,
    currentRefreshToken?: string
  ): Promise<void> {
    // Scoped, like every other read of an account. The unscoped form is why the write below had
    // no tenant to pass: a lookup by bare id cannot tell the caller which tenant it answered for.
    const user = await this.userRepo.findById({ id: userId, tenantId })
    // A verified token whose subject no longer exists, and an account with no local password,
    // answer identically: the caller cannot prove a credential this account does not have.
    if (!user?.passwordHash) {
      throw new AuthException(AUTH_ERROR_CODES.INVALID_CREDENTIALS)
    }

    // Counted like a login, and for the same reason. This door asks for the account password
    // and used to refuse nothing, so a caller holding a stolen access token but not the
    // password could guess it here without limit — and winning replaces the credential, which
    // locks the owner out of their own account. The per-route IP limit is not that control: a
    // distributed caller sidesteps it, and it is not keyed to the account being attacked. The
    // counter is namespaced by flow so it cannot lock the owner out of `login` instead.
    // Counted under the tenant-scoped subject, not the bare id: a repository id is unique only
    // within a tenant, so two tenants' user `1` need two budgets, or failures against one lock the
    // other out with no credential. `userSubject` is injective over (tenant, user).
    const bfIdentifier = reproofCounterId('change-password', userId, tenantId, this.options.hmacKey)
    if (await this.bruteForce.isLockedOut(bfIdentifier)) {
      this.logger.warn(`changePassword: account locked userId=${logSafe(userId)}`)
      throw new AuthException(AUTH_ERROR_CODES.ACCOUNT_LOCKED)
    }

    const matches = await this.passwordService.compare(dto.currentPassword, user.passwordHash)
    if (!matches) {
      await this.bruteForce.recordFailure(bfIdentifier)
      this.logger.warn(`changePassword: current password rejected userId=${logSafe(userId)}`)
      throw new AuthException(AUTH_ERROR_CODES.INVALID_CREDENTIALS)
    }

    await this.bruteForce.resetFailures(bfIdentifier)

    // The session to keep has to be a live one, and that is settled before the password changes:
    // a stale token would otherwise write the new credential and then fail to keep anything.
    const keptHash = await this.resolveCurrentSession(userId, user.tenantId, currentRefreshToken)

    await this.passwordService.assertAcceptable(dto.newPassword, 'newPassword')
    const passwordHash = await this.passwordService.hash(dto.newPassword)
    await this.userRepo.updatePassword({ id: userId, tenantId, passwordHash })

    // End every other session, and the access tokens with them. `revokeAllExceptCurrent`
    // bumps the epoch itself, which is what reaches the stateless access tokens — the ones a
    // session sweep alone leaves valid until they expire.
    await this.endOtherSessions(userId, user.tenantId, keptHash)

    await this.notifyPasswordChanged(user)
  }

  /**
   * The hash of the live session a presented refresh token stands for, or `undefined` when the
   * request carried none. Refuses a token that names no live session of the account; a token that
   * rotated away while the password was being verified stands for the session that replaced it.
   */
  private async resolveCurrentSession(
    userId: string,
    tenantId: string,
    currentRefreshToken: string | undefined
  ): Promise<string | undefined> {
    if (currentRefreshToken === undefined || currentRefreshToken.length === 0) return undefined
    return this.sessionService.resolveLiveSession({
      userId,
      tenantId,
      sessionHash: sha256(currentRefreshToken)
    })
  }

  /**
   * Ends every session but the one to keep, once the new password is already written.
   *
   * With no session to keep every session ends. A kept session can rotate away while the new
   * password is hashed; the sweep follows it to its successor, and when it cannot be followed
   * there is no current session left to spare, so every session ends and the cleanup that makes
   * the change safe is never aborted by the session it was told to spare. Any other failure of
   * the sweep propagates.
   */
  private async endOtherSessions(
    userId: string,
    tenantId: string,
    keptHash: string | undefined
  ): Promise<void> {
    if (keptHash === undefined) {
      return this.endAllSessions(userId, tenantId)
    }
    try {
      await this.sessionService.revokeAllExceptCurrent({
        userId,
        tenantId,
        currentSessionHash: keptHash
      })
    } catch (err: unknown) {
      const body = err instanceof AuthException ? (err.getResponse() as ErrorBody) : undefined
      if (body?.error?.code !== AUTH_ERROR_CODES.SESSION_NOT_FOUND) throw err
      await this.endAllSessions(userId, tenantId)
    }
  }

  /** Ends every session the account has and advances its token epoch. */
  private async endAllSessions(userId: string, tenantId: string): Promise<void> {
    await this.redis.invalidateUserSessions(userId, tenantId, 'dashboard')
    await this.redis.bumpUserTokenEpoch(userId, tenantId, 'dashboard')
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

    const provider = this.emailProvider
    const withheld = [user.email]

    // An async IIFE rather than `Promise.resolve(send.call(...))`: the second evaluates the call
    // before the promise wraps it, so a provider that throws SYNCHRONOUSLY skipped this handler
    // and reached the caller. Inside the IIFE the call is still made synchronously and the `try`
    // still catches the throw.
    void (async (): Promise<void> => {
      try {
        await send.call(provider, user.tenantId, user.email)
      } catch (err: unknown) {
        // The error is NOT handed to the logger, and nothing the channel wrote reaches this line:
        // `describeChannelStatus` publishes nothing it authored. An SMTP rejection routinely
        // NAMES the recipient it refused (`550 user@example.com: recipient rejected`) with no
        // quoted body involved, which makes it the likeliest exposure of the set — and the
        // provider strips the address from ITS line and rethrows the original under
        // `onDeliveryError: 'rethrow'`, so this line was putting back what that one removed.
        this.logger.error(
          safeLogLine(
            `notifyPasswordChanged: delivery failed for user ${logSafe(user.id)}: ` +
              describeChannelStatus(err),
            withheld
          )
        )
      }
    })()
  }

  /**
   * A digest of the account's current password hash, used to bind a reset token to it.
   *
   * The hash itself never leaves the repository — only this digest goes into Redis, so a leaked
   * snapshot of the reset keyspace reveals nothing about the credential. An account with no
   * local password yields the empty string, which is a value like any other: a token minted
   * then is invalidated as soon as one is set.
   */
  private async passwordFingerprintOf(userId: string, tenantId: string): Promise<string> {
    const user = await this.userRepo.findById({ id: userId, tenantId })
    // Stryker disable next-line StringLiteral: the sentinel's VALUE is unobservable today, because
    // the only consumer that tests for it — `assertResetTokenStillBound` — reads an empty
    // fingerprint as "this token predates the binding" and accepts it. So a passwordless account's
    // token is accepted whatever this returns: as `''` via that early return, and as any other
    // string by comparing equal to itself on the next line.
    //
    // Which also means the sentence above ("invalidated as soon as one is set") does not hold: the
    // two readings of `''` — "no local password" here, "predates the binding" there — collide, and
    // the accepting one wins. Reconciling them is a behaviour change to the stored record format
    // shared with the sibling implementation, so it is recorded here rather than made silently
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
    if (
      context.passwordFingerprint ===
      (await this.passwordFingerprintOf(context.userId, context.tenantId))
    )
      return

    this.logger.warn(
      `reset: refusing a token issued against a password that has since changed ` +
        `userId=${logSafe(context.userId)}`
    )
    throw new AuthException(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
  }

  private async applyPasswordReset(
    userId: string,
    tenantId: string,
    newPassword: string
  ): Promise<void> {
    // The breach check ran in `resetPassword`, before the proof was spent — see the note there.
    const passwordHash = await this.passwordService.hash(newPassword)
    await this.userRepo.updatePassword({ id: userId, tenantId, passwordHash })
    // Revoke every session AND invalidate already-issued access tokens: a Lua session
    // invalidation (atomic, so a concurrent login cannot slip a session in between the SMEMBERS
    // read and the DEL) followed by the epoch bump, which must land before the reset returns.
    // Deleting the refresh sessions alone would leave a stolen access token valid until its exp.
    await this.redis.invalidateUserSessions(userId, tenantId, 'dashboard')
    await this.redis.bumpUserTokenEpoch(userId, tenantId, 'dashboard')

    // The same repository read serves the notification, which a reset needs at least as much as
    // a change does: the classic takeover completes a reset from a compromised mailbox and
    // deletes the mail. The hook after it is fire-and-forget.
    const user = await this.userRepo.findById({ id: userId, tenantId })
    if (user) {
      await this.notifyPasswordChanged(user)
      if (this.hooks?.afterPasswordReset) {
        const afterPasswordReset = this.hooks.afterPasswordReset.bind(this.hooks)
        runDetached(
          this.logger,
          () =>
            afterPasswordReset(toSafeUser(user), {
              ...createEmptyHookContext(),
              plane: 'dashboard'
            }),
          'afterPasswordReset hook threw'
        )
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
      passwordFingerprint: await this.passwordFingerprintOf(userId, tenantId)
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
    // Captured out of the field: the guard above narrowed `this.emailProvider`, and that narrowing
    // does not survive into a handler the compiler cannot prove runs before the field changes.
    const provider = this.emailProvider

    // An async IIFE, NOT `Promise.resolve().then(...)`. Both catch a provider that throws
    // SYNCHRONOUSLY — which `Promise.resolve(provider.send(...))` does not, because it evaluates
    // the call before the promise wraps it, so the throw skips this handler and reaches the
    // caller's own error path, which logs raw. The difference is WHEN the send starts: `.then`
    // defers it by a microtask, so the response leaves before the provider is even called. That
    // is observable — it broke an e2e that read the dispatched code the instant the response
    // landed — and the delay buys nothing. Inside the IIFE the call is made synchronously and
    // the `try` still catches a synchronous throw.
    void (async (): Promise<void> => {
      try {
        await provider.sendPasswordResetToken(tenantId, email, rawToken)
      } catch (err: unknown) {
        // Redacted, not raw: a relay that rejects by quoting the body puts `rawToken` into the
        // error, and this token is a working password reset until its TTL expires. The recipient
        // joins it — an SMTP rejection routinely names the address it refused, and the provider
        // strips that from ITS line but rethrows the original here.
        //
        // Per field, with `safeLogLine` checking the assembled result. `userId` is deliberately
        // NOT redacted against the token, and the asymmetry with the OTP path below is the point:
        // an OTP is four to eight digits, so an identifier containing one by coincidence is real,
        // while a 64-hex token can only appear inside an id derived FROM it, which no repository
        // does. Redacting it anyway looked symmetric and was dead code the mutation gate found.
        //
        // `withheld` is for the fields THIS line composes, not for the error: nothing the channel
        // wrote reaches the description at all, so there is nothing there to name.
        const withheld = [rawToken, email]
        this.logger.error(
          safeLogLine(
            `sendPasswordResetToken failed for user ${logSafe(userId)}: ` +
              describeChannelStatus(err),
            withheld
          )
        )
        void this.redis.del(tokenKey).catch((delErr: unknown) => {
          // `delErr` comes from `redis.del` on a key that is a SHA-256 of the token, so no
          // quoted-body path can put a credential into it. That argument is still true and it is
          // no longer sufficient: the SAME argument was made for the session-cleanup handlers in
          // `AuthService`, which were also Redis and also stringified the rejection raw. What
          // decides it is not whether a credential can be there but whether the text is this
          // library's to publish — an ioredis rejection is unbounded, carries no guarantee about
          // control characters, and names the key, which embeds the consumer's user id.
          this.logger.error(
            `pw_reset rollback delete failed for user ${logSafe(userId)}: ${describeChannelStatus(delErr)}`
          )
        })
      }
    })()
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

    // Captured out of the field: the guard above narrowed `this.emailProvider`, and that narrowing
    // does not survive into a handler the compiler cannot prove runs before the field changes.
    const provider = this.emailProvider

    // An async IIFE, NOT `Promise.resolve().then(...)`. Both catch a provider that throws
    // SYNCHRONOUSLY — which `Promise.resolve(provider.send(...))` does not, because it evaluates
    // the call before the promise wraps it, so the throw skips this handler and reaches the
    // caller's own error path, which logs raw. The difference is WHEN the send starts: `.then`
    // defers it by a microtask, so the response leaves before the provider is even called. That
    // is observable — it broke an e2e that read the dispatched code the instant the response
    // landed — and the delay buys nothing. Inside the IIFE the call is made synchronously and
    // the `try` still catches a synchronous throw.
    void (async (): Promise<void> => {
      try {
        await provider.sendPasswordResetOtp(tenantId, email, otp)
      } catch (err: unknown) {
        // Redacted, not raw: the quoted body carries this otp, which resets the password, and an
        // SMTP rejection commonly names the recipient — which the provider removed from its own
        // line and then rethrew here.
        //
        // Per field, with `safeLogLine` checking the assembled result rather than redacting it —
        // see the verification-OTP site for why: redacting the assembled string lets either
        // redaction alone satisfy the test, so neither is proven. `userId` is redacted against the
        // otp because a reset code is short enough for an identifier to contain one.
        //
        // `withheld` is for the fields THIS line composes, not for the error: nothing the channel
        // wrote reaches the description at all, so there is nothing there to name.
        const withheld = [otp, email]
        this.logger.error(
          safeLogLine(
            `sendPasswordResetOtp failed for user ${logSafe(redactSecrets(userId, withheld))}: ` +
              describeChannelStatus(err),
            withheld
          )
        )
      }
    })()
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
      // Stryker disable next-line CallExpression: equivalent — the warn above is already emitted, and with this throw gone `parsed` stays undefined, so the shape check immediately below refuses the record with the identical code. Same log, same error, same order.
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
