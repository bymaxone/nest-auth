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
import { TokenManagerService } from './token-manager.service'
import type { ResolvedOptions } from '../config/resolved-options'
import { hmacSha256, sha256 } from '../crypto/secure-token'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import type { AuthErrorCode } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { HookContext, IAuthHooks } from '../interfaces/auth-hooks.interface'
import type {
  AuthResult,
  MfaChallengeResult,
  RotatedTokenResult
} from '../interfaces/auth-result.interface'
import type { IEmailProvider } from '../interfaces/email-provider.interface'
import type {
  AuthUser,
  IUserRepository,
  SafeAuthUser
} from '../interfaces/user-repository.interface'
import { AuthRedisService } from '../redis/auth-redis.service'
import { maskEmail } from '../utils/mask-email'
import { createEmptyHookContext, sanitizeHeaders } from '../utils/sanitize-headers'
import { sleep } from '../utils/sleep'

/** Minimum response time in ms for anti-enumeration endpoints. */
const ANTI_ENUM_MIN_MS = 300

/**
 * Core authentication service for dashboard (tenant) users.
 *
 * Orchestrates the full authentication lifecycle: registration, login, logout,
 * token refresh, email verification, and brute-force protection. All security-
 * sensitive operations (password hashing, JWT issuance, brute-force tracking)
 * are delegated to specialized services.
 *
 * @remarks
 * Hook errors from `after*` and `on*` hooks are caught and logged — they must
 * never propagate to the caller. Only `beforeRegister` can block the flow.
 */
@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name)

  constructor(
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions,
    @Inject(BYMAX_AUTH_USER_REPOSITORY) private readonly userRepo: IUserRepository,
    @Inject(BYMAX_AUTH_EMAIL_PROVIDER)
    @Optional()
    private readonly emailProvider: IEmailProvider | null,
    @Inject(BYMAX_AUTH_HOOKS) @Optional() private readonly hooks: IAuthHooks | null,
    private readonly passwordService: PasswordService,
    private readonly tokenManager: TokenManagerService,
    private readonly bruteForce: BruteForceService,
    private readonly redis: AuthRedisService,
    private readonly otpService: OtpService,
    private readonly sessionService: SessionService
  ) {}

  // ---------------------------------------------------------------------------
  // Register
  // ---------------------------------------------------------------------------

  /**
   * Registers a new dashboard user.
   *
   * @param dto - Registration payload (email, password, name, tenantId from body,
   *   or tenantId resolved from request via `tenantIdResolver`).
   * @param req - Incoming Express request (used for tenantId resolution and hooks).
   * @returns Full auth result with tokens and safe user object.
   * @throws {@link AuthException} with `EMAIL_ALREADY_EXISTS` if the email is taken.
   * @throws {@link AuthException} with `FORBIDDEN` if `beforeRegister` hook rejects.
   */
  async register(
    dto: { email: string; password: string; name: string; tenantId: string },
    req: Request
  ): Promise<AuthResult> {
    const tenantId = await this.resolveTenantId(dto.tenantId, req)
    const ip = req.ip ?? ''
    const userAgent = String(req.headers['user-agent'] ?? '')
    const context = this.buildHookContext({ tenantId, email: dto.email, ip, userAgent, req })

    // beforeRegister hook — only hook that can block the flow.
    if (this.hooks?.beforeRegister) {
      const hookResult = await this.hooks.beforeRegister(
        { email: dto.email, name: dto.name, tenantId },
        context
      )
      if (!hookResult.allowed) {
        throw new AuthException(AUTH_ERROR_CODES.FORBIDDEN)
      }
      if (hookResult.modifiedData) {
        // Merge hook overrides immutably — avoids mutating the validated DTO and
        // bypassing class-validator constraints already applied by the pipe.
        dto = { ...dto, ...hookResult.modifiedData } as typeof dto
      }
    }

    // Check uniqueness before hashing password (cheaper than scrypt on conflict).
    const existing = await this.userRepo.findByEmail(dto.email, tenantId)
    if (existing) {
      throw new AuthException(AUTH_ERROR_CODES.EMAIL_ALREADY_EXISTS)
    }

    const passwordHash = await this.passwordService.hash(dto.password)

    const augmented = dto as Record<string, unknown>
    const newUser = await this.userRepo.create({
      email: dto.email,
      name: dto.name,
      passwordHash,
      tenantId,
      ...(typeof augmented['role'] === 'string' && { role: augmented['role'] }),
      ...(typeof augmented['status'] === 'string' && { status: augmented['status'] }),
      ...(this.options.emailVerification.required
        ? { emailVerified: false }
        : typeof augmented['emailVerified'] === 'boolean'
          ? { emailVerified: augmented['emailVerified'] }
          : {})
    })

    // Send email verification OTP if required.
    if (this.options.emailVerification.required) {
      await this.sendVerificationOtp(tenantId, dto.email, newUser.id)
    }

    const safeUser = toSafeUser(newUser)
    const result = await this.tokenManager.issueTokens(safeUser, ip, userAgent)

    // Track the session when sessions are enabled (enforces concurrent session limit).
    if (this.options.sessions.enabled) {
      await this.sessionService.createSession(safeUser.id, result.rawRefreshToken, ip, userAgent)
    }

    this.logger.log(`register: user registered userId=${newUser.id} tenantId=${tenantId}`)

    // afterRegister — fire-and-forget; errors must not propagate.
    if (this.hooks?.afterRegister) {
      void Promise.resolve(this.hooks.afterRegister(safeUser, context)).catch((err: unknown) => {
        this.logger.error('afterRegister hook threw', err)
      })
    }

    return result
  }

  // ---------------------------------------------------------------------------
  // Login
  // ---------------------------------------------------------------------------

  /**
   * Authenticates a dashboard user with email and password.
   *
   * Returns either a full {@link AuthResult} or a {@link MfaChallengeResult}
   * when the user has MFA enabled.
   *
   * @param dto - Login credentials.
   * @param req - Incoming Express request.
   * @returns Auth result or MFA challenge prompt.
   * @throws {@link AuthException} with `ACCOUNT_LOCKED` when brute-force limit reached.
   * @throws {@link AuthException} with `INVALID_CREDENTIALS` on bad email/password.
   */
  async login(
    dto: { email: string; password: string; tenantId: string },
    req: Request
  ): Promise<AuthResult | MfaChallengeResult> {
    const tenantId = await this.resolveTenantId(dto.tenantId, req)
    const ip = req.ip ?? ''
    const userAgent = String(req.headers['user-agent'] ?? '')

    // Brute-force identifier: HMAC-SHA256 prevents rainbow-table reversal of the email.
    // The ':' separator ensures 'tenantABC' + 'x@y.com' and 'tenantABCx' + '@y.com'
    // never produce the same input string (prefix-collision resistance).
    const bfIdentifier = hmacSha256(`${tenantId}:${dto.email}`, this.options.hmacKey)

    const locked = await this.bruteForce.isLockedOut(bfIdentifier)
    if (locked) {
      this.logger.warn(`login: account locked email=${maskEmail(dto.email)} tenantId=${tenantId}`)
      const remainingSeconds = await this.bruteForce.getRemainingLockoutSeconds(bfIdentifier)
      throw new AuthException(AUTH_ERROR_CODES.ACCOUNT_LOCKED, 429, {
        retryAfterSeconds: remainingSeconds
      })
    }

    const context = this.buildHookContext({ tenantId, email: dto.email, ip, userAgent, req })

    if (this.hooks?.beforeLogin) {
      await this.hooks.beforeLogin(dto.email, tenantId, context)
    }

    const user = await this.userRepo.findByEmail(dto.email, tenantId)

    // User-not-found path: we do NOT attempt a dummy scrypt compare. The brute-force
    // counter lockout is the primary protection against credential probing — a constant-time
    // dummy compare would add CPU amplification to every unknown-email request. The timing
    // difference is intentionally bounded by `recordFailure` latency (a single Redis op) and
    // masked by the brute-force lockout threshold.
    if (!user || !user.passwordHash) {
      await this.bruteForce.recordFailure(bfIdentifier)
      throw new AuthException(AUTH_ERROR_CODES.INVALID_CREDENTIALS)
    }

    // Status check before expensive scrypt — avoid wasting CPU on blocked accounts.
    this.assertUserNotBlocked(user)

    // Email verification gate.
    if (this.options.emailVerification.required && !user.emailVerified) {
      throw new AuthException(AUTH_ERROR_CODES.EMAIL_NOT_VERIFIED)
    }

    const passwordMatch = await this.passwordService.compare(dto.password, user.passwordHash)
    if (!passwordMatch) {
      await this.bruteForce.recordFailure(bfIdentifier)
      this.logger.warn(
        `login: invalid credentials email=${maskEmail(dto.email)} tenantId=${tenantId}`
      )
      throw new AuthException(AUTH_ERROR_CODES.INVALID_CREDENTIALS)
    }

    // Reset brute-force counter on success.
    await this.bruteForce.resetFailures(bfIdentifier)

    // MFA challenge path.
    if (user.mfaEnabled) {
      const mfaTempToken = await this.tokenManager.issueMfaTempToken(user.id, 'dashboard')
      this.logger.log(`login: MFA challenge issued userId=${user.id} tenantId=${tenantId}`)
      return { mfaRequired: true, mfaTempToken }
    }

    const safeUser = toSafeUser(user)
    const result = await this.tokenManager.issueTokens(safeUser, ip, userAgent)

    // Track the session when sessions are enabled (enforces concurrent session limit).
    if (this.options.sessions.enabled) {
      await this.sessionService.createSession(safeUser.id, result.rawRefreshToken, ip, userAgent)
    }

    this.logger.log(`login: success userId=${safeUser.id} tenantId=${tenantId}`)

    // Non-blocking side effects.
    void this.userRepo.updateLastLogin(user.id).catch((err: unknown) => {
      this.logger.error('updateLastLogin failed', err)
    })
    if (this.hooks?.afterLogin) {
      void Promise.resolve(this.hooks.afterLogin(safeUser, context)).catch((err: unknown) => {
        this.logger.error('afterLogin hook threw', err)
      })
    }

    return result
  }

  // ---------------------------------------------------------------------------
  // Logout
  // ---------------------------------------------------------------------------

  /**
   * Logs out a dashboard user by revoking the access token and deleting the refresh session.
   *
   * @param accessToken - Raw JWT access token (used to extract `jti` for revocation).
   * @param rawRefreshToken - Raw opaque refresh token (session key is derived from its hash).
   * @param userId - The authenticated user's ID (for hook context).
   */
  async logout(accessToken: string, rawRefreshToken: string, userId: string): Promise<void> {
    this.logger.log(`logout: userId=${userId}`)
    // Decode without verifying — the token may be expired at logout time.
    try {
      const payload = this.tokenManager.decodeToken(accessToken)
      const now = Math.floor(Date.now() / 1000)
      const remainingTtl = payload.exp - now
      if (remainingTtl > 0) {
        await this.redis.set(`rv:${payload.jti}`, '1', remainingTtl)
      }
    } catch {
      // Malformed token — no revocation entry needed.
    }

    // Delete the refresh token key — always required for auth security.
    const sessionHash = sha256(rawRefreshToken)
    await this.redis.del(`rt:${sessionHash}`)

    // Delegate session metadata cleanup to SessionService.revokeSession(), which
    // performs an atomic SISMEMBER ownership check before deleting sd:{hash} and
    // SREMing from sess:{userId}. The rt:{hash} DEL above already ran — revokeSession's
    // internal DEL will be a no-op (Redis DEL is idempotent when key is absent).
    // SESSION_NOT_FOUND: session was evicted, already revoked, or the refresh token
    // does not belong to this user — in all cases authentication is already invalidated.
    if (this.options.sessions.enabled) {
      await this.sessionService.revokeSession(userId, sessionHash).catch((err: unknown) => {
        const errCode =
          err instanceof AuthException
            ? (err.getResponse() as { error: { code: string } }).error.code
            : undefined
        if (errCode !== AUTH_ERROR_CODES.SESSION_NOT_FOUND) {
          this.logger.warn(`logout: session cleanup failed — ${String(err)}`)
        }
      })
    }

    if (this.hooks?.afterLogout) {
      void Promise.resolve(this.hooks.afterLogout(userId, createEmptyHookContext())).catch(
        (err: unknown) => {
          this.logger.error('afterLogout hook threw', err)
        }
      )
    }
  }

  // ---------------------------------------------------------------------------
  // Refresh
  // ---------------------------------------------------------------------------

  /**
   * Rotates a dashboard refresh token.
   *
   * Delegates to {@link TokenManagerService.reissueTokens}. Callers that need the
   * full user record in the HTTP response must fetch it from the user repository
   * using the returned `session.userId`.
   *
   * @param oldRefreshToken - The raw refresh token from the client.
   * @param ip - Client IP address.
   * @param userAgent - User-Agent header value.
   * @returns New tokens and minimal session identity.
   */
  async refresh(
    oldRefreshToken: string,
    ip: string,
    userAgent: string
  ): Promise<RotatedTokenResult> {
    const result = await this.tokenManager.reissueTokens(oldRefreshToken, ip, userAgent)

    // Rotate the session detail record to the new token hash.
    // Fire-and-forget: sd: keys are display metadata only — a rotation failure
    // does not invalidate the auth tokens already issued above.
    if (this.options.sessions.enabled) {
      void this.sessionService
        .rotateSession(sha256(oldRefreshToken), sha256(result.rawRefreshToken), ip, userAgent)
        .catch((err: unknown) => {
          this.logger.warn(`refresh: session detail rotation failed — ${String(err)}`)
        })
    }

    return result
  }

  // ---------------------------------------------------------------------------
  // GetMe
  // ---------------------------------------------------------------------------

  /**
   * Retrieves the full safe user record for the currently authenticated user.
   *
   * @param userId - Subject claim from the verified JWT.
   * @returns Safe user object (credential fields excluded).
   * @throws {@link AuthException} with `TOKEN_INVALID` if the user no longer exists.
   */
  async getMe(userId: string): Promise<SafeAuthUser> {
    const user = await this.userRepo.findById(userId)
    if (!user) {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }
    return toSafeUser(user)
  }

  // ---------------------------------------------------------------------------
  // Email verification
  // ---------------------------------------------------------------------------

  /**
   * Verifies the user's email address using a one-time password.
   *
   * The user is identified by the `(tenantId, email)` pair — the OTP is keyed on
   * the same pair, so only the user who received the OTP can consume it. The
   * server derives `userId` from the repository after OTP validation; the client
   * never supplies it, preventing a caller with a valid OTP from verifying a
   * different user's account.
   *
   * @param tenantId - Tenant scope.
   * @param email - The email address being verified.
   * @param otp - The OTP supplied by the user.
   * @throws {@link AuthException} with `OTP_INVALID` when the OTP does not match
   *   or the user does not exist (response shape is identical to prevent
   *   account enumeration via this endpoint).
   */
  async verifyEmail(tenantId: string, email: string, otp: string): Promise<void> {
    const identifier = hmacSha256(`${tenantId}:${email}`, this.options.hmacKey)
    await this.otpService.verify('email_verification', identifier, otp)

    const user = await this.userRepo.findByEmail(email, tenantId)
    if (!user) {
      // Treat as OTP_INVALID rather than USER_NOT_FOUND to avoid a timing oracle
      // for callers probing email existence after a brute-forced OTP.
      throw new AuthException(AUTH_ERROR_CODES.OTP_INVALID)
    }

    await this.userRepo.updateEmailVerified(user.id, true)
    this.logger.log(`verifyEmail: email verified userId=${user.id} tenantId=${tenantId}`)

    if (this.hooks?.afterEmailVerified) {
      void Promise.resolve(
        this.hooks.afterEmailVerified(toSafeUser(user), createEmptyHookContext())
      ).catch((err: unknown) => {
        this.logger.error('afterEmailVerified hook threw', err)
      })
    }
  }

  /**
   * Resends an email verification OTP with an atomic cooldown.
   *
   * A `SET NX EX 60` guard prevents duplicate sends within 60 seconds, even
   * under concurrent requests. The response is always the same to prevent
   * email enumeration (timing normalization applied).
   *
   * @param tenantId - Tenant scope.
   * @param email - The email address to re-send to (not validated — always succeeds).
   */
  async resendVerificationEmail(tenantId: string, email: string): Promise<void> {
    const start = Date.now()
    const cooldownKey = `resend:email_verification:${hmacSha256(`${tenantId}:${email}`, this.options.hmacKey)}`

    // Atomic NX: only one send allowed per 60 seconds. SET NX EX is atomic — no TOCTOU race.
    const wasSet = await this.redis.setnx(cooldownKey, 60)
    if (!wasSet) {
      await sleep(Math.max(0, ANTI_ENUM_MIN_MS - (Date.now() - start)))
      return // Already sent recently — silently succeed.
    }

    const user = await this.userRepo.findByEmail(email, tenantId)
    if (user && !user.emailVerified) {
      await this.sendVerificationOtp(tenantId, email, user.id)
    }

    await sleep(Math.max(0, ANTI_ENUM_MIN_MS - (Date.now() - start)))
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  private async resolveTenantId(dtoTenantId: string, req: Request): Promise<string> {
    if (this.options.tenantIdResolver) {
      return this.options.tenantIdResolver(req)
    }
    return dtoTenantId
  }

  private buildHookContext(opts: {
    tenantId?: string
    email?: string
    userId?: string
    ip: string
    userAgent: string
    req: Request
  }): HookContext {
    const headers = opts.req.headers as Record<string, string | string[] | undefined>
    const sanitized = sanitizeHeaders(
      Object.fromEntries(
        Object.entries(headers).map(([k, v]) => [k, Array.isArray(v) ? v.join(', ') : (v ?? '')])
      )
    )
    const ctx: HookContext = {
      ip: opts.ip,
      userAgent: opts.userAgent,
      sanitizedHeaders: sanitized
    }
    // exactOptionalPropertyTypes: only assign optional fields when defined.
    if (opts.userId !== undefined) ctx.userId = opts.userId
    if (opts.email !== undefined) ctx.email = opts.email
    if (opts.tenantId !== undefined) ctx.tenantId = opts.tenantId
    return ctx
  }

  private assertUserNotBlocked(user: AuthUser): void {
    const blocked = this.options.blockedStatuses.map((s) => s.toLowerCase())
    if (blocked.includes(user.status.toLowerCase())) {
      const codeMap: Record<string, AuthErrorCode> = {
        banned: AUTH_ERROR_CODES.ACCOUNT_BANNED,
        inactive: AUTH_ERROR_CODES.ACCOUNT_INACTIVE,
        suspended: AUTH_ERROR_CODES.ACCOUNT_SUSPENDED,
        pending: AUTH_ERROR_CODES.PENDING_APPROVAL,
        pending_approval: AUTH_ERROR_CODES.PENDING_APPROVAL
      }

      const code: AuthErrorCode =
        codeMap[user.status.toLowerCase()] ?? AUTH_ERROR_CODES.ACCOUNT_INACTIVE
      throw new AuthException(code, 403)
    }
  }

  private async sendVerificationOtp(
    tenantId: string,
    email: string,
    userId: string
  ): Promise<void> {
    if (!this.emailProvider) {
      this.logger.warn('sendVerificationOtp: no email provider configured — OTP not sent')
      return
    }

    const identifier = hmacSha256(`${tenantId}:${email}`, this.options.hmacKey)
    const length = 6 // emailVerification does not expose otpLength; use fixed 6-digit OTPs
    const ttl = this.options.emailVerification.otpTtlSeconds
    const otp = this.otpService.generate(length)
    await this.otpService.store('email_verification', identifier, otp, ttl)

    void this.emailProvider.sendEmailVerificationOtp(email, otp).catch((err: unknown) => {
      this.logger.error(`sendEmailVerificationOtp failed for user ${userId}`, err)
    })
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
