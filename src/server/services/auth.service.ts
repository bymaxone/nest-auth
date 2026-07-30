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
import { AuthException } from '../errors/auth-exception'
import type { HookContext, IAuthHooks } from '../interfaces/auth-hooks.interface'
import type {
  AuthResult,
  DashboardRefreshResult,
  MfaChallengeResult
} from '../interfaces/auth-result.interface'
import type { IEmailProvider } from '../interfaces/email-provider.interface'
import type {
  AuthUser,
  IUserRepository,
  SafeAuthUser
} from '../interfaces/user-repository.interface'
import { AuthRedisService } from '../redis/auth-redis.service'
import { assertNotBlocked } from '../utils/assert-not-blocked'
import { maskEmail } from '../utils/mask-email'
import { normalizeEmail } from '../utils/normalize-email'
import { resolveTenantId } from '../utils/resolve-tenant-id'
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
 *
 * @layer Service
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

  /**
   * Re-derive a proven password at the current parameters and store it.
   *
   * Detached from the login it follows: the user is already authenticated, and a failure here
   * costs nothing but the upgrade — the old hash keeps working. Errors are logged rather than
   * propagated for that reason.
   *
   * @param userId - The account whose stored hash is being upgraded.
   * @param plain - The plaintext just verified against the old hash.
   */
  private async rehashPassword(userId: string, plain: string): Promise<void> {
    try {
      await this.userRepo.updatePassword(userId, await this.passwordService.hash(plain))
    } catch (err: unknown) {
      this.logger.error('rehash on verify failed — the stored hash is unchanged', err)
    }
  }

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

    // Canonicalize the email at the service boundary. The DTO `@Transform` is not
    // enough: the controllers run `ValidationPipe` without `transform: true`, so the
    // handler receives the raw body. Normalizing here guarantees the stored identity
    // and every email-keyed control use the same canonical value regardless of pipe
    // config. Merged immutably to avoid mutating the validated DTO.
    dto = { ...dto, email: normalizeEmail(dto.email) }

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
      // Stryker disable next-line ConditionalExpression: spreading a falsy `modifiedData` (`{ ...undefined }`) is a no-op, so guarding with `if (true)` produces the same merged result
      if (hookResult.modifiedData) {
        // Merge hook overrides immutably — avoids mutating the validated DTO and
        // bypassing class-validator constraints already applied by the pipe.
        dto = { ...dto, ...hookResult.modifiedData } as typeof dto
      }
    }

    // Uniqueness before hashing — but the conflict path still pays the KDF.
    //
    // Skipping it is the cheaper thing to do and it leaks: a taken address answers in
    // single-digit milliseconds while a free one spends ~100 ms deriving, which enumerates
    // accounts by clock even for a caller who ignores the status code. The response itself
    // cannot be made uniform here — registration issues tokens, and there are none to issue for
    // an account the caller does not own — so the timing is the part that can be fixed, and it
    // is. What bounds the disclosure that remains is the route's own limit (10/hour), now keyed
    // to an address the caller cannot choose.
    //
    // The dummy derivation is the same one the login path spends on an unknown address, so this
    // adds no amplification a login could not already be used for.
    const existing = await this.userRepo.findByEmail(dto.email, tenantId)
    if (existing) {
      await this.passwordService.compareDummy(dto.password)
      throw new AuthException(AUTH_ERROR_CODES.EMAIL_ALREADY_EXISTS)
    }

    await this.passwordService.assertNotCompromised(dto.password)
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

    // Canonicalize the email before deriving ANY email-keyed value below. The DTO
    // `@Transform` is discarded because the controllers run `ValidationPipe` without
    // `transform: true`, so without this the brute-force lockout key and the user
    // lookup would be computed from caller-controlled casing — the case-rotation
    // lockout bypass. Merged immutably to avoid mutating the validated DTO.
    dto = { ...dto, email: normalizeEmail(dto.email) }

    // Brute-force identifier: HMAC-SHA256 prevents rainbow-table reversal of the email.
    // The ':' separator ensures 'tenantABC' + 'x@y.com' and 'tenantABCx' + '@y.com'
    // never produce the same input string (prefix-collision resistance).
    const bfIdentifier = hmacSha256(`${tenantId}:${dto.email}`, this.options.hmacKey)

    const context = this.buildHookContext({ tenantId, email: dto.email, ip, userAgent, req })

    const locked = await this.bruteForce.isLockedOut(bfIdentifier)
    if (locked) {
      this.logger.warn(`login: account locked email=${maskEmail(dto.email)} tenantId=${tenantId}`)
      const remainingSeconds = await this.bruteForce.getRemainingLockoutSeconds(bfIdentifier)
      this.emitLoginFailed({ email: dto.email, tenantId, reason: 'locked_out' }, context)
      throw new AuthException(AUTH_ERROR_CODES.ACCOUNT_LOCKED, 429, {
        retryAfterSeconds: remainingSeconds
      })
    }

    if (this.hooks?.beforeLogin) {
      await this.hooks.beforeLogin(dto.email, tenantId, context)
    }

    const user = await this.userRepo.findByEmail(dto.email, tenantId)

    // User-not-found path: run a dummy scrypt derivation before failing so that an
    // unknown e-mail takes the same wall-clock time as a known e-mail with a wrong
    // password. Skipping this leaks a timing oracle (~single-digit ms vs. tens of ms)
    // that enumerates which accounts exist despite the identical error message. The
    // cost matches one normal failed login — no new amplification — and route-level
    // rate limiting bounds it further.
    if (!user || !user.passwordHash) {
      await this.passwordService.compareDummy(dto.password)
      await this.recordLoginFailure(bfIdentifier, { email: dto.email, tenantId }, context)
      throw new AuthException(AUTH_ERROR_CODES.INVALID_CREDENTIALS)
    }

    // Status check before expensive scrypt — avoid wasting CPU on blocked accounts.
    try {
      this.assertUserNotBlocked(user)
    } catch (err: unknown) {
      this.emitLoginFailed(
        { email: dto.email, tenantId, userId: user.id, reason: 'account_blocked' },
        context
      )
      throw err
    }

    // Email verification gate.
    if (this.options.emailVerification.required && !user.emailVerified) {
      this.emitLoginFailed(
        { email: dto.email, tenantId, userId: user.id, reason: 'email_not_verified' },
        context
      )
      throw new AuthException(AUTH_ERROR_CODES.EMAIL_NOT_VERIFIED)
    }

    const passwordMatch = await this.passwordService.compare(dto.password, user.passwordHash)
    if (!passwordMatch) {
      this.logger.warn(
        `login: invalid credentials email=${maskEmail(dto.email)} tenantId=${tenantId}`
      )
      await this.recordLoginFailure(
        bfIdentifier,
        { email: dto.email, tenantId, userId: user.id },
        context
      )
      throw new AuthException(AUTH_ERROR_CODES.INVALID_CREDENTIALS)
    }

    // Reset brute-force counter on success.
    await this.bruteForce.resetFailures(bfIdentifier)

    // Transparent upgrade: the password has just been proven, so a hash written under weaker
    // parameters can be re-derived at the current cost and stored, without the user doing
    // anything. This is what makes
    // `password.costFactor` raisable at all: without it the only way to move to stronger
    // parameters would be to invalidate every stored hash. Fire-and-forget, so a slow or
    // failing write never delays or breaks a login that has already succeeded.
    if (this.passwordService.needsRehash(user.passwordHash)) {
      void this.rehashPassword(user.id, dto.password)
    }

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
   * The route is deliberately **not** behind the access-token guard. The overwhelmingly
   * common case is a user who comes back after the 15-minute access token expired and clicks
   * "sign out": refusing that request leaves the refresh session — the long-lived credential
   * logout exists to kill — alive for its full lifetime, on a device the user just told the
   * system to sign out. The refresh token is the credential that authorizes this operation,
   * and possession of it is what the caller proves.
   *
   * The owner is read from the stored session rather than from the access token's claims, so
   * an absent, expired or forged access token cannot name a different user's session. The
   * access token is still *verified* (signature and pinned algorithm) before its `jti` is
   * blacklisted, only skipping the expiry check — reading it unverified would let a caller
   * blacklist someone else's access token by naming its id.
   *
   * @param accessToken - Raw JWT access token. Optional in practice: absent or expired is the
   *   normal case, and only a signature-valid token contributes a blacklist entry.
   * @param rawRefreshToken - Raw opaque refresh token (session key is derived from its hash).
   * @returns The id of the user whose session was revoked, or `''` when no live session
   *   matched the presented refresh token (already logged out, or expired).
   */
  async logout(accessToken: string, rawRefreshToken: string): Promise<string> {
    // The stored session names its owner. Presenting the refresh token proves possession;
    // the record proves whose it is. Claims from an unverified token would not.
    const sessionHash = sha256(rawRefreshToken)
    const userId = await this.redis.readSessionOwner(`rt:${sessionHash}`)
    this.logger.log(`logout: userId=${userId || '(no live session)'}`)

    // Verify signature and algorithm but not expiry: an expired token is the normal case here,
    // a forged one must not be able to blacklist an id it does not own.
    try {
      const payload = this.tokenManager.verifyIgnoringExpiry(accessToken)
      const now = Math.floor(Date.now() / 1000)
      const remainingTtl = payload.exp - now
      if (remainingTtl > 0) {
        await this.redis.set(`rv:${payload.jti}`, '1', remainingTtl)
      }
    } catch {
      // Absent, malformed, or signed by a secret nobody holds — no revocation entry to make.
      // The refresh session below is revoked either way, which is the part that matters.
    }

    // Delete the refresh token key — always required for auth security.
    await this.redis.del(`rt:${sessionHash}`)

    // …and the rotation grace pointer for the same hash. A token presented at logout may
    // already have been rotated and still be inside its grace window, in which case the
    // `rt:` key above is gone but `rp:{hash}` remains — and a grace hit mints a fresh
    // session. Deleting it is what makes logout final for the token the caller handed us,
    // rather than final only for a token that had not yet rotated. rust-auth clears the
    // same pointer on its logout path.
    await this.redis.del(`rp:${sessionHash}`)

    // Delegate session metadata cleanup to SessionService.revokeSession(), which
    // performs an atomic SISMEMBER ownership check before deleting sd:{hash} and
    // SREMing from sess:{userId}. The rt:{hash} DEL above already ran — revokeSession's
    // internal DEL will be a no-op (Redis DEL is idempotent when key is absent).
    // SESSION_NOT_FOUND: session was evicted, already revoked, or the refresh token
    // does not belong to this user — in all cases authentication is already invalidated.
    if (this.options.sessions.enabled && userId) {
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

    // The hook names the user who was signed out, so it only fires when the session told us
    // who that was. A logout for an already-gone session has nobody to name.
    if (this.hooks?.afterLogout && userId) {
      void Promise.resolve(this.hooks.afterLogout(userId, createEmptyHookContext())).catch(
        (err: unknown) => {
          this.logger.error('afterLogout hook threw', err)
        }
      )
    }

    return userId
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
  ): Promise<DashboardRefreshResult> {
    const result = await this.tokenManager.reissueTokens(oldRefreshToken, ip, userAgent)

    // Re-read the account and re-apply the status gate. Rotation works entirely from the Redis
    // record, so nothing else on this path ever looks at the user again: without this a
    // suspended or banned account renews its access token every fifteen minutes for the
    // refresh token's whole seven days. The ban closes the login door, and a signed-in user
    // never needs to open it again — which makes the ban advisory in practice. ASVS v5 §7.4.2
    // requires an account being disabled to terminate its sessions.
    //
    // The check runs AFTER rotation because that is the only point where the owner is known on
    // both the live and the grace path. The compensation is deliberately total: every session
    // the account holds is revoked, including the one just minted, and the epoch bump kills
    // the access token issued a line above. Touching the system while blocked ends everything
    // at once, which is what the ban was supposed to mean.
    const user = await this.userRepo.findById(result.session.userId)
    if (!user) {
      // The account is gone. The session record outlived it, so end it rather than hand back
      // a token for a user nobody can look up.
      await this.revokeAllSessions(result.session.userId)
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }
    try {
      this.assertUserNotBlocked(user)
    } catch (err: unknown) {
      // Compensate, then rethrow the status error the gate produced. The check goes through
      // `assertUserNotBlocked` rather than testing `blockedStatuses` inline so there is one
      // definition of "blocked" — the inline version would have to re-implement the
      // case-insensitive comparison, and a second implementation is a second thing to drift.
      await this.revokeAllSessions(result.session.userId)
      throw err
    }

    // The same email-verification gate `login` applies, for the same reason. `register` issues
    // a full session deliberately — a consumer needs one to render the "check your inbox"
    // screen — and this library's own specification bounds the resulting window at one
    // access-token lifetime. Rotation is what un-bounded it: the gate lived only on `login`, a
    // door the caller never has to open again once register handed them a refresh token, so an
    // address nobody ever proved held an authenticated session indefinitely.
    //
    // Refused, but NOT compensated. An unproven address is an unfinished onboarding, not a
    // denied account: the refusal alone bounds the window to the fifteen minutes the spec
    // promises, while revoking everything would also kill the access token the consumer is
    // using to render that very screen. The rotation above did already spend the presented
    // refresh token, so a user who verifies after the grace window signs in again — which is
    // the right end state for an account that had not proven its address.
    if (this.options.emailVerification.required && !user.emailVerified) {
      throw new AuthException(AUTH_ERROR_CODES.EMAIL_NOT_VERIFIED)
    }

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

    return { ...result, user: toSafeUser(user) }
  }

  // ---------------------------------------------------------------------------
  // Session revocation
  // ---------------------------------------------------------------------------

  /**
   * Ends every dashboard session for one account, and kills the access tokens already issued.
   *
   * The dashboard twin of {@link PlatformAuthService.revokeAllPlatformSessions}. It exists
   * because a library cannot see the moment a host suspends, bans, or deletes an account —
   * the user record is the host's — and until the host says so, the account's live sessions
   * keep working. ASVS v5 §7.4.2 requires that moment to terminate them, so the host needs a
   * supported way to say it. `SessionService.revokeAllExceptCurrent` cannot serve: it wants
   * the hash of a session to keep, and an administrator banning somebody else has none.
   *
   * Call it from wherever the account's status changes. Refresh applies the same gate on its
   * own, so a ban takes effect within one access-token lifetime even if this is never called
   * — but that is a backstop, not the mechanism.
   *
   * The epoch is bumped after the sweep, not before: a failure in the sweep then leaves the
   * operation visibly incomplete rather than reading as done while the sessions live on.
   *
   * @param userId - The account whose sessions are being ended.
   */
  async revokeAllSessions(userId: string): Promise<void> {
    await this.redis.invalidateUserSessions(userId)
    await this.redis.bumpUserTokenEpoch(userId)
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
  // Password-less token issuance (workspace switch, impersonation)
  // ---------------------------------------------------------------------------

  /**
   * Issues a full dashboard session for an existing user **without** verifying
   * a password. Used by consumer applications that implement
   * "switch workspace" or "impersonate user" flows where ownership has
   * already been proven via a different mechanism (typically: an
   * authenticated JWT for a sibling user row sharing the same email).
   *
   * **Authorisation is the caller's responsibility.** This method assumes the
   * controller invoking it has already enforced whatever ownership rule
   * applies — e.g. "the current session's email matches the target user's
   * email" for the workspace-switch use case. Calling it without an
   * application-level guard makes every userId log-in-able directly.
   *
   * Status validation matches the password-login path so a SUSPENDED /
   * BANNED / INACTIVE user cannot be revived via the switch:
   *
   *   - `ACCOUNT_INACTIVE` / `ACCOUNT_SUSPENDED` / `ACCOUNT_BANNED` /
   *     `PENDING_APPROVAL` — surfaced verbatim per status.
   *   - `EMAIL_NOT_VERIFIED` when `emailVerification.required` is true.
   *   - `MFA_REQUIRED` (no challenge issued) when the target user has MFA
   *     enabled. The consumer is expected to detect `mfaEnabled` BEFORE
   *     calling this method and route through `MfaService.challenge`
   *     instead — issuing tokens with `mfaVerified: false` would let the
   *     dashboard's `MfaRequiredGuard` lock the user out on every request.
   *
   * Side effects mirror `login()`:
   *   - Concurrent-session limit enforced via `sessionService.createSession`
   *     when `sessions.enabled`.
   *   - `userRepo.updateLastLogin` runs non-blocking.
   *   - `IAuthHooks.afterLogin` fires non-blocking.
   *   - `newSession` notification flow runs through the same hook.
   *
   * @param userId - The target user. Must exist; no fallback or auto-create.
   * @param ip - Client IP for session tracking + audit.
   * @param userAgent - Client User-Agent for session description.
   * @returns `AuthResult` with `accessToken`, `rawRefreshToken`, and the
   *   target user's `SafeAuthUser` projection.
   * @throws `TOKEN_INVALID` if `userId` does not match any row.
   * @throws `ACCOUNT_INACTIVE` | `ACCOUNT_SUSPENDED` | `ACCOUNT_BANNED` |
   *   `PENDING_APPROVAL` per user status.
   * @throws `EMAIL_NOT_VERIFIED` when verification is required globally.
   * @throws `MFA_REQUIRED` when the target user has MFA enabled — the
   *   consumer must route through the MFA challenge flow for that user.
   */
  async issueTokensForUserId(userId: string, ip: string, userAgent: string): Promise<AuthResult> {
    const user = await this.userRepo.findById(userId)
    if (!user) {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    // Same status guards as login — keeps the password-less path from
    // bypassing account-level holds.
    this.assertUserNotBlocked(user)
    if (this.options.emailVerification.required && !user.emailVerified) {
      throw new AuthException(AUTH_ERROR_CODES.EMAIL_NOT_VERIFIED)
    }

    // MFA-enabled users must complete a TOTP challenge before a full session
    // is issued. Throwing here forces the consumer to handle the branch
    // explicitly (typically by issuing a `mfaTempToken` and redirecting to
    // the MFA challenge page) rather than silently shipping a token with
    // `mfaVerified: false` that would 401 every subsequent request.
    if (user.mfaEnabled) {
      throw new AuthException(AUTH_ERROR_CODES.MFA_REQUIRED)
    }

    const safeUser = toSafeUser(user)
    const result = await this.tokenManager.issueTokens(safeUser, ip, userAgent)

    if (this.options.sessions.enabled) {
      await this.sessionService.createSession(safeUser.id, result.rawRefreshToken, ip, userAgent)
    }

    this.logger.log(
      `issueTokensForUserId: success userId=${safeUser.id} tenantId=${safeUser.tenantId}`
    )

    void this.userRepo.updateLastLogin(user.id).catch((err: unknown) => {
      this.logger.error('updateLastLogin failed', err)
    })
    if (this.hooks?.afterLogin) {
      void Promise.resolve(
        this.hooks.afterLogin(safeUser, {
          userId: safeUser.id,
          ip,
          userAgent,
          sanitizedHeaders: {}
        })
      ).catch((err: unknown) => {
        this.logger.error('afterLogin hook threw', err)
      })
    }

    return result
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
  async verifyEmail(tenantId: string, email: string, otp: string, req: Request): Promise<void> {
    // The configured resolver is authoritative, exactly as it is for login and register: a
    // deployment that derives the tenant from the request has stated that the body's value is
    // not to be trusted. Without this, a caller could name any tenant and probe for accounts
    // in it — and a verification issued under the resolved tenant could never be completed,
    // because the OTP identifier here would be derived from a different one.
    tenantId = await this.resolveTenantId(tenantId, req)
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
  async resendVerificationEmail(tenantId: string, email: string, req: Request): Promise<void> {
    // See `verifyEmail`: the resolver decides the tenant whenever one is configured.
    tenantId = await this.resolveTenantId(tenantId, req)
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
  // unlockAccount()
  // ---------------------------------------------------------------------------

  /**
   * Clears an account's brute-force lockout so the next attempt is judged on its merits.
   *
   * A lockout is a denial of service the library imposes on its own users, and until now it
   * could only be waited out: the counter is keyed by an HMAC of `{tenantId}:{email}` under
   * the library's own `hmacKey`, which no consumer can derive, so a support desk facing "I
   * am locked out and I need in now" had nothing to offer. ASVS v5 §6.1.1 asks for an
   * administrative path to clear it — and the lockout is also the lever an attacker pulls to
   * deny service to a specific account, which makes the ability to undo it part of the
   * defence rather than a convenience.
   *
   * **This grants no access.** It restores the ability to *try*: the password, the status
   * gate, the verification gate and MFA all still apply. Authorising the caller is the
   * consumer's job — the library deliberately ships no route for this, because who may
   * unlock whom is a decision only the host application can make.
   *
   * Idempotent: unlocking an account that is not locked is a no-op.
   *
   * @param email - The account's address. Normalized here the same way login normalizes it,
   *   or the derived key would miss the counter the lockout actually wrote.
   * @param tenantId - The tenant the account belongs to.
   */
  async unlockAccount(email: string, tenantId: string): Promise<void> {
    const identifier = hmacSha256(`${tenantId}:${normalizeEmail(email)}`, this.options.hmacKey)
    await this.bruteForce.resetFailures(identifier)
    this.logger.log(
      `unlockAccount: lockout cleared email=${maskEmail(normalizeEmail(email))} tenantId=${tenantId}`
    )
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  private async resolveTenantId(dtoTenantId: string, req: Request): Promise<string> {
    return await resolveTenantId(dtoTenantId, req, this.options.tenantIdResolver)
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

  /**
   * Records a failed credential attempt against the brute-force counter, and emits the failure
   * hooks the moment they are due — including {@link IAuthHooks.onLockout} on the attempt that
   * crosses the threshold.
   *
   * The lockout signal has to be emitted here rather than on the *next* attempt: an attacker
   * who trips the lock and walks away would otherwise never produce the event, and the account
   * would sit locked with nothing having announced it.
   */
  private async recordLoginFailure(
    bfIdentifier: string,
    who: { email: string; tenantId: string; userId?: string },
    context: HookContext
  ): Promise<void> {
    await this.bruteForce.recordFailure(bfIdentifier)
    this.emitLoginFailed({ ...who, reason: 'invalid_credentials' }, context)

    if (this.hooks?.onLockout && (await this.bruteForce.isLockedOut(bfIdentifier))) {
      const retryAfterSeconds = await this.bruteForce.getRemainingLockoutSeconds(bfIdentifier)
      this.fireAndForget(
        () => this.hooks?.onLockout?.({ ...who, retryAfterSeconds }, context),
        'onLockout'
      )
    }
  }

  /** Emits {@link IAuthHooks.onLoginFailed}, fire-and-forget. */
  private emitLoginFailed(
    details: Parameters<NonNullable<IAuthHooks['onLoginFailed']>>[0],
    context: HookContext
  ): void {
    this.fireAndForget(() => this.hooks?.onLoginFailed?.(details, context), 'onLoginFailed')
  }

  /**
   * Runs a hook without awaiting it and without letting it change the caller's outcome.
   *
   * Every hook on this interface is advisory: a consumer's SIEM being down must not turn a
   * refused login into a different refusal, nor a successful one into a failure.
   */
  private fireAndForget(run: () => Promise<void> | void, name: string): void {
    try {
      void Promise.resolve(run()).catch((err: unknown) => {
        this.logger.error(`${name} hook threw`, err)
      })
    } catch (err: unknown) {
      this.logger.error(`${name} hook threw synchronously`, err)
    }
  }

  private assertUserNotBlocked(user: AuthUser): void {
    assertNotBlocked(user.status, this.options.blockedStatuses)
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
