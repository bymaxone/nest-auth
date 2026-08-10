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
import { logSafe } from '../utils/log-safe'
import { maskEmail } from '../utils/mask-email'
import { normalizeEmail } from '../utils/normalize-email'
import { resolveTenantId } from '../utils/resolve-tenant-id'
import { createEmptyHookContext, sanitizeHeaders } from '../utils/sanitize-headers'
import { sleep } from '../utils/sleep'
import { tenantScoped } from '../utils/tenant-scoped'

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

  /**
   * Whether the tenant-mismatch misconfiguration has already been reported.
   *
   * The warning describes a permanent property of the deployment — a repository whose
   * `findByEmail` ignores its `tenantId` argument — so the second line and every line after it
   * carry no information the first did not. Emitting one per request would make the log a
   * function of traffic, and put a side effect on the losing side of a refusal that is meant to
   * be indistinguishable from the other two. Once is enough to make the defect visible.
   */
  private warnedTenantMismatch = false

  constructor(
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions,
    @Inject(BYMAX_AUTH_USER_REPOSITORY) private readonly userRepo: IUserRepository,
    @Inject(BYMAX_AUTH_EMAIL_PROVIDER)
    @Optional()
    private readonly emailProvider: IEmailProvider | null,
    @Inject(BYMAX_AUTH_HOOKS) @Optional() private readonly hooks: IAuthHooks | null,
    @Inject(PasswordService) private readonly passwordService: PasswordService,
    @Inject(TokenManagerService) private readonly tokenManager: TokenManagerService,
    @Inject(BruteForceService) private readonly bruteForce: BruteForceService,
    @Inject(AuthRedisService) private readonly redis: AuthRedisService,
    @Inject(OtpService) private readonly otpService: OtpService,
    @Inject(SessionService) private readonly sessionService: SessionService
  ) {}

  /**
   * Re-derive a proven password at the current parameters and store it.
   *
   * Detached from the login it follows: the user is already authenticated, and a failure here
   * costs nothing but the upgrade — the old hash keeps working. Errors are logged rather than
   * propagated for that reason.
   *
   * **`verifiedHash` is what makes this safe to detach.** The task carries the plaintext of the
   * password it is upgrading, and a KDF derivation is slow by construction, so it lands some
   * time after the login that scheduled it. In between, the same account may have changed its
   * password — and the case where that is most likely is exactly the dangerous one: the user
   * resets *because* the old password was compromised, and the attacker's own login is what
   * scheduled the task. Writing unconditionally then re-installs the compromised credential
   * over the new one, the old password works again, the new one does not, and the "password
   * changed" mail has already gone out. The window is the whole rehash, and `needsRehash` is
   * true for EVERY account during the parameter migration this feature exists to serve, so it
   * is not a rare alignment.
   *
   * So the write is conditional on the stored hash still being the one that was verified. This
   * is a re-read rather than a compare-and-set because `IUserRepository` is implemented by the
   * consuming application and a CAS primitive cannot be required of every backing store; the
   * remaining race is the repository round-trip rather than the derivation, and it can only
   * lose an upgrade, never a password — the next login reschedules it.
   *
   * @param userId - The account whose stored hash is being upgraded.
   * @param tenantId - The tenant that account belongs to, so the re-read cannot answer with a
   *   different tenant's row in a store whose ids are not globally unique.
   * @param plain - The plaintext just verified against `verifiedHash`.
   * @param verifiedHash - The stored hash this upgrade is allowed to replace.
   */
  private async rehashPassword(
    userId: string,
    tenantId: string,
    plain: string,
    verifiedHash: string
  ): Promise<void> {
    try {
      const upgraded = await this.passwordService.hash(plain)
      // Tenant-scoped, because `IUserRepository.findById` takes the argument precisely so a
      // store whose ids are not globally unique cannot answer with another tenant's row. This
      // is not an admin flow — it is a read on behalf of one account — and an unscoped answer
      // would have the guard comparing the verified hash against a DIFFERENT row, which either
      // drops a legitimate upgrade or admits a write the guard exists to refuse.
      const current = await this.userRepo.findById(userId, tenantId)
      if (current?.passwordHash !== verifiedHash) {
        this.logger.log(`rehash on verify skipped — the stored hash changed userId=${userId}`)
        return
      }
      await this.userRepo.updatePassword(userId, upgraded)
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
    dto: { email: string; password: string; name: string; tenantId?: string },
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

    /**
     * Privileged fields the `beforeRegister` hook may set, held SEPARATELY from `dto`.
     *
     * They used to be merged into `dto` and read back off it, which made a `role` the hook chose
     * indistinguishable from one the CALLER sent. Through the shipped controller that was not
     * reachable — `createAuthValidationPipe()` sets `whitelist` and `forbidNonWhitelisted`, so
     * `{"role":"ADMIN"}` in the body is a 400 — but `AuthService` is exported precisely so a host
     * can write its own registration route, and the moment one calls `register(req.body, req)`
     * the only control standing between an unauthenticated caller and `role: 'ADMIN'` lived in a
     * different file, on a decorator that host is free not to use. A privilege boundary that
     * depends on a collaborator's configuration is not a boundary.
     */
    let hookOverrides: { role?: string; status?: string; emailVerified?: boolean } = {}

    // beforeRegister hook — only hook that can block the flow.
    if (this.hooks?.beforeRegister) {
      const hookResult = await this.hooks.beforeRegister(
        { email: dto.email, name: dto.name, tenantId },
        context
      )
      if (!hookResult.allowed) {
        throw new AuthException(AUTH_ERROR_CODES.FORBIDDEN)
      }
      // Stryker disable next-line ConditionalExpression: spreading a falsy `modifiedData` (`{ ...undefined }`) is a no-op, so guarding with `if (true)` produces the same assignment
      if (hookResult.modifiedData) {
        hookOverrides = hookResult.modifiedData
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

    await this.passwordService.assertAcceptable(dto.password, 'password')
    const passwordHash = await this.passwordService.hash(dto.password)

    // Read from `hookOverrides`, never from `dto`: a caller-supplied `role` or `status` is inert
    // here no matter how this service is invoked. See the declaration for why that matters.
    const newUser = await this.userRepo.create({
      email: dto.email,
      name: dto.name,
      passwordHash,
      tenantId,
      ...(typeof hookOverrides.role === 'string' && { role: hookOverrides.role }),
      ...(typeof hookOverrides.status === 'string' && { status: hookOverrides.status }),
      ...(this.options.emailVerification.required
        ? { emailVerified: false }
        : typeof hookOverrides.emailVerified === 'boolean'
          ? { emailVerified: hookOverrides.emailVerified }
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

    this.logger.log(`register: user registered userId=${newUser.id} tenantId=${logSafe(tenantId)}`)

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
    dto: { email: string; password: string; tenantId?: string },
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
    const bfIdentifier = this.lockoutIdentifier(tenantId, dto.email)

    const context = this.buildHookContext({ tenantId, email: dto.email, ip, userAgent, req })

    const locked = await this.bruteForce.isLockedOut(bfIdentifier)
    if (locked) {
      this.logger.warn(
        `login: account locked email=${maskEmail(dto.email)} tenantId=${logSafe(tenantId)}`
      )
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
    //
    // The tenant the repository answered with must be the tenant that was asked for. The
    // lookup passes `tenantId` and the contract says to scope by it, but the repository is the
    // host's and the trait can only ask — and a single-tenant host writing `findByEmail` that
    // ignores its second argument is the shape nobody notices. Under one, every distinct
    // `tenantId` in the request body resolves the same account while deriving a *different*
    // `lf:` counter, so rotating the value gives an unlimited supply of fresh 5-attempt
    // budgets and the lockout never engages. Refusing the mismatch is also tenant isolation in
    // its own right: an account in tenant A must not authenticate through a request naming
    // tenant B, whatever the repository returns.
    //
    // Folded into the same condition as the not-found case so the refusal is byte- and
    // timing-identical: a caller learns nothing about which of the three it hit.
    const tenantMismatch = user !== null && user.tenantId !== tenantId
    // Reported once per process, not once per request. The condition is a property of the
    // deployment rather than of the caller, so repeating it says nothing new — and a per-request
    // write is a side effect on one of the three branches that are supposed to be
    // indistinguishable, however far below the KDF's noise floor a log line sits.
    if (tenantMismatch && !this.warnedTenantMismatch) {
      this.warnedTenantMismatch = true
      this.logger.warn(
        `login: repository returned an account outside the requested tenant — check that ` +
          `IUserRepository.findByEmail scopes by its tenantId argument`
      )
    }
    if (!user || !user.passwordHash || tenantMismatch) {
      await this.passwordService.compareDummy(dto.password)
      await this.recordLoginFailure(bfIdentifier, { email: dto.email, tenantId }, context)
      throw new AuthException(AUTH_ERROR_CODES.INVALID_CREDENTIALS)
    }

    // The password is proved FIRST, before the status and verification gates below.
    //
    // Those gates used to run here, ahead of the KDF, to spare the CPU of hashing against an
    // account that could never sign in. The saving was real and the cost was worse: a blocked
    // or unverified account answered with its own status code, in a millisecond, without
    // touching the failure counter — so anyone could enumerate addresses AND read their
    // moderation state at whatever rate the per-IP limiter allowed, and never trip a lockout.
    // The CPU it saved is bounded by that same limiter; the disclosure it bought was bounded
    // by nothing.
    //
    // Proving the password first costs one derivation on a blocked account and buys the
    // property that matters: every answer an attacker can reach is the same answer.
    const passwordMatch = await this.passwordService.compare(dto.password, user.passwordHash)
    if (!passwordMatch) {
      this.logger.warn(
        `login: invalid credentials email=${maskEmail(dto.email)} tenantId=${logSafe(tenantId)}`
      )
      await this.recordLoginFailure(
        bfIdentifier,
        { email: dto.email, tenantId, userId: user.id },
        context
      )
      throw new AuthException(AUTH_ERROR_CODES.INVALID_CREDENTIALS)
    }

    // Only now, with the password proved, may the account's own state be described. The
    // holder of the credential is not the attacker this hides from, and telling them "your
    // address is unverified" is the whole point of the flow.
    try {
      this.assertUserNotBlocked(user)
    } catch (err: unknown) {
      this.emitLoginFailed(
        { email: dto.email, tenantId, userId: user.id, reason: 'account_blocked' },
        context
      )
      throw err
    }

    if (this.options.emailVerification.required && !user.emailVerified) {
      this.emitLoginFailed(
        { email: dto.email, tenantId, userId: user.id, reason: 'email_not_verified' },
        context
      )
      throw new AuthException(AUTH_ERROR_CODES.EMAIL_NOT_VERIFIED)
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
      void this.rehashPassword(user.id, user.tenantId, dto.password, user.passwordHash)
    }

    // MFA challenge path.
    if (user.mfaEnabled) {
      const mfaTempToken = await this.tokenManager.issueMfaTempToken(user.id, 'dashboard')
      this.logger.log(`login: MFA challenge issued userId=${user.id} tenantId=${logSafe(tenantId)}`)
      return { mfaRequired: true, mfaTempToken }
    }

    const safeUser = toSafeUser(user)
    const result = await this.tokenManager.issueTokens(safeUser, ip, userAgent)

    // Track the session when sessions are enabled (enforces concurrent session limit).
    if (this.options.sessions.enabled) {
      await this.sessionService.createSession(safeUser.id, result.rawRefreshToken, ip, userAgent)
    }

    this.logger.log(`login: success userId=${safeUser.id} tenantId=${logSafe(tenantId)}`)

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

    // Re-stamp the access token from the account that was just re-read.
    //
    // Rotation builds its claims from the session record written at LOGIN, and that record
    // carries the role and tenant the account had then — inherited unchanged through every
    // rotation. So demoting an ADMIN to MEMBER, or moving a user between tenants, had no
    // effect on a live session: they kept minting tokens with the old authority for the
    // refresh token's whole lifetime, and every role guard in the system reads the claim.
    // The status gate above already re-read the account; the authority was sitting right
    // there, unused.
    //
    // The comparison covers every claim the token carries authority in, not just the two that
    // motivated the original fix. Naming a subset is what left `mfaEnabled` stale:
    // `MfaRequiredGuard` decides on `mfaEnabled && !mfaVerified`, so a session created while
    // the account had no second factor kept minting `mfaEnabled: false` tokens for the refresh
    // token's whole lifetime and every MFA-gated route waved it through — reachable whenever
    // the host flips MFA through its own admin surface rather than this library's, since only
    // `verifyAndEnable` revokes the sessions and bumps the epoch.
    //
    // `status` is deliberately NOT compared: `buildRotatedResult` stamps it empty by
    // construction, because the session record carries no live status, so comparing it would
    // differ on every refresh and prove nothing. It is re-validated per request against the
    // `us:` cache instead — and when this branch does fire for another reason, the re-stamp
    // below fills it from the account that was just read.
    //
    // The comparison reads the token rotation just issued rather than the session record,
    // since the token is the thing whose claims are about to be trusted. Decoding it costs one
    // HMAC and no round trip. Only re-signed when a claim actually differs, so the ordinary
    // rotation still costs nothing extra.
    const rotated = this.tokenManager.verifyIgnoringExpiry(result.accessToken)
    let authoritative = result.accessToken
    if (
      rotated.role !== user.role ||
      rotated.tenantId !== user.tenantId ||
      rotated.mfaEnabled !== user.mfaEnabled
    ) {
      authoritative = this.tokenManager.issueAccess({
        sub: user.id,
        tenantId: user.tenantId,
        role: user.role,
        type: 'dashboard',
        status: user.status,
        mfaEnabled: user.mfaEnabled,
        // Carried across from the token the rotation just produced: a second factor already
        // cleared on this session stays cleared, and re-stamping the authority must not
        // silently demand it again.
        mfaVerified: rotated.mfaVerified,
        epoch: await this.redis.getUserTokenEpoch(user.id)
      })
    }

    // Rotate the session detail record to the new token hash.
    // Fire-and-forget: sd: keys are display metadata only — a rotation failure
    // does not invalidate the auth tokens already issued above.
    //
    // That holds only because pruning is guarded by the `rt:` key's own existence
    // (`AuthRedisService.pruneDeadMembers`). Were a reader to un-index a member on the strength
    // of a missing `sd:` alone, a failure here would drop a live session out of `sess:{userId}`,
    // and it would then survive a revoke-all while still rotating. Keep the two facts together:
    // this call may fail silently precisely because nothing treats `sd:` as proof of a session.
    if (this.options.sessions.enabled) {
      void this.sessionService
        .rotateSession(sha256(oldRefreshToken), sha256(result.rawRefreshToken), ip, userAgent)
        .catch((err: unknown) => {
          this.logger.warn(`refresh: session detail rotation failed — ${String(err)}`)
        })
    }

    return { ...result, accessToken: authoritative, user: toSafeUser(user) }
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
      `issueTokensForUserId: success userId=${safeUser.id} tenantId=${logSafe(safeUser.tenantId)}`
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
  async verifyEmail(
    tenantId: string | undefined,
    email: string,
    otp: string,
    req: Request
  ): Promise<void> {
    // The configured resolver is authoritative, exactly as it is for login and register: a
    // deployment that derives the tenant from the request has stated that the body's value is
    // not to be trusted. Without this, a caller could name any tenant and probe for accounts
    // in it — and a verification issued under the resolved tenant could never be completed,
    // because the OTP identifier here would be derived from a different one.
    tenantId = await this.resolveTenantId(tenantId, req)
    // Canonicalized here, not merely at the door that issued the OTP: the record, its
    // five-attempt ceiling and the resend cooldown all hang off `hmac(tenantId:email)`, so a
    // caller who varied the case of the address keyed a different record and drew a fresh
    // budget of guesses at the same six-digit code.
    email = normalizeEmail(email)
    await this.otpService.verify('email_verification', this.otpIdentifier(tenantId, email), otp)

    const user = tenantScoped(await this.userRepo.findByEmail(email, tenantId), tenantId)
    if (!user) {
      // Treat as OTP_INVALID rather than USER_NOT_FOUND to avoid a timing oracle
      // for callers probing email existence after a brute-forced OTP.
      throw new AuthException(AUTH_ERROR_CODES.OTP_INVALID)
    }

    await this.userRepo.updateEmailVerified(user.id, true)

    // Drop the verified-flag the UserStatusGuard caches under `uev:{tenantId}:{userId}`, so the
    // account reaches its protected routes on the very next request rather than after the cache TTL.
    // The key must be byte-identical to the guard's — same tenant, same percent-encoding of each
    // half — or the delete misses and the stale `0` keeps the just-verified account locked out until
    // the TTL expires. The guard refreshes the flag from the repository on the miss this creates.
    await this.redis.del(`uev:${encodeURIComponent(tenantId)}:${encodeURIComponent(user.id)}`)

    this.logger.log(`verifyEmail: email verified userId=${user.id} tenantId=${logSafe(tenantId)}`)

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
  async resendVerificationEmail(
    tenantId: string | undefined,
    email: string,
    req: Request
  ): Promise<void> {
    // See `verifyEmail`: the resolver decides the tenant whenever one is configured.
    tenantId = await this.resolveTenantId(tenantId, req)
    // See `verifyEmail`: raw, a change of case is a change of cooldown key, and the one-send-
    // per-minute limit that key exists to enforce becomes one send per spelling.
    email = normalizeEmail(email)
    const start = Date.now()
    const cooldownKey = `resend:email_verification:${this.otpIdentifier(tenantId, email)}`

    // Atomic NX: only one send allowed per 60 seconds. SET NX EX is atomic — no TOCTOU race.
    const wasSet = await this.redis.setnx(cooldownKey, 60)
    if (!wasSet) {
      await sleep(Math.max(0, ANTI_ENUM_MIN_MS - (Date.now() - start)))
      return // Already sent recently — silently succeed.
    }

    const user = tenantScoped(await this.userRepo.findByEmail(email, tenantId), tenantId)
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
    const identifier = this.lockoutIdentifier(tenantId, normalizeEmail(email))
    await this.bruteForce.resetFailures(identifier)
    this.logger.log(
      `unlockAccount: lockout cleared email=${maskEmail(normalizeEmail(email))} tenantId=${logSafe(tenantId)}`
    )
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  /**
   * Derives the OTP-record identifier for a `tenantId + email` pair.
   *
   * HMAC rather than a bare digest because an address is low-entropy: a bare SHA-256 of one is
   * reversible by dictionary, and these identifiers are the Redis key an operator can read.
   * The preimage is pinned by `conformance/wire-contract.json` and shared byte-for-byte with
   * rust-auth, which keys the same records in the same Redis.
   *
   * Deliberately distinct from {@link lockoutIdentifier}: that one namespaces the login
   * keyspace with a `dashboard:` prefix, and the two must never collide.
   *
   * @param tenantId - Tenant scope.
   * @param email - The canonicalized address.
   * @returns Hex HMAC-SHA-256 identifier.
   */
  private otpIdentifier(tenantId: string, email: string): string {
    return hmacSha256(`${tenantId}:${email}`, this.options.hmacKey)
  }
  /**
   * The brute-force counter key for a dashboard account.
   *
   * The identity PLANE is part of the preimage, not just the tenant. Without it a tenant whose
   * id is literally `platform` produced a byte-identical identifier to the platform plane's
   * own `platform:{email}` — so five unauthenticated dashboard logins against an operator's
   * address locked that operator out of the console, repeatably, without the platform surface
   * ever being touched. The reverse held too: a successful dashboard login in that tenant
   * cleared the operator's lockout mid-attack. The MFA counters already carry their plane for
   * exactly this reason.
   *
   * One method rather than two call sites: `login` writes this counter and `unlockAccount`
   * clears it, and a preimage that drifted between them would make the unlock silently do
   * nothing — the failure mode is invisible, because clearing a key that does not exist
   * succeeds.
   *
   * @param tenantId - The resolved tenant.
   * @param email - The address, already normalized by the caller.
   * @returns The HMAC identifier, opaque and non-reversible.
   */

  private lockoutIdentifier(tenantId: string, email: string): string {
    return hmacSha256(`dashboard:${tenantId}:${email}`, this.options.hmacKey)
  }

  private async resolveTenantId(dtoTenantId: string | undefined, req: Request): Promise<string> {
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

    const identifier = this.otpIdentifier(tenantId, email)
    const length = 6 // emailVerification does not expose otpLength; use fixed 6-digit OTPs
    const ttl = this.options.emailVerification.otpTtlSeconds
    const otp = this.otpService.generate(length)
    await this.otpService.store('email_verification', identifier, otp, ttl)

    void this.emailProvider.sendEmailVerificationOtp(tenantId, email, otp).catch((err: unknown) => {
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
