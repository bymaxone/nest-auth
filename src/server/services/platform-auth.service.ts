import { Inject, Injectable, Logger, Optional } from '@nestjs/common'

import {
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_PLATFORM_USER_REPOSITORY
} from '../bymax-auth.constants'
import { BruteForceService } from './brute-force.service'
import { PasswordService } from './password.service'
import { TokenManagerService } from './token-manager.service'
import type { ResolvedOptions } from '../config/resolved-options'
import { sessionIndexKey } from '../constants/user-keys'
import { hmacSha256, sha256 } from '../crypto/secure-token'
import type { PlatformLoginDto } from '../dto/platform-login.dto'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { HookContext, IAuthHooks } from '../interfaces/auth-hooks.interface'
import type {
  MfaChallengeResult,
  PlatformAuthResult,
  RotatedTokenResult
} from '../interfaces/auth-result.interface'
import type {
  IPlatformUserRepository,
  SafeAuthPlatformUser
} from '../interfaces/platform-user-repository.interface'
import { AuthRedisService } from '../redis/auth-redis.service'
import { assertNotBlocked } from '../utils/assert-not-blocked'
import { describeChannelStatus } from '../utils/describe-error'
import { logSafe } from '../utils/log-safe'
import { maskEmail } from '../utils/mask-email'
import { normalizeEmail } from '../utils/normalize-email'
import { createEmptyHookContext } from '../utils/sanitize-headers'

/**
 * Core authentication service for platform administrators.
 *
 * Orchestrates login, logout, token refresh, and session revocation for the
 * operator/super-admin layer. Platform admins are not tenant-scoped — they
 * authenticate against the global `IPlatformUserRepository`.
 *
 * All brute-force tracking uses an HMAC-SHA-256 identifier derived from the email
 * so that no PII appears in Redis keys and the identifier cannot be reversed via
 * dictionary lookup.
 *
 * @remarks
 * Platform refresh tokens are stored under `prt:{sha256(token)}` in Redis.
 * The `sess:{userId}` SET tracks all active session keys for a given admin,
 * enabling full-session revocation via {@link revokeAllPlatformSessions}.
 *
 * @layer Service
 */
@Injectable()
export class PlatformAuthService {
  private readonly logger = new Logger(PlatformAuthService.name)

  constructor(
    @Inject(BYMAX_AUTH_PLATFORM_USER_REPOSITORY)
    private readonly platformUserRepo: IPlatformUserRepository,
    @Inject(PasswordService) private readonly passwordService: PasswordService,
    @Inject(TokenManagerService) private readonly tokenManager: TokenManagerService,
    @Inject(BruteForceService) private readonly bruteForce: BruteForceService,
    @Inject(AuthRedisService) private readonly redis: AuthRedisService,
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions,
    // Defaulted, not merely `@Optional()`. This service is exported from the package entry for
    // consumers driving their own platform routes, so the emitted constructor signature is public
    // API: a parameter without a default is REQUIRED in the generated `.d.ts`, and every existing
    // six-argument construction would stop compiling. The default keeps those callers source-
    // compatible while Nest still injects the provider when one is registered.
    @Inject(BYMAX_AUTH_HOOKS) @Optional() private readonly hooks: IAuthHooks | null = null
  ) {}

  // ---------------------------------------------------------------------------
  // Login
  // ---------------------------------------------------------------------------

  /**
   * Authenticates a platform administrator with email and password.
   *
   * Returns either a full {@link PlatformAuthResult} or a {@link MfaChallengeResult}
   * when the admin has MFA enabled.
   *
   * @param dto - Login credentials (email + password).
   * @param ip - Client IP address (for session audit and brute-force tracking).
   * @param userAgent - User-Agent header value (for session description).
   * @returns Auth result or MFA challenge prompt.
   * @throws {@link AuthException} with `ACCOUNT_LOCKED` (429) when brute-force limit reached.
   * @throws {@link AuthException} with `INVALID_CREDENTIALS` on bad email/password.
   * @throws {@link AuthException} with the matching status code (403) when the admin's
   *   account status is configured as blocked.
   */
  async login(
    dto: PlatformLoginDto,
    ip: string,
    userAgent: string
  ): Promise<PlatformAuthResult | MfaChallengeResult> {
    // Canonicalize the email before deriving ANY email-keyed value below. The controllers
    // run `ValidationPipe` without `transform: true`, so a DTO `@Transform` would be
    // discarded and the lockout identifier would be derived from caller-controlled casing
    // — the case-rotation bypass, where each casing is a distinct lockout bucket yet
    // resolves the same admin. Merged immutably to avoid mutating the validated DTO.
    dto = { ...dto, email: normalizeEmail(dto.email) }

    const bfIdentifier = this.lockoutIdentifier(dto.email)

    const locked = await this.bruteForce.isLockedOut(bfIdentifier)
    if (locked) {
      this.logger.warn(`login: account locked email=${maskEmail(dto.email)}`)
      const retryAfterSeconds = await this.bruteForce.getRemainingLockoutSeconds(bfIdentifier)
      throw new AuthException(AUTH_ERROR_CODES.ACCOUNT_LOCKED, { retryAfterSeconds })
    }

    const admin = await this.platformUserRepo.findByEmail(dto.email)

    // Admin-not-found path: run a dummy scrypt derivation before failing so an unknown
    // address costs the same wall-clock time as a known address with a wrong password.
    // Skipping it leaks a timing oracle (single-digit vs. tens of milliseconds) that
    // enumerates which administrator accounts exist despite the identical error body —
    // the same oracle the dashboard login already closes.
    if (!admin) {
      await this.passwordService.compareDummy(dto.password)
      await this.bruteForce.recordFailure(bfIdentifier)
      this.logger.warn(`login: invalid credentials email=${maskEmail(dto.email)}`)
      throw new AuthException(AUTH_ERROR_CODES.INVALID_CREDENTIALS)
    }

    // The password is proved FIRST. The status gate below used to run ahead of the KDF to deny
    // an attacker hashing work on an account that could never sign in — but it answered with
    // the administrator's own status, in a millisecond, without touching the failure counter,
    // which enumerated operator accounts and read their moderation state on the
    // highest-privilege plane in the system. The hashing it saved is bounded by the per-IP
    // limiter; the disclosure was bounded by nothing.
    const passwordMatch = await this.passwordService.compare(dto.password, admin.passwordHash)
    if (!passwordMatch) {
      await this.bruteForce.recordFailure(bfIdentifier)
      this.logger.warn(`login: invalid credentials email=${maskEmail(dto.email)}`)
      throw new AuthException(AUTH_ERROR_CODES.INVALID_CREDENTIALS)
    }

    // Only now, with the password proved, is the account's state described. A suspended,
    // inactive, or banned administrator must never authenticate — without this a revoked
    // operator keeps full platform access as long as the password is known.
    assertNotBlocked(admin.status, this.options.blockedStatuses)

    await this.bruteForce.resetFailures(bfIdentifier)

    // MFA challenge path: issue a short-lived temp token and stop here.
    if (admin.mfaEnabled) {
      const mfaTempToken = await this.tokenManager.issueMfaTempToken(admin.id, 'platform')
      this.logger.log(`login: MFA challenge issued adminId=${logSafe(admin.id)}`)
      return { mfaRequired: true, mfaTempToken }
    }

    // Destructure credential fields before issuing tokens.
    const {
      passwordHash: _passwordHash,
      mfaSecret: _mfaSecret,
      mfaRecoveryCodes: _mfaRecoveryCodes,
      ...safeAdmin
    } = admin

    const result = await this.tokenManager.issuePlatformTokens(safeAdmin, ip, userAgent)
    this.logger.log(`login: success adminId=${logSafe(admin.id)}`)

    // Fire-and-forget: a slow or failing DB update must not block the auth response.
    void this.platformUserRepo.updateLastLogin(admin.id).catch((err: unknown) => {
      this.logger.error(`updateLastLogin failed: ${describeChannelStatus(err)}`)
    })

    return result
  }

  // ---------------------------------------------------------------------------
  // Logout
  // ---------------------------------------------------------------------------

  /**
   * Logs out a platform administrator by revoking the access token JTI and
   * deleting the associated platform refresh session from Redis.
   *
   * @param userId - The authenticated admin's ID (from the verified JWT `sub` claim).
   * @param jti - The JWT ID claim (`jti`) from the access token (for revocation blacklist).
   * @param exp - The expiry Unix timestamp from the access token (for TTL calculation).
   * @param rawRefreshToken - The raw opaque platform refresh token.
   */
  async logout(accessToken: string, rawRefreshToken: string): Promise<string> {
    // The stored session names its owner. Presenting the refresh token proves possession; the
    // record proves whose it is. Claims from an unverified token would not — and claims from a
    // *verified* one were previously the only source, which is why this route sat behind a
    // guard that refuses an expired token: an operator who stepped away for longer than the
    // fifteen-minute access lifetime could not sign out at all, and the seven-day refresh
    // session of the highest-privilege identity in the system stayed live on a console they
    // believed they had left. The dashboard plane was fixed for exactly this; the platform
    // plane kept the old shape.
    const tokenHash = sha256(rawRefreshToken)
    const { userId } = await this.redis.readSessionOwner(`prt:${tokenHash}`)
    this.logger.log(`logout: adminId=${logSafe(userId || '(no live session)')}`)

    // Verify signature and algorithm but not expiry: an expired token is the normal case here,
    // a forged one must not be able to blacklist an id it does not own.
    try {
      const payload = this.tokenManager.verifyPlatformIgnoringExpiry(accessToken)
      const remainingTtl = payload.exp - Math.floor(Date.now() / 1000)
      if (remainingTtl > 0) {
        await this.redis.set(`rv:${payload.jti}`, '1', remainingTtl)
      }
    } catch {
      // Absent, malformed, or signed by a secret nobody holds — no revocation entry to make.
      // The refresh session below is revoked either way, which is the part that matters.
    }

    // Delete the primary session key and its grace pointer (if it exists from the
    // last rotation). Both are tracked in the per-user index SET so both must be
    // removed from it to keep it accurate for future invalidateUserSessions calls.
    //
    // The index is named through `sessionIndexKey`, not by concatenating `'psess:' + userId`.
    // Writing the raw form here while every other path writes the derived one would leave this
    // SREM operating on a key nothing else touches: the session records would be deleted, the
    // real index would keep their members, and it would grow with every logout until a full
    // sweep or expiry. Silent, and only visible as an index that never shrinks.
    await this.redis.del('prt:' + tokenHash)
    await this.redis.del('prp:' + tokenHash)
    if (userId) {
      const index = sessionIndexKey('platform', userId, this.options.hmacKey, undefined)
      await this.redis.srem(index, 'prt:' + tokenHash)
      await this.redis.srem(index, 'prp:' + tokenHash)
    }
    await this.redis.del('psd:' + tokenHash)

    this.emitPlatformLogout(userId)

    return userId
  }

  /**
   * Announces a completed platform logout, the only hook `PlatformAuthService` emits.
   *
   * Owns three concerns a reader of `logout` does not need: whether a hook is registered, the
   * fire-and-forget discipline, and the rejection log. It mirrors `TokenManagerService`'s
   * `emitReuseDetected`, which carries the same three for the same reason.
   *
   * The event is its own hook rather than a share of `afterLogout`, because a consumer's dashboard
   * handler may resolve a tenant and a platform administrator has none. Fire-and-forget: a hook
   * that throws must not turn a completed logout into a failed one, so the rejection is logged
   * rather than propagated — and logged rather than swallowed, so a broken consumer hook stays
   * visible.
   *
   * @param userId - The administrator who signed out; empty when the record named no owner, in
   *   which case there is nobody to announce and nothing fires.
   */
  private emitPlatformLogout(userId: string): void {
    if (!this.hooks?.afterPlatformLogout || !userId) return
    const context: HookContext = { ...createEmptyHookContext(), plane: 'platform', userId }

    // The invocation sits INSIDE the try, not just the promise it returns. `afterPlatformLogout`
    // may be declared `void`, so a consumer implementation is free to throw synchronously — and a
    // synchronous throw happens before `Promise.resolve` exists to wrap it, so `.catch` never sees
    // it and the exception escapes into `logout`, whose Redis writes have already completed. The
    // caller would then be told a finished logout failed, and might retry it. Same shape and same
    // remedy as `TokenManagerService.emitReuseDetected`.
    try {
      void Promise.resolve(this.hooks.afterPlatformLogout(userId, context)).catch(
        (err: unknown) => {
          this.logger.error(`afterPlatformLogout hook threw: ${describeChannelStatus(err)}`)
        }
      )
    } catch (err: unknown) {
      this.logger.error(
        `afterPlatformLogout hook threw synchronously: ${describeChannelStatus(err)}`
      )
    }
  }

  // ---------------------------------------------------------------------------
  // Refresh
  // ---------------------------------------------------------------------------

  /**
   * Rotates a platform administrator's refresh token.
   *
   * Delegates to {@link TokenManagerService.reissuePlatformTokens}. Callers that
   * need the full admin record in the HTTP response must fetch it from the
   * repository using the returned `session.userId`.
   *
   * @param rawRefreshToken - The raw opaque platform refresh token from the client.
   * @param ip - Client IP address.
   * @param userAgent - User-Agent header value.
   * @returns New tokens and minimal session identity.
   * @throws {@link AuthException} with `REFRESH_TOKEN_INVALID` if the token is invalid or expired.
   */
  async refresh(
    rawRefreshToken: string,
    ip: string,
    userAgent: string
  ): Promise<RotatedTokenResult> {
    const result = await this.tokenManager.reissuePlatformTokens(rawRefreshToken, ip, userAgent)

    // Re-read the administrator and re-apply the status gate — the backstop the dashboard
    // plane has carried since ASVS v5 §7.4.2 was applied to it, and which this plane went
    // without. Rotation works entirely from the stored `prt:` record, so nothing else on this
    // path ever looks at the account again: a SUSPENDED or BANNED operator kept renewing
    // access every fifteen minutes for the refresh token's whole lifetime, on the
    // highest-privilege identity in the system, and the kill switch was advisory exactly
    // where it mattered most.
    const admin = await this.platformUserRepo.findById(result.session.userId)
    if (!admin) {
      // The account was deleted while the session outlived it. Clear what is left rather than
      // leaving the freshly rotated records to be rotated again.
      await this.revokeAllPlatformSessions(result.session.userId)
      throw new AuthException(AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID)
    }

    try {
      assertNotBlocked(admin.status, this.options.blockedStatuses)
    } catch (err: unknown) {
      // Compensated, not merely refused: the rotation above already minted a live pair, and
      // leaving it would hand back exactly the access this gate exists to end.
      await this.revokeAllPlatformSessions(admin.id)
      throw err
    }

    // Re-stamp the access token from the administrator that was just re-read — the same fix
    // the dashboard plane carries, on the plane where the authority is worth more. Rotation
    // builds its claims from the `prt:` record written at login, so a demotion from
    // `super_admin` to `support` had no effect on a live console session: it kept minting
    // tokens with the old role for the refresh token's whole lifetime, and every role check
    // reads that claim. `mfaEnabled` is re-stamped for the same reason it is on the dashboard
    // plane — it gates whether a second factor is demanded at all.
    //
    // The account was already read a few lines above for the status gate; the authority was
    // sitting there, unused. Only re-signed when a claim actually differs.
    const rotated = this.tokenManager.verifyPlatformIgnoringExpiry(result.accessToken)
    if (rotated.role !== admin.role || rotated.mfaEnabled !== admin.mfaEnabled) {
      return {
        ...result,
        session: { ...result.session, role: admin.role },
        accessToken: await this.tokenManager.reissuePlatformAccessWithAuthority(
          rotated,
          admin.role,
          admin.mfaEnabled
        )
      }
    }

    return result
  }

  // ---------------------------------------------------------------------------
  // GetMe
  // ---------------------------------------------------------------------------

  /**
   * Retrieves the full safe platform admin record for the currently authenticated admin.
   *
   * @param userId - Subject claim from the verified platform JWT.
   * @returns Safe admin object (credential fields excluded).
   * @throws {@link AuthException} with `TOKEN_INVALID` if the admin no longer exists.
   */
  async getMe(userId: string): Promise<SafeAuthPlatformUser> {
    const admin = await this.platformUserRepo.findById(userId)
    if (!admin) {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    const {
      passwordHash: _passwordHash,
      mfaSecret: _mfaSecret,
      mfaRecoveryCodes: _mfaRecoveryCodes,
      ...safeAdmin
    } = admin

    return safeAdmin
  }

  // ---------------------------------------------------------------------------
  // Session revocation
  // ---------------------------------------------------------------------------

  /**
   * Derives the brute-force identifier for a platform login: `hmac('platform:{email}')`.
   *
   * HMAC rather than a bare digest keeps PII out of the Redis key and blocks dictionary
   * reversal, and the derived `hmacKey` keeps the identifier domain independent of the
   * JWT-signing secret. The `platform:` namespace is what keeps this counter disjoint from
   * the dashboard's: without it, a tenant whose id is literally `platform` produced a
   * byte-identical identifier, so unauthenticated dashboard logins against an operator's
   * address could lock that operator out of the console — and a successful one cleared the
   * lockout mid-attack.
   *
   * Single source on purpose: every platform site that touches the counter derives it here,
   * so no two of them can drift apart. The preimage is pinned by
   * `conformance/wire-contract.json` and shared byte-for-byte with rust-auth.
   *
   * @param email - The canonicalized address.
   * @returns Hex HMAC-SHA-256 identifier.
   */
  private lockoutIdentifier(email: string): string {
    return hmacSha256(`platform:${email}`, this.options.hmacKey)
  }
  /**
   * Revokes all active platform sessions for the given admin.
   *
   * Delegates to {@link AuthRedisService.invalidateUserSessions} which uses an atomic
   * Lua script to read the platform index SET, delete all session and grace-pointer
   * keys, and remove the SET itself in a single Redis round-trip. This prevents the
   * TOCTOU race that would arise from a non-atomic SMEMBERS + loop + DEL approach.
   *
   * The token epoch is then advanced, so outstanding platform **access** tokens die with
   * the refresh sessions rather than working on to expiry — "log out everywhere" that
   * leaves every access token alive is not what those words promise. Bumped after the
   * sweep for the same reason the dashboard flow bumps last: a failure in the sweep
   * leaves the epoch untouched and the operation visibly incomplete, instead of the
   * reverse, which would read as done while the sessions live on.
   *
   * @param userId - The platform admin's internal ID.
   */

  async revokeAllPlatformSessions(userId: string): Promise<void> {
    // The platform plane carries no tenant: its admins are cross-tenant by definition, which
    // is the same asymmetry `userSubject` encodes for every other user-derived key.
    await this.redis.invalidateUserSessions(userId, undefined, 'platform')
    await this.redis.bumpUserTokenEpoch(userId, undefined, 'platform')
  }
}
