import { randomInt } from 'node:crypto'

import { Inject, Injectable, Optional } from '@nestjs/common'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_PLATFORM_USER_REPOSITORY,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-one-nest-auth.constants'
import { BruteForceService } from './brute-force.service'
import { PasswordService } from './password.service'
import { TokenManagerService } from './token-manager.service'
import type { ResolvedOptions } from '../config/resolved-options'
import { decrypt, encrypt } from '../crypto/aes-gcm'
import { hmacSha256 } from '../crypto/secure-token'
import { buildTotpUri, generateTotpSecret, verifyTotp } from '../crypto/totp'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { IAuthHooks } from '../interfaces/auth-hooks.interface'
import type { AuthResult, PlatformAuthResult } from '../interfaces/auth-result.interface'
import type { IEmailProvider } from '../interfaces/email-provider.interface'
import type {
  AuthPlatformUser,
  IPlatformUserRepository,
  SafeAuthPlatformUser,
  UpdatePlatformMfaData
} from '../interfaces/platform-user-repository.interface'
import type {
  AuthUser,
  IUserRepository,
  SafeAuthUser
} from '../interfaces/user-repository.interface'
import { AuthRedisService } from '../redis/auth-redis.service'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** TTL in seconds for the pending MFA setup data (10 minutes). */
const MFA_SETUP_TTL_SECONDS = 600

/**
 * TTL in seconds for the TOTP anti-replay key.
 *
 * A code accepted at step −1 (the first step of the ±1 window) remains valid
 * in `verifyTotp` until the end of step +1 — a span of up to 60 s. Adding a
 * 30-second buffer gives a 90-second TTL, ensuring the anti-replay key outlives
 * every code that `verifyTotp` would accept: (2 × window + 1) × 30 = 90 s for
 * window=1. Adjust proportionally if `totpWindow` is increased.
 */
const TOTP_ANTI_REPLAY_TTL_SECONDS = 90

/** Number of recovery codes generated when MFA is enabled. */
const DEFAULT_RECOVERY_CODE_COUNT = 8

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/**
 * Result returned by {@link MfaService.setup} containing the TOTP secret,
 * a QR code URI for authenticator apps, and the one-time plain-text recovery codes.
 *
 * @remarks
 * `recoveryCodes` must be displayed to the user **once** at setup time and never
 * stored in plain text — the service stores their scrypt hashes.
 * `secret` is provided for manual entry in authenticator apps that cannot scan a QR code.
 */
export interface MfaSetupResult {
  /** Base32-encoded TOTP secret for manual entry in authenticator apps. */
  secret: string
  /** `otpauth://totp/` URI for QR code generation. */
  qrCodeUri: string
  /** Plain-text recovery codes. Display once and never persist in this form. */
  recoveryCodes: string[]
}

/**
 * Shape stored in Redis during the MFA setup pending phase.
 *
 * `encryptedSecret` and `encryptedPlainCodes` are both AES-256-GCM encrypted so
 * that a Redis compromise during the 10-minute setup window does not expose the
 * TOTP secret or plain-text recovery codes.
 *
 * @internal
 */
interface MfaSetupData {
  /** AES-256-GCM encrypted Base32 TOTP secret. */
  encryptedSecret: string
  /** scrypt hashes of the recovery codes (stored in the DB after enable). */
  hashedCodes: string[]
  /**
   * AES-256-GCM encrypted JSON array of plain-text recovery codes.
   * Stored only to support idempotent re-display within the setup window.
   */
  encryptedPlainCodes: string
}

// ---------------------------------------------------------------------------
// MfaService
// ---------------------------------------------------------------------------

/**
 * Manages TOTP-based multi-factor authentication lifecycle.
 *
 * Handles the complete MFA flow for both dashboard users and platform admins:
 * - **Setup**: generate TOTP secret + recovery codes, store temporarily in Redis
 * - **Verify & Enable**: confirm first TOTP code, persist encrypted secret to DB
 * - **Challenge**: exchange a valid MFA temp token + code for full access tokens
 * - **Disable**: require a current TOTP code to disable MFA
 *
 * @remarks
 * This service is only registered when `options.mfa` is configured in
 * `BymaxAuthModule.registerAsync()`. All crypto operations use `node:crypto` only.
 */
@Injectable()
export class MfaService {
  constructor(
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions,
    @Inject(BYMAX_AUTH_USER_REPOSITORY) private readonly userRepo: IUserRepository,
    @Optional()
    @Inject(BYMAX_AUTH_PLATFORM_USER_REPOSITORY)
    private readonly platformUserRepo: IPlatformUserRepository | null,
    private readonly redis: AuthRedisService,
    private readonly tokenManager: TokenManagerService,
    private readonly bruteForce: BruteForceService,
    private readonly passwordService: PasswordService,
    @Inject(BYMAX_AUTH_EMAIL_PROVIDER) private readonly emailProvider: IEmailProvider,
    @Inject(BYMAX_AUTH_HOOKS) private readonly hooks: IAuthHooks
  ) {}

  // ---------------------------------------------------------------------------
  // Private accessor — options.mfa is guaranteed non-null when service is active
  // ---------------------------------------------------------------------------

  /**
   * Convenience accessor for the resolved MFA options.
   *
   * `options.mfa` is always present when `MfaService` is registered — the module
   * only registers the service when `mfa` is configured. The single suppression
   * here eliminates repetitive `!` assertions throughout the class.
   */
  private get mfaOptions(): Required<NonNullable<ResolvedOptions['mfa']>> {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return this.options.mfa!
  }

  // ---------------------------------------------------------------------------
  // Private crypto helpers
  // ---------------------------------------------------------------------------

  /**
   * Encrypts a TOTP secret for storage in the database using AES-256-GCM.
   */
  private encryptSecret(secret: string): string {
    return encrypt(secret, this.mfaOptions.encryptionKey)
  }

  /**
   * Decrypts a stored TOTP secret.
   *
   * Re-throws any decryption failure as an opaque `TOKEN_INVALID` to prevent
   * error-type oracle attacks (callers cannot distinguish format vs. tamper errors).
   */
  private decryptSecret(encrypted: string): string {
    try {
      return decrypt(encrypted, this.mfaOptions.encryptionKey)
    } catch {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }
  }

  /**
   * Generates `count` numeric recovery codes in `dddd-dddd-dddd` format.
   *
   * Returns both the plain-text (shown once to the user) and scrypt-hashed
   * versions (stored in the database).
   */
  private async hashRecoveryCodes(
    count: number
  ): Promise<{ plainCodes: string[]; hashedCodes: string[] }> {
    const plainCodes: string[] = []
    const hashedCodes: string[] = []

    for (let i = 0; i < count; i++) {
      const g1 = randomInt(0, 10_000).toString().padStart(4, '0')
      const g2 = randomInt(0, 10_000).toString().padStart(4, '0')
      const g3 = randomInt(0, 10_000).toString().padStart(4, '0')
      const code = `${g1}-${g2}-${g3}`
      plainCodes.push(code)
      hashedCodes.push(await this.passwordService.hash(code))
    }

    return { plainCodes, hashedCodes }
  }

  /**
   * Compares a submitted recovery code against all stored scrypt hashes.
   *
   * Always evaluates every hash (constant-time iteration) to avoid leaking the
   * position of the matching code via timing.
   *
   * @returns Index of the matching hash, or `-1` if none match.
   */
  private async verifyRecoveryCode(code: string, hashedCodes: string[]): Promise<number> {
    let matchIndex = -1
    for (const [i, hashedCode] of hashedCodes.entries()) {
      const isMatch = await this.passwordService.compare(code, hashedCode)
      if (isMatch) matchIndex = i
    }
    return matchIndex
  }

  /**
   * Returns a `SafeAuthUser` projection of a dashboard user, stripping credentials
   * and MFA secret fields before passing to hooks or email providers.
   */
  private toSafeUser(user: AuthUser): SafeAuthUser {
    const { passwordHash: _ph, mfaSecret: _ms, mfaRecoveryCodes: _mrc, ...safe } = user
    return safe
  }

  /**
   * Returns a `SafeAuthPlatformUser` projection of a platform admin, stripping
   * credentials and MFA secret fields.
   */
  private toSafePlatformUser(admin: AuthPlatformUser): SafeAuthPlatformUser {
    const { passwordHash: _ph, mfaSecret: _ms, mfaRecoveryCodes: _mrc, ...safe } = admin
    return safe
  }

  /**
   * Constructs a `SafeAuthUser`-compatible object from a `SafeAuthPlatformUser` so
   * that it can be passed to hooks typed for `SafeAuthUser`.
   *
   * Platform admins have no `tenantId` or `emailVerified` fields. These are filled
   * with sentinel values (`''` and `true` respectively) since platform admins are
   * provisioned directly and do not participate in the tenant/email-verification flow.
   */
  private platformUserAsSafeUser(admin: AuthPlatformUser): SafeAuthUser {
    const safe = this.toSafePlatformUser(admin)
    return {
      ...safe,
      tenantId: '',
      emailVerified: true
    }
  }

  // ---------------------------------------------------------------------------
  // setup — TOTP secret generation, idempotent key reservation, recovery codes
  // ---------------------------------------------------------------------------

  /**
   * Initiates the MFA setup flow for a dashboard user.
   *
   * Generates a TOTP secret and 8 recovery codes, stores them temporarily in
   * Redis (10 minutes), and returns the data needed to display the QR code and
   * recovery codes to the user.
   *
   * Idempotent: concurrent or repeated calls within the TTL window all receive the
   * same secret and codes. An atomic SET-NX is used so that two simultaneous setup
   * requests cannot generate different secrets.
   *
   * @param userId - Internal ID of the user enabling MFA.
   * @returns Setup result containing the secret, QR URI, and plain recovery codes.
   * @throws `MFA_ALREADY_ENABLED` if MFA is already active on the account.
   */
  async setup(userId: string): Promise<MfaSetupResult> {
    const user = await this.userRepo.findById(userId)
    if (!user) throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    if (user.mfaEnabled) throw new AuthException(AUTH_ERROR_CODES.MFA_ALREADY_ENABLED)

    // Key is HMAC-keyed so the Redis keyspace does not expose user IDs.
    const setupKey = `mfa_setup:${hmacSha256(userId, this.options.jwt.secret)}`

    // Generate the data unconditionally first, then attempt an atomic SET-NX to claim
    // the key. This prevents the TOCTOU race of GET → generate → SET where two
    // concurrent requests both see null and each stores a different secret.
    const { base32: secretBase32 } = generateTotpSecret()
    const encryptedSecret = this.encryptSecret(secretBase32)
    const recoveryCount = this.mfaOptions.recoveryCodeCount ?? DEFAULT_RECOVERY_CODE_COUNT
    const { plainCodes, hashedCodes } = await this.hashRecoveryCodes(recoveryCount)
    const encryptedPlainCodes = encrypt(JSON.stringify(plainCodes), this.mfaOptions.encryptionKey)

    const setupData: MfaSetupData = { encryptedSecret, hashedCodes, encryptedPlainCodes }
    const payload = JSON.stringify(setupData)

    const wasSet = await this.redis.setIfAbsent(setupKey, payload, MFA_SETUP_TTL_SECONDS)

    if (!wasSet) {
      // Another request already started setup — return their data for idempotency.
      const existing = await this.redis.get(setupKey)
      if (existing !== null) {
        const data = JSON.parse(existing) as MfaSetupData
        const existingSecret = this.decryptSecret(data.encryptedSecret)
        const decryptedCodesJson = decrypt(data.encryptedPlainCodes, this.mfaOptions.encryptionKey)
        const existingCodes = JSON.parse(decryptedCodesJson) as string[]
        const qrCodeUri = buildTotpUri(existingSecret, user.email, this.mfaOptions.issuer)
        return { secret: existingSecret, qrCodeUri, recoveryCodes: existingCodes }
      }
      // Extremely rare: key expired between setIfAbsent and get — store our data.
      // A concurrent verifyAndEnable that completed just before this branch is
      // safe: verifyAndEnable checks mfaEnabled at entry via findById, so a
      // re-enabled account will throw MFA_ALREADY_ENABLED on the next setup call.
      await this.redis.set(setupKey, payload, MFA_SETUP_TTL_SECONDS)
    }

    const qrCodeUri = buildTotpUri(secretBase32, user.email, this.mfaOptions.issuer)
    return { secret: secretBase32, qrCodeUri, recoveryCodes: plainCodes }
  }

  // ---------------------------------------------------------------------------
  // verifyAndEnable — first-time TOTP validation and permanent MFA activation
  // ---------------------------------------------------------------------------

  /**
   * Verifies the first TOTP code from the user's authenticator app and permanently
   * enables MFA on the account.
   *
   * After enabling, all existing refresh sessions are atomically invalidated to
   * force re-authentication through the MFA challenge endpoint. Active access tokens
   * (up to `accessExpiresIn`, default 15 min) remain valid — they are not
   * blacklisted since the library does not track JTIs server-side.
   *
   * @param userId - Internal ID of the user completing MFA setup.
   * @param code - 6-digit TOTP code from the authenticator app.
   * @param ip - Client IP address (forwarded to hooks).
   * @param userAgent - User-Agent header (forwarded to hooks).
   * @throws `MFA_SETUP_REQUIRED` if no pending setup data is found in Redis.
   * @throws `MFA_INVALID_CODE` if the submitted TOTP code is invalid.
   */
  async verifyAndEnable(
    userId: string,
    code: string,
    ip: string,
    userAgent: string
  ): Promise<void> {
    // Fetch once at entry — used for mfaEnabled guard, email notification, and hook.
    const user = await this.userRepo.findById(userId)
    if (!user) throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    if (user.mfaEnabled) throw new AuthException(AUTH_ERROR_CODES.MFA_ALREADY_ENABLED)

    const setupKey = `mfa_setup:${hmacSha256(userId, this.options.jwt.secret)}`
    const raw = await this.redis.get(setupKey)
    if (raw === null) throw new AuthException(AUTH_ERROR_CODES.MFA_SETUP_REQUIRED)

    const data = JSON.parse(raw) as MfaSetupData
    const secretBase32 = this.decryptSecret(data.encryptedSecret)

    const totpWindow = this.mfaOptions.totpWindow
    // Use anti-replay even for the enable step to prevent a racing/intercepted code
    // from being reused via the challenge endpoint within the acceptance window.
    const codeValid = await this.verifyTotpWithAntiReplay(userId, secretBase32, code, totpWindow)
    if (!codeValid) {
      throw new AuthException(AUTH_ERROR_CODES.MFA_INVALID_CODE)
    }

    // Atomically consume the setup key — this acts as the completion gate that
    // prevents a double-enable race where two concurrent valid submissions both
    // persist to the database and send duplicate notification emails.
    await this.redis.del(setupKey)

    await this.userRepo.updateMfa(userId, {
      mfaEnabled: true,
      mfaSecret: data.encryptedSecret,
      mfaRecoveryCodes: data.hashedCodes
    })

    // Atomically invalidate all existing refresh sessions so the user must re-login
    // with the MFA challenge. Access tokens up to 15 min remain valid — accepted tradeoff.
    await this.redis.invalidateUserSessions(userId)

    await this.emailProvider.sendMfaEnabledNotification(user.email)

    // Fire-and-forget hook — errors must not roll back a completed DB operation.
    if (this.hooks.afterMfaEnabled) {
      void Promise.resolve(
        this.hooks.afterMfaEnabled(this.toSafeUser(user), {
          userId,
          ip,
          userAgent,
          sanitizedHeaders: {}
        })
      ).catch(() => undefined)
    }
  }

  // ---------------------------------------------------------------------------
  // challenge — MFA temp token exchange for full auth tokens (TOTP or recovery code)
  // ---------------------------------------------------------------------------

  /**
   * Validates a TOTP or recovery code and exchanges the MFA temp token for full
   * access tokens.
   *
   * Handles both `'dashboard'` and `'platform'` contexts. Applies brute-force
   * protection per-user. TOTP codes include anti-replay protection via a short-lived
   * Redis key keyed on an HMAC of the code and user ID.
   *
   * @param mfaTempToken - Short-lived MFA challenge JWT issued at login.
   * @param code - 6-digit TOTP code or `dddd-dddd-dddd` recovery code.
   * @param ip - Client IP address for session audit.
   * @param userAgent - User-Agent header for session description.
   * @returns `AuthResult` for dashboard context, `PlatformAuthResult` for platform context.
   * @throws `MFA_TEMP_TOKEN_INVALID` if the token is invalid or already consumed.
   * @throws `ACCOUNT_LOCKED` if the brute-force threshold has been reached.
   * @throws `MFA_INVALID_CODE` if the submitted code is incorrect.
   */
  async challenge(
    mfaTempToken: string,
    code: string,
    ip: string,
    userAgent: string
  ): Promise<AuthResult | PlatformAuthResult> {
    // Step 1: Verify and consume the MFA temp token (single-use via GETDEL).
    const { userId, context } = await this.tokenManager.verifyMfaTempToken(mfaTempToken)

    // Step 2: Brute-force check. HMAC key prevents Redis key reversal.
    // The 'challenge:' prefix namespaces this counter away from the 'disable' counter —
    // preventing a pre-auth attacker (who only has a mfaTempToken) from exhausting the
    // lockout threshold and blocking the authenticated user's ability to call disable().
    const bfIdentifier = hmacSha256(`challenge:${userId}`, this.options.jwt.secret)
    if (await this.bruteForce.isLockedOut(bfIdentifier)) {
      throw new AuthException(AUTH_ERROR_CODES.ACCOUNT_LOCKED)
    }

    // Step 3: Fetch user from the correct repository.
    const user = await this.fetchUserForContext(context, userId)

    if (!user.mfaEnabled || !user.mfaSecret) {
      throw new AuthException(AUTH_ERROR_CODES.MFA_NOT_ENABLED)
    }

    // Step 4: Decrypt TOTP secret and validate the submitted code.
    const secretBase32 = this.decryptSecret(user.mfaSecret)
    const isTotpCode = /^\d{6}$/.test(code)
    const totpWindow = this.mfaOptions.totpWindow
    let codeValid = false
    let usedRecoveryIndex = -1

    if (isTotpCode) {
      codeValid = await this.verifyTotpWithAntiReplay(userId, secretBase32, code, totpWindow)
    } else {
      const recoveryCodes = user.mfaRecoveryCodes ?? []
      usedRecoveryIndex = await this.verifyRecoveryCode(code, recoveryCodes)
      codeValid = usedRecoveryIndex >= 0
    }

    if (!codeValid) {
      await this.bruteForce.recordFailure(bfIdentifier)
      throw new AuthException(AUTH_ERROR_CODES.MFA_INVALID_CODE)
    }

    await this.bruteForce.resetFailures(bfIdentifier)

    // Step 5: Consume the used recovery code (branch on context to use the correct repo).
    if (usedRecoveryIndex >= 0) {
      // mfaRecoveryCodes is guaranteed non-empty here: verifyRecoveryCode only returns ≥ 0
      // when it found a match by iterating the array, so the array cannot be empty or undefined.
      const updatedCodes = [...(user.mfaRecoveryCodes as string[])]
      updatedCodes.splice(usedRecoveryIndex, 1)
      const mfaUpdate = {
        mfaEnabled: true as const,
        mfaSecret: user.mfaSecret,
        mfaRecoveryCodes: updatedCodes
      }
      if (context === 'platform' && this.platformUserRepo) {
        await this.platformUserRepo.updateMfa(userId, mfaUpdate as UpdatePlatformMfaData)
      } else {
        await this.userRepo.updateMfa(userId, mfaUpdate)
      }
    }

    // Step 6: Issue full tokens with mfaVerified: true.
    if (context === 'dashboard') {
      const safeUser = this.toSafeUser(user as AuthUser)
      const result = await this.tokenManager.issueTokens(safeUser, ip, userAgent, {
        mfaVerified: true
      })

      if (this.hooks.afterLogin) {
        void Promise.resolve(
          this.hooks.afterLogin(safeUser, { userId, ip, userAgent, sanitizedHeaders: {} })
        ).catch(() => undefined)
      }

      return result
    }

    // Platform context — reuse the already-fetched user to avoid a TOCTOU double-read.
    // platformUserRepo presence was already validated in fetchUserForContext; this cast is safe.
    const platformUser = user as AuthPlatformUser
    const result = await this.tokenManager.issuePlatformTokens(
      this.toSafePlatformUser(platformUser),
      ip,
      userAgent,
      { mfaVerified: true }
    )

    if (this.hooks.afterLogin) {
      void Promise.resolve(
        this.hooks.afterLogin(this.platformUserAsSafeUser(platformUser), {
          userId,
          ip,
          userAgent,
          sanitizedHeaders: {}
        })
      ).catch(() => undefined)
    }

    return result
  }

  // ---------------------------------------------------------------------------
  // disable — TOTP-verified MFA deactivation with session invalidation
  // ---------------------------------------------------------------------------

  /**
   * Disables MFA on a user's account after verifying a current TOTP code.
   *
   * Only TOTP codes are accepted — recovery codes cannot disable MFA by design.
   * See {@link MfaDisableDto} for the rationale.
   *
   * Supports both dashboard users and platform administrators. The caller must
   * pass the correct `context` value derived from the authenticated JWT `type`
   * claim so the right repository is used.
   *
   * After disabling, all refresh sessions are atomically invalidated so that the
   * next rotation produces tokens with `mfaEnabled: false` and `mfaVerified: false`,
   * clearing any stale `mfaVerified: true` claims from previously issued access tokens.
   *
   * @param userId - Internal ID of the user disabling MFA.
   * @param code - 6-digit TOTP code from the authenticator app.
   * @param ip - Client IP address (forwarded to hooks).
   * @param userAgent - User-Agent header (forwarded to hooks).
   * @param context - Which repository to use: `'dashboard'` (default) or `'platform'`.
   * @throws `TOKEN_INVALID` if the user is not found.
   * @throws `MFA_NOT_ENABLED` if MFA is not currently active.
   * @throws `ACCOUNT_LOCKED` if the brute-force threshold has been reached.
   * @throws `MFA_INVALID_CODE` if the submitted TOTP code is incorrect.
   */
  async disable(
    userId: string,
    code: string,
    ip: string,
    userAgent: string,
    context: 'dashboard' | 'platform' = 'dashboard'
  ): Promise<void> {
    const user = await this.fetchUserForContext(context, userId)
    if (!user.mfaEnabled) throw new AuthException(AUTH_ERROR_CODES.MFA_NOT_ENABLED)

    // 'disable:' prefix namespaces this counter away from the 'challenge' counter —
    // preventing a pre-auth attacker from exhausting the lockout threshold via the
    // challenge endpoint and blocking the authenticated user from disabling MFA.
    const bfIdentifier = hmacSha256(`disable:${userId}`, this.options.jwt.secret)
    if (await this.bruteForce.isLockedOut(bfIdentifier)) {
      throw new AuthException(AUTH_ERROR_CODES.ACCOUNT_LOCKED)
    }

    if (!user.mfaSecret) {
      // mfaEnabled is true but mfaSecret is absent — database inconsistency.
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    const secretBase32 = this.decryptSecret(user.mfaSecret)
    const totpWindow = this.mfaOptions.totpWindow

    const codeValid = await this.verifyTotpWithAntiReplay(userId, secretBase32, code, totpWindow)
    if (!codeValid) {
      await this.bruteForce.recordFailure(bfIdentifier)
      throw new AuthException(AUTH_ERROR_CODES.MFA_INVALID_CODE)
    }

    await this.bruteForce.resetFailures(bfIdentifier)

    const disableData = { mfaEnabled: false as const, mfaSecret: null, mfaRecoveryCodes: null }
    if (context === 'platform' && this.platformUserRepo) {
      await this.platformUserRepo.updateMfa(userId, disableData)
    } else {
      await this.userRepo.updateMfa(userId, disableData)
    }

    // Invalidate all sessions so subsequent rotations produce tokens with mfaEnabled: false.
    await this.redis.invalidateUserSessions(userId)

    await this.emailProvider.sendMfaDisabledNotification(user.email)

    const safeUser =
      context === 'platform'
        ? this.platformUserAsSafeUser(user as AuthPlatformUser)
        : this.toSafeUser(user as AuthUser)

    if (this.hooks.afterMfaDisabled) {
      void Promise.resolve(
        this.hooks.afterMfaDisabled(safeUser, {
          userId,
          ip,
          userAgent,
          sanitizedHeaders: {}
        })
      ).catch(() => undefined)
    }
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  /**
   * Verifies a TOTP code and enforces anti-replay within the validation window.
   *
   * Stores a Redis key `tu:{hmac}` where `hmac = hmacSha256("{userId}:{code}", jwtSecret)`
   * with a 90-second TTL. A second submission of the same code within the TTL is
   * rejected as a replay. The HMAC key ties the replay marker to both user and code
   * value, preventing both code disclosure in Redis and cross-user replay attacks.
   *
   * @returns `true` if the code is valid and has not been replayed, `false` otherwise.
   */
  private async verifyTotpWithAntiReplay(
    userId: string,
    secretBase32: string,
    code: string,
    window: number
  ): Promise<boolean> {
    if (!verifyTotp(secretBase32, code, window)) return false

    // The HMAC ties the replay key to both the user identity and the specific code,
    // preventing cross-user replay and avoiding plaintext code storage in Redis.
    const replayKey = `tu:${hmacSha256(`${userId}:${code}`, this.options.jwt.secret)}`
    const isNew = await this.redis.setnx(replayKey, TOTP_ANTI_REPLAY_TTL_SECONDS)
    if (!isNew) return false

    return true
  }

  /**
   * Fetches a user from the correct repository based on the MFA context.
   *
   * @throws `TOKEN_INVALID` if the user is not found.
   */
  private async fetchUserForContext(
    context: 'dashboard' | 'platform',
    userId: string
  ): Promise<AuthUser | AuthPlatformUser> {
    if (context === 'dashboard') {
      const user = await this.userRepo.findById(userId)
      if (!user) throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
      return user
    }

    if (!this.platformUserRepo) {
      // Misconfiguration: consumer set controllers.mfa: true without supplying
      // BYMAX_AUTH_PLATFORM_USER_REPOSITORY in extraProviders. Throw AuthException so
      // NestJS exception filters produce a clean response rather than leaking internal details.
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }
    const admin = await this.platformUserRepo.findById(userId)
    if (!admin) throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    return admin
  }
}
