import { Inject, Injectable, Logger, Optional } from '@nestjs/common'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_PLATFORM_USER_REPOSITORY,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-auth.constants'
import { MfaChallengeService } from './mfa-challenge.service'
import { MfaFlowLockoutService } from './mfa-flow-lockout.service'
import { MfaManagementService } from './mfa-management.service'
import { MfaRecordService } from './mfa-record.service'
import { ReauthenticationService } from './reauthentication.service'
import { SessionService } from './session.service'
import { TokenManagerService } from './token-manager.service'
import type { ResolvedOptions } from '../config/resolved-options'
import { userSubject } from '../constants/user-subject'
import { encrypt } from '../crypto/aes-gcm'
import { hmacSha256 } from '../crypto/secure-token'
import { buildTotpUri, generateTotpSecret } from '../crypto/totp'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { IAuthHooks } from '../interfaces/auth-hooks.interface'
import type { AuthResult, PlatformAuthResult } from '../interfaces/auth-result.interface'
import type { IEmailProvider } from '../interfaces/email-provider.interface'
import type { IPlatformUserRepository } from '../interfaces/platform-user-repository.interface'
import type { IUserRepository } from '../interfaces/user-repository.interface'
import { AuthRedisService } from '../redis/auth-redis.service'
import { logSafe } from '../utils/log-safe'
import { notifyMfaChange } from '../utils/mfa-notify'
import { assertPlaneTenant } from '../utils/mfa-plane-tenant'
import { DEFAULT_RECOVERY_CODE_COUNT, generateRecoveryCodes } from '../utils/mfa-recovery-codes'
import { committedSafeUser } from '../utils/mfa-safe-user'
import { decryptMfaSecret, encryptMfaSecret } from '../utils/mfa-secret-cipher'
import { parsePlainRecoveryCodes, parseSetupData, type MfaSetupData } from '../utils/mfa-setup-data'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** TTL in seconds for the pending MFA setup data (10 minutes). */
const MFA_SETUP_TTL_SECONDS = 600

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/**
 * Result returned by {@link MfaService.setup} containing the TOTP secret,
 * a QR code URI for authenticator apps, and the one-time plain-text recovery codes.
 *
 * @remarks
 * `recoveryCodes` must be displayed to the user **once** at setup time and never
 * stored in plain text — the service stores a keyed HMAC-SHA-256 of each one.
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
 *
 * @layer Service
 */
@Injectable()
export class MfaService {
  private readonly logger = new Logger(MfaService.name)

  constructor(
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions,
    @Inject(BYMAX_AUTH_USER_REPOSITORY) private readonly userRepo: IUserRepository,
    @Optional()
    @Inject(BYMAX_AUTH_PLATFORM_USER_REPOSITORY)
    private readonly platformUserRepo: IPlatformUserRepository | null,
    @Inject(AuthRedisService) private readonly redis: AuthRedisService,
    @Inject(TokenManagerService) private readonly tokenManager: TokenManagerService,
    @Inject(MfaRecordService) private readonly records: MfaRecordService,
    @Inject(MfaChallengeService) private readonly challengeFlow: MfaChallengeService,
    @Inject(MfaManagementService) private readonly management: MfaManagementService,
    @Inject(MfaFlowLockoutService) private readonly flowLockout: MfaFlowLockoutService,
    @Inject(ReauthenticationService) private readonly reauthentication: ReauthenticationService,
    @Inject(SessionService) private readonly sessionService: SessionService,
    @Inject(BYMAX_AUTH_EMAIL_PROVIDER) private readonly emailProvider: IEmailProvider,
    @Inject(BYMAX_AUTH_HOOKS) private readonly hooks: IAuthHooks
  ) {}

  // ---------------------------------------------------------------------------
  // Private accessor — options.mfa is guaranteed non-null when service is active
  // ---------------------------------------------------------------------------

  /**
   * Returns the resolved MFA configuration. `options.mfa` is always present when `MfaService` is registered.
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

  // ---------------------------------------------------------------------------
  // setup — TOTP secret generation, idempotent key reservation, recovery codes
  // ---------------------------------------------------------------------------

  /**
   * Initiates the MFA setup flow for a dashboard user or platform administrator.
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
   * @param context - Which repository to use: `'dashboard'` (default) or `'platform'`.
   * @returns Setup result containing the secret, QR URI, and plain recovery codes.
   * @throws `MFA_ALREADY_ENABLED` if MFA is already active on the account.
   * @throws `MFA_NOT_ENABLED` if `context === 'platform'` and the platform user
   *   repository was not configured at module registration. The error code is
   *   reused (rather than introducing a new one) because the consumer-facing
   *   meaning is the same: "platform MFA cannot operate".
   */
  async setup(
    userId: string,
    context: 'dashboard' | 'platform' = 'dashboard',
    password?: string,
    tenantId?: string
  ): Promise<MfaSetupResult> {
    assertPlaneTenant(context, tenantId)
    if (context === 'platform' && !this.platformUserRepo) {
      // Misconfiguration: caller asked for a platform setup but the host
      // application did not register BYMAX_AUTH_PLATFORM_USER_REPOSITORY.
      // Failing fast here surfaces the bug at the first request rather than
      // letting the flow silently fall back to the dashboard repo (which
      // would persist the platform admin's MFA secret on a tenant user row).
      throw new AuthException(AUTH_ERROR_CODES.MFA_NOT_ENABLED)
    }

    const user = await this.records.loadAccount(context, userId, tenantId)
    if (user.mfaEnabled) throw new AuthException(AUTH_ERROR_CODES.MFA_ALREADY_ENABLED)

    // Re-authenticate before minting a factor. Enabling MFA is a change to how the account
    // authenticates, and an access token alone is not proof of who is asking: a token lifted
    // by XSS or a shared machine could enrol an authenticator the attacker holds, and the
    // enable then invalidates the sessions and bumps the epoch — locking the real owner out
    // of the account they still know the password to, with the recovery codes displayed only
    // to the attacker. ASVS requires re-authentication before changing an authentication
    // factor; `disable` already honours that by demanding a TOTP code. Gating `setup` rather
    // than `verify-enable` means the attacker cannot even obtain a secret they control, and
    // it costs the user one prompt at the natural moment.
    //
    // An account with no local password — provisioned purely through OAuth — has nothing to
    // re-authenticate against here, and refusing it would make MFA unreachable for those
    // users. Their credential is the provider's, which this library cannot re-verify inline.
    await this.reauthentication.assertReauthenticated(
      context,
      userId,
      user.passwordHash,
      password,
      tenantId
    )

    // Key is HMAC-keyed so the Redis keyspace does not expose user IDs.
    const setupKey = `mfa_setup:${hmacSha256(userSubject(context, userId, tenantId), this.options.hmacKey)}`

    // Fast-path idempotency check: if a setup payload already exists for this user,
    // return it without performing the expensive scrypt + AES work. This prevents a
    // CPU-amplification vector where an attacker who has captured a user's access
    // token could repeatedly hit /mfa/setup and force N × scrypt calls per request
    // (each request would hash `recoveryCodeCount` codes only to lose the SET-NX race).
    // The narrow TOCTOU window between this fast-path GET and the SET-NX below is
    // benign — at worst, two concurrent first-time setups race and one's payload is
    // discarded by SET-NX after wasted work; subsequent requests hit the fast path.
    const existingFast = await this.redis.get(setupKey)
    if (existingFast !== null) {
      const data = parseSetupData(existingFast, userId, this.logger)
      const existingSecret = decryptMfaSecret(data.encryptedSecret, this.mfaOptions)
      const decryptedCodesJson = decryptMfaSecret(data.encryptedPlainCodes, this.mfaOptions)
      const existingCodes = parsePlainRecoveryCodes(decryptedCodesJson, userId, this.logger)
      const qrCodeUri = buildTotpUri(existingSecret, user.email, this.mfaOptions.issuer)
      return { secret: existingSecret, qrCodeUri, recoveryCodes: existingCodes }
    }

    // First-time setup: generate the data, then attempt an atomic SET-NX to claim
    // the key. The pre-generation is required to keep SET-NX atomic — two concurrent
    // requests both see null in the fast path, both generate, and SET-NX awards the
    // key to one of them. The losing request reads the winner's payload below.
    const { base32: secretBase32 } = generateTotpSecret()
    const encryptedSecret = encryptMfaSecret(secretBase32, this.mfaOptions)
    const recoveryCount = this.mfaOptions.recoveryCodeCount ?? DEFAULT_RECOVERY_CODE_COUNT
    const { plainCodes, hashedCodes } = generateRecoveryCodes(recoveryCount, this.options.hmacKey)
    const encryptedPlainCodes = encrypt(JSON.stringify(plainCodes), this.mfaOptions.encryptionKey)

    const setupData: MfaSetupData = { encryptedSecret, hashedCodes, encryptedPlainCodes }
    const payload = JSON.stringify(setupData)

    const wasSet = await this.redis.setIfAbsent(setupKey, payload, MFA_SETUP_TTL_SECONDS)

    if (!wasSet) {
      // Another request already started setup — return their data for idempotency.
      const existing = await this.redis.get(setupKey)
      if (existing !== null) {
        const data = parseSetupData(existing, userId, this.logger)
        const existingSecret = decryptMfaSecret(data.encryptedSecret, this.mfaOptions)
        const decryptedCodesJson = decryptMfaSecret(data.encryptedPlainCodes, this.mfaOptions)
        const existingCodes = parsePlainRecoveryCodes(decryptedCodesJson, userId, this.logger)
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
    this.logger.log(`setup: MFA setup initiated userId=${logSafe(userId)} context=${context}`)
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
   * @param context - Which repository to use: `'dashboard'` (default) or `'platform'`.
   * @throws {@link AuthException} MFA_ALREADY_ENABLED when MFA is already active on the account.
   * @throws `MFA_SETUP_REQUIRED` if no pending setup data is found in Redis.
   * @throws `MFA_INVALID_CODE` if the submitted TOTP code is invalid.
   * @throws `MFA_NOT_ENABLED` if `context === 'platform'` and the platform user
   *   repository was not configured at module registration.
   */
  async verifyAndEnable(
    userId: string,
    code: string,
    ip: string,
    userAgent: string,
    context: 'dashboard' | 'platform' = 'dashboard',
    tenantId?: string
  ): Promise<void> {
    assertPlaneTenant(context, tenantId)
    if (context === 'platform' && !this.platformUserRepo) {
      // See setup() — same misconfiguration guard, same rationale.
      throw new AuthException(AUTH_ERROR_CODES.MFA_NOT_ENABLED)
    }

    // Fetch once at entry — used for mfaEnabled guard, email notification, and hook.
    const user = await this.records.loadAccount(context, userId, tenantId)
    if (user.mfaEnabled) throw new AuthException(AUTH_ERROR_CODES.MFA_ALREADY_ENABLED)

    const setupKey = `mfa_setup:${hmacSha256(userSubject(context, userId, tenantId), this.options.hmacKey)}`
    const raw = await this.redis.get(setupKey)
    if (raw === null) throw new AuthException(AUTH_ERROR_CODES.MFA_SETUP_REQUIRED)

    const data = parseSetupData(raw, userId, this.logger)
    const secretBase32 = decryptMfaSecret(data.encryptedSecret, this.mfaOptions)

    const totpWindow = this.mfaOptions.totpWindow
    // Use anti-replay even on MFA enable to prevent a racing/intercepted code
    // from being reused via the challenge endpoint within the acceptance window.
    const codeValid = await this.records.verifyTotpWithAntiReplay(
      context,
      userId,
      secretBase32,
      code,
      totpWindow,
      tenantId
    )
    if (!codeValid) {
      this.logger.warn(`verifyAndEnable: invalid TOTP code userId=${logSafe(userId)}`)
      throw new AuthException(AUTH_ERROR_CODES.MFA_INVALID_CODE)
    }

    // Atomic completion gate: GETDEL returns the stored value and deletes the key
    // in one round-trip. Only the first concurrent caller observes a non-null
    // value and proceeds to the DB write + email. Any racing request that arrived
    // with the same valid TOTP code sees `null` and is treated as MFA_SETUP_REQUIRED,
    // preventing duplicate `updateMfa` writes and duplicate enablement emails.
    const consumed = await this.redis.getdel(setupKey)
    if (consumed === null) {
      this.logger.warn(
        `verifyAndEnable: setup key consumed by concurrent request userId=${logSafe(userId)}`
      )
      throw new AuthException(AUTH_ERROR_CODES.MFA_SETUP_REQUIRED)
    }

    // Serialized against every other MFA transition. The `getdel` above already makes the
    // enable single-shot among concurrent verify calls; this puts it in the same queue as
    // `disable` and the challenge splice, which write the same three fields.
    await this.records.transition(context, userId, tenantId, () => ({
      mfaEnabled: true,
      mfaSecret: data.encryptedSecret,
      mfaRecoveryCodes: data.hashedCodes
    }))

    // Atomically invalidate all existing refresh sessions so the user must re-login
    // with the MFA challenge, then advance the token epoch so outstanding ACCESS tokens die
    // too. Every token issued before this moment is stamped `mfaEnabled: false`, and the MFA
    // gate refuses only `mfaEnabled && !mfaVerified` — so without the bump, a stolen access
    // token keeps clearing every MFA-gated route for its remaining lifetime, at the exact
    // moment the user enabled a second factor because they suspected that theft.
    // Scoped to the caller's own plane: the two id spaces come from different repositories
    // and may collide, so an unscoped revoke would log out the unrelated account sharing it.
    await this.redis.invalidateUserSessions(userId, tenantId, context)
    await this.redis.bumpUserTokenEpoch(userId, tenantId, context)

    this.logger.log(`verifyAndEnable: MFA enabled userId=${logSafe(userId)} context=${context}`)
    notifyMfaChange(
      this.logger,
      this.emailProvider,
      'verifyAndEnable',
      userId,
      user,
      (provider, tenant, email) => provider.sendMfaEnabledNotification(tenant, email)
    )

    // Fire-and-forget hook — errors must not roll back a completed DB operation.
    if (this.hooks.afterMfaEnabled) {
      const safeUser = committedSafeUser(context, user, true)
      void Promise.resolve(
        this.hooks.afterMfaEnabled(safeUser, {
          // The plane, because the tenant cannot carry it: a platform admin is rendered with the
          // sentinel `tenantId: ''` while a platform token has no tenant claim at all.
          plane: context,
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
   * Handles both `'dashboard'` and `'platform'` contexts; the flow lives in
   * {@link MfaChallengeService.challenge}.
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
    return this.challengeFlow.challenge(mfaTempToken, code, ip, userAgent, this.mfaOptions)
  }

  /**
   * The challenge for an entry point that serves the platform plane only: a dashboard token is
   * refused with `PLATFORM_AUTH_REQUIRED` before anything is spent. See
   * {@link MfaChallengeService.challengePlatformOnly}.
   *
   * @param mfaTempToken - Short-lived MFA challenge JWT issued at platform login.
   * @param code - 6-digit TOTP code or `dddd-dddd-dddd` recovery code.
   * @param ip - Client IP address for session audit.
   * @param userAgent - User-Agent header for session description.
   * @returns The platform auth result.
   * @throws `PLATFORM_AUTH_REQUIRED` if the token is for the dashboard plane.
   * @throws `MFA_TEMP_TOKEN_INVALID` if the token is invalid or already consumed.
   * @throws `ACCOUNT_LOCKED` if the brute-force threshold has been reached.
   * @throws `MFA_INVALID_CODE` if the submitted code is incorrect.
   */
  async challengePlatformOnly(
    mfaTempToken: string,
    code: string,
    ip: string,
    userAgent: string
  ): Promise<PlatformAuthResult> {
    return this.challengeFlow.challengePlatformOnly(
      mfaTempToken,
      code,
      ip,
      userAgent,
      this.mfaOptions
    )
  }

  // ---------------------------------------------------------------------------
  // disable, resetMfa, regenerateRecoveryCodes — changes to an existing enrolment
  // ---------------------------------------------------------------------------

  /**
   * Disables MFA on a user's account after verifying a current TOTP code.
   *
   * Only TOTP codes are accepted — recovery codes cannot disable MFA by design. The flow lives in
   * {@link MfaManagementService.disable}.
   *
   * @param userId - Internal ID of the user disabling MFA.
   * @param code - 6-digit TOTP code from the authenticator app.
   * @param ip - Client IP address (forwarded to hooks).
   * @param userAgent - User-Agent header (forwarded to hooks).
   * @param context - Which repository to use: `'dashboard'` (default) or `'platform'`.
   * @param tenantId - The tenant on the dashboard plane; absent on the platform plane.
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
    context: 'dashboard' | 'platform' = 'dashboard',
    tenantId?: string
  ): Promise<void> {
    return this.management.disable(userId, code, ip, userAgent, context, tenantId, this.mfaOptions)
  }

  /**
   * Removes a user's second factor without their TOTP code, for a support desk facing a user who
   * has lost their authenticator AND their recovery codes.
   *
   * Authorising the caller is the consumer's job: the library ships no route for this. The flow
   * lives in {@link MfaManagementService.resetMfa}. Idempotent.
   *
   * @param userId - Internal ID of the user whose second factor is being removed.
   * @param context - Which identity plane the user belongs to: `'dashboard'` (default) or
   *   `'platform'`. Must match the plane the account lives in, or the lookup misses.
   * @param tenantId - The tenant on the dashboard plane; absent on the platform plane.
   * @throws `TOKEN_INVALID` if no user with that ID exists in the given plane.
   */
  async resetMfa(
    userId: string,
    context: 'dashboard' | 'platform' = 'dashboard',
    tenantId?: string
  ): Promise<void> {
    return this.management.resetMfa(userId, context, tenantId)
  }

  /**
   * Regenerates the user's MFA recovery codes after verifying a current TOTP code. Sessions are
   * intentionally NOT invalidated: the TOTP secret is unchanged. The flow lives in
   * {@link MfaManagementService.regenerateRecoveryCodes}.
   *
   * @param userId - Internal ID of the user rotating recovery codes.
   * @param totpCode - 6-digit TOTP code from the authenticator app.
   * @param ip - Client IP address (forwarded to hooks).
   * @param userAgent - User-Agent header (forwarded to hooks).
   * @param context - Which repository to use: `'dashboard'` (default) or `'platform'`.
   * @param tenantId - The tenant on the dashboard plane; absent on the platform plane.
   * @throws `TOKEN_INVALID` if the user is not found or `mfaSecret` is missing
   *   when `mfaEnabled` is `true` (database inconsistency).
   * @throws `MFA_NOT_ENABLED` if MFA is not currently active, or if
   *   `context === 'platform'` and the platform user repository was not
   *   configured at module registration.
   * @throws `ACCOUNT_LOCKED` if the brute-force threshold has been reached.
   * @throws `MFA_INVALID_CODE` if the submitted TOTP code is incorrect.
   * @returns The freshly generated plain-text recovery codes, one-time display.
   */
  async regenerateRecoveryCodes(
    userId: string,
    totpCode: string,
    ip: string,
    userAgent: string,
    context: 'dashboard' | 'platform' = 'dashboard',
    tenantId?: string
  ): Promise<{ recoveryCodes: string[] }> {
    return this.management.regenerateRecoveryCodes(
      userId,
      totpCode,
      ip,
      userAgent,
      context,
      tenantId,
      this.mfaOptions
    )
  }
}
