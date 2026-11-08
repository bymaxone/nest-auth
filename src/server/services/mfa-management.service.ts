/**
 * @fileoverview Changing an MFA enrolment that already exists: turning it off with a TOTP code,
 * removing it administratively, and replacing its recovery codes.
 *
 * @layer Service
 */

import { Inject, Injectable, Logger, Optional } from '@nestjs/common'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_PLATFORM_USER_REPOSITORY
} from '../bymax-auth.constants'
import type { MfaConfig } from './mfa-challenge.service'
import { MfaFlowLockoutService } from './mfa-flow-lockout.service'
import { MfaRecordService } from './mfa-record.service'
import type { ResolvedOptions } from '../config/resolved-options'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { IAuthHooks } from '../interfaces/auth-hooks.interface'
import type { IEmailProvider } from '../interfaces/email-provider.interface'
import type {
  AuthPlatformUser,
  IPlatformUserRepository
} from '../interfaces/platform-user-repository.interface'
import type { AuthUser } from '../interfaces/user-repository.interface'
import { AuthRedisService } from '../redis/auth-redis.service'
import { logSafe } from '../utils/log-safe'
import { MFA_LOG_CONTEXT } from '../utils/mfa-log-context'
import { notifyMfaChange } from '../utils/mfa-notify'
import { assertPlaneTenant } from '../utils/mfa-plane-tenant'
import { DEFAULT_RECOVERY_CODE_COUNT, generateRecoveryCodes } from '../utils/mfa-recovery-codes'
import { committedSafeUser, platformUserAsSafeUser, toSafeUser } from '../utils/mfa-safe-user'
import { decryptMfaSecret } from '../utils/mfa-secret-cipher'

/** The plane, account and tenant an MFA change applies to. */
interface AccountScope {
  userId: string
  context: 'dashboard' | 'platform'
  tenantId: string | undefined
}

/** Turns an enrolment off, removes it administratively, or replaces its recovery codes. */
@Injectable()
export class MfaManagementService {
  private readonly logger = new Logger(MFA_LOG_CONTEXT)

  constructor(
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions,
    @Optional()
    @Inject(BYMAX_AUTH_PLATFORM_USER_REPOSITORY)
    private readonly platformUserRepo: IPlatformUserRepository | null,
    @Inject(AuthRedisService) private readonly redis: AuthRedisService,
    @Inject(MfaFlowLockoutService) private readonly flowLockout: MfaFlowLockoutService,
    @Inject(MfaRecordService) private readonly records: MfaRecordService,
    @Inject(BYMAX_AUTH_EMAIL_PROVIDER) private readonly emailProvider: IEmailProvider,
    @Inject(BYMAX_AUTH_HOOKS) private readonly hooks: IAuthHooks
  ) {}

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
   * @param context - Which repository to use: `'dashboard'` or `'platform'`.
   * @param tenantId - The tenant on the dashboard plane; absent on the platform plane.
   * @param mfa - The resolved MFA configuration (cipher keys and TOTP window).
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
    context: 'dashboard' | 'platform',
    tenantId: string | undefined,
    mfa: MfaConfig
  ): Promise<void> {
    assertPlaneTenant(context, tenantId)
    const scope: AccountScope = { userId, context, tenantId }
    const user = await this.records.loadAccount(context, userId, tenantId)
    if (!user.mfaEnabled) throw new AuthException(AUTH_ERROR_CODES.MFA_NOT_ENABLED)

    await this.spendTotpAttempt('disable', scope, user, code, mfa)
    await this.clearFactor(scope)

    this.logger.log(`disable: MFA disabled userId=${logSafe(userId)} context=${context}`)
    this.notifyDisabled('disable', scope, user)
    this.fireDisabledHook(scope, user, ip, userAgent)
  }

  /**
   * Removes a user's second factor without their TOTP code, for a support desk facing a user
   * who has lost their authenticator AND their recovery codes.
   *
   * Every self-service exit from MFA needs the factor itself: {@link disable} wants a valid
   * TOTP code, and the recovery codes want the codes. A user who has lost both is locked out
   * permanently, by the control that exists to protect them — ASVS v5 §6.1.1 asks for an
   * administrative path out for exactly that reason.
   *
   * **Authorising the caller is the consumer's job.** The library deliberately ships no route
   * for this, the same decision and for the same reason as {@link AuthService.unlockAccount}:
   * who may reset whom is a question only the host application can answer, and every route
   * this library ships is scoped to the caller's own account.
   *
   * Idempotent: resetting an account that has no second factor is a no-op, so a support desk
   * retrying does not get an error for a job already done.
   *
   * Three things happen beyond clearing the record, and none of them are optional:
   *
   * - **Sessions are invalidated and the token epoch is bumped**, so access tokens carrying
   *   `mfaVerified: true` die with the factor rather than outliving it.
   * - **The user is notified**, through the same channel {@link disable} uses. An
   *   administrative reset that the account holder cannot see is an account-takeover path:
   *   an attacker who reaches the support desk removes the second factor silently. The
   *   notification is what makes it an event the owner can detect and dispute.
   * - **It is logged** under its own prefix, so an administrative removal is distinguishable
   *   from a user-initiated one in the library's own log.
   *
   * The `afterMfaDisabled` hook fires too, so consumer-side alerting keeps working. It is not
   * given a separate hook: the consumer is the one calling this method, so they already know
   * an administrative reset happened — the hook exists to tell them about the paths they do
   * not initiate.
   *
   * @param userId - Internal ID of the user whose second factor is being removed.
   * @param context - Which identity plane the user belongs to: `'dashboard'` or `'platform'`.
   *   Must match the plane the account lives in, or the lookup misses.
   * @param tenantId - The tenant on the dashboard plane; absent on the platform plane.
   * @throws `TOKEN_INVALID` if no user with that ID exists in the given plane.
   */
  async resetMfa(
    userId: string,
    context: 'dashboard' | 'platform',
    tenantId: string | undefined
  ): Promise<void> {
    assertPlaneTenant(context, tenantId)
    const scope: AccountScope = { userId, context, tenantId }
    const user = await this.records.loadAccount(context, userId, tenantId)

    if (!user.mfaEnabled) {
      this.logger.log(
        `resetMfa: no second factor to remove userId=${logSafe(userId)} context=${context}`
      )
      return
    }

    await this.clearFactor(scope)

    this.logger.warn(
      `resetMfa: MFA removed administratively userId=${logSafe(userId)} context=${context}`
    )
    this.notifyDisabled('resetMfa', scope, user)
    // No request context: this call does not come from one. Empty rather than invented, so a
    // consumer logging the hook cannot mistake a placeholder for a real address.
    this.fireDisabledHook(scope, user, '', '')
  }

  /**
   * Regenerates the user's MFA recovery codes after verifying a current TOTP code.
   *
   * Mirrors {@link disable} in its security posture: only TOTP codes are accepted
   * (recovery codes cannot rotate themselves by design), the brute-force counter
   * is checked, and the regeneration is fired against the correct repository for
   * the supplied `context`. The TOTP secret on the user record is unchanged — only
   * the recovery code list is replaced.
   *
   * The order is deliberate and differs from the challenge: the account is read and the enrolment
   * checked BEFORE the lockout. The challenge runs its brute-force check first because it is a
   * PUBLIC endpoint, where an attacker who knows a userId could otherwise force a database read
   * per request. This and `disable` sit behind a JWT guard that binds the caller to a userId, so
   * the counter exists to throttle repeated TOTP guesses by the legitimate user, or by someone
   * holding their access token, and a read per request from an authenticated session is
   * acceptable for that threat model. Do not reorder it to match the challenge.
   *
   * Returns the plain-text codes once. They are NOT persisted in plain form; only a
   * keyed HMAC-SHA-256 of each goes into the database. The caller is responsible for showing the
   * codes to the user exactly once and warning them to save them safely.
   *
   * @remarks
   * **Sessions are intentionally NOT invalidated after this call.** Unlike
   * {@link disable}, which flips `mfaEnabled` back to `false`, this method does not change
   * the verification credential — the TOTP secret stays the same and existing
   * `mfaVerified: true` access tokens remain valid. Invalidating sessions here
   * would force a redundant re-auth on every recovery-code rotation, which is a
   * routine hygiene action a user might perform several times over the lifetime
   * of an account.
   *
   * @param userId - Internal ID of the user rotating recovery codes.
   * @param totpCode - 6-digit TOTP code from the authenticator app.
   * @param ip - Client IP address (forwarded to hooks).
   * @param userAgent - User-Agent header (forwarded to hooks).
   * @param context - Which repository to use: `'dashboard'` or `'platform'`.
   * @param tenantId - The tenant on the dashboard plane; absent on the platform plane.
   * @param mfa - The resolved MFA configuration (cipher keys, TOTP window, code count).
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
    context: 'dashboard' | 'platform',
    tenantId: string | undefined,
    mfa: MfaConfig
  ): Promise<{ recoveryCodes: string[] }> {
    assertPlaneTenant(context, tenantId)
    if (context === 'platform' && !this.platformUserRepo) {
      // Same misconfiguration guard as setup() and verifyAndEnable().
      throw new AuthException(AUTH_ERROR_CODES.MFA_NOT_ENABLED)
    }
    const scope: AccountScope = { userId, context, tenantId }
    const user = await this.records.loadAccount(context, userId, tenantId)
    if (!user.mfaEnabled) throw new AuthException(AUTH_ERROR_CODES.MFA_NOT_ENABLED)

    // The 'disable' counter is shared: both flows are TOTP-gated MFA changes from an
    // authenticated user, so they draw on one lockout pool, which is already isolated from the
    // public 'challenge' counter.
    await this.spendTotpAttempt('regenerateRecoveryCodes', scope, user, totpCode, mfa)

    // Same entropy, formatting and keyed-MAC digesting as the initial setup() path.
    const recoveryCount = mfa.recoveryCodeCount ?? DEFAULT_RECOVERY_CODE_COUNT
    const { plainCodes, hashedCodes } = generateRecoveryCodes(recoveryCount, this.options.hmacKey)

    // Serialized against every other MFA transition: the prior set is replaced wholesale so an
    // old code can never coexist with the new one, which a challenge that read the old list could
    // otherwise undo by splicing it back after this write. The TOTP secret is preserved.
    const replaced = await this.records.transition(context, userId, tenantId, (current) => {
      // MFA was disabled while the new codes were being derived. Writing them would re-enable
      // it with the pre-disable secret, so the caller is told the factor is gone instead.
      if (!current.mfaEnabled) return null
      return { mfaEnabled: true, mfaSecret: current.mfaSecret, mfaRecoveryCodes: hashedCodes }
    })
    if (!replaced) throw new AuthException(AUTH_ERROR_CODES.MFA_NOT_ENABLED)

    this.logger.log(
      `regenerateRecoveryCodes: recovery codes regenerated userId=${logSafe(userId)} context=${context}`
    )
    this.fireRegeneratedHook(scope, user, ip, userAgent)

    return { recoveryCodes: plainCodes }
  }

  /**
   * Checks the lockout, then verifies a TOTP code for an authenticated MFA change, counting a
   * wrong code and clearing the counter on a right one.
   *
   * The 'disable' counter is namespaced away from 'challenge', so a pre-auth attacker holding only
   * a temp token cannot exhaust the threshold and block the authenticated user's own changes.
   *
   * @param origin - The calling flow, for the log lines.
   * @param scope - The plane, account and tenant the change applies to.
   * @param user - The account, holding the encrypted secret.
   * @param code - The submitted TOTP code.
   * @param mfa - The resolved MFA configuration.
   * @throws {@link AuthException} `ACCOUNT_LOCKED` at the ceiling, `TOKEN_INVALID` when the secret
   *   is absent on an enabled account (a database inconsistency), `MFA_INVALID_CODE` on a wrong
   *   code.
   */
  private async spendTotpAttempt(
    origin: string,
    scope: AccountScope,
    user: AuthUser | AuthPlatformUser,
    code: string,
    mfa: MfaConfig
  ): Promise<void> {
    const { userId, context, tenantId } = scope
    if (await this.flowLockout.isLockedOut('disable', context, userId, tenantId)) {
      this.logger.warn(`${origin}: account locked userId=${logSafe(userId)} context=${context}`)
      throw new AuthException(AUTH_ERROR_CODES.ACCOUNT_LOCKED)
    }
    if (!user.mfaSecret) {
      // mfaEnabled is true but mfaSecret is absent — database inconsistency.
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }
    const valid = await this.records.verifyTotpWithAntiReplay(
      context,
      userId,
      decryptMfaSecret(user.mfaSecret, mfa),
      code,
      mfa.totpWindow,
      tenantId
    )
    if (!valid) {
      await this.flowLockout.recordFailure('disable', context, userId, tenantId)
      this.logger.warn(`${origin}: invalid MFA code userId=${logSafe(userId)} context=${context}`)
      throw new AuthException(AUTH_ERROR_CODES.MFA_INVALID_CODE)
    }
    await this.flowLockout.reset('disable', context, userId, tenantId)
  }

  /**
   * Clears the MFA record and revokes everything issued under it.
   *
   * Serialized against every other MFA transition, so a challenge that read the record a moment
   * earlier cannot splice `mfaEnabled: true` and the old secret back on top of this. Sessions are
   * invalidated and the token epoch advances so outstanding access tokens die with the factor: an
   * auth-state change revokes everything issued under the previous state, in both directions, the
   * same rule the password-reset flow applies. Scoped to the caller's own identity plane.
   *
   * @param scope - The plane, account and tenant to clear.
   */
  private async clearFactor(scope: AccountScope): Promise<void> {
    const { userId, context, tenantId } = scope
    await this.records.transition(context, userId, tenantId, () => ({
      mfaEnabled: false,
      mfaSecret: null,
      mfaRecoveryCodes: null
    }))
    await this.redis.invalidateUserSessions(userId, tenantId, context)
    await this.redis.bumpUserTokenEpoch(userId, tenantId, context)
  }

  /**
   * Tells the account holder their second factor was turned off.
   *
   * @param origin - The calling flow, for the log line.
   * @param scope - The plane, account and tenant that changed.
   * @param user - The account, read for its address.
   */
  private notifyDisabled(
    origin: string,
    scope: AccountScope,
    user: AuthUser | AuthPlatformUser
  ): void {
    notifyMfaChange(
      this.logger,
      this.emailProvider,
      origin,
      scope.userId,
      user,
      (provider, tenant, email) => provider.sendMfaDisabledNotification(tenant, email)
    )
  }

  /**
   * Fires the `afterMfaDisabled` hook, fire-and-forget: its failure must not undo a completed
   * removal.
   *
   * @param scope - The plane, account and tenant that changed.
   * @param user - The account as read before the change.
   * @param ip - Client IP address, or empty for an administrative call.
   * @param userAgent - User-Agent header, or empty for an administrative call.
   */
  private fireDisabledHook(
    scope: AccountScope,
    user: AuthUser | AuthPlatformUser,
    ip: string,
    userAgent: string
  ): void {
    const safeUser = committedSafeUser(scope.context, user, false)

    if (this.hooks.afterMfaDisabled) {
      void Promise.resolve(
        this.hooks.afterMfaDisabled(safeUser, {
          plane: scope.context,
          userId: scope.userId,
          ip,
          userAgent,
          sanitizedHeaders: {}
        })
      ).catch(() => undefined)
    }
  }

  /**
   * Fires the `afterMfaRecoveryCodesRegenerated` hook, fire-and-forget: its failure must not undo
   * a completed regeneration.
   *
   * @param scope - The plane, account and tenant that changed.
   * @param user - The account as read before the change.
   * @param ip - Client IP address.
   * @param userAgent - User-Agent header.
   */
  private fireRegeneratedHook(
    scope: AccountScope,
    user: AuthUser | AuthPlatformUser,
    ip: string,
    userAgent: string
  ): void {
    if (this.hooks.afterMfaRecoveryCodesRegenerated) {
      const safeUser =
        scope.context === 'platform'
          ? platformUserAsSafeUser(user as AuthPlatformUser)
          : toSafeUser(user as AuthUser)
      void Promise.resolve(
        this.hooks.afterMfaRecoveryCodesRegenerated(safeUser, {
          plane: scope.context,
          userId: scope.userId,
          ip,
          userAgent,
          sanitizedHeaders: {}
        })
      ).catch(() => undefined)
    }
  }
}
