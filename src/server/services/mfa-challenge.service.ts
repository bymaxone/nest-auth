/**
 * @fileoverview The MFA challenge: exchanging an MFA temp token and a TOTP or recovery code for
 * full session tokens, on either identity plane.
 *
 * @layer Service
 */

import { Inject, Injectable, Logger, Optional } from '@nestjs/common'

import {
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  GUARDED_PLATFORM_USER_REPOSITORY,
  GUARDED_USER_REPOSITORY
} from '../bymax-auth.constants'
import { MfaFlowLockoutService } from './mfa-flow-lockout.service'
import { MfaRecordService, type MfaRecordUpdate } from './mfa-record.service'
import { SessionService } from './session.service'
import { TokenManagerService } from './token-manager.service'
import type { ResolvedOptions } from '../config/resolved-options'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { IAuthHooks } from '../interfaces/auth-hooks.interface'
import type { AuthResult, PlatformAuthResult } from '../interfaces/auth-result.interface'
import type {
  AuthPlatformUser,
  IPlatformUserRepository
} from '../interfaces/platform-user-repository.interface'
import type { AuthUser, IUserRepository } from '../interfaces/user-repository.interface'
import { logEvent } from '../observability/log-event'
import { markingPlane } from '../observability/observed-outcome'
import { MFA_LOG_CONTEXT } from '../utils/mfa-log-context'
import { verifyRecoveryCode } from '../utils/mfa-recovery-codes'
import { platformUserAsSafeUser, toSafePlatformUser, toSafeUser } from '../utils/mfa-safe-user'
import { decryptWithRotation, encryptMfaSecret, holdsSecret } from '../utils/mfa-secret-cipher'
import { runDetached } from '../utils/run-detached'
import { checked, pinned, PinnedAll } from '../utils/settle'

/** The resolved MFA configuration group, present whenever the MFA services are registered. */
export type MfaConfig = Required<NonNullable<ResolvedOptions['mfa']>>

/** The plane, account and tenant an MFA challenge belongs to, as read from the temp token. */
interface ChallengeScope {
  userId: string
  context: 'dashboard' | 'platform'
  tenantId: string | undefined
}

/**
 * The record update that spends one recovery code, computed against the record as it stands
 * inside the transition lock.
 *
 * Returns `null` to abandon the write when the record moved underneath the challenge:
 * - MFA stopped being enabled — a `disable` that already completed. Writing would re-enable it
 *   with the pre-disable secret, so the code stays spent (its `rcu:` claim stands) and nothing is
 *   written back.
 * - The secret the challenge opened was replaced — a re-enrolment — and the code belongs to the
 *   list that went with it. A record a sibling challenge only re-encrypted still holds the same
 *   secret and is spliced.
 * - The spent digest is no longer in the current list.
 *
 * @param current - The record inside the lock.
 * @param existingCodes - The digests read at the start of the challenge.
 * @param recoveryIndex - Index of the spent digest in `existingCodes`.
 * @param opened - The decrypted secret the challenge opened, and whether it opened under a retired
 *   key, in which case this write also re-encrypts it and drains the rotation for free.
 * @param mfa - The resolved MFA configuration.
 * @returns The update to write, or `null` to abandon.
 */
function spliceSpentCode(
  current: AuthUser | AuthPlatformUser,
  existingCodes: string[],
  recoveryIndex: number,
  opened: { secret: string; stale: boolean },
  mfa: MfaConfig
): MfaRecordUpdate | null {
  if (!current.mfaEnabled) return null
  if (!holdsSecret(current.mfaSecret, opened.secret, mfa)) return null
  // Stryker disable next-line ArrayDeclaration: the fallback's CONTENTS are unobservable. It
  // stands in for "this account has no recovery codes", and the only thing done with the list
  // is `indexOf(spentDigest)` — a digest that cannot be in a list the account does not have,
  // so any placeholder yields the same -1 and the same early return
  const currentCodes = current.mfaRecoveryCodes ?? []
  // Re-locate the code in the CURRENT list: the index computed against the earlier read
  // may name a different code, or none, after a concurrent write.
  /* istanbul ignore next -- defensive `noUncheckedIndexedAccess` fallback, unreachable: `recoveryIndex >= 0` only after `verifyRecoveryCode` matched a code inside this very array */
  // Stryker disable next-line StringLiteral: unreachable — the index came from a match found by iterating `existingCodes`, so the element always exists and the fallback's value can never be read
  const spentDigest = existingCodes[recoveryIndex] ?? ''
  const liveIndex = currentCodes.indexOf(spentDigest)
  if (liveIndex < 0) return null
  const updatedCodes = [...currentCodes]
  updatedCodes.splice(liveIndex, 1)
  return {
    mfaEnabled: true,
    mfaSecret: opened.stale ? encryptMfaSecret(opened.secret, mfa) : current.mfaSecret,
    mfaRecoveryCodes: updatedCodes
  }
}

/** Completes an MFA challenge: verifies the code, spends the temp token and issues the session. */
@PinnedAll()
@Injectable()
export class MfaChallengeService {
  private readonly logger = new Logger(MFA_LOG_CONTEXT)

  constructor(
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions,
    @Inject(GUARDED_USER_REPOSITORY) private readonly userRepo: IUserRepository,
    @Optional()
    @Inject(GUARDED_PLATFORM_USER_REPOSITORY)
    private readonly platformUserRepo: IPlatformUserRepository | null,
    @Inject(TokenManagerService) private readonly tokenManager: TokenManagerService,
    @Inject(MfaFlowLockoutService) private readonly flowLockout: MfaFlowLockoutService,
    @Inject(MfaRecordService) private readonly records: MfaRecordService,
    @Inject(SessionService) private readonly sessionService: SessionService,
    @Inject(BYMAX_AUTH_HOOKS) private readonly hooks: IAuthHooks
  ) {}

  /**
   * Validates a TOTP or recovery code and exchanges the MFA temp token for full
   * access tokens.
   *
   * Handles both `'dashboard'` and `'platform'` contexts. Applies brute-force
   * protection per-user. TOTP codes include anti-replay protection via a short-lived
   * Redis key keyed on an HMAC of the code and user ID.
   *
   * The order is part of the contract: the temp token is verified but NOT consumed until the code
   * passes, so a mistyped digit is retryable (`MFA_INVALID_CODE`) rather than a dead end
   * (`MFA_TEMP_TOKEN_INVALID`); the lockout counter caps how many wrong codes one token can try;
   * and the consume must win before a session is issued.
   *
   * @param mfaTempToken - Short-lived MFA challenge JWT issued at login.
   * @param code - 6-digit TOTP code or `dddd-dddd-dddd` recovery code.
   * @param ip - Client IP address for session audit.
   * @param userAgent - User-Agent header for session description.
   * @param mfa - The resolved MFA configuration (cipher keys and TOTP window).
   * @returns `AuthResult` for dashboard context, `PlatformAuthResult` for platform context.
   * @throws `MFA_TEMP_TOKEN_INVALID` if the token is invalid or already consumed.
   * @throws `ACCOUNT_LOCKED` if the brute-force threshold has been reached.
   * @throws `MFA_INVALID_CODE` if the submitted code is incorrect.
   */
  async challenge(
    mfaTempToken: string,
    code: string,
    ip: string,
    userAgent: string,
    mfa: MfaConfig
  ): Promise<AuthResult | PlatformAuthResult> {
    // Step 1: verify, without consuming, the MFA temp token.
    const {
      userId,
      context,
      tenantId,
      jti: tempTokenJti
    } = await pinned(this.tokenManager.verifyMfaTempToken(mfaTempToken))
    const scope: ChallengeScope = { userId, context, tenantId }

    // The token verified, so its plane is known: every way the rest of the challenge can end carries it.
    return checked(
      await pinned(
        markingPlane(context, async () =>
          checked(await this.admitChallenge(scope, tempTokenJti, code, ip, userAgent, mfa))
        )
      )
    )
  }

  /** The checks and the session of one challenge, run on the plane the temp token names. */
  private async admitChallenge(
    scope: ChallengeScope,
    tempTokenJti: string,
    code: string,
    ip: string,
    userAgent: string,
    mfa: MfaConfig
  ): Promise<AuthResult | PlatformAuthResult> {
    const { userId, context, tenantId } = scope
    await pinned(this.assertNotLocked(scope))

    const user = await pinned(this.records.loadAccount(context, userId, tenantId))
    if (!user.mfaEnabled || !user.mfaSecret) {
      throw new AuthException(AUTH_ERROR_CODES.MFA_NOT_ENABLED)
    }

    const opened = decryptWithRotation(user.mfaSecret, mfa)
    const { valid, recoveryIndex } = await pinned(
      this.checkCode(user, scope, opened.secret, code, mfa)
    )
    if (!valid) await pinned(this.refuseWrongCode(scope))
    await pinned(this.flowLockout.reset('challenge', context, userId, tenantId))

    await pinned(this.consumeOrRefuse(tempTokenJti))
    await pinned(this.settleRecovery(user, scope, opened, recoveryIndex, mfa))

    logEvent(this.logger, 'AUTH_MFA_CHALLENGE_PASSED', { plane: context, userId })
    return checked(
      await pinned(
        context === 'dashboard'
          ? this.issueDashboardSession(user as AuthUser, userId, ip, userAgent)
          : this.issuePlatformSession(user as AuthPlatformUser, userId, ip, userAgent)
      )
    )
  }

  /**
   * Consumes the temp token, and the consume must WIN: two concurrent submissions both see the marker, and on the recovery-code
   * path one code and one token would mint two sessions. The loser is reported as an invalid temp token.
   */
  private async consumeOrRefuse(tempTokenJti: string): Promise<void> {
    if (!(await pinned(this.tokenManager.consumeMfaTempToken(tempTokenJti)))) {
      throw new AuthException(AUTH_ERROR_CODES.MFA_TEMP_TOKEN_INVALID)
    }
  }

  /**
   * Refuses a challenge for an account at its failure ceiling.
   *
   * The 'challenge' counter is namespaced away from 'disable', so a pre-auth attacker holding only
   * a temp token cannot lock the user out of `disable()`, and away from the other identity plane,
   * whose id space may collide.
   *
   * @param scope - The plane, account and tenant the challenge belongs to.
   * @throws {@link AuthException} `ACCOUNT_LOCKED` at the ceiling.
   */
  private async assertNotLocked(scope: ChallengeScope): Promise<void> {
    const { userId, context, tenantId } = scope
    if (await pinned(this.flowLockout.isLockedOut('challenge', context, userId, tenantId))) {
      logEvent(this.logger, 'AUTH_MFA_LOCKED', { plane: context, flow: 'challenge' })
      throw new AuthException(AUTH_ERROR_CODES.ACCOUNT_LOCKED)
    }
  }

  /**
   * Counts a wrong code and refuses it. The temp token stays alive: the user can retry under it
   * until the lockout surfaces `ACCOUNT_LOCKED`.
   *
   * @param scope - The plane, account and tenant the challenge belongs to.
   * @throws {@link AuthException} `MFA_INVALID_CODE`, always.
   */
  private async refuseWrongCode(scope: ChallengeScope): Promise<never> {
    const { userId, context, tenantId } = scope
    await pinned(this.flowLockout.recordFailure('challenge', context, userId, tenantId))
    logEvent(this.logger, 'AUTH_MFA_CODE_INVALID', { plane: context, flow: 'challenge' })
    throw new AuthException(AUTH_ERROR_CODES.MFA_INVALID_CODE)
  }

  /**
   * Validates the submitted code against the account: a six-digit TOTP code with anti-replay, or a
   * recovery code compared in constant time and then claimed for exactly one challenge.
   *
   * @param user - The account, holding the stored recovery-code digests.
   * @param scope - The plane, account and tenant the challenge belongs to.
   * @param secretBase32 - The decrypted TOTP secret.
   * @param code - The submitted code.
   * @param mfa - The resolved MFA configuration.
   * @returns Whether the code is valid, and the index of the matched recovery digest (`-1` for
   *   TOTP and for a recovery code that matched nothing).
   */
  private async checkCode(
    user: AuthUser | AuthPlatformUser,
    scope: ChallengeScope,
    secretBase32: string,
    code: string,
    mfa: MfaConfig
  ): Promise<{ valid: boolean; recoveryIndex: number }> {
    const { userId, context, tenantId } = scope
    if (/^\d{6}$/.test(code)) {
      const valid = await pinned(
        this.records.verifyTotpWithAntiReplay(
          context,
          userId,
          secretBase32,
          code,
          mfa.totpWindow,
          tenantId
        )
      )
      return checked({ valid, recoveryIndex: -1 })
    }
    // Stryker disable next-line ArrayDeclaration: equivalent — the fallback stands in for an
    // account with no stored codes, and any content it could hold fails the constant-time
    // comparison exactly as the empty array does.
    const recoveryCodes = user.mfaRecoveryCodes ?? []
    const recoveryIndex = await pinned(
      verifyRecoveryCode(code, recoveryCodes, this.options.hmacKey, this.options.previousHmacKeys)
    )
    const valid =
      recoveryIndex >= 0 &&
      (await pinned(this.records.claimRecoveryCode(context, userId, code, tenantId)))
    return checked({ valid, recoveryIndex })
  }

  /**
   * Spends the recovery code a challenge used, or migrates the secret to the current key.
   *
   * A recovery challenge removes the matched digest in a serialized transition, spliced against
   * the record as it stands INSIDE the lock rather than the copy read earlier: splicing the stale
   * copy would roll a concurrent `regenerateRecoveryCodes` back wholesale and undo a completed
   * `disable` — see `MfaRecordService.transition`. A TOTP challenge writes nothing on its own, so
   * a secret that opened under a retired key is re-encrypted by a detached write: the challenge
   * has already succeeded and the retired key still opens the secret, so a failure costs the
   * migration and nothing else.
   *
   * @param user - The account as read at the start of the challenge.
   * @param scope - The plane, account and tenant the challenge belongs to.
   * @param opened - The decrypted secret, and whether it opened under a retired key.
   * @param recoveryIndex - Index of the spent recovery digest, or `-1` after a TOTP challenge.
   * @param mfa - The resolved MFA configuration.
   */
  private async settleRecovery(
    user: AuthUser | AuthPlatformUser,
    scope: ChallengeScope,
    opened: { secret: string; stale: boolean },
    recoveryIndex: number,
    mfa: MfaConfig
  ): Promise<void> {
    const { userId, context, tenantId } = scope
    if (recoveryIndex < 0) {
      if (opened.stale) {
        void this.records.reencryptSecret(userId, context, opened.secret, tenantId, mfa)
      }
      return
    }
    // mfaRecoveryCodes is guaranteed non-empty here: verifyRecoveryCode only returns ≥ 0
    // when it found a match by iterating the array, so the array cannot be empty or undefined.
    const existingCodes =
      user.mfaRecoveryCodes ??
      /* istanbul ignore next -- verifyRecoveryCode returns ≥0 only after iterating a non-null array */
      // Stryker disable next-line ArrayDeclaration: unreachable — this branch is only taken
      // when `verifyRecoveryCode` matched a code inside an array it had to iterate first.
      []
    await pinned(
      this.records.transition(context, userId, tenantId, (current) =>
        spliceSpentCode(current, existingCodes, recoveryIndex, opened, mfa)
      )
    )
  }

  /**
   * Issues the dashboard session for a challenge that passed.
   *
   * @param user - The dashboard account.
   * @param userId - The account id from the temp token, for the hook context.
   * @param ip - Client IP address for session audit.
   * @param userAgent - User-Agent header for session description.
   * @returns The dashboard auth result.
   */
  private async issueDashboardSession(
    user: AuthUser,
    userId: string,
    ip: string,
    userAgent: string
  ): Promise<AuthResult> {
    const safeUser = toSafeUser(user)
    const result = await pinned(
      this.tokenManager.issueTokens(safeUser, ip, userAgent, {
        mfaVerified: true,
        credentialProved: true
      })
    )

    // Track the session when sessions are enabled (enforces concurrent session limit).
    if (this.options.sessions.enabled) {
      await pinned(
        this.sessionService.createSession({
          userId: safeUser.id,
          tenantId: safeUser.tenantId,
          rawRefreshToken: result.rawRefreshToken,
          ip,
          userAgent
        })
      )
    }

    // The login the password step (or the OAuth callback) stopped short of: for an MFA account
    // this is the only place the last-login time can move.
    runDetached(
      this.logger,
      () => this.userRepo.updateLastLogin({ id: safeUser.id, tenantId: safeUser.tenantId }),
      'updateLastLogin'
    )

    if (this.hooks.afterLogin) {
      const afterLogin = this.hooks.afterLogin.bind(this.hooks)
      runDetached(
        this.logger,
        () =>
          afterLogin(safeUser, { plane: 'dashboard', userId, ip, userAgent, sanitizedHeaders: {} }),
        'afterLogin'
      )
    }

    return checked(result)
  }

  /**
   * Issues the platform session for a challenge that passed, reusing the account already fetched
   * to avoid a TOCTOU double-read. The platform repository's presence was validated by
   * `MfaRecordService.loadAccount`, so the cast below is safe.
   *
   * @param platformUser - The platform administrator.
   * @param userId - The account id from the temp token, for the hook context.
   * @param ip - Client IP address for session audit.
   * @param userAgent - User-Agent header for session description.
   * @returns The platform auth result.
   */
  private async issuePlatformSession(
    platformUser: AuthPlatformUser,
    userId: string,
    ip: string,
    userAgent: string
  ): Promise<PlatformAuthResult> {
    const result = await pinned(
      this.tokenManager.issuePlatformTokens(toSafePlatformUser(platformUser), ip, userAgent, {
        mfaVerified: true
      })
    )

    runDetached(
      this.logger,
      () => (this.platformUserRepo as IPlatformUserRepository).updateLastLogin(platformUser.id),
      'updateLastLogin'
    )

    if (this.hooks.afterLogin) {
      const afterLogin = this.hooks.afterLogin.bind(this.hooks)
      runDetached(
        this.logger,
        () =>
          afterLogin(platformUserAsSafeUser(platformUser), {
            plane: 'platform',
            userId,
            ip,
            userAgent,
            sanitizedHeaders: {}
          }),
        'afterLogin'
      )
    }

    return checked(result)
  }

  /**
   * The challenge for an entry point that serves the platform plane only.
   *
   * Reads the plane from the temp token first and refuses a dashboard token with
   * `PLATFORM_AUTH_REQUIRED` before anything is spent. {@link MfaChallengeService.challenge} consumes the
   * token, burns the TOTP code, stores a session, stamps the last login and fires the hooks, so
   * refusing after it leaves an orphan session nobody holds a token for. The first verification only
   * reads: it touches neither the brute-force counter nor the TOTP anti-replay key. The challenge
   * verifies the token again, and the plane is a signed claim, so both reads see the same one.
   *
   * @param mfaTempToken - Short-lived MFA challenge JWT issued at platform login.
   * @param code - 6-digit TOTP code or `dddd-dddd-dddd` recovery code.
   * @param ip - Client IP address for session audit.
   * @param userAgent - User-Agent header for session description.
   * @param mfa - The resolved MFA configuration (cipher keys and TOTP window).
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
    userAgent: string,
    mfa: MfaConfig
  ): Promise<PlatformAuthResult> {
    const { context } = await pinned(this.tokenManager.verifyMfaTempToken(mfaTempToken))
    if (context !== 'platform') {
      throw new AuthException(AUTH_ERROR_CODES.PLATFORM_AUTH_REQUIRED)
    }
    const result = await pinned(this.challenge(mfaTempToken, code, ip, userAgent, mfa))
    // The plane was verified above, so a dashboard-shaped result means the two disagree.
    if (!('admin' in result)) {
      throw new AuthException(AUTH_ERROR_CODES.PLATFORM_AUTH_REQUIRED)
    }
    return checked(result)
  }
}
