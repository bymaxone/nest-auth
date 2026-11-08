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
  BYMAX_AUTH_PLATFORM_USER_REPOSITORY,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-auth.constants'
import { MfaFlowLockoutService } from './mfa-flow-lockout.service'
import { MfaRecordService } from './mfa-record.service'
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
import { logSafe } from '../utils/log-safe'
import { verifyRecoveryCode } from '../utils/mfa-recovery-codes'
import { platformUserAsSafeUser, toSafePlatformUser, toSafeUser } from '../utils/mfa-safe-user'
import { decryptWithRotation, encryptMfaSecret, holdsSecret } from '../utils/mfa-secret-cipher'
import { runDetached } from '../utils/run-detached'

/** The resolved MFA configuration group, present whenever the MFA services are registered. */
export type MfaConfig = Required<NonNullable<ResolvedOptions['mfa']>>

/** Completes an MFA challenge: verifies the code, spends the temp token and issues the session. */
@Injectable()
export class MfaChallengeService {
  private readonly logger = new Logger(MfaChallengeService.name)

  constructor(
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions,
    @Inject(BYMAX_AUTH_USER_REPOSITORY) private readonly userRepo: IUserRepository,
    @Optional()
    @Inject(BYMAX_AUTH_PLATFORM_USER_REPOSITORY)
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
    // Step 1: Verify the MFA temp token. We DO NOT consume it here — the
    // token stays alive in Redis until the TOTP / recovery code passes,
    // so a single mistyped digit surfaces as `MFA_INVALID_CODE` (retryable)
    // instead of `MFA_TEMP_TOKEN_INVALID` (dead end). The brute-force
    // counter (Step 2) caps how many wrong codes can be tried under one
    // token. The token is consumed atomically in Step 5 once the code is
    // confirmed valid.
    const {
      userId,
      context,
      tenantId,
      jti: tempTokenJti
    } = await this.tokenManager.verifyMfaTempToken(mfaTempToken)

    // Step 2: Brute-force check. HMAC key prevents Redis key reversal.
    // The 'challenge:' prefix namespaces this counter away from the 'disable' counter —
    // preventing a pre-auth attacker (who only has a mfaTempToken) from exhausting the
    // lockout threshold and blocking the authenticated user's ability to call disable().
    // The context namespaces it away from the OTHER identity plane: the two id spaces come
    // from different consumer repositories and may collide, so a counter keyed on the id
    // alone lets either party exhaust — or clear — the other's lockout budget.
    if (await this.flowLockout.isLockedOut('challenge', context, userId, tenantId)) {
      this.logger.warn(`challenge: account locked userId=${logSafe(userId)}`)
      throw new AuthException(AUTH_ERROR_CODES.ACCOUNT_LOCKED)
    }

    // Step 3: Fetch user from the correct repository, tenant-scoped for a dashboard challenge
    // (the temp token guarantees the tenant is present) so status / secret / session all resolve
    // against the account the login authenticated, not a homonym in another tenant.
    const user = await this.records.loadAccount(context, userId, tenantId)

    // The account status was re-checked by `loadAccount` above. Login gated it before
    // issuing the temp token, but that token outlives the check by its whole TTL: an account
    // suspended in between would otherwise complete the challenge and receive a full session.
    // Revoking access must not depend on how far through the login the holder already was.
    // Running it before Step 4 also keeps a blocked account from spending the KDF — the
    // recovery-code path costs one derivation per stored code.

    if (!user.mfaEnabled || !user.mfaSecret) {
      throw new AuthException(AUTH_ERROR_CODES.MFA_NOT_ENABLED)
    }

    // Step 4: Decrypt TOTP secret and validate the submitted code.
    const { secret: secretBase32, stale: encryptedUnderRetiredKey } = decryptWithRotation(
      user.mfaSecret,
      mfa
    )
    const isTotpCode = /^\d{6}$/.test(code)
    const totpWindow = mfa.totpWindow
    // Stryker disable next-line BooleanLiteral: `codeValid` is unconditionally reassigned in both branches before it is ever read, so its initializer is irrelevant
    let codeValid = false
    let usedRecoveryIndex = -1

    if (isTotpCode) {
      codeValid = await this.records.verifyTotpWithAntiReplay(
        context,
        userId,
        secretBase32,
        code,
        totpWindow,
        tenantId
      )
    } else {
      // Stryker disable next-line ArrayDeclaration: equivalent — the fallback stands in for an
      // account with no stored codes, and any content it could hold fails the constant-time
      // comparison exactly as the empty array does.
      const recoveryCodes = user.mfaRecoveryCodes ?? []
      usedRecoveryIndex = await verifyRecoveryCode(
        code,
        recoveryCodes,
        this.options.hmacKey,
        this.options.previousHmacKeys
      )
      codeValid =
        usedRecoveryIndex >= 0 &&
        (await this.records.claimRecoveryCode(context, userId, code, tenantId))
    }

    if (!codeValid) {
      await this.flowLockout.recordFailure('challenge', context, userId, tenantId)
      this.logger.warn(`challenge: invalid MFA code userId=${logSafe(userId)} context=${context}`)
      // Keep the MFA temp token alive — the user can retry with the next
      // TOTP window or a different recovery code under the same token.
      // bruteForce.recordFailure will eventually surface `ACCOUNT_LOCKED`
      // if attempts keep failing.
      throw new AuthException(AUTH_ERROR_CODES.MFA_INVALID_CODE)
    }

    await this.flowLockout.reset('challenge', context, userId, tenantId)

    // Step 5a: consume the MFA temp token now that the code is confirmed valid — and the
    // consume must WIN. Two concurrent submissions both observe the marker and both delete
    // it; without gating on which delete actually removed it, both issue a full session. That
    // is not a benign duplicate for the same legitimate user: on the recovery-code path a
    // code's whole security model is that it is single-use, and this is one code and one token
    // minting two sessions. The loser is reported as an invalid temp token.
    if (!(await this.tokenManager.consumeMfaTempToken(tempTokenJti))) {
      throw new AuthException(AUTH_ERROR_CODES.MFA_TEMP_TOKEN_INVALID)
    }

    // Step 5b: Consume the used recovery code (branch on context to use the correct repo).
    if (usedRecoveryIndex >= 0) {
      // mfaRecoveryCodes is guaranteed non-empty here: verifyRecoveryCode only returns ≥ 0
      // when it found a match by iterating the array, so the array cannot be empty or undefined.
      const existingCodes =
        user.mfaRecoveryCodes ??
        /* istanbul ignore next -- verifyRecoveryCode returns ≥0 only after iterating a non-null array */
        // Stryker disable next-line ArrayDeclaration: unreachable — this branch is only taken
        // when `verifyRecoveryCode` matched a code inside an array it had to iterate first.
        []
      // Serialized, and spliced against the record as it stands INSIDE the lock rather than
      // the copy read at the top of this method. Splicing the stale copy would roll a concurrent
      // `regenerateRecoveryCodes` back wholesale and undo a completed `disable` — see
      // `MfaRecordService.transition`.
      await this.records.transition(context, userId, tenantId, (current) => {
        // The account stopped having MFA while this challenge was in flight — a `disable`
        // that has already completed. Writing here would re-enable it with the pre-disable
        // secret, so the code is spent (its `rcu:` claim already stands) and nothing is
        // written back.
        if (!current.mfaEnabled) return null
        // The secret this challenge opened was replaced — a re-enrolment — and the code belongs to
        // the list that went with it. Writing the splice would put the old secret back. A record a
        // sibling challenge only re-encrypted still holds the same secret and is spliced.
        if (!holdsSecret(current.mfaSecret, secretBase32, mfa)) return null
        // Stryker disable next-line ArrayDeclaration: the fallback's CONTENTS are unobservable. It
        // stands in for "this account has no recovery codes", and the only thing done with the list
        // is `indexOf(spentDigest)` — a digest that cannot be in a list the account does not have,
        // so any placeholder yields the same -1 and the same early return
        const currentCodes = current.mfaRecoveryCodes ?? []
        // Re-locate the code in the CURRENT list: the index computed against the earlier read
        // may name a different code, or none, after a concurrent write.
        /* istanbul ignore next -- defensive `noUncheckedIndexedAccess` fallback, unreachable: `usedRecoveryIndex >= 0` only after `verifyRecoveryCode` matched a code inside this very array */
        // Stryker disable next-line StringLiteral: unreachable — the index came from a match found by iterating `existingCodes`, so the element always exists and the fallback's value can never be read
        const spentDigest = existingCodes[usedRecoveryIndex] ?? ''
        const liveIndex = currentCodes.indexOf(spentDigest)
        if (liveIndex < 0) return null
        const updatedCodes = [...currentCodes]
        updatedCodes.splice(liveIndex, 1)
        return {
          mfaEnabled: true,
          // Re-encrypted here when the secret opened under a retired key: the write is
          // already happening, so the rotation drains for free.
          mfaSecret: encryptedUnderRetiredKey
            ? encryptMfaSecret(secretBase32, mfa)
            : current.mfaSecret,
          mfaRecoveryCodes: updatedCodes
        }
      })
    } else if (encryptedUnderRetiredKey) {
      // A TOTP challenge writes nothing on its own, so the re-encryption needs its own write.
      // Fire-and-forget: the challenge has already succeeded and the retired key still opens
      // the secret, so a failure costs the migration and nothing else.
      void this.records.reencryptSecret(userId, context, secretBase32, tenantId, mfa)
    }

    this.logger.log(`challenge: MFA challenge passed userId=${logSafe(userId)} context=${context}`)

    // Step 6: Issue full tokens with mfaVerified: true.
    if (context === 'dashboard') {
      const safeUser = toSafeUser(user as AuthUser)
      const result = await this.tokenManager.issueTokens(safeUser, ip, userAgent, {
        mfaVerified: true
      })

      // Track the session when sessions are enabled (enforces concurrent session limit).
      if (this.options.sessions.enabled) {
        await this.sessionService.createSession({
          userId: safeUser.id,
          tenantId: safeUser.tenantId,
          rawRefreshToken: result.rawRefreshToken,
          ip,
          userAgent
        })
      }

      // The login the password step (or the OAuth callback) stopped short of: for an MFA account
      // this is the only place the last-login time can move.
      runDetached(
        this.logger,
        () => this.userRepo.updateLastLogin({ id: safeUser.id, tenantId: safeUser.tenantId }),
        'challenge: updateLastLogin failed'
      )

      if (this.hooks.afterLogin) {
        const afterLogin = this.hooks.afterLogin.bind(this.hooks)
        runDetached(
          this.logger,
          () =>
            afterLogin(safeUser, {
              plane: 'dashboard',
              userId,
              ip,
              userAgent,
              sanitizedHeaders: {}
            }),
          'challenge: afterLogin hook threw'
        )
      }

      return result
    }

    // Platform context — reuse the already-fetched user to avoid a TOCTOU double-read.
    // platformUserRepo presence was already validated in loadAccount; this cast is safe.
    const platformUser = user as AuthPlatformUser
    const result = await this.tokenManager.issuePlatformTokens(
      toSafePlatformUser(platformUser),
      ip,
      userAgent,
      { mfaVerified: true }
    )

    runDetached(
      this.logger,
      () => (this.platformUserRepo as IPlatformUserRepository).updateLastLogin(platformUser.id),
      'challenge: platform updateLastLogin failed'
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
        'challenge: afterLogin hook threw'
      )
    }

    return result
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
    const { context } = await this.tokenManager.verifyMfaTempToken(mfaTempToken)
    if (context !== 'platform') {
      throw new AuthException(AUTH_ERROR_CODES.PLATFORM_AUTH_REQUIRED)
    }
    const result = await this.challenge(mfaTempToken, code, ip, userAgent, mfa)
    // The plane was verified above, so a dashboard-shaped result means the two disagree.
    if (!('admin' in result)) {
      throw new AuthException(AUTH_ERROR_CODES.PLATFORM_AUTH_REQUIRED)
    }
    return result
  }
}
