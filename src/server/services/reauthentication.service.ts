/**
 * @fileoverview Re-proving who is at the keyboard before a sensitive change: the account password,
 * counted like a login, or for an account with no password a recent real authentication.
 *
 * @layer Service
 */

import { Inject, Injectable, Logger } from '@nestjs/common'

import { MfaFlowLockoutService, type MfaFlowPlane } from './mfa-flow-lockout.service'
import { PasswordService } from './password.service'
import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import { recentAuthKey } from '../constants/recent-auth'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { logSafe } from '../utils/log-safe'

/** Re-authentication for the callers that change a credential or a membership. */
@Injectable()
export class ReauthenticationService {
  private readonly logger = new Logger(ReauthenticationService.name)

  constructor(
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions,
    @Inject(AuthRedisService) private readonly redis: AuthRedisService,
    @Inject(PasswordService) private readonly passwordService: PasswordService,
    @Inject(MfaFlowLockoutService) private readonly lockout: MfaFlowLockoutService
  ) {}

  /**
   * Requires the caller to re-prove the account password before a factor is changed.
   *
   * Counted like a login, and for the same reason. `login` refuses an account after N wrong
   * passwords; this door asks for the same secret and used to refuse nothing, so a caller
   * holding a stolen access token but not the password could guess it here indefinitely. The
   * only control left was the per-route IP limit, which a distributed caller sidesteps — and
   * winning the guess buys the whole account: enrol a factor, change the password, move the
   * address. A door that takes the password has to carry the password's lockout.
   *
   * The identifier is namespaced by flow and by plane. Sharing one counter with `login` would
   * let an authenticated caller lock the owner out of their own sign-in, and sharing it across
   * planes would let a dashboard user and a platform admin holding the same id exhaust each
   * other's budget — the same two reasons the challenge and disable counters are split.
   *
   * @param context - The authentication plane, part of the counter's key.
   * @param userId - The account being changed, part of the counter's key.
   * @param passwordHash - The account's stored hash, or `null` for an OAuth-only account.
   * @param password - The password the caller submitted, if any.
   * @throws {@link AuthException} `ACCOUNT_LOCKED` once the failure budget for this flow is
   *   spent, or `INVALID_CREDENTIALS` when the account has a password and the submitted one is
   *   absent or wrong. The latter is deliberately the same code a failed login returns: an
   *   attacker holding a stolen token learns nothing from it beyond what they already knew.
   */
  async assertReauthenticated(
    context: MfaFlowPlane,
    userId: string,
    passwordHash: string | null,
    password: string | undefined,
    tenantId: string | undefined
  ): Promise<void> {
    if (passwordHash === null) {
      // No local password to re-prove — the account was provisioned through OAuth and its
      // credential belongs to the provider, which this library cannot verify inline. So the
      // proof is temporal instead of cryptographic: the caller must have completed a REAL
      // authentication within the last few minutes.
      //
      // This branch used to return, and that was the single worst thing in the library. An
      // access token lifted by XSS or from a shared machine was enough to enrol a factor the
      // ATTACKER holds; the enable then invalidates every session and bumps the epoch, so the
      // owner — who still signs in with Google perfectly well — is stopped at a challenge they
      // cannot pass, with the recovery codes having been displayed once, to the attacker. And
      // there was no way back: `disable` and `regenerateRecoveryCodes` both demand a live TOTP
      // code, and the reset flow refuses an account with no password. A fifteen-minute token
      // theft became permanent, unrecoverable loss of the account.
      //
      // The marker is written by `TokenManagerService.issueTokens` and NOT by `reissueTokens`,
      // which is what makes it proof of anything: an attacker holding a stolen session can
      // rotate it indefinitely and never make the mark fresh again. Producing one requires
      // driving a real sign-in, which requires the provider credentials the theft did not
      // include.
      const recent = await this.redis.get(
        recentAuthKey(context, userId, this.options.hmacKey, tenantId)
      )
      if (recent === null) {
        this.logger.warn(
          `reauthenticate: no recent authentication userId=${logSafe(userId)} context=${context}`
        )
        throw new AuthException(AUTH_ERROR_CODES.REAUTHENTICATION_REQUIRED)
      }
      return
    }

    if (await this.lockout.isLockedOut('reauth', context, userId, tenantId)) {
      this.logger.warn(
        `reauthenticate: account locked userId=${logSafe(userId)} context=${context}`
      )
      throw new AuthException(AUTH_ERROR_CODES.ACCOUNT_LOCKED)
    }

    // A missing password still pays the KDF, so "no password sent" and "wrong password" take
    // the same time — otherwise the response separates them for free.
    const supplied = password ?? ''
    const matches = await this.passwordService.compare(supplied, passwordHash)
    if (!matches) {
      await this.lockout.recordFailure('reauth', context, userId, tenantId)
      throw new AuthException(AUTH_ERROR_CODES.INVALID_CREDENTIALS)
    }

    await this.lockout.reset('reauth', context, userId, tenantId)
  }
}
