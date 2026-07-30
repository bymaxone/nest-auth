import { Inject, Injectable, Logger } from '@nestjs/common'
import type { OnModuleInit } from '@nestjs/common'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-auth.constants'
import { PasswordService } from './password.service'
import type { ResolvedOptions } from '../config/resolved-options'
import { generateSecureToken, sha256 } from '../crypto/secure-token'
import type { ChangeEmailDto } from '../dto/change-email.dto'
import type { ConfirmEmailChangeDto } from '../dto/confirm-email-change.dto'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { IEmailProvider } from '../interfaces/email-provider.interface'
import type { AuthUser, IUserRepository } from '../interfaces/user-repository.interface'
import { AuthRedisService } from '../redis/auth-redis.service'
import { maskEmail } from '../utils/mask-email'
import { normalizeEmail } from '../utils/normalize-email'

/** Bytes of entropy in an address-change token before hex encoding (256-bit, 64 hex chars). */
const EMAIL_CHANGE_TOKEN_BYTES = 32

/**
 * Stored payload for a pending address change, kept in Redis under `ec:{sha256(token)}`.
 *
 * Held byte-compatible with rust-auth: the two backends share this keyspace, so a change
 * requested through one has to be confirmable through the other.
 */
interface EmailChangeContext {
  /** The account the change belongs to. */
  userId: string
  /** The address being moved to, already normalized. */
  newEmail: string
  /** The tenant the account belongs to, for the uniqueness re-check at confirm time. */
  tenantId: string
  /** Digest of the password hash in force when the token was minted. */
  passwordFingerprint: string
}

/** Whether an unknown value is a stored address-change context. */
function isEmailChangeContext(value: unknown): value is EmailChangeContext {
  if (typeof value !== 'object' || value === null) return false
  const v = value as Record<string, unknown>
  return (
    typeof v['userId'] === 'string' &&
    typeof v['newEmail'] === 'string' &&
    typeof v['tenantId'] === 'string'
  )
}

/**
 * Changing the address on an account, in two steps.
 *
 * The address is the account's recovery credential: whoever controls it can drive a password
 * reset to a mailbox the owner does not read. That makes moving it a security operation, not
 * a profile edit, and it is why the flow costs three things rather than one.
 *
 * **The current password is re-proved.** A stolen access token alone cannot move the recovery
 * address — the thief has to already hold the credential that would let them take the account
 * anyway.
 *
 * **The new address is proved before it is adopted.** A token goes to it and nowhere else, so
 * a typo cannot lock the owner out of their own account and an attacker cannot point the
 * account at a mailbox they merely claim.
 *
 * **The old address is told.** NIST SP 800-63B §4.6 asks for notification of a credential
 * change, and this is the one that matters most: it is the last message the owner can receive
 * at an address they still control, and it is what turns a silent takeover into one they can
 * see happening.
 *
 * @layer Service
 */
@Injectable()
export class EmailChangeService implements OnModuleInit {
  private readonly logger = new Logger(EmailChangeService.name)

  constructor(
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions,
    @Inject(BYMAX_AUTH_USER_REPOSITORY) private readonly userRepo: IUserRepository,
    @Inject(BYMAX_AUTH_EMAIL_PROVIDER) private readonly emailProvider: IEmailProvider,
    private readonly passwordService: PasswordService,
    private readonly redis: AuthRedisService
  ) {}

  /**
   * Refuses to boot when the flow is enabled but the provider cannot deliver its token.
   *
   * This service is registered only when `controllers.emailChange` is on, so its presence is
   * the flow being enabled. Checking at startup rather than on the first request is the
   * difference between a deployment that fails immediately and one that mints `ec:` keys
   * nobody ever receives — a failure that looks like success from every side, and that a user
   * experiences as a verification email that simply never arrives.
   *
   * @throws When the configured {@link IEmailProvider} implements no
   *   `sendEmailChangeVerification`.
   */
  onModuleInit(): void {
    if (!this.emailProvider.sendEmailChangeVerification) {
      throw new Error(
        'BymaxAuthModule: controllers.emailChange is enabled but the configured email provider ' +
          'implements no sendEmailChangeVerification. The address-change flow cannot deliver ' +
          'its token without it.'
      )
    }
  }

  // ---------------------------------------------------------------------------
  // requestChange()
  // ---------------------------------------------------------------------------

  /**
   * Starts an address change: re-proves the password, then mails a single-use token to the
   * new address. Nothing about the account changes until that token comes back.
   *
   * @param userId - The authenticated caller, from their own claims — never the body.
   * @param dto - The new address and the current password.
   * @throws {@link AuthException} `INVALID_CREDENTIALS` when the account has no local password
   *   or the submitted one is wrong — the same code a failed login returns, so a thief holding
   *   an access token learns nothing they did not already know.
   * @throws {@link AuthException} `EMAIL_ALREADY_EXISTS` when the address is the account's own
   *   or belongs to another account in the tenant.
   */
  async requestChange(userId: string, dto: ChangeEmailDto): Promise<void> {
    const newEmail = normalizeEmail(dto.newEmail)

    const user = await this.userRepo.findById(userId)
    // A verified token whose subject no longer exists, and an account with no local password,
    // answer identically: the caller cannot prove a credential this account does not have.
    if (!user?.passwordHash) {
      throw new AuthException(AUTH_ERROR_CODES.INVALID_CREDENTIALS)
    }

    const matches = await this.passwordService.compare(dto.currentPassword, user.passwordHash)
    if (!matches) {
      this.logger.warn(`requestChange: current password rejected userId=${userId}`)
      throw new AuthException(AUTH_ERROR_CODES.INVALID_CREDENTIALS)
    }

    await this.assertAddressIsFree(user, newEmail)

    const rawToken = generateSecureToken(EMAIL_CHANGE_TOKEN_BYTES)
    const context: EmailChangeContext = {
      userId,
      newEmail,
      tenantId: user.tenantId,
      // Binds the token to the password in force right now, exactly as a reset token is bound.
      // An attacker who plants a change request and waits loses it the moment the victim
      // changes their password — which is the first thing a victim does.
      passwordFingerprint: sha256(user.passwordHash)
    }
    await this.redis.set(
      `ec:${sha256(rawToken)}`,
      JSON.stringify(context),
      this.options.emailChange.tokenTtlSeconds
    )

    // Non-null by construction: `onModuleInit` refuses to boot without it.
    await this.emailProvider.sendEmailChangeVerification?.(newEmail, rawToken)
    this.logger.log(
      `requestChange: verification sent userId=${userId} newEmail=${maskEmail(newEmail)}`
    )
  }

  // ---------------------------------------------------------------------------
  // confirmChange()
  // ---------------------------------------------------------------------------

  /**
   * Completes an address change against a token that came back from the new address.
   *
   * @param dto - The single-use token.
   * @throws {@link AuthException} `EMAIL_CHANGE_TOKEN_INVALID` when the token is unknown,
   *   expired, already used, malformed, or no longer bound to the account's password.
   * @throws {@link AuthException} `EMAIL_ALREADY_EXISTS` when the address was taken between
   *   the request and the confirmation.
   */
  async confirmChange(dto: ConfirmEmailChangeDto): Promise<void> {
    // Atomic read-and-delete: a link works exactly once, whatever happens after.
    const raw = await this.redis.getdel(`ec:${sha256(dto.token)}`)
    if (raw === null) {
      throw new AuthException(AUTH_ERROR_CODES.EMAIL_CHANGE_TOKEN_INVALID)
    }

    const context = this.parseContext(raw)
    if (context === null) {
      throw new AuthException(AUTH_ERROR_CODES.EMAIL_CHANGE_TOKEN_INVALID)
    }

    const user = await this.userRepo.findById(context.userId)
    if (!user) {
      throw new AuthException(AUTH_ERROR_CODES.EMAIL_CHANGE_TOKEN_INVALID)
    }

    this.assertStillBound(context, user)
    // Re-checked here and not only at request time: the two are separated by the whole TTL,
    // and whoever registers the address in between would otherwise lose it to this change.
    await this.assertAddressIsFree(user, context.newEmail)

    const oldEmail = user.email
    await this.userRepo.updateEmail(context.userId, context.newEmail)
    this.logger.log(
      `confirmChange: address changed userId=${context.userId} ` +
        `from=${maskEmail(oldEmail)} to=${maskEmail(context.newEmail)}`
    )

    await this.notifyOldAddress(oldEmail, context.newEmail)
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  /**
   * Refuses an address the account already has, or that another account in the tenant holds.
   *
   * Answering `EMAIL_ALREADY_EXISTS` does disclose that an address is registered — the same
   * disclosure `register` and invitation acceptance already make, and the same one the caller
   * could obtain there. Withholding it here would buy nothing while leaving a user who typos
   * into a colleague's address waiting on a message that never comes, with no way to tell why.
   *
   * The account's own current address is refused through the same code: it is a change that
   * changes nothing, and letting it through would send a verification for a move that is not
   * happening.
   *
   * @param user - The account requesting the change.
   * @param newEmail - The normalized target address.
   */
  private async assertAddressIsFree(user: AuthUser, newEmail: string): Promise<void> {
    if (normalizeEmail(user.email) === newEmail) {
      throw new AuthException(AUTH_ERROR_CODES.EMAIL_ALREADY_EXISTS)
    }
    const existing = await this.userRepo.findByEmail(newEmail, user.tenantId)
    if (existing) {
      throw new AuthException(AUTH_ERROR_CODES.EMAIL_ALREADY_EXISTS)
    }
  }

  /**
   * Refuses a token whose binding no longer matches the account's password.
   *
   * An empty stored fingerprint means the token predates the binding — a rolling deploy, or a
   * sibling implementation that has not taken this change — and is accepted, exactly as the
   * reset flow accepts one: refusing them would break every change in flight for a window
   * this narrow.
   *
   * @param context - The stored record.
   * @param user - The account it names.
   */
  private assertStillBound(context: EmailChangeContext, user: AuthUser): void {
    const stored = context.passwordFingerprint
    if (typeof stored !== 'string' || stored === '') return

    // An account with no password cannot match a non-empty fingerprint — and `stored` is
    // non-empty by the guard above — so the comparison is decided before it is made. Written
    // as its own refusal rather than as a value that could never match: a placeholder here
    // would read as a comparison that might succeed.
    const current = user.passwordHash === null ? null : sha256(user.passwordHash)
    if (current === null || stored !== current) {
      this.logger.warn(
        `confirmChange: token no longer bound to the account password userId=${context.userId}`
      )
      throw new AuthException(AUTH_ERROR_CODES.EMAIL_CHANGE_TOKEN_INVALID)
    }
  }

  /**
   * Parses a stored context, answering `null` for anything that is not one.
   *
   * @param raw - The stored JSON.
   * @returns The validated record, or `null`.
   */
  private parseContext(raw: string): EmailChangeContext | null {
    let parsed: unknown
    try {
      parsed = JSON.parse(raw)
    } catch {
      // Deliberately swallowed and deliberately not an early return: an unparsed value stays
      // `undefined` and fails the guard below, which is the same answer by the same route
      // every other malformed record takes.
    }
    return isEmailChangeContext(parsed) ? parsed : null
  }

  /**
   * Tells the old address that the account moved, fire-and-forget.
   *
   * A delivery failure does not roll back a change the user asked for and has proven — but it
   * is logged, because this message is the owner's last chance to see a takeover at an address
   * they still control, and an operator needs to know when it did not go out.
   *
   * @param oldEmail - The address the account is leaving.
   * @param newEmail - The address it moved to.
   */
  private async notifyOldAddress(oldEmail: string, newEmail: string): Promise<void> {
    if (!this.emailProvider.sendEmailChangedNotification) return
    try {
      await this.emailProvider.sendEmailChangedNotification(oldEmail, newEmail)
    } catch (err: unknown) {
      this.logger.error('confirmChange: notification to the previous address failed', err)
    }
  }
}
