/**
 * @fileoverview No-operation default implementation of {@link IEmailProvider}.
 *
 * All send methods resolve immediately without dispatching any email. Used as the
 * fallback when the consuming application does not register a custom email provider.
 *
 * @layer Provider
 */
import { Injectable, Logger } from '@nestjs/common'

import type {
  IEmailProvider,
  InviteData,
  SessionInfo
} from '../interfaces/email-provider.interface'
import { maskEmail } from '../utils/mask-email'

/**
 * No-operation email provider for development and testing environments.
 *
 * Implements {@link IEmailProvider} by logging each call via NestJS `Logger`
 * and resolving immediately without sending any real email. Inject this
 * provider via `BymaxAuthModule.forRoot({ emailProvider: NoOpEmailProvider })`
 * when email delivery is not required (local development, integration tests).
 *
 * @remarks
 * **Never use this provider in production.** Replace it with a concrete
 * adapter (e.g. Resend, SendGrid, Nodemailer) that implements `IEmailProvider`.
 *
 * Logged messages include the method name and a MASKED recipient — never the full address,
 * and never tokens, OTPs, or passwords.
 *
 * The mask matters because this is the DEFAULT provider: a deployment that ships without
 * wiring `BYMAX_AUTH_EMAIL_PROVIDER` gets it, and it would otherwise write every user's
 * address to stdout on every reset, verification, MFA notification and invitation — a PII
 * disclosure to whatever collects the logs, produced by an omission rather than a decision.
 */
@Injectable()
export class NoOpEmailProvider implements IEmailProvider {
  private readonly logger = new Logger(NoOpEmailProvider.name)

  /** @inheritdoc */
  async sendPasswordResetToken(email: string, _token: string, _locale?: string): Promise<void> {
    this.logger.log(`sendPasswordResetToken → ${maskEmail(email)} (no-op)`)
  }

  /** @inheritdoc */
  async sendPasswordResetOtp(email: string, _otp: string, _locale?: string): Promise<void> {
    this.logger.log(`sendPasswordResetOtp → ${maskEmail(email)} (no-op)`)
  }

  /** @inheritdoc */
  async sendEmailVerificationOtp(email: string, _otp: string, _locale?: string): Promise<void> {
    this.logger.log(`sendEmailVerificationOtp → ${maskEmail(email)} (no-op)`)
  }

  /** @inheritdoc */
  async sendMfaEnabledNotification(email: string, _locale?: string): Promise<void> {
    this.logger.log(`sendMfaEnabledNotification → ${maskEmail(email)} (no-op)`)
  }

  /** @inheritdoc */
  async sendMfaDisabledNotification(email: string, _locale?: string): Promise<void> {
    this.logger.log(`sendMfaDisabledNotification → ${maskEmail(email)} (no-op)`)
  }

  /** @inheritdoc */
  async sendNewSessionAlert(
    email: string,
    _sessionInfo: SessionInfo,
    _locale?: string
  ): Promise<void> {
    this.logger.log(`sendNewSessionAlert → ${maskEmail(email)} (no-op)`)
  }

  /** @inheritdoc */
  async sendInvitation(email: string, _inviteData: InviteData, _locale?: string): Promise<void> {
    this.logger.log(`sendInvitation → ${maskEmail(email)} (no-op)`)
  }
}
