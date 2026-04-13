import { Injectable, Logger } from '@nestjs/common'

import type {
  IEmailProvider,
  InviteData,
  SessionInfo
} from '../interfaces/email-provider.interface'

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
 * Logged messages include only the method name and the recipient email — never
 * tokens, OTPs, or passwords.
 */
@Injectable()
export class NoOpEmailProvider implements IEmailProvider {
  private readonly logger = new Logger(NoOpEmailProvider.name)

  /** @inheritdoc */
  async sendPasswordResetToken(email: string, _token: string, _locale?: string): Promise<void> {
    this.logger.log(`sendPasswordResetToken → ${email} (no-op)`)
  }

  /** @inheritdoc */
  async sendPasswordResetOtp(email: string, _otp: string, _locale?: string): Promise<void> {
    this.logger.log(`sendPasswordResetOtp → ${email} (no-op)`)
  }

  /** @inheritdoc */
  async sendEmailVerificationOtp(email: string, _otp: string, _locale?: string): Promise<void> {
    this.logger.log(`sendEmailVerificationOtp → ${email} (no-op)`)
  }

  /** @inheritdoc */
  async sendMfaEnabledNotification(email: string, _locale?: string): Promise<void> {
    this.logger.log(`sendMfaEnabledNotification → ${email} (no-op)`)
  }

  /** @inheritdoc */
  async sendMfaDisabledNotification(email: string, _locale?: string): Promise<void> {
    this.logger.log(`sendMfaDisabledNotification → ${email} (no-op)`)
  }

  /** @inheritdoc */
  async sendNewSessionAlert(
    email: string,
    _sessionInfo: SessionInfo,
    _locale?: string
  ): Promise<void> {
    this.logger.log(`sendNewSessionAlert → ${email} (no-op)`)
  }

  /** @inheritdoc */
  async sendInvitation(email: string, _inviteData: InviteData, _locale?: string): Promise<void> {
    this.logger.log(`sendInvitation → ${email} (no-op)`)
  }
}
