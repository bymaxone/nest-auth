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
  SessionAlertInfo,
  WorkspaceInviteData
} from '../interfaces/email-provider.interface'
import { logEvent } from '../observability/log-event'

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
  async sendPasswordResetToken(
    _tenantId: string,
    _email: string,
    _token: string,
    _locale?: string
  ): Promise<void> {
    logEvent(this.logger, 'AUTH_EMAIL_NOT_SENT', { kind: 'sendPasswordResetToken' })
  }

  /** @inheritdoc */
  async sendPasswordResetOtp(
    _tenantId: string,
    _email: string,
    _otp: string,
    _locale?: string
  ): Promise<void> {
    logEvent(this.logger, 'AUTH_EMAIL_NOT_SENT', { kind: 'sendPasswordResetOtp' })
  }

  /** @inheritdoc */
  async sendEmailVerificationOtp(
    _tenantId: string,
    _email: string,
    _otp: string,
    _locale?: string
  ): Promise<void> {
    logEvent(this.logger, 'AUTH_EMAIL_NOT_SENT', { kind: 'sendEmailVerificationOtp' })
  }

  /** @inheritdoc */
  async sendMfaEnabledNotification(
    _tenantId: string,
    _email: string,
    _locale?: string
  ): Promise<void> {
    logEvent(this.logger, 'AUTH_EMAIL_NOT_SENT', { kind: 'sendMfaEnabledNotification' })
  }

  /** @inheritdoc */
  async sendMfaDisabledNotification(
    _tenantId: string,
    _email: string,
    _locale?: string
  ): Promise<void> {
    logEvent(this.logger, 'AUTH_EMAIL_NOT_SENT', { kind: 'sendMfaDisabledNotification' })
  }

  /** @inheritdoc */
  async sendNewSessionAlert(
    _tenantId: string,
    _email: string,
    _sessionInfo: SessionAlertInfo,
    _locale?: string
  ): Promise<void> {
    logEvent(this.logger, 'AUTH_EMAIL_NOT_SENT', { kind: 'sendNewSessionAlert' })
  }

  /** @inheritdoc */
  async sendInvitation(
    _tenantId: string,
    _email: string,
    _inviteData: InviteData,
    _locale?: string
  ): Promise<void> {
    logEvent(this.logger, 'AUTH_EMAIL_NOT_SENT', { kind: 'sendInvitation' })
  }

  /** @inheritdoc */
  async sendWorkspaceInvitation(
    _tenantId: string,
    _email: string,
    _data: WorkspaceInviteData,
    _locale?: string
  ): Promise<void> {
    logEvent(this.logger, 'AUTH_EMAIL_NOT_SENT', { kind: 'sendWorkspaceInvitation' })
  }
}
