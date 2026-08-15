/**
 * @fileoverview Overridable default implementation of {@link IEmailProvider}.
 *
 * Ships the security-notification policy every backend would otherwise hand-write to bridge this
 * library's email port onto a delivery channel: HTML escaping on a message path that carries
 * caller-chosen text, CR/LF stripping on the subject header so a name cannot inject one, the NIST
 * SP 800-63B notification catalogue (a password-changed notice, MFA enable/disable notices, an
 * email-changed notice to the *previous* address), and a swallow-and-log failure policy so a down
 * channel never turns "enable MFA" into a failed request.
 *
 * It sends through {@link AuthEmailSink}, a channel port narrow enough that this file depends on no
 * concrete mailer — `@bymax-one/nest-notification`'s `EmailService` satisfies it structurally, and
 * so does any `send({ tenantId, to, subject, html, text })`. The tenant the port now carries is
 * passed straight through to the sink, so a multi-tenant channel can attribute and route each
 * message.
 *
 * The copy is deliberately plain and entirely replaceable: pass `messages` to override any subset
 * of the catalogue with a product's own wording, and return `html` from an override for real links,
 * layout and branding. What must survive a rewrite is the security shape — a code is stated once,
 * and a notice of a change the user may not have made tells them how to react.
 *
 * **On what reaches the log.** A delivery failure logs the message's subject and a bounded,
 * redacted description of the error — never a body, code, address, stack, or the error object
 * itself. The distinction is load-bearing and was learnt the hard way: this file previously logged
 * the raw error on the reasoning that a channel's error is the channel's own rather than the
 * rendered body. A relay that rejects with `550` while quoting the offending content makes those
 * the same thing, and the OTP this provider had just rendered went to the log in clear text. An
 * override that puts a code into a *subject* still breaks this, because the subject is logged by
 * design — the port says so, and it is the one place a rewrite can reintroduce the leak.
 *
 * Coverage for this file is owned by the unit suite.
 *
 * @layer Provider
 */
import { Logger } from '@nestjs/common'

import type {
  IEmailProvider,
  InviteData,
  SessionInfo
} from '../interfaces/email-provider.interface'
import { logSafe } from '../utils/log-safe'
import { redactSecrets } from '../utils/redact-secrets'

/**
 * How much of a delivery error's text may reach the log line.
 *
 * A bound rather than a formatting preference. {@link redactSecrets} removes the credentials this
 * library knows it put in the body, but it cannot find one the relay re-encoded, so the second
 * lock is to refuse to relay an unbounded quantity of channel-controlled text into the log at all.
 * The diagnosis an operator actually needs — `535 authentication failed`, `ECONNREFUSED` — is
 * short and comes first; a rejection that quotes an entire message body is exactly the long one.
 */
const DELIVERY_ERROR_TEXT_LIMIT = 200

/**
 * How far down the `cause` chain the description walks.
 *
 * Chains are how a channel reports "the send failed BECAUSE the relay said". The useful context
 * is near the top, and the depth is capped so a self-referential or pathological chain cannot
 * turn one failed send into an unbounded log record.
 */
const DELIVERY_ERROR_CAUSE_DEPTH = 3

/**
 * Renders a delivery error into one bounded, secret-free line.
 *
 * Never returns the error object and never reads its `stack` or its own properties. That is the
 * point rather than an omission: a channel's error carries whatever the channel decided to put
 * in it — nodemailer, for one, hangs the server's full reply on `response` — so an allowlist of
 * `name` and `message` is the only shape whose contents this library can reason about. Each piece
 * is redacted, length-capped, and passed through {@link logSafe}, because text that came back
 * from a remote relay is untrusted input and a CR/LF in it would forge a second log record.
 *
 * @param error - Whatever the channel threw.
 * @param secrets - Credentials this message carried, which must not survive into the line.
 * @returns A single-line description safe to log.
 */
function describeDeliveryError(error: unknown, secrets: readonly string[]): string {
  const parts: string[] = []
  let current: unknown = error

  for (let depth = 0; depth < DELIVERY_ERROR_CAUSE_DEPTH && current !== undefined; depth++) {
    if (!(current instanceof Error)) {
      // A thrown non-Error has no contract at all — a string, an object, a rejected promise's
      // value. Its type is the most that can be said about it without stringifying something
      // whose `toString` is the channel's code.
      parts.push(`<non-error: ${typeof current}>`)
      break
    }

    const name = logSafe(redactSecrets(current.name, secrets))
    const message = logSafe(redactSecrets(current.message, secrets))
    // Capped once, on the composed piece, rather than on each half: two bounds let one link of
    // the chain contribute twice the intended budget, and the pair says nothing the single bound
    // does not. An empty message leaves the name standing alone rather than trailing a colon.
    const described = message === '' ? name : `${name}: ${message}`

    parts.push(described.slice(0, DELIVERY_ERROR_TEXT_LIMIT))
    current = current.cause
  }

  return parts.join(' <- ')
}

/**
 * The delivery channel {@link DefaultAuthEmailProvider} sends through.
 *
 * Narrow by design: it names only the one call the provider makes, so the provider couples to no
 * concrete mailer. `@bymax-one/nest-notification`'s `EmailService.send` satisfies it structurally
 * — its input carries these fields and more, all the extras optional — and so does any adapter
 * exposing the same shape.
 */
export interface AuthEmailSink {
  /**
   * Delivers one rendered message.
   *
   * @param input - Tenant, recipient, and the rendered subject and bodies.
   * @returns Anything; the provider ignores the result and never surfaces a rejection.
   */
  send(input: {
    /** Tenant the message is attributed to, for the channel's audit log and routing. */
    tenantId: string
    /** Recipient address. */
    to: string
    /** Subject line. */
    subject: string
    /** HTML body. */
    html: string
    /** Plain-text body. */
    text: string
  }): Promise<unknown>
}

/** One rendered message, before the tenant and recipient are attached to it. */
export interface AuthEmailMessage {
  /** Subject line. Plain text — never rendered as HTML, so it needs no escaping. */
  readonly subject: string
  /** Body as plain text. Rendered to minimal, escaped HTML by the provider when `html` is absent. */
  readonly text: string
  /**
   * Body as HTML, used verbatim when present. The provider does not escape it — an override that
   * sets this owns its own escaping, which is the point: it is the seam for a product's real
   * `<a>` links, layout and branding, none of which the escaped-text default can carry. Leave it
   * unset to have the provider render {@link text} into safe, escaped paragraphs.
   */
  readonly html?: string | undefined
}

/**
 * The copy for every message the port can send, as pure renderers keyed by event.
 *
 * Each returns an {@link AuthEmailMessage}; the provider attaches the tenant and recipient and
 * handles escaping and delivery. Override any subset through
 * {@link DefaultAuthEmailProviderOptions.messages} — an entry left unset keeps the secure default.
 */
export interface AuthEmailCatalogue {
  /** Password-reset link carrying a signed token. */
  passwordResetToken(input: { token: string; locale?: string | undefined }): AuthEmailMessage
  /** One-time code for the password-reset flow. */
  passwordResetOtp(input: { otp: string; locale?: string | undefined }): AuthEmailMessage
  /** One-time code that activates a newly registered account. */
  emailVerificationOtp(input: { otp: string; locale?: string | undefined }): AuthEmailMessage
  /** Notice that the account password changed (NIST SP 800-63B §4.6). */
  passwordChanged(input: { locale?: string | undefined }): AuthEmailMessage
  /** Code confirming ownership of an address the user is moving to. */
  emailChangeVerification(input: { token: string; locale?: string | undefined }): AuthEmailMessage
  /** Notice to the previous address that the account's email moved. */
  emailChanged(input: {
    oldEmail: string
    newEmail: string
    locale?: string | undefined
  }): AuthEmailMessage
  /** Notice that a second factor was added. */
  mfaEnabled(input: { locale?: string | undefined }): AuthEmailMessage
  /** Notice that a second factor was removed. */
  mfaDisabled(input: { locale?: string | undefined }): AuthEmailMessage
  /** Security alert about a newly established session. */
  newSessionAlert(input: {
    sessionInfo: SessionInfo
    locale?: string | undefined
  }): AuthEmailMessage
  /** Invitation to join a tenant. */
  invitation(input: { invite: InviteData; locale?: string | undefined }): AuthEmailMessage
}

/** How the provider reacts to a delivery failure. */
export type DeliveryErrorPolicy = 'swallow' | 'rethrow'

/** Options for {@link DefaultAuthEmailProvider}. */
export interface DefaultAuthEmailProviderOptions {
  /**
   * Per-event copy overrides. Any renderer set here replaces the default for that message; every
   * unset event keeps its secure default. The escaping and delivery-error policy apply to
   * overrides too.
   */
  readonly messages?: Partial<AuthEmailCatalogue>

  /**
   * What to do when the channel rejects a send. `'swallow'` (the default) logs the failure and
   * resolves, so a down channel never turns a notification into a failed user request. `'rethrow'`
   * logs and then re-throws, restoring the throw the two flows that react to one expect —
   * `PasswordResetService` deletes an undelivered reset token early, and `EmailChangeService` lets
   * a failed verification send surface rather than reporting "sent". The trade is symmetric: under
   * `'rethrow'` a channel outage also fails MFA, invitation and the other awaited sends. Pick the
   * failure mode the deployment's channel reliability warrants.
   *
   * **`'rethrow'` hands you an error that may contain the credential.** The provider's own log
   * line is redacted, but what it re-throws is the channel's original error, unaltered — because
   * a caller that opted into this policy did so to branch on the channel's codes, and a laundered
   * replacement would take those away. A relay that rejects by quoting the message body puts the
   * OTP or invitation token into that error, so whatever catches it must not log it raw. Run
   * {@link redactSecrets} over the text first, or send it through a pipeline that redacts. This
   * is the one credential this library cannot contain on your behalf.
   */
  readonly onDeliveryError?: DeliveryErrorPolicy
}

/** How long a verification or reset code stays valid, stated in the message that carries it. */
const CODE_VALIDITY_TEXT = 'It expires shortly, so use it soon.'

/** Closing line on every message announcing a change the recipient may not have made. */
const UNEXPECTED_CHANGE_TEXT =
  'If this was not you, secure your account immediately: change your password and sign out of every session.'

/**
 * The built-in copy, security shape first and wording second.
 *
 * Each entry is a pure function of its inputs, which is what makes an override a drop-in
 * replacement and keeps the copy testable without a provider around it.
 */
const DEFAULT_MESSAGES: AuthEmailCatalogue = {
  passwordResetToken: ({ token }) => ({
    subject: 'Reset your password',
    text: `Use this token to reset your password: ${token}\n\n${CODE_VALIDITY_TEXT}\n\nIf you did not ask to reset your password, ignore this message and nothing will change.`
  }),
  passwordResetOtp: ({ otp }) => ({
    subject: 'Your password reset code',
    text: `Your password reset code is ${otp}.\n\n${CODE_VALIDITY_TEXT}\n\nIf you did not ask to reset your password, ignore this message and nothing will change.`
  }),
  emailVerificationOtp: ({ otp }) => ({
    subject: 'Verify your email address',
    text: `Your verification code is ${otp}.\n\n${CODE_VALIDITY_TEXT}\n\nIf you did not create an account, ignore this message.`
  }),
  passwordChanged: () => ({
    subject: 'Your password was changed',
    text: `The password on your account was changed.\n\n${UNEXPECTED_CHANGE_TEXT}`
  }),
  emailChangeVerification: ({ token }) => ({
    subject: 'Confirm your new email address',
    text: `Your confirmation code is ${token}.\n\n${CODE_VALIDITY_TEXT}\n\nIf you did not ask to change your email address, ignore this message.`
  }),
  emailChanged: ({ newEmail }) => ({
    subject: 'Your email address was changed',
    text: `The email address on your account was changed to ${newEmail}, and this address no longer signs in to it.\n\n${UNEXPECTED_CHANGE_TEXT}`
  }),
  mfaEnabled: () => ({
    subject: 'Two-factor authentication is on',
    text: `Two-factor authentication was enabled on your account.\n\n${UNEXPECTED_CHANGE_TEXT}`
  }),
  mfaDisabled: () => ({
    subject: 'Two-factor authentication is off',
    text: `Two-factor authentication was disabled on your account.\n\n${UNEXPECTED_CHANGE_TEXT}`
  }),
  newSessionAlert: ({ sessionInfo }) => ({
    subject: 'New sign-in to your account',
    text: `A new session was started on your account.\n\nDevice: ${sessionInfo.device}\nIP: ${sessionInfo.ip}\nSession: ${sessionInfo.sessionHash}\n\n${UNEXPECTED_CHANGE_TEXT}`
  }),
  invitation: ({ invite }) => ({
    subject: `${invite.inviterName} invited you to ${invite.tenantName}`,
    text: `${invite.inviterName} invited you to join ${invite.tenantName}.\n\nUse this token to accept: ${invite.inviteToken}\n\nIt expires on ${invite.expiresAt.toISOString()}.\n\nIf you were not expecting this invitation, ignore this message.`
  })
}

/**
 * Escapes the five characters that can change the structure of an HTML document.
 *
 * Not optional: some bodies carry values the sender chose — an inviter's display name, a tenant's
 * name, the address an account moved to — and an unescaped `<` turns a message into markup a mail
 * client renders: a fake link, a hidden block, or a rewritten instruction next to a real code.
 *
 * @param value - Text to place inside an element.
 * @returns The same text, safe to interpolate.
 */
function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

/**
 * Renders a plain-text body as the minimal HTML the channel also wants: one escaped paragraph per
 * blank-line-separated block, with a single newline inside a block becoming a `<br>`. Without the
 * `<br>`, HTML's whitespace collapsing would fold a body like the new-session alert — where device,
 * IP and session sit on their own lines — back onto one line, so the HTML would say something the
 * plain-text body did not. Deliberately not a template engine: a product that needs real layout
 * returns `html` from its override instead.
 *
 * @param text - Plain-text body.
 * @returns The body as escaped HTML paragraphs, intra-paragraph newlines preserved as `<br>`.
 */
function toHtml(text: string): string {
  return text
    .split('\n\n')
    .map((paragraph) => `<p>${escapeHtml(paragraph).replace(/\n/g, '<br>')}</p>`)
    .join('\n')
}

/**
 * Strips CR and LF from a subject line.
 *
 * A subject is a single email header, and a header ends at the first newline. Caller-chosen text
 * reaches the subject — an inviter's name, a tenant's name — so a `\r` or `\n` smuggled into one
 * would otherwise let a channel that builds headers by concatenation read the rest of the value as
 * additional headers (a hidden `Bcc:`), or reject the message outright. Newlines carry no meaning
 * in a subject, so they are removed rather than escaped. The provider applies this to every subject,
 * default or overridden, because the sink is a generic port that makes no such promise itself.
 *
 * @param subject - The rendered subject line.
 * @returns The subject with each run of CR/LF replaced by a single space.
 */
function sanitizeSubject(subject: string): string {
  return subject.replace(/[\r\n]+/g, ' ')
}

/**
 * Default {@link IEmailProvider} over a {@link AuthEmailSink} delivery channel.
 *
 * Wire it by binding the auth email-provider token to a factory that hands it the channel:
 *
 * ```typescript
 * {
 *   provide: BYMAX_AUTH_EMAIL_PROVIDER,
 *   useFactory: (email: EmailService) => new DefaultAuthEmailProvider(email),
 *   inject: [EmailService]
 * }
 * ```
 *
 * No method throws on a delivery failure — the library awaits most of these calls (enabling MFA,
 * sending an invitation, confirming an address change), so a channel that is down would turn each
 * into a failed request over a message that is a notification rather than the operation itself.
 * The failure is logged and the flow continues.
 *
 * That choice has a cost worth stating, because two flows react to a *throw* from the port. A
 * reset-token send that rejects lets `PasswordResetService` delete the stored token early rather
 * than leave it to its TTL; and `EmailChangeService` awaits the verification send before it records
 * "verification sent". Under the default both degrade gracefully rather than break: the reset token
 * still expires at its TTL and was never delivered to anyone, and the change still requires the
 * verification the recipient never got, so it cannot complete. A deployment that wants the throw
 * back on those flows constructs the provider with `{ onDeliveryError: 'rethrow' }`, accepting that
 * an outage then also fails the awaited sends (MFA, invitation). The default optimizes for the
 * common case: a transient channel outage must not fail the user's action.
 */
export class DefaultAuthEmailProvider implements IEmailProvider {
  /** Records a delivery this provider swallowed, so a silent channel is still visible somewhere. */
  private readonly logger = new Logger(DefaultAuthEmailProvider.name)

  /** The copy in effect: the defaults, with any provided overrides layered on top. */
  private readonly messages: AuthEmailCatalogue

  /** Whether a rejected send is re-thrown after logging; `false` (swallow) unless asked otherwise. */
  private readonly rethrowOnError: boolean

  /**
   * @param sink - The delivery channel to send through.
   * @param options - Optional copy overrides and delivery-error policy.
   */
  public constructor(
    private readonly sink: AuthEmailSink,
    options?: DefaultAuthEmailProviderOptions
  ) {
    this.messages = { ...DEFAULT_MESSAGES, ...options?.messages }
    this.rethrowOnError = options?.onDeliveryError === 'rethrow'
  }

  /** @inheritdoc */
  public async sendPasswordResetToken(
    tenantId: string,
    email: string,
    token: string,
    locale?: string
  ): Promise<void> {
    await this.deliver(tenantId, email, this.messages.passwordResetToken({ token, locale }), [
      token
    ])
  }

  /** @inheritdoc */
  public async sendPasswordResetOtp(
    tenantId: string,
    email: string,
    otp: string,
    locale?: string
  ): Promise<void> {
    await this.deliver(tenantId, email, this.messages.passwordResetOtp({ otp, locale }), [otp])
  }

  /** @inheritdoc */
  public async sendEmailVerificationOtp(
    tenantId: string,
    email: string,
    otp: string,
    locale?: string
  ): Promise<void> {
    await this.deliver(tenantId, email, this.messages.emailVerificationOtp({ otp, locale }), [otp])
  }

  /** @inheritdoc */
  public async sendPasswordChangedNotification(
    tenantId: string,
    email: string,
    locale?: string
  ): Promise<void> {
    await this.deliver(tenantId, email, this.messages.passwordChanged({ locale }))
  }

  /** @inheritdoc */
  public async sendEmailChangeVerification(
    tenantId: string,
    newEmail: string,
    token: string,
    locale?: string
  ): Promise<void> {
    await this.deliver(
      tenantId,
      newEmail,
      this.messages.emailChangeVerification({ token, locale }),
      [token]
    )
  }

  /** @inheritdoc */
  public async sendEmailChangedNotification(
    tenantId: string,
    oldEmail: string,
    newEmail: string,
    locale?: string
  ): Promise<void> {
    await this.deliver(
      tenantId,
      oldEmail,
      this.messages.emailChanged({ oldEmail, newEmail, locale })
    )
  }

  /** @inheritdoc */
  public async sendMfaEnabledNotification(
    tenantId: string,
    email: string,
    locale?: string
  ): Promise<void> {
    await this.deliver(tenantId, email, this.messages.mfaEnabled({ locale }))
  }

  /** @inheritdoc */
  public async sendMfaDisabledNotification(
    tenantId: string,
    email: string,
    locale?: string
  ): Promise<void> {
    await this.deliver(tenantId, email, this.messages.mfaDisabled({ locale }))
  }

  /** @inheritdoc */
  public async sendNewSessionAlert(
    tenantId: string,
    email: string,
    sessionInfo: SessionInfo,
    locale?: string
  ): Promise<void> {
    await this.deliver(tenantId, email, this.messages.newSessionAlert({ sessionInfo, locale }))
  }

  /** @inheritdoc */
  public async sendInvitation(
    tenantId: string,
    email: string,
    inviteData: InviteData,
    locale?: string
  ): Promise<void> {
    await this.deliver(tenantId, email, this.messages.invitation({ invite: inviteData, locale }), [
      inviteData.inviteToken
    ])
  }

  /**
   * Renders the body to HTML (unless the message already carries its own), hands the message to the
   * channel, and swallows any delivery error.
   *
   * @param tenantId - Tenant the message is attributed to.
   * @param to - Recipient address.
   * @param message - The rendered subject and body, and optionally its own HTML.
   * @param secrets - Credentials rendered into this message. A channel that rejects by quoting
   *   the body puts them into the error it raises, so they are named here to be stripped from the
   *   log line. Messages carrying no credential pass nothing.
   */
  private async deliver(
    tenantId: string,
    to: string,
    message: AuthEmailMessage,
    // Stryker disable next-line ArrayDeclaration: filling this default with any value is
    // equivalent. Redaction searches the error text for each entry, so a default of
    // `["Stryker was here"]` differs from `[]` only for an error whose message contains that
    // literal — nothing a test could produce except by asserting on the marker itself. Dropping
    // the default and passing `[]` at the six credential-free call sites moves the same
    // equivalence to six places instead of one.
    secrets: readonly string[] = []
  ): Promise<void> {
    // Stripped once, then used for both the header and the log line: a subject is a single header,
    // and a smuggled CR/LF must reach neither the channel (header injection) nor the logger.
    const subject = sanitizeSubject(message.subject)
    try {
      await this.sink.send({
        tenantId,
        to,
        subject,
        html: message.html ?? toHtml(message.text),
        text: message.text
      })
    } catch (error: unknown) {
      // The subject names the message; the address is deliberately left out, because a log line
      // reaches a wider audience than the inbox it was going to.
      //
      // The error is NOT passed to the logger. This line used to read `logger.error(msg, error)`
      // on the reasoning that "the error is the channel's own, not the rendered body" — which a
      // measurement against a real relay disproved. A policy or DLP relay rejects with `550` and
      // QUOTES THE OFFENDING CONTENT, so the channel's own error is the rendered body, and for
      // this provider that body is a live OTP or invitation token. It went to the operator's log
      // in clear text, valid until expiry. `describeDeliveryError` is what replaces it: an
      // allowlist of `name` and `message`, each redacted, bounded and control-character stripped.
      this.logger.error(
        `delivery failed for "${subject}": ${describeDeliveryError(error, secrets)}`
      )
      // Log first, then honour the configured policy: a deployment on 'rethrow' wants the failure
      // to reach the caller that reacts to it, not to be absorbed here.
      //
      // The error rethrown here is the ORIGINAL and may still carry the quoted body — deliberately,
      // because a caller that opted into 'rethrow' did so to inspect the failure, and handing it a
      // laundered error would take away the codes it branches on. That makes the credential the
      // caller's to contain: log this through a pipeline that redacts, or run `redactSecrets` on
      // it, which is exported for exactly this. See the option's own documentation.
      if (this.rethrowOnError) {
        throw error
      }
    }
  }
}
