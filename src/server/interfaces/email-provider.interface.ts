/**
 * Email provider plugin contract for @bymax-one/nest-auth.
 *
 * Defines the interface that any email delivery implementation must satisfy.
 * The library never imports a concrete mailer — consumers provide their own
 * adapter (e.g. Resend, SendGrid, Nodemailer) that implements `IEmailProvider`
 * and inject it via the NestJS DI token.
 *
 * @layer Interface
 */

/**
 * Contextual information about a new user session sent in security alerts.
 */
export interface SessionInfo {
  /** Human-readable description of the device or browser (e.g. "Chrome on macOS"). */
  device: string

  /**
   * IP address from which the session was established.
   *
   * @remarks
   * In privacy-sensitive jurisdictions (GDPR, LGPD), IP addresses may constitute
   * personal data. Consider truncating or masking the last octet of IPv4 addresses
   * (e.g. `'192.168.1.x'`) before populating this field when passing to a
   * third-party email provider.
   *
   * This value must be extracted using a trusted proxy configuration (e.g. Express
   * `app.set('trust proxy', 1)`). Never read directly from `X-Forwarded-For`
   * without proxy trust configured — false IPs undermine new-session alerting.
   */
  ip: string

  /**
   * A truncated or hashed representation of the session identifier.
   * Must never expose the raw session token — use a short hash suitable for
   * display purposes only (e.g. first 8 chars of SHA-256 hex).
   */
  sessionHash: string
}

/**
 * Data required to render and send a tenant invitation email.
 */
export interface InviteData {
  /** Display name of the user who sent the invitation. */
  inviterName: string
  /** Name of the tenant (workspace/organization) the invitee is joining. */
  tenantName: string
  /**
   * Raw invitation token (64 hex chars) that the consumer must embed into an accept URL.
   * The `IEmailProvider` implementation is responsible for constructing the full URL
   * (e.g. `https://app.example.com/accept-invite?token=<inviteToken>`).
   */
  inviteToken: string
  /** UTC timestamp after which the invitation link is no longer valid. */
  expiresAt: Date
}

/**
 * Contract for transactional email delivery in @bymax-one/nest-auth.
 *
 * Each method corresponds to a specific auth event. Implementations are
 * responsible for template rendering, localization, and delivery. The library
 * never calls any method directly — it relies on the concrete adapter injected
 * by the consumer.
 *
 * @remarks
 * - All methods return `Promise<void>`. Delivery errors should be handled by
 *   the implementation (retry logic, dead-letter queues, etc.).
 * - The optional `locale` parameter enables per-user language selection.
 *   Implementations should fall back to a default locale when omitted.
 * - Never log email content, tokens, OTPs, or passwords inside implementations.
 */
export interface IEmailProvider {
  /**
   * Sends a password-reset link containing a signed token to the user.
   *
   * Called when the user requests a password reset via the token-based flow.
   * The email should contain a time-limited URL with the token embedded as a
   * query parameter (e.g. `/reset-password?token=...`).
   *
   * @param tenantId - The tenant the account belongs to, so a multi-tenant provider can
   *   attribute and route the message. Resolved by the auth flow; a single-tenant provider ignores it.
   * @param email - Recipient's email address.
   * @param token - Signed, opaque reset token. Never log or expose this value.
   * @param locale - BCP 47 locale tag for email language (e.g. `'en'`, `'pt-BR'`).
   */
  sendPasswordResetToken(
    tenantId: string,
    email: string,
    token: string,
    locale?: string
  ): Promise<void>

  /**
   * Sends a one-time password (OTP) code for password reset to the user.
   *
   * Called when the user requests a password reset via the OTP-based flow.
   * The email should display the numeric/alphanumeric code clearly and state
   * its expiry time.
   *
   * @param tenantId - The tenant the account belongs to, so a multi-tenant provider can
   *   attribute and route the message. Resolved by the auth flow; a single-tenant provider ignores it.
   * @param email - Recipient's email address.
   * @param otp - Short-lived OTP code. Never log or expose this value.
   * @param locale - BCP 47 locale tag for email language (e.g. `'en'`, `'pt-BR'`).
   */
  sendPasswordResetOtp(tenantId: string, email: string, otp: string, locale?: string): Promise<void>

  /**
   * Sends an OTP code to verify the user's email address during registration or
   * email-change flows.
   *
   * Called immediately after account creation (when email verification is enabled)
   * or when the user requests a new verification code.
   *
   * @param tenantId - The tenant the account belongs to, so a multi-tenant provider can
   *   attribute and route the message. Resolved by the auth flow; a single-tenant provider ignores it.
   * @param email - Recipient's email address to be verified.
   * @param otp - Short-lived OTP code for verification. Never log or expose this value.
   * @param locale - BCP 47 locale tag for email language (e.g. `'en'`, `'pt-BR'`).
   */
  sendEmailVerificationOtp(
    tenantId: string,
    email: string,
    otp: string,
    locale?: string
  ): Promise<void>

  /**
   * Notifies the user that the password on their account has changed.
   *
   * Called after a completed password change *and* after a completed password reset. Both are
   * credential-binding events, and NIST SP 800-63B §4.6 requires the subscriber to be notified
   * through a channel independent of the transaction that made the change. The classic
   * takeover starts with a compromised mailbox: the attacker triggers a reset, completes it,
   * and deletes the mail. This notice is what turns "the victim finds out days later, at a
   * failed login" into "the victim finds out now" — and it is the one credential change this
   * interface used to stay silent about while announcing every MFA change unprompted.
   *
   * **Optional.** Declared with `?` so an existing provider keeps compiling; the library calls
   * it when present and logs at debug when it is not, rather than failing a password change
   * over a missing notification.
   *
   * @param tenantId - The tenant the account belongs to, so a multi-tenant provider can
   *   attribute and route the message. Resolved by the auth flow; a single-tenant provider ignores it.
   * @param email - Recipient's email address.
   * @param locale - BCP 47 locale tag for email language (e.g. `'en'`, `'pt-BR'`).
   */
  sendPasswordChangedNotification?(tenantId: string, email: string, locale?: string): Promise<void>

  /**
   * Sends the address-change verification link to the **new** address.
   *
   * The token goes here and nowhere else: receiving it is what proves the requester controls
   * the address before it becomes the account's. The old address gets no token — only the
   * notification below, and only once the change has actually happened.
   *
   * Optional on the interface so an existing consumer keeps compiling, but the flow refuses
   * to mint a token when it is absent rather than writing one nobody will ever receive.
   *
   * @param tenantId - The tenant the account belongs to, so a multi-tenant provider can
   *   attribute and route the message. Resolved by the auth flow; a single-tenant provider ignores it.
   * @param newEmail - The address being moved to.
   * @param token - The raw single-use token. The provider builds the confirmation URL.
   * @param locale - Optional locale for the template.
   */
  sendEmailChangeVerification?(
    tenantId: string,
    newEmail: string,
    token: string,
    locale?: string
  ): Promise<void>

  /**
   * Notifies the **old** address that the account's address has changed.
   *
   * NIST SP 800-63B §4.6 asks for notification of a credential change, and the address is the
   * recovery credential: someone who moves it can then drive a password reset to a mailbox
   * the owner does not read. This message is what puts that in front of the owner while they
   * still control the address it arrives at.
   *
   * Fire-and-forget — a delivery failure does not roll back a change the user asked for and
   * has already proven.
   *
   * @param tenantId - The tenant the account belongs to, so a multi-tenant provider can
   *   attribute and route the message. Resolved by the auth flow; a single-tenant provider ignores it.
   * @param oldEmail - The address the account is leaving.
   * @param newEmail - The address it moved to, so the notice can say what happened.
   * @param locale - Optional locale for the template.
   */
  sendEmailChangedNotification?(
    tenantId: string,
    oldEmail: string,
    newEmail: string,
    locale?: string
  ): Promise<void>

  /**
   * Notifies the user that multi-factor authentication (MFA) has been enabled on
   * their account.
   *
   * Called immediately after a successful MFA enrollment. The email serves as a
   * security alert — if the user did not initiate this change, they should be
   * directed to contact support or reset their credentials.
   *
   * @param tenantId - The tenant the account belongs to, so a multi-tenant provider can
   *   attribute and route the message. Resolved by the auth flow; a single-tenant provider ignores it.
   * @param email - Recipient's email address.
   * @param locale - BCP 47 locale tag for email language (e.g. `'en'`, `'pt-BR'`).
   */
  sendMfaEnabledNotification(tenantId: string, email: string, locale?: string): Promise<void>

  /**
   * Notifies the user that multi-factor authentication (MFA) has been disabled on
   * their account.
   *
   * Called immediately after MFA is turned off. The email serves as a security
   * alert — if the user did not initiate this change, they should be directed to
   * contact support or reset their credentials immediately.
   *
   * @param tenantId - The tenant the account belongs to, so a multi-tenant provider can
   *   attribute and route the message. Resolved by the auth flow; a single-tenant provider ignores it.
   * @param email - Recipient's email address.
   * @param locale - BCP 47 locale tag for email language (e.g. `'en'`, `'pt-BR'`).
   */
  sendMfaDisabledNotification(tenantId: string, email: string, locale?: string): Promise<void>

  /**
   * Sends a security alert about a newly established session.
   *
   * **This library never calls it.** The method is optional, and it is here as a typed
   * signature for you to call from the {@link IAuthHooks.onNewSession} hook — which the
   * library does fire, on every session it creates, with the same {@link SessionInfo} this
   * takes.
   *
   * The alert deliberately does not live inside the library, because the library cannot send
   * it well. Without device recognition it fires on *every* login, and an alert that arrives
   * on every login is one the user learns to dismiss — at which point the control has stopped
   * existing while still appearing to be in place. Recognizing a device means keeping a
   * per-user device history, and the consumer already has one (or can key it to their own
   * user record); the library would have to invent that state in the Redis keyspace it shares
   * with rust-auth, which is a contract change to solve a problem the caller is better placed
   * to solve.
   *
   * So: decide in your `onNewSession` hook whether the session is worth alerting about, and
   * call this when it is.
   *
   * @param tenantId - The tenant the account belongs to, so a multi-tenant provider can
   *   attribute and route the message. Resolved by the auth flow; a single-tenant provider ignores it.
   * @param email - Recipient's email address.
   * @param sessionInfo - Device, IP, and session identifier details.
   * @param locale - BCP 47 locale tag for email language (e.g. `'en'`, `'pt-BR'`).
   */
  sendNewSessionAlert?(
    tenantId: string,
    email: string,
    sessionInfo: SessionInfo,
    locale?: string
  ): Promise<void>

  /**
   * Sends a tenant invitation email to a prospective member.
   *
   * Called when an admin or owner invites a new user to join their workspace.
   * The email should prominently display the inviter's name, the tenant name,
   * the accept URL, and the expiry date/time.
   *
   * @param tenantId - The tenant the account belongs to, so a multi-tenant provider can
   *   attribute and route the message. Resolved by the auth flow; a single-tenant provider ignores it.
   * @param email - Recipient's email address (the invitee).
   * @param inviteData - Invitation metadata required to render the email.
   * @param locale - BCP 47 locale tag for email language (e.g. `'en'`, `'pt-BR'`).
   */
  sendInvitation(
    tenantId: string,
    email: string,
    inviteData: InviteData,
    locale?: string
  ): Promise<void>
}
