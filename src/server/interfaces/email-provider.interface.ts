/**
 * Email provider plugin contract for @bymax-one/nest-auth.
 *
 * Defines the interface that any email delivery implementation must satisfy.
 * The library never imports a concrete mailer — consumers provide their own
 * adapter (e.g. Resend, SendGrid, Nodemailer) that implements `IEmailProvider`
 * and inject it via the NestJS DI token.
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
  /** Fully-qualified URL the invitee must visit to accept the invitation. */
  inviteUrl: string
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
   * @param email - Recipient's email address.
   * @param token - Signed, opaque reset token. Never log or expose this value.
   * @param locale - BCP 47 locale tag for email language (e.g. `'en'`, `'pt-BR'`).
   */
  sendPasswordResetToken(email: string, token: string, locale?: string): Promise<void>

  /**
   * Sends a one-time password (OTP) code for password reset to the user.
   *
   * Called when the user requests a password reset via the OTP-based flow.
   * The email should display the numeric/alphanumeric code clearly and state
   * its expiry time.
   *
   * @param email - Recipient's email address.
   * @param otp - Short-lived OTP code. Never log or expose this value.
   * @param locale - BCP 47 locale tag for email language (e.g. `'en'`, `'pt-BR'`).
   */
  sendPasswordResetOtp(email: string, otp: string, locale?: string): Promise<void>

  /**
   * Sends an OTP code to verify the user's email address during registration or
   * email-change flows.
   *
   * Called immediately after account creation (when email verification is enabled)
   * or when the user requests a new verification code.
   *
   * @param email - Recipient's email address to be verified.
   * @param otp - Short-lived OTP code for verification. Never log or expose this value.
   * @param locale - BCP 47 locale tag for email language (e.g. `'en'`, `'pt-BR'`).
   */
  sendEmailVerificationOtp(email: string, otp: string, locale?: string): Promise<void>

  /**
   * Notifies the user that multi-factor authentication (MFA) has been enabled on
   * their account.
   *
   * Called immediately after a successful MFA enrollment. The email serves as a
   * security alert — if the user did not initiate this change, they should be
   * directed to contact support or reset their credentials.
   *
   * @param email - Recipient's email address.
   * @param locale - BCP 47 locale tag for email language (e.g. `'en'`, `'pt-BR'`).
   */
  sendMfaEnabledNotification(email: string, locale?: string): Promise<void>

  /**
   * Notifies the user that multi-factor authentication (MFA) has been disabled on
   * their account.
   *
   * Called immediately after MFA is turned off. The email serves as a security
   * alert — if the user did not initiate this change, they should be directed to
   * contact support or reset their credentials immediately.
   *
   * @param email - Recipient's email address.
   * @param locale - BCP 47 locale tag for email language (e.g. `'en'`, `'pt-BR'`).
   */
  sendMfaDisabledNotification(email: string, locale?: string): Promise<void>

  /**
   * Sends a security alert when a new session is detected from an unrecognized
   * device or location.
   *
   * Called after a successful login when new-session detection is enabled. The
   * email should display the device description, IP address, and session hash so
   * the user can identify whether the login was authorized.
   *
   * @param email - Recipient's email address.
   * @param sessionInfo - Device, IP, and session identifier details.
   * @param locale - BCP 47 locale tag for email language (e.g. `'en'`, `'pt-BR'`).
   */
  sendNewSessionAlert(email: string, sessionInfo: SessionInfo, locale?: string): Promise<void>

  /**
   * Sends a tenant invitation email to a prospective member.
   *
   * Called when an admin or owner invites a new user to join their workspace.
   * The email should prominently display the inviter's name, the tenant name,
   * the accept URL, and the expiry date/time.
   *
   * @param email - Recipient's email address (the invitee).
   * @param inviteData - Invitation metadata required to render the email.
   * @param locale - BCP 47 locale tag for email language (e.g. `'en'`, `'pt-BR'`).
   */
  sendInvitation(email: string, inviteData: InviteData, locale?: string): Promise<void>
}
