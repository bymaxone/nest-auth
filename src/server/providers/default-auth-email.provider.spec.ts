import { Logger } from '@nestjs/common'

import type { InviteData, SessionInfo } from '../interfaces/email-provider.interface'
import {
  DefaultAuthEmailProvider,
  type AuthEmailSink,
  type AuthEmailCatalogue
} from './default-auth-email.provider'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** The two shared closing lines, mirrored here so the expected bodies below are exact. */
const CODE_VALIDITY = 'It expires shortly, so use it soon.'
const UNEXPECTED =
  'If this was not you, secure your account immediately: change your password and sign out of every session.'

/** Escapes exactly as the provider does, so expected HTML is computed independently, not copied. */
function esc(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

/** Renders the minimal HTML the provider is expected to produce for a plain-text body. */
function html(text: string): string {
  return text
    .split('\n\n')
    .map((paragraph) => `<p>${esc(paragraph)}</p>`)
    .join('\n')
}

/** A sink whose single `send` is a spy, so every delivery can be inspected. */
function makeSink(): { send: jest.Mock<Promise<unknown>, [Parameters<AuthEmailSink['send']>[0]]> } {
  return { send: jest.fn<Promise<unknown>, [Parameters<AuthEmailSink['send']>[0]]>() }
}

/** The single argument passed to the sink on the most recent send. */
function lastSend(sink: ReturnType<typeof makeSink>): Parameters<AuthEmailSink['send']>[0] {
  const call = sink.send.mock.calls.at(-1)
  if (!call) throw new Error('sink.send was not called')
  return call[0]
}

const INVITE: InviteData = {
  inviterName: 'Ada',
  tenantName: 'Acme',
  inviteToken: 'a'.repeat(64),
  expiresAt: new Date('2026-12-31T23:59:59.000Z')
}

const SESSION: SessionInfo = {
  device: 'Chrome on macOS',
  ip: '203.0.113.7',
  sessionHash: 'deadbeef'
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('DefaultAuthEmailProvider', () => {
  let sink: ReturnType<typeof makeSink>
  let provider: DefaultAuthEmailProvider
  let errorSpy: jest.SpyInstance

  beforeEach(() => {
    sink = makeSink()
    sink.send.mockResolvedValue({ messageId: 'mid' })
    provider = new DefaultAuthEmailProvider(sink)
    errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  // Every message carries the tenant and recipient the port handed it, plus both a plain-text and
  // an HTML rendering of the body. Asserting the whole object pins the copy (so a mutated subject
  // or body is caught) and the HTML rendering together.

  // Scenario: password-reset token. Rule: the token is stated once in the body and never linked to.
  it('sends the password-reset token with the tenant, recipient and full copy', async () => {
    await provider.sendPasswordResetToken('tenant-1', 'user@example.com', 'TOK123')
    const text = `Use this token to reset your password: TOK123\n\n${CODE_VALIDITY}\n\nIf you did not ask to reset your password, ignore this message and nothing will change.`
    expect(sink.send).toHaveBeenCalledWith({
      tenantId: 'tenant-1',
      to: 'user@example.com',
      subject: 'Reset your password',
      html: html(text),
      text
    })
  })

  // Scenario: password-reset OTP. Rule: the code is stated once and its expiry is named.
  it('sends the password-reset OTP with the tenant, recipient and full copy', async () => {
    await provider.sendPasswordResetOtp('tenant-1', 'user@example.com', '654321')
    const text = `Your password reset code is 654321.\n\n${CODE_VALIDITY}\n\nIf you did not ask to reset your password, ignore this message and nothing will change.`
    expect(sink.send).toHaveBeenCalledWith({
      tenantId: 'tenant-1',
      to: 'user@example.com',
      subject: 'Your password reset code',
      html: html(text),
      text
    })
  })

  // Scenario: account-activation OTP. Rule: the verification code is stated once.
  it('sends the email-verification OTP with the tenant, recipient and full copy', async () => {
    await provider.sendEmailVerificationOtp('tenant-1', 'user@example.com', '112233')
    const text = `Your verification code is 112233.\n\n${CODE_VALIDITY}\n\nIf you did not create an account, ignore this message.`
    expect(sink.send).toHaveBeenCalledWith({
      tenantId: 'tenant-1',
      to: 'user@example.com',
      subject: 'Verify your email address',
      html: html(text),
      text
    })
  })

  // Scenario: password-changed notice (NIST SP 800-63B §4.6). Rule: it tells the user how to react.
  it('sends the password-changed notice with the tenant, recipient and full copy', async () => {
    await provider.sendPasswordChangedNotification('tenant-1', 'user@example.com')
    const text = `The password on your account was changed.\n\n${UNEXPECTED}`
    expect(sink.send).toHaveBeenCalledWith({
      tenantId: 'tenant-1',
      to: 'user@example.com',
      subject: 'Your password was changed',
      html: html(text),
      text
    })
  })

  // Scenario: address-change confirmation. Rule: the token goes to the NEW address, nowhere else.
  it('sends the email-change verification to the new address with full copy', async () => {
    await provider.sendEmailChangeVerification('tenant-1', 'new@example.com', 'CONF99')
    const text = `Your confirmation code is CONF99.\n\n${CODE_VALIDITY}\n\nIf you did not ask to change your email address, ignore this message.`
    expect(sink.send).toHaveBeenCalledWith({
      tenantId: 'tenant-1',
      to: 'new@example.com',
      subject: 'Confirm your new email address',
      html: html(text),
      text
    })
  })

  // Scenario: address-changed notice. Rule: it goes to the PREVIOUS address and names the new one.
  it('sends the email-changed notice to the old address and names the new one', async () => {
    await provider.sendEmailChangedNotification('tenant-1', 'old@example.com', 'new@example.com')
    const text = `The email address on your account was changed to new@example.com, and this address no longer signs in to it.\n\n${UNEXPECTED}`
    expect(sink.send).toHaveBeenCalledWith({
      tenantId: 'tenant-1',
      to: 'old@example.com',
      subject: 'Your email address was changed',
      html: html(text),
      text
    })
  })

  // Scenario: MFA enabled. Rule: an added factor is announced with react-if-not-you guidance.
  it('sends the MFA-enabled notice with the tenant, recipient and full copy', async () => {
    await provider.sendMfaEnabledNotification('tenant-1', 'user@example.com')
    const text = `Two-factor authentication was enabled on your account.\n\n${UNEXPECTED}`
    expect(sink.send).toHaveBeenCalledWith({
      tenantId: 'tenant-1',
      to: 'user@example.com',
      subject: 'Two-factor authentication is on',
      html: html(text),
      text
    })
  })

  // Scenario: MFA disabled. Rule: removing a factor is the one notice that reaches the real owner.
  it('sends the MFA-disabled notice with the tenant, recipient and full copy', async () => {
    await provider.sendMfaDisabledNotification('tenant-1', 'user@example.com')
    const text = `Two-factor authentication was disabled on your account.\n\n${UNEXPECTED}`
    expect(sink.send).toHaveBeenCalledWith({
      tenantId: 'tenant-1',
      to: 'user@example.com',
      subject: 'Two-factor authentication is off',
      html: html(text),
      text
    })
  })

  // Scenario: new-session alert. Rule: the device, IP and session identifier are stated for the user.
  it('sends the new-session alert with the session details and full copy', async () => {
    await provider.sendNewSessionAlert('tenant-1', 'user@example.com', SESSION)
    const text = `A new session was started on your account.\n\nDevice: ${SESSION.device}\nIP: ${SESSION.ip}\nSession: ${SESSION.sessionHash}\n\n${UNEXPECTED}`
    expect(sink.send).toHaveBeenCalledWith({
      tenantId: 'tenant-1',
      to: 'user@example.com',
      subject: 'New sign-in to your account',
      html: html(text),
      text
    })
  })

  // Scenario: invitation. Rule: the inviter, tenant, token and expiry are all stated.
  it('sends the invitation with the inviter, tenant, token and expiry', async () => {
    await provider.sendInvitation('tenant-1', 'invitee@example.com', INVITE)
    const text = `Ada invited you to join Acme.\n\nUse this token to accept: ${INVITE.inviteToken}\n\nIt expires on 2026-12-31T23:59:59.000Z.\n\nIf you were not expecting this invitation, ignore this message.`
    expect(sink.send).toHaveBeenCalledWith({
      tenantId: 'tenant-1',
      to: 'invitee@example.com',
      subject: 'Ada invited you to Acme',
      html: html(text),
      text
    })
  })

  // ---------------------------------------------------------------------------
  // HTML escaping
  // ---------------------------------------------------------------------------

  // Caller-chosen text (an inviter's display name) reaches an HTML body, so all five structural
  // metacharacters must be escaped — otherwise a name is markup a mail client renders.
  it('escapes every HTML metacharacter in caller-supplied text', async () => {
    const hostile: InviteData = { ...INVITE, inviterName: `<b>&"'x` }
    await provider.sendInvitation('tenant-1', 'invitee@example.com', hostile)
    const { html: rendered } = lastSend(sink)
    expect(rendered).toContain('&lt;b&gt;&amp;&quot;&#39;x')
    expect(rendered).not.toContain('<b>')
    expect(rendered).not.toContain(`&"'`)
  })

  // The body is split on blank lines into one paragraph element each — a body with three blocks
  // renders as three <p> elements joined by newlines, not one.
  it('renders each blank-line-separated block as its own paragraph', async () => {
    await provider.sendPasswordChangedNotification('tenant-1', 'user@example.com')
    const { html: rendered } = lastSend(sink)
    expect(rendered).toBe(
      `<p>The password on your account was changed.</p>\n<p>${esc(UNEXPECTED)}</p>`
    )
    expect(rendered.match(/<p>/g)).toHaveLength(2)
  })

  // ---------------------------------------------------------------------------
  // Failure policy
  // ---------------------------------------------------------------------------

  // The library awaits most of these calls, so a down channel must not throw: the failure is
  // logged and the method still resolves.
  it('swallows a delivery failure and logs it without rejecting', async () => {
    const boom = new Error('channel down')
    sink.send.mockRejectedValueOnce(boom)
    await expect(
      provider.sendMfaEnabledNotification('tenant-1', 'user@example.com')
    ).resolves.toBeUndefined()
    expect(errorSpy).toHaveBeenCalledWith(
      'delivery failed for "Two-factor authentication is on"',
      boom
    )
  })

  // The log line names the message but never the recipient — a log reaches a wider audience than
  // the inbox the mail was going to.
  it('keeps the recipient out of the failure log', async () => {
    sink.send.mockRejectedValueOnce(new Error('channel down'))
    await provider.sendPasswordResetToken('tenant-1', 'secret@example.com', 'TOK')
    const logged = errorSpy.mock.calls[0]?.[0] as string
    expect(logged).not.toContain('secret@example.com')
  })

  // ---------------------------------------------------------------------------
  // Overrides
  // ---------------------------------------------------------------------------

  // A product replaces any subset of the copy; an overridden event uses the product's wording while
  // every other event keeps its default.
  it('uses an overridden renderer for its event and defaults for the rest', async () => {
    const messages: Partial<AuthEmailCatalogue> = {
      mfaEnabled: () => ({ subject: 'Custom MFA on', text: 'Branded body.' })
    }
    const custom = new DefaultAuthEmailProvider(sink, { messages })

    await custom.sendMfaEnabledNotification('tenant-1', 'user@example.com')
    expect(lastSend(sink)).toEqual({
      tenantId: 'tenant-1',
      to: 'user@example.com',
      subject: 'Custom MFA on',
      html: html('Branded body.'),
      text: 'Branded body.'
    })

    // A non-overridden event still uses the built-in copy.
    await custom.sendMfaDisabledNotification('tenant-1', 'user@example.com')
    expect(lastSend(sink).subject).toBe('Two-factor authentication is off')
  })

  // An options object with no `messages` key falls back to the full default catalogue — the spread
  // over `options?.messages` must tolerate its absence.
  it('falls back to the defaults when options carry no messages', async () => {
    const custom = new DefaultAuthEmailProvider(sink, {})
    await custom.sendMfaEnabledNotification('tenant-1', 'user@example.com')
    expect(lastSend(sink).subject).toBe('Two-factor authentication is on')
  })

  // The locale the port carries is threaded to the renderer, so an override can localize.
  it('passes the locale through to the renderer', async () => {
    const seen: Array<string | undefined> = []
    const messages: Partial<AuthEmailCatalogue> = {
      passwordResetOtp: ({ otp, locale }) => {
        seen.push(locale)
        return { subject: 's', text: otp }
      }
    }
    const custom = new DefaultAuthEmailProvider(sink, { messages })
    await custom.sendPasswordResetOtp('tenant-1', 'user@example.com', '000000', 'pt-BR')
    expect(seen).toEqual(['pt-BR'])
  })

  // The three notices whose only renderer input is the locale must still thread it — their default
  // copy ignores the payload, so nothing but an override proves the locale reaches the renderer at
  // all rather than being dropped on the way.
  it('threads the locale to the payload-free notices', async () => {
    const seen: Record<string, string | undefined> = {}
    const messages: Partial<AuthEmailCatalogue> = {
      passwordChanged: ({ locale }) => {
        seen['passwordChanged'] = locale
        return { subject: 's', text: 't' }
      },
      mfaEnabled: ({ locale }) => {
        seen['mfaEnabled'] = locale
        return { subject: 's', text: 't' }
      },
      mfaDisabled: ({ locale }) => {
        seen['mfaDisabled'] = locale
        return { subject: 's', text: 't' }
      }
    }
    const custom = new DefaultAuthEmailProvider(sink, { messages })
    await custom.sendPasswordChangedNotification('tenant-1', 'user@example.com', 'pt-BR')
    await custom.sendMfaEnabledNotification('tenant-1', 'user@example.com', 'es-ES')
    await custom.sendMfaDisabledNotification('tenant-1', 'user@example.com', 'fr-FR')
    expect(seen).toEqual({
      passwordChanged: 'pt-BR',
      mfaEnabled: 'es-ES',
      mfaDisabled: 'fr-FR'
    })
  })
})
