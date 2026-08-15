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
    .map((paragraph) => `<p>${esc(paragraph).replace(/\n/g, '<br>')}</p>`)
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

  // A subject is a single email header, so a CR/LF smuggled through a caller-chosen name must not
  // survive into it — otherwise a channel that builds headers by concatenation could read the rest
  // of the value as additional headers.
  it('strips CR/LF from the subject to prevent header injection', async () => {
    const hostile: InviteData = { ...INVITE, inviterName: 'Ada\r\nBcc: evil@example.com' }
    await provider.sendInvitation('tenant-1', 'invitee@example.com', hostile)
    const { subject } = lastSend(sink)
    expect(subject).not.toMatch(/[\r\n]/)
    expect(subject).toBe('Ada Bcc: evil@example.com invited you to Acme')
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

  // A single newline inside a paragraph becomes a <br>, so the new-session details keep their line
  // breaks — without it HTML whitespace collapsing would fold device, IP and session onto one line.
  it('renders intra-paragraph newlines as <br> in the new-session alert', async () => {
    await provider.sendNewSessionAlert('tenant-1', 'user@example.com', SESSION)
    const { html: rendered } = lastSend(sink)
    expect(rendered).toContain(
      `Device: ${SESSION.device}<br>IP: ${SESSION.ip}<br>Session: ${SESSION.sessionHash}`
    )
  })

  // An override that returns its own `html` owns it: the provider sends it verbatim, unescaped, so a
  // product can emit real <a> links — while a body without `html` is still escaped into paragraphs.
  it('uses an override-provided html body verbatim without escaping', async () => {
    const messages: Partial<AuthEmailCatalogue> = {
      passwordResetToken: ({ token }) => ({
        subject: 'Reset',
        text: `token ${token}`,
        html: `<a href="https://app/reset?token=${token}">Reset</a>`
      })
    }
    const custom = new DefaultAuthEmailProvider(sink, { messages })
    await custom.sendPasswordResetToken('tenant-1', 'user@example.com', 'TOK')
    const sent = lastSend(sink)
    expect(sent.html).toBe('<a href="https://app/reset?token=TOK">Reset</a>')
    expect(sent.text).toBe('token TOK')
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
      'delivery failed for "Two-factor authentication is on": Error: channel down'
    )
  })

  // The error OBJECT never reaches the logger — only the description built from it. Asserted on
  // the call's arity because that is the property that matters: a second argument would hand Nest
  // the raw error, and Nest prints its stack and its own properties, which is where a channel
  // hides the server's full reply (nodemailer's `response`, for one).
  it('passes no error object to the logger, only a rendered line', async () => {
    sink.send.mockRejectedValueOnce(new Error('channel down'))
    await provider.sendMfaEnabledNotification('tenant-1', 'user@example.com')
    expect(errorSpy.mock.calls[0]).toHaveLength(1)
  })

  // The log line names the message but never the recipient — a log reaches a wider audience than
  // the inbox the mail was going to.
  it('keeps the recipient out of the failure log', async () => {
    sink.send.mockRejectedValueOnce(new Error('channel down'))
    await provider.sendPasswordResetToken('tenant-1', 'secret@example.com', 'TOK')
    const logged = errorSpy.mock.calls[0]?.[0] as string
    expect(logged).not.toContain('secret@example.com')
  })

  // On the 'rethrow' policy the failure is logged AND propagated, so a caller that reacts to a
  // rejection — early reset-token cleanup, a failed email-change surfacing — gets it back.
  it('re-throws after logging when onDeliveryError is rethrow', async () => {
    const boom = new Error('channel down')
    sink.send.mockRejectedValueOnce(boom)
    const strict = new DefaultAuthEmailProvider(sink, { onDeliveryError: 'rethrow' })
    await expect(strict.sendPasswordResetToken('tenant-1', 'user@example.com', 'TOK')).rejects.toBe(
      boom
    )
    expect(errorSpy).toHaveBeenCalledWith(
      'delivery failed for "Reset your password": Error: channel down'
    )
  })

  // The rethrown error is the ORIGINAL, unlaundered. Deliberate, and asserted so a later "let us
  // sanitize what we throw too" cannot land silently: a caller opted into this policy to branch on
  // the channel's own codes, and a replacement error takes those away. The consequence — that the
  // quoted body travels with it — is the caller's to contain, which is why `redactSecrets` is
  // exported and the option documents the duty.
  it('re-throws the original error object rather than a sanitized copy', async () => {
    const boom = new Error('550 rejected: "Your code is 424242."')
    sink.send.mockRejectedValueOnce(boom)
    const strict = new DefaultAuthEmailProvider(sink, { onDeliveryError: 'rethrow' })

    await expect(
      strict.sendPasswordResetOtp('tenant-1', 'user@example.com', '424242')
    ).rejects.toBe(boom)
    expect(boom.message).toContain('424242')
  })

  // ---------------------------------------------------------------------------
  // Credentials must not reach the log when the channel quotes the body back
  // ---------------------------------------------------------------------------

  // The measured failure, as a test. A policy/DLP relay rejects with 550 and QUOTES the offending
  // content, so the channel's error IS the rendered body — the premise this file's old comment got
  // wrong, and the reason a live OTP reached an operator's log in clear text on a real deployment.
  // Every credential-bearing method is covered, because each one renders a different secret into
  // a different body and one of them being threaded is no evidence about the others.
  it.each([
    [
      'password-reset OTP',
      (p: DefaultAuthEmailProvider) => p.sendPasswordResetOtp('t', 'u@example.com', '699647'),
      '699647'
    ],
    [
      'email-verification OTP',
      (p: DefaultAuthEmailProvider) => p.sendEmailVerificationOtp('t', 'u@example.com', '318250'),
      '318250'
    ],
    [
      'password-reset token',
      (p: DefaultAuthEmailProvider) =>
        p.sendPasswordResetToken('t', 'u@example.com', 'a1b2c3d4e5f6a1b2'),
      'a1b2c3d4e5f6a1b2'
    ],
    [
      'email-change token',
      (p: DefaultAuthEmailProvider) =>
        p.sendEmailChangeVerification('t', 'new@example.com', 'f6e5d4c3b2a1f6e5'),
      'f6e5d4c3b2a1f6e5'
    ],
    [
      'invitation token',
      (p: DefaultAuthEmailProvider) =>
        p.sendInvitation('t', 'u@example.com', {
          inviterName: 'Ana',
          tenantName: 'Acme',
          inviteToken: '0f1e2d3c4b5a0f1e',
          expiresAt: new Date('2026-01-01T00:00:00.000Z')
        }),
      '0f1e2d3c4b5a0f1e'
    ]
  ])('keeps the %s out of the log when the relay quotes it back', async (_why, send, secret) => {
    sink.send.mockRejectedValueOnce(
      new Error(`550 5.7.1 rejected by policy: "Your code is ${secret}. It expires soon."`)
    )

    await send(provider)

    const logged = errorSpy.mock.calls[0]?.[0] as string
    expect(logged).not.toContain(secret)
    expect(logged).toContain('<redacted>')
  })

  // A channel reports "send failed BECAUSE the relay said", and the quoted body lands one level
  // down. Reading only the top-level message would leave the credential in the chain — which is
  // precisely the shape a sibling library shipped and had to fix.
  it('redacts a secret quoted in a nested cause', async () => {
    sink.send.mockRejectedValueOnce(
      new Error('send failed', {
        cause: new Error('550 rejected: "Your code is 550123."')
      })
    )

    await provider.sendPasswordResetOtp('t', 'u@example.com', '550123')

    const logged = errorSpy.mock.calls[0]?.[0] as string
    expect(logged).not.toContain('550123')
    // The whole line, not just the absence of the code: the links must stay visibly separated so
    // an operator can tell "the send failed" from "the relay said" instead of reading one run-on
    // sentence stitched from two different errors.
    expect(logged).toBe(
      'delivery failed for "Your password reset code": Error: send failed <- ' +
        'Error: 550 rejected: "Your code is <redacted>."'
    )
  })

  // Text that came back from a remote relay is untrusted input. A CR/LF in it would close the log
  // record and open a forged one, so the description is control-character stripped — the same
  // guarantee `logSafe` gives every other request-derived value that reaches a log template.
  it('does not let a relay forge a second log record', async () => {
    sink.send.mockRejectedValueOnce(
      new Error('rejected\nLOG [AuthService] login: success userId=victim')
    )

    await provider.sendPasswordResetOtp('t', 'u@example.com', '111111')

    const logged = errorSpy.mock.calls[0]?.[0] as string
    // Both halves are needed. Asserting only the absence of a newline passes trivially on any
    // build that keeps channel text out of the line altogether, which would make this test agree
    // with a version that reports nothing; asserting the line carries the channel's own diagnosis
    // is what makes the first assertion mean "included AND neutralised".
    expect(logged).toContain('<malformed>')
    expect(logged).not.toContain('\n')
  })

  // The bound is the second lock, for a relay that re-encodes the body so substring matching
  // cannot find the credential at all. It cannot make that case safe, but it stops one failed
  // send from relaying an unbounded quantity of channel-controlled text into the log.
  it('caps how much channel text reaches the line', async () => {
    sink.send.mockRejectedValueOnce(new Error('x'.repeat(5_000)))

    await provider.sendPasswordResetOtp('t', 'u@example.com', '222222')

    const logged = errorSpy.mock.calls[0]?.[0] as string
    // Truncated, not dropped: the second assertion keeps this from passing on a build that omits
    // the channel's message entirely, which would satisfy a bare length check while removing the
    // diagnosis operators depend on.
    //
    // The bound is tight on purpose. The cap is 200 and the prefix
    // (`delivery failed for "Your password reset code": Error: `) is ~55, so ~255 is the real
    // answer; a loose `< 400` would still pass if the cap were quietly raised to 300, which is
    // exactly the regression this test exists to catch.
    expect(logged.length).toBeLessThan(270)
    expect(logged).toContain('xxx')
  })

  // The subject is consumer-controlled through a `messages` override, and it lands in a log
  // template. `sanitizeSubject` only strips CR and LF, because its job is the mail header; the
  // rest of the C0/C1 range reaches the log line, and more than CR/LF can forge a record in a
  // line-oriented pipeline. `logSafe` is the second guard, and this is the case that needs it.
  // The subject is logged by design, and an override is free to put the code in it —
  // `passwordResetOtp: ({ otp }) => ({ subject: `Code ${otp}` })` looks reasonable to write. That
  // used to be documented as a known way to reopen the leak; it is closed instead, since the
  // secrets are already in hand on the line that builds the record.
  it('redacts a code an override put in the subject', async () => {
    const messages = {
      passwordResetOtp: ({ otp }: { otp: string }) => ({
        subject: `Your code ${otp}`,
        text: `Your code is ${otp}.`
      })
    }
    const custom = new DefaultAuthEmailProvider(sink, { messages })
    sink.send.mockRejectedValueOnce(new Error('channel down'))

    await custom.sendPasswordResetOtp('t', 'u@example.com', '246810')

    const logged = errorSpy.mock.calls[0]?.[0] as string
    expect(logged).not.toContain('246810')
    expect(logged).toContain('<redacted>')
  })

  it('neutralises a control character an override put in the subject', async () => {
    const messages = {
      mfaEnabled: () => ({ subject: 'MFALOG [AuthService] forged', text: 'body' })
    }
    const custom = new DefaultAuthEmailProvider(sink, { messages })
    sink.send.mockRejectedValueOnce(new Error('channel down'))

    await custom.sendMfaEnabledNotification('t', 'u@example.com')

    const logged = errorSpy.mock.calls[0]?.[0] as string
    expect(logged).not.toContain('')
    expect(logged).toContain('<malformed>')
  })

  // `name` and `message` are typed `string` but are ordinary writable properties, and an error
  // revived from JSON or built by sloppy code can leave either holding something else. Without
  // coercion the redaction call throws a TypeError INSIDE this catch block — turning a failure
  // the swallow policy promises to absorb into an unhandled rejection with no log line at all,
  // which is worse than the poor log line the coercion produces.
  it('survives an error whose message is not a string', async () => {
    const malformed = new Error('placeholder')
    Object.defineProperty(malformed, 'message', { value: { nested: 'object' } })
    sink.send.mockRejectedValueOnce(malformed)

    await expect(provider.sendMfaEnabledNotification('t', 'u@example.com')).resolves.toBeUndefined()
    expect(errorSpy).toHaveBeenCalledTimes(1)
  })

  // `name`, `message` and `cause` look like plain properties but any of them can be an accessor
  // that throws — they belong to whoever built the error, which for a mail channel is a
  // third-party client. A throw while DESCRIBING the failure escapes the provider's catch block
  // and turns a delivery failure the swallow policy promises to absorb into an unhandled
  // rejection with no log line at all: worse than the leak this whole change exists to close.
  it.each([
    ['name', 'name'],
    ['message', 'message'],
    ['cause', 'cause']
  ])('survives an error whose %s getter throws', async (_why, property) => {
    const hostile = new Error('placeholder')
    Object.defineProperty(hostile, property, {
      get: () => {
        throw new Error('hostile getter')
      }
    })
    sink.send.mockRejectedValueOnce(hostile)

    await expect(
      provider.sendPasswordResetOtp('t', 'u@example.com', '777777')
    ).resolves.toBeUndefined()

    const logged = errorSpy.mock.calls[0]?.[0] as string
    expect(logged).toContain('delivery failed')
    expect(logged).not.toContain('777777')
  })

  // A `toString` that throws is the same hazard one level down: `String()` on a non-string field
  // runs code the channel wrote. The description still has to come back as a description.
  it('survives an error whose message coercion throws', async () => {
    const hostile = new Error('placeholder')
    Object.defineProperty(hostile, 'message', {
      value: {
        toString: () => {
          throw new Error('hostile toString')
        }
      }
    })
    sink.send.mockRejectedValueOnce(hostile)

    await expect(
      provider.sendPasswordResetOtp('t', 'u@example.com', '888888')
    ).resolves.toBeUndefined()
    expect(errorSpy.mock.calls[0]?.[0]).toContain('<malformed-error>')
  })

  // `cause: null` is not the same as no cause. An absent `cause` reads as `undefined`, but
  // `new Error(msg, { cause: null })` installs an own property holding `null`, so a walk that
  // only stops on `undefined` takes one more step and reports a spurious `<non-error: object>`
  // link that no channel ever produced. Both terminators are needed, and this is the one nothing
  // else exercises.
  it('treats an explicitly null cause as the end of the chain', async () => {
    sink.send.mockRejectedValueOnce(new Error('channel down', { cause: null }))

    await provider.sendMfaEnabledNotification('t', 'u@example.com')

    expect(errorSpy).toHaveBeenCalledWith(
      'delivery failed for "Two-factor authentication is on": Error: channel down'
    )
  })

  // A thrown `undefined` is legal — `Promise.reject()` produces one. The cause-walk guard that
  // stops the chain would otherwise skip the body entirely and return an empty description,
  // emitting `delivery failed for "X": ` with a dangling colon and no diagnosis whatsoever.
  it('describes a rejection that carries no value at all', async () => {
    sink.send.mockRejectedValueOnce(undefined)

    await provider.sendMfaEnabledNotification('t', 'u@example.com')

    expect(errorSpy).toHaveBeenCalledWith(
      'delivery failed for "Two-factor authentication is on": <non-error: undefined>'
    )
  })

  // A channel may reject with something that is not an Error at all. Stringifying it would run
  // the channel's own `toString`, so its type is reported instead and the walk stops.
  it('describes a thrown non-error without stringifying it', async () => {
    sink.send.mockRejectedValueOnce({
      toString: () => 'code 999999 leaked via toString'
    })

    await provider.sendPasswordResetOtp('t', 'u@example.com', '999999')

    const logged = errorSpy.mock.calls[0]?.[0] as string
    expect(logged).not.toContain('999999')
    expect(logged).toContain('<non-error: object>')
  })

  // A channel can throw an error with no message at all — `new Error()`, or one whose entire
  // message was control characters and got replaced. The name then stands alone rather than
  // trailing a colon with nothing after it, so the line still reads as a diagnosis.
  it('reports the error name alone when the message is empty', async () => {
    sink.send.mockRejectedValueOnce(new Error())

    await provider.sendPasswordResetOtp('t', 'u@example.com', '444444')

    expect(errorSpy).toHaveBeenCalledWith('delivery failed for "Your password reset code": Error')
  })

  // A cycle in the cause chain must not turn one failed send into an unbounded record. The depth
  // cap is what guarantees termination; without it this test hangs rather than fails.
  it('stops walking a self-referential cause chain', async () => {
    const looped = new Error('outer')
    Object.defineProperty(looped, 'cause', { value: looped })
    sink.send.mockRejectedValueOnce(looped)

    await provider.sendPasswordResetOtp('t', 'u@example.com', '333333')

    const logged = errorSpy.mock.calls[0]?.[0] as string
    expect(logged.match(/outer/g)).toHaveLength(3)
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
