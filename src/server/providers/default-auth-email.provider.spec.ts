import { Logger } from '@nestjs/common'

import type { InviteData, SessionInfo } from '../interfaces/email-provider.interface'
import {
  AUTH_EMAIL_KINDS,
  DefaultAuthEmailProvider,
  type AuthEmailSink,
  type AuthEmailCatalogue,
  type DeliveryErrorPolicyMap
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
      text,
      kind: 'passwordResetToken',
      containsCredential: true
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
      text,
      kind: 'passwordResetOtp',
      containsCredential: true
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
      text,
      kind: 'emailVerificationOtp',
      containsCredential: true
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
      text,
      kind: 'passwordChanged',
      containsCredential: false
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
      text,
      kind: 'emailChangeVerification',
      containsCredential: true
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
      text,
      kind: 'emailChanged',
      containsCredential: false
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
      text,
      kind: 'mfaEnabled',
      containsCredential: false
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
      text,
      kind: 'mfaDisabled',
      containsCredential: false
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
      text,
      kind: 'newSessionAlert',
      containsCredential: false
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
      text,
      kind: 'invitation',
      containsCredential: true
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
    // `channel down` carries no status, so nothing of the transport's own words survives and the
    // stand-in is the whole description. That is the contract on EVERY path here, not only the
    // credential-bearing ones: a relay is as free to re-encode what it quotes when the body held
    // an address as when it held a code, and a substring match sees through neither.
    expect(errorSpy).toHaveBeenCalledWith('delivery failed sending mfaEnabled: <error>')
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

  // The exported list is frozen at RUNTIME, not merely `as const`. It is exported, and expanding
  // a bare `'rethrow'` iterates it — a consumer splicing an entry out would silently stop that
  // message being covered by a policy the deployment believes is global.
  it('cannot be edited by a consumer', () => {
    expect(Object.isFrozen(AUTH_EMAIL_KINDS)).toBe(true)
    // `Reflect.set` rather than an assignment through a cast: it reports the refusal as a return
    // value, so the write is proved rejected without widening the type to something the compiler
    // is right to reject.
    expect(Reflect.set(AUTH_EMAIL_KINDS, 0, 'forged')).toBe(false)
    expect(AUTH_EMAIL_KINDS[0]).toBe('passwordResetToken')
    expect(AUTH_EMAIL_KINDS).toHaveLength(10)
  })

  // WHICH messages declare a credential, pinned as a whole set rather than one at a time. A new
  // message added to the catalogue without a decision here shows up as a diff on this list, which
  // is the point: "does this body carry something that unlocks an account" is a question somebody
  // has to answer per message, and a default of `false` would answer it silently.
  //
  // The five that do are the ones whose body renders a value a recipient can use: two codes, two
  // tokens, and the invitation. The five that do not are notices about a change that already
  // happened — they still carry personal data, which is why this library publishes none of a
  // channel's text for them either.
  it('declares a credential for exactly the five messages that render one', async () => {
    sink.send.mockResolvedValue(undefined)

    await provider.sendPasswordResetToken('t', 'u@e.com', 'tok')
    await provider.sendPasswordResetOtp('t', 'u@e.com', '424242')
    await provider.sendEmailVerificationOtp('t', 'u@e.com', '424242')
    await provider.sendPasswordChangedNotification('t', 'u@e.com')
    await provider.sendEmailChangeVerification('t', 'u@e.com', 'tok')
    await provider.sendEmailChangedNotification('t', 'old@e.com', 'new@e.com')
    await provider.sendMfaEnabledNotification('t', 'u@e.com')
    await provider.sendMfaDisabledNotification('t', 'u@e.com')
    await provider.sendNewSessionAlert('t', 'u@e.com', SESSION)
    await provider.sendInvitation('t', 'u@e.com', INVITE)

    const declared = sink.send.mock.calls.map(([input]) => [input.kind, input.containsCredential])

    expect(declared).toEqual([
      ['passwordResetToken', true],
      ['passwordResetOtp', true],
      ['emailVerificationOtp', true],
      ['passwordChanged', false],
      ['emailChangeVerification', true],
      ['emailChanged', false],
      ['mfaEnabled', false],
      ['mfaDisabled', false],
      ['newSessionAlert', false],
      ['invitation', true]
    ])
    // Every catalogue entry is represented, so a message added without a line here is visible as
    // a length mismatch rather than as a silent omission.
    expect(declared).toHaveLength(AUTH_EMAIL_KINDS.length)
  })

  // The case the kind cannot see. `messages` replaces a renderer outright, so a product whose own
  // `mfaEnabled` copy hands the user recovery codes has made a notice credential-bearing while
  // its kind still reads `mfaEnabled`. Without the rendering's own declaration the sink is told
  // `false` about a body carrying a live secret — the flag being WRONG, which is worse than the
  // flag being merely non-protective.
  it('lets a rendering declare a credential the kind does not imply', async () => {
    sink.send.mockResolvedValue(undefined)
    const withRecoveryCodes = new DefaultAuthEmailProvider(sink, {
      messages: {
        mfaEnabled: () => ({
          subject: 'Two-factor is on',
          text: 'Recovery codes: 11111-22222',
          containsCredential: true
        })
      }
    })

    await withRecoveryCodes.sendMfaEnabledNotification('t', 'u@e.com')

    expect(sink.send).toHaveBeenCalledWith(
      expect.objectContaining({ kind: 'mfaEnabled', containsCredential: true })
    )
  })

  // The other direction, which must not work. The kind is a baseline a renderer cannot weaken:
  // an override for a credential-bearing flow that omits the credential from ITS copy still
  // reaches a sink that may be reused for the default rendering, and a downgrade here would be a
  // consumer silently turning off a statement this library makes about its own messages.
  it('never lets a rendering downgrade a credential the kind implies', async () => {
    sink.send.mockResolvedValue(undefined)
    const downgrading = new DefaultAuthEmailProvider(sink, {
      messages: {
        passwordResetOtp: () => ({
          subject: 'Reset',
          text: 'Open the app to continue',
          containsCredential: false
        })
      }
    })

    await downgrading.sendPasswordResetOtp('t', 'u@e.com', '424242')

    expect(sink.send).toHaveBeenCalledWith(
      expect.objectContaining({ kind: 'passwordResetOtp', containsCredential: true })
    )
  })

  // An override that says nothing about credentials is the ordinary case — branding and copy,
  // no security claim — and must leave the kind's answer exactly as it was.
  it('leaves the kind to decide when a rendering says nothing', async () => {
    sink.send.mockResolvedValue(undefined)
    const rebranded = new DefaultAuthEmailProvider(sink, {
      messages: { mfaEnabled: () => ({ subject: 'Two-factor is on', text: 'All set.' }) }
    })

    await rebranded.sendMfaEnabledNotification('t', 'u@e.com')

    expect(sink.send).toHaveBeenCalledWith(
      expect.objectContaining({ kind: 'mfaEnabled', containsCredential: false })
    )
  })

  // The reason the option takes a map. A deployment opts into the throw for ONE flow — the reset
  // token, so the stored token can be deleted early — and a bare `'rethrow'` would hand it the
  // unlaundered channel error on the OTP paths too, which are the ones carrying a credential in
  // the body. Naming the flow keeps the opt-in where it was asked for.
  it('re-throws only for the message the map names', async () => {
    const selective = new DefaultAuthEmailProvider(sink, {
      onDeliveryError: { passwordResetToken: 'rethrow' }
    })
    sink.send.mockRejectedValue(new Error('550 rejected'))

    await expect(selective.sendPasswordResetToken('t', 'u@e.com', 'tok')).rejects.toThrow()
    // The credential-bearing sibling is NOT opted in and still resolves.
    await expect(selective.sendPasswordResetOtp('t', 'u@e.com', '424242')).resolves.toBeUndefined()
  })

  // The direction of the default, which is the property that makes the map safe to widen: a
  // message left out keeps swallowing. A map that opted everything in by omission would make
  // every catalogue addition a silent behaviour change.
  it('leaves an unnamed message swallowing', async () => {
    const selective = new DefaultAuthEmailProvider(sink, {
      onDeliveryError: { passwordResetToken: 'rethrow' }
    })
    sink.send.mockRejectedValue(new Error('550 rejected'))

    await expect(selective.sendMfaEnabledNotification('t', 'u@e.com')).resolves.toBeUndefined()
    await expect(selective.sendInvitation('t', 'u@e.com', INVITE)).resolves.toBeUndefined()
  })

  // An explicit `'swallow'` in the map is not the same statement as omission, and both must work —
  // a deployment writing the safe value down deserves the same behaviour as one leaving it out.
  it('honours an explicit swallow in the map', async () => {
    const selective = new DefaultAuthEmailProvider(sink, {
      onDeliveryError: { passwordResetToken: 'swallow', passwordResetOtp: 'rethrow' }
    })
    sink.send.mockRejectedValue(new Error('550 rejected'))

    await expect(selective.sendPasswordResetToken('t', 'u@e.com', 'tok')).resolves.toBeUndefined()
    await expect(selective.sendPasswordResetOtp('t', 'u@e.com', '424242')).rejects.toThrow()
  })

  // A key the catalogue does not know is dropped, and it lands on the SAFE side: the message keeps
  // swallowing. TypeScript rejects the typo outright, so this is the JavaScript caller's path —
  // and the direction is what matters. A deployment that mistypes gets less throwing than it
  // meant, never a credential-bearing error handed to a handler that did not ask for one.
  it('drops a key the catalogue does not know, leaving it on swallow', async () => {
    const typo = new DefaultAuthEmailProvider(sink, {
      onDeliveryError: { passwordReset: 'rethrow' } as DeliveryErrorPolicyMap
    })
    sink.send.mockRejectedValue(new Error('550 rejected'))

    await expect(typo.sendPasswordResetToken('t', 'u@e.com', 'tok')).resolves.toBeUndefined()
    await expect(typo.sendPasswordResetOtp('t', 'u@e.com', '424242')).resolves.toBeUndefined()
  })

  // The prototype is not a source of policy. A plain object inherits `toString`, and none of the
  // ten names collides with an inherited one today — this pins that the resolution never reads
  // the chain at all, so a later rename cannot make it matter.
  it('takes no policy from the prototype chain', async () => {
    const inherited = Object.create({ passwordResetToken: 'rethrow' }) as DeliveryErrorPolicyMap
    const viaPrototype = new DefaultAuthEmailProvider(sink, { onDeliveryError: inherited })
    sink.send.mockRejectedValue(new Error('550 rejected'))

    await expect(
      viaPrototype.sendPasswordResetToken('t', 'u@e.com', 'tok')
    ).resolves.toBeUndefined()
  })

  // The bare policy still reaches every method. Completeness of the kind list is proved by the
  // compiler in the source; what a type cannot show is that expanding it actually covers each send
  // path, so that is asserted behaviourally — one call per method, all of them rejecting.
  it('applies a bare policy to every message', async () => {
    const everywhere = new DefaultAuthEmailProvider(sink, { onDeliveryError: 'rethrow' })
    sink.send.mockRejectedValue(new Error('550 rejected'))

    const sends: readonly Promise<void>[] = [
      everywhere.sendPasswordResetToken('t', 'u@e.com', 'tok'),
      everywhere.sendPasswordResetOtp('t', 'u@e.com', '424242'),
      everywhere.sendEmailVerificationOtp('t', 'u@e.com', '424242'),
      everywhere.sendPasswordChangedNotification('t', 'u@e.com'),
      everywhere.sendEmailChangeVerification('t', 'u@e.com', 'tok'),
      everywhere.sendEmailChangedNotification('t', 'old@e.com', 'new@e.com'),
      everywhere.sendMfaEnabledNotification('t', 'u@e.com'),
      everywhere.sendMfaDisabledNotification('t', 'u@e.com'),
      everywhere.sendNewSessionAlert('t', 'u@e.com', SESSION),
      everywhere.sendInvitation('t', 'u@e.com', INVITE)
    ]

    // As many sends as the catalogue has entries: a method added without a line here leaves the
    // count short, and the assertion says so.
    expect(sends).toHaveLength(AUTH_EMAIL_KINDS.length)
    const settled = await Promise.allSettled(sends)
    expect(settled.every((r) => r.status === 'rejected')).toBe(true)
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
    // A credential path, so nothing the channel wrote reaches the line — neither the message nor
    // the name, whatever either happened to contain.
    expect(errorSpy).toHaveBeenCalledWith('delivery failed sending passwordResetToken: <error>')
  })

  // The rethrown error is the ORIGINAL, unlaundered. Deliberate, and asserted so a later "let us
  // sanitize what we throw too" cannot land silently: a caller opted into this policy to branch on
  // the channel's own codes, and a replacement error takes those away. The consequence — that the
  // quoted body travels with it — is the caller's to contain, which is why `describeChannelStatus`
  // is exported and the option documents the duty. NOT `redactSecrets`: a substring match cannot
  // remove a body the relay re-encoded, which is the gap this whole change exists for.
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
      '699647',
      'passwordResetOtp'
    ],
    [
      'email-verification OTP',
      (p: DefaultAuthEmailProvider) => p.sendEmailVerificationOtp('t', 'u@example.com', '318250'),
      '318250',
      'emailVerificationOtp'
    ],
    [
      'password-reset token',
      (p: DefaultAuthEmailProvider) =>
        p.sendPasswordResetToken('t', 'u@example.com', 'a1b2c3d4e5f6a1b2'),
      'a1b2c3d4e5f6a1b2',
      'passwordResetToken'
    ],
    [
      'email-change token',
      (p: DefaultAuthEmailProvider) =>
        p.sendEmailChangeVerification('t', 'new@example.com', 'f6e5d4c3b2a1f6e5'),
      'f6e5d4c3b2a1f6e5',
      'emailChangeVerification'
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
      '0f1e2d3c4b5a0f1e',
      'invitation'
    ]
    // The fourth column is the label the line must carry. Asserted per case rather than as one
    // literal, because that is what pins the MAPPING from message to label — a send wired to the
    // wrong label would still satisfy every absence, and would satisfy a single shared literal too.
  ])(
    'keeps the %s out of the log when the relay quotes it back',
    async (_why, send, secret, label) => {
      sink.send.mockRejectedValueOnce(
        new Error(`550 5.7.1 rejected by policy: "Your code is ${secret}. It expires soon."`)
      )

      await send(provider)

      const logged = errorSpy.mock.calls[0]?.[0] as string
      // The credential is gone AND so is the channel's prose. What survives is the message's own
      // label, which this file wrote, and the stand-in saying a throw happened.
      expect(logged).not.toContain(secret)
      expect(logged).not.toContain('rejected by policy')
      expect(logged).not.toContain('550')
      expect(logged).toBe(`delivery failed sending ${label}: <error>`)
    }
  )

  // The measurement that decided the policy, kept as a test because it is the only evidence that
  // the two obvious defences are NOT enough on their own. A relay is free to quote the body it
  // rejected in transfer encoding rather than verbatim, and base64 is the ordinary case. Redaction
  // then matches nothing — the credential's characters are not in the line — and the length cap
  // does not help either, because the encoding runs from the body's first byte, so the code sits
  // near the front, well inside any cap. Measured on the real reset-code body: the whole thing is
  // 96 base64 characters, and the first 200 of the line decode straight back to the OTP. Dropping
  // the channel's text is what closes it; this test fails if the drop is ever relaxed to a cap or
  // a redaction.
  it('does not leak a credential a relay quoted back in base64', async () => {
    const otp = '135791'
    const body = Buffer.from(`Your password reset code is ${otp}. It expires in 10 minutes.`)
    sink.send.mockRejectedValueOnce(
      new Error(`550 5.7.1 message rejected: ${body.toString('base64')}`)
    )

    await provider.sendPasswordResetOtp('t', 'u@example.com', otp)

    const logged = errorSpy.mock.calls[0]?.[0] as string
    // Asserting the absence of the digits would pass while the leak is live — encoded, they are
    // not there to find. The assertion has to be the one an attacker would run: decode whatever
    // survived and look for the code in the plaintext.
    const decoded = logged
      .split(/[^A-Za-z0-9+/=]+/)
      .map((chunk) => Buffer.from(chunk, 'base64').toString('utf8'))
      .join(' ')
    expect(decoded).not.toContain(otp)
    expect(logged).not.toContain(otp)
    expect(logged).not.toContain('550')
    expect(logged).toBe('delivery failed sending passwordResetOtp: <error>')
  })

  // The measurement that killed the shape check, kept as a test because the shape check LOOKED
  // sufficient and was not. Validating the name as an identifier bounded in length excludes a
  // quoted body and does NOT exclude an encoded one: `MTIzNDU2` is the base64 of the OTP `123456`
  // — eight characters, alphanumeric, leading letter, a valid identifier by any such rule, and
  // reversible by anyone reading the log. No shape test can tell `SmtpRejection` from a credential
  // in transfer encoding, which is the exact threat this rule exists for, so on any credential
  // path no name comes through at all.
  it('does not publish a name that is the credential in transfer encoding', async () => {
    const otp = '123456'
    const named = new Error('550 5.7.1 rejected')
    named.name = Buffer.from(otp).toString('base64')
    sink.send.mockRejectedValueOnce(named)

    await provider.sendPasswordResetOtp('t', 'u@example.com', otp)

    const logged = errorSpy.mock.calls[0]?.[0] as string
    // The attacker's own test: decode whatever survived and look for the code in the plaintext.
    // Asserting the absence of the digits passes while the leak is live, because encoded they are
    // not there to find.
    const decoded = logged
      .split(/[^A-Za-z0-9+/=]+/)
      .map((chunk) => Buffer.from(chunk, 'base64').toString('utf8'))
      .join(' ')
    expect(decoded).not.toContain(otp)
    expect(logged).not.toContain('MTIzNDU2')
    expect(logged).toBe('delivery failed sending passwordResetOtp: <error>')
  })

  // The status was the last channel-derived field and it is gone, for a reason the independence
  // test makes sharp. `550 5.7.1` reassembling into a valid OTP was coincidence — the same reply
  // appears whatever the code is. THIS is not: an OTP of `424242` grouped as `424-242` at the head
  // of a quoted body publishes `424`, and a different code publishes different digits. The output
  // depends on the secret, which is derivation, and no grammar separates a reply from body text
  // shaped like one.
  it('publishes no status, however much the message looks like a reply', async () => {
    const otp = '424242'
    sink.send.mockRejectedValueOnce(new Error(`424-242 is your code, quoted back by the relay`))

    await provider.sendPasswordResetOtp('t', 'u@example.com', otp)

    const logged = errorSpy.mock.calls[0]?.[0] as string
    // Not even the first three digits, which is what a reply-code parser would have kept.
    expect(logged).not.toContain(otp.slice(0, 3))
    expect(logged).toBe('delivery failed sending passwordResetOtp: <error>')
  })

  // The error's NAME is the other field the channel controls, and dropping the message while
  // letting the name through would have moved the leak one field over rather than closing it — an
  // error class built around a relay reply (`name = `SmtpRejection: ${response}``) is a normal
  // thing for a mail client to do.
  //
  // Validating the name by SHAPE was the first answer and is the reason this test is written
  // around one: `SmtpError 550 rejected by policy RelayTail` would pass a check anchored at only
  // one end, admitted for its head or for its tail, with the relay's own words riding in between.
  // It fails a whole-string identifier check — and that check was not enough either, because an
  // encoded credential IS a valid identifier, which is what took the name out of the line
  // entirely. The assertion holds for the stronger rule and would have caught the weaker one's
  // gap.
  it('publishes no part of a name the channel built out of its reply', async () => {
    const named = new Error('channel down')
    named.name = 'SmtpError 550 rejected by policy RelayTail'
    sink.send.mockRejectedValueOnce(named)

    await provider.sendPasswordResetOtp('t', 'u@example.com', '112233')

    const logged = errorSpy.mock.calls[0]?.[0] as string
    expect(logged).not.toContain('rejected by policy')
    expect(logged).not.toContain('SmtpError')
    expect(logged).not.toContain('RelayTail')
    // A stand-in that names what happened, not an empty gap: a line reading `delivery failed for
    // "x": ` tells an operator nothing about why the name is missing.
    expect(logged).toBe('delivery failed sending passwordResetOtp: <error>')
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
    // The whole line. The links stay visibly separated so an operator can tell "the send failed"
    // from "the relay said" — and on a credential path each link contributes only its stand-in,
    // never the relay's prose and nothing parsed off it.
    expect(logged).not.toContain('550123')
    expect(logged).toBe('delivery failed sending passwordResetOtp: <error> <- <error>')
  })
  // The subject NEVER reaches the log line — the message's label does. A subject comes from the
  // `messages` catalogue, which a consumer may override with arbitrary code, so logging it
  // publishes a string this library did not write. Redacting it was the earlier answer and is not
  // enough: a renderer that TRANSFORMS a value defeats a substring match, and `Code 123-456` for
  // the OTP `123456` is a reasonable-looking thing to write, as is its base64.
  //
  // Asserted with an override that would be unmistakable if it leaked, and on the whole line, so
  // this also pins that nothing else consumer-authored slipped in beside it.
  it('publishes the message label rather than the rendered subject', async () => {
    const messages = {
      mfaEnabled: () => ({ subject: 'Code 123-456 for u@example.com', text: 'body' })
    }
    const custom = new DefaultAuthEmailProvider(sink, { messages })
    sink.send.mockRejectedValueOnce(new Error('channel down'))

    await custom.sendMfaEnabledNotification('t', 'u@example.com')

    expect(errorSpy).toHaveBeenCalledWith('delivery failed sending mfaEnabled: <error>')
  })

  // Every method's label, because the label is now the ONLY thing identifying which message
  // failed — the rendered subject is gone from the line. An empty or wrong one leaves an operator
  // with a delivery failure and no way to tell a reset code from an invitation, and nine of these
  // were unpinned when the subject stopped being logged.
  it.each([
    [
      'passwordResetToken',
      (p: DefaultAuthEmailProvider) => p.sendPasswordResetToken('t', 'u@e.com', 'tok')
    ],
    [
      'passwordResetOtp',
      (p: DefaultAuthEmailProvider) => p.sendPasswordResetOtp('t', 'u@e.com', '111111')
    ],
    [
      'emailVerificationOtp',
      (p: DefaultAuthEmailProvider) => p.sendEmailVerificationOtp('t', 'u@e.com', '222222')
    ],
    [
      'passwordChanged',
      (p: DefaultAuthEmailProvider) => p.sendPasswordChangedNotification('t', 'u@e.com')
    ],
    [
      'emailChangeVerification',
      (p: DefaultAuthEmailProvider) => p.sendEmailChangeVerification('t', 'new@e.com', 'tok')
    ],
    [
      'emailChanged',
      (p: DefaultAuthEmailProvider) => p.sendEmailChangedNotification('t', 'old@e.com', 'new@e.com')
    ],
    ['mfaEnabled', (p: DefaultAuthEmailProvider) => p.sendMfaEnabledNotification('t', 'u@e.com')],
    ['mfaDisabled', (p: DefaultAuthEmailProvider) => p.sendMfaDisabledNotification('t', 'u@e.com')],
    [
      'newSessionAlert',
      (p: DefaultAuthEmailProvider) =>
        p.sendNewSessionAlert('t', 'u@e.com', { device: 'd', ip: '1.2.3.4', sessionHash: 'h' })
    ],
    ['invitation', (p: DefaultAuthEmailProvider) => p.sendInvitation('t', 'u@e.com', INVITE)]
  ])('names %s in the line when its send fails', async (label, send) => {
    sink.send.mockRejectedValueOnce(new Error('channel down'))

    await send(provider)

    expect(errorSpy).toHaveBeenCalledWith(`delivery failed sending ${label}: <error>`)
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
  //
  // On THIS path the coercion is never reached, and that is the assertion. A credential is in
  // flight, so the policy discards the message — and reading it anyway, only to throw it away,
  // would let the channel pick which stand-in the log shows by throwing on demand. The line is
  // `<error>` because the hostile field was not touched, not because touching it was survived.
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
    expect(errorSpy.mock.calls[0]?.[0]).toBe('delivery failed sending passwordResetOtp: <error>')
  })

  // Even asking "is this an Error?" runs code the thrower controls: `instanceof` performs the
  // prototype lookup, and a Proxy can install a `getPrototypeOf` trap that throws. That exception
  // would escape the classification — outside the guards on the property reads — and out of the
  // provider's catch block, which is the unhandled rejection this module exists to prevent.
  it('survives a rejection whose own classification throws', async () => {
    const hostile = new Proxy(new Error('unreachable'), {
      getPrototypeOf() {
        throw new Error('hostile getPrototypeOf')
      }
    })
    sink.send.mockRejectedValueOnce(hostile)

    await expect(
      provider.sendPasswordResetOtp('t', 'u@example.com', '135790')
    ).resolves.toBeUndefined()

    // Asserted as the CLASSIFICATION, not merely as "did not crash". This Proxy traps only
    // `getPrototypeOf`, so its `name` and `message` read through to the target — a build that
    // treated a hostile classification as an Error would produce a plausible `Error: unreachable`
    // line and satisfy any weaker assertion. The contract is that a value whose own classification
    // is hostile is reported as a non-error, which is what it has earned.
    expect(errorSpy).toHaveBeenCalledWith(
      'delivery failed sending passwordResetOtp: <non-error: object>'
    )
  })

  // A thrown `undefined` is legal — `Promise.reject()` produces one. The cause-walk guard that
  // stops the chain would otherwise skip the body entirely and return an empty description,
  // emitting `delivery failed for "X": ` with a dangling colon and no diagnosis whatsoever.
  it('describes a rejection that carries no value at all', async () => {
    sink.send.mockRejectedValueOnce(undefined)

    await provider.sendMfaEnabledNotification('t', 'u@example.com')

    expect(errorSpy).toHaveBeenCalledWith(
      'delivery failed sending mfaEnabled: <non-error: undefined>'
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

  // A quoted body carries more than credentials, so these two get the same treatment. Both notices
  // RENDER identifying data — `emailChanged` states the new address, `newSessionAlert` states
  // device, IP and session hash — and a relay that rejects by quoting the body puts all of it into
  // the error. The address one matters most: this provider deliberately keeps the recipient out of
  // the log, on the grounds that a log line reaches a wider audience than the inbox, and a quoted
  // body walked straight past that decision.
  //
  // Redacting them is not enough, and "not a credential" was never the standard. A relay is as
  // free to quote THIS body re-encoded as it is to quote a reset code's, and redaction sees
  // through neither — so an IP, which is personal data, would reach the log by the same route the
  // credential fix closed. All of the channel's text goes; what stays is this library's own label,
  // which is the half that says WHICH message failed and the half no relay can forge.
  it.each([
    [
      'the addresses the email-changed notice renders',
      (p: DefaultAuthEmailProvider) =>
        p.sendEmailChangedNotification('t', 'old@example.com', 'new@example.com'),
      'new@example.com',
      'emailChanged'
    ],
    [
      'the IP the new-session alert renders',
      (p: DefaultAuthEmailProvider) =>
        p.sendNewSessionAlert('t', 'u@example.com', {
          device: 'Chrome on macOS',
          ip: '203.0.113.7',
          sessionHash: 'deadbeef'
        }),
      '203.0.113.7',
      'newSessionAlert'
    ]
  ])(
    'keeps %s out of the log when the relay quotes it back',
    async (_why, send, rendered, label) => {
      sink.send.mockRejectedValueOnce(new Error(`550 rejected by policy: "... ${rendered} ..."`))

      await send(provider)

      const logged = errorSpy.mock.calls[0]?.[0] as string
      expect(logged).not.toContain(rendered)
      expect(logged).not.toContain('rejected by policy')
      expect(logged).not.toContain('550')
      expect(logged).toBe(`delivery failed sending ${label}: <error>`)
    }
  )

  // The likeliest shape of all, and it needs no quoted body: an SMTP rejection NAMES the
  // recipient it refused. The template deliberately omits the address — a log line reaches a
  // wider audience than the inbox — so the transport's own diagnostic was putting back exactly
  // what the template left out.
  it('keeps the recipient out of the log when the transport names it', async () => {
    sink.send.mockRejectedValueOnce(new Error('550 recipient@example.com: recipient rejected'))

    await provider.sendMfaEnabledNotification('t', 'recipient@example.com')

    const logged = errorSpy.mock.calls[0]?.[0] as string
    // Nothing the transport wrote reaches the line, so the address cannot — not because it was
    // matched and removed, but because its carrier was never published.
    //
    // The three absences name what the fixture actually put in the error, and the final equality
    // is what keeps this from passing on a build that logs nothing at all: every absence below is
    // satisfied by an empty line, which would destroy the diagnosis this test exists to protect.
    expect(logged).not.toContain('recipient@example.com')
    expect(logged).not.toContain('recipient rejected')
    expect(logged).not.toContain('550')
    expect(logged).toBe('delivery failed sending mfaEnabled: <error>')
  })

  // The COMPOSITION of two clean components can spell a secret neither contains. `name` and
  // `message` are redacted separately, then joined as `name: message` — so a declared secret of
  // `Error: boom` matches neither half and appears in full in the joined line. The end-to-end
  // redaction over the finished description is what covers it, and this pins that rather than
  // the per-component pass which looks sufficient and is not.
  it('removes a secret formed by joining two clean components', async () => {
    sink.send.mockRejectedValueOnce(new Error('boom'))

    await provider.sendPasswordResetOtp('t', 'u@example.com', 'Error: boom')

    const logged = errorSpy.mock.calls[0]?.[0] as string
    expect(logged).not.toContain('Error: boom')
  })

  // Redaction runs per component, and things happen AFTER it: `logSafe` replaces a
  // control-character value with `<malformed>`, a failed link becomes `<malformed-error>`, and the
  // links are joined with a separator. Each writes text the per-component pass never saw, so a
  // caller whose declared secret is one of those markers gets it published by the function meant
  // to remove it. Here the message is a bare newline, `logSafe` turns it into `<malformed>`, and
  // that string is the declared secret — so the finished line must not contain it.
  it('removes a secret that redaction itself created downstream', async () => {
    sink.send.mockRejectedValueOnce(new Error('\n'))

    await provider.sendPasswordResetOtp('t', 'u@example.com', '<malformed>')

    const logged = errorSpy.mock.calls[0]?.[0] as string
    expect(logged).not.toContain('<malformed>')
  })

  // The bound is on the WHOLE line, not on each link of the chain. Capping per link lets a
  // three-deep chain contribute three times the budget — measured at 608 characters for a limit
  // of 200 — which defeats the point: the cap exists so a channel cannot relay an unbounded
  // quantity of its own text into a log, and a cause chain is the channel's text just as its
  // message is. The single-link cap test above passes either way, so this is what pins it.
  it('caps the whole chain, not each link of it', async () => {
    sink.send.mockRejectedValueOnce(
      new Error('a'.repeat(300), {
        cause: new Error('b'.repeat(300), { cause: new Error('c'.repeat(300)) })
      })
    )

    await provider.sendPasswordResetOtp('t', 'u@example.com', '246813')

    const logged = errorSpy.mock.calls[0]?.[0] as string
    expect(logged.length).toBeLessThan(270)
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
      text: 'Branded body.',
      // Overriding the copy does not change WHICH message this is, and the credential fact is
      // taken from the kind rather than from the rendered words — a consumer rewriting a notice
      // cannot make the provider misdeclare what the body carries, in either direction.
      kind: 'mfaEnabled',
      containsCredential: false
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
