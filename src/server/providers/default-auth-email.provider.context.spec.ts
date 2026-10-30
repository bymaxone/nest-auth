/**
 * @fileoverview What every catalogue renderer is told about the delivery it renders for.
 *
 * A renderer builds the message body, and a link inside it has to carry the tenant: a recipient who
 * opens it in a browser with no tenant cookie is refused by a `tenantIdResolver` otherwise. The
 * provider's methods hold the tenant and the recipient, and the renderer is the only place the URL
 * is built, so each renderer must receive both.
 */

import type { InviteData, SessionAlertInfo } from '../interfaces/email-provider.interface'
import {
  AUTH_EMAIL_KINDS,
  DefaultAuthEmailProvider,
  type AuthEmailCatalogue,
  type AuthEmailKind,
  type AuthEmailSink
} from './default-auth-email.provider'

const INVITE: InviteData = {
  inviterName: 'Ada',
  tenantName: 'Acme',
  inviteToken: 'a'.repeat(64),
  expiresAt: new Date('2026-12-31T23:59:59.000Z')
}

const SESSION: SessionAlertInfo = {
  device: 'Chrome on macOS',
  ip: '203.0.113.7',
  sessionHash: 'ab'
}

const TENANT = 'tenant-7'
const EMAIL = 'recipient@example.com'

/** Every provider method, each invoked the way the library invokes it, keyed by the renderer it reaches. */
const SENDERS: Record<AuthEmailKind, (provider: DefaultAuthEmailProvider) => Promise<void>> = {
  passwordResetToken: (p) => p.sendPasswordResetToken(TENANT, EMAIL, 'TOK', 'en'),
  passwordResetOtp: (p) => p.sendPasswordResetOtp(TENANT, EMAIL, '123456', 'en'),
  emailVerificationOtp: (p) => p.sendEmailVerificationOtp(TENANT, EMAIL, '123456', 'en'),
  passwordChanged: (p) => p.sendPasswordChangedNotification(TENANT, EMAIL, 'en'),
  emailChangeVerification: (p) => p.sendEmailChangeVerification(TENANT, EMAIL, 'TOK', 'en'),
  emailChanged: (p) => p.sendEmailChangedNotification(TENANT, EMAIL, 'new@example.com', 'en'),
  mfaEnabled: (p) => p.sendMfaEnabledNotification(TENANT, EMAIL, 'en'),
  mfaDisabled: (p) => p.sendMfaDisabledNotification(TENANT, EMAIL, 'en'),
  newSessionAlert: (p) => p.sendNewSessionAlert(TENANT, EMAIL, SESSION, 'en'),
  invitation: (p) => p.sendInvitation(TENANT, EMAIL, INVITE, 'en')
}

/** A catalogue whose every renderer records the input it was given. */
function recordingCatalogue(seen: Map<AuthEmailKind, unknown>): AuthEmailCatalogue {
  const entries = AUTH_EMAIL_KINDS.map((kind) => [
    kind,
    (input: unknown) => {
      seen.set(kind, input)
      return { subject: kind, text: kind }
    }
  ])
  return Object.fromEntries(entries) as unknown as AuthEmailCatalogue
}

describe('the input every catalogue renderer receives', () => {
  const sink: AuthEmailSink = { send: jest.fn().mockResolvedValue(undefined) }

  // Scenario: each of the ten messages is sent. Expected: its renderer is told the tenant and the
  // recipient, next to the fields of its own message. Why: a link built inside a renderer cannot carry
  // `tenantId` otherwise, and the consumer's only workarounds are a shared mutable field on the
  // singleton provider (a cross-tenant race) or re-implementing the renderer.
  it.each(AUTH_EMAIL_KINDS)('tells the %s renderer the tenant and the recipient', async (kind) => {
    const seen = new Map<AuthEmailKind, unknown>()
    const provider = new DefaultAuthEmailProvider(sink, { messages: recordingCatalogue(seen) })

    await SENDERS[kind](provider)

    expect(seen.get(kind)).toEqual(expect.objectContaining({ tenantId: TENANT, email: EMAIL }))
  })

  // Scenario: the notice that goes to the previous address while naming both. Expected: `email` is
  // the address the message is delivered to, and the old and new addresses are passed as their own fields. Why:
  // `email` means "the recipient" for every renderer, so a renderer can address its reader without
  // knowing which message it renders.
  it('keeps the recipient apart from the addresses the emailChanged notice names', async () => {
    const seen = new Map<AuthEmailKind, unknown>()
    const provider = new DefaultAuthEmailProvider(sink, { messages: recordingCatalogue(seen) })

    await SENDERS.emailChanged(provider)

    expect(seen.get('emailChanged')).toEqual(
      expect.objectContaining({
        email: EMAIL,
        oldEmail: EMAIL,
        newEmail: 'new@example.com'
      })
    )
  })
})
