/**
 * @fileoverview The workspace invitation message of `DefaultAuthEmailProvider`: its copy, its
 * escaping, the credential declaration and the delivery-error policy, which are the ones every
 * other message of the provider follows.
 *
 * @layer Test
 */

import { Logger } from '@nestjs/common'

import { DefaultAuthEmailProvider, type AuthEmailSink } from './default-auth-email.provider'
import { BOOTSTRAP_INVITE, WORKSPACE_INVITE } from './__tests__/workspace-invite.fixture'

/** Escapes as the provider does, so the expected HTML is computed independently of it. */
function esc(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

/** The HTML the provider renders for a plain-text body: one escaped paragraph per block. */
function html(text: string): string {
  return text
    .split('\n\n')
    .map((paragraph) => `<p>${esc(paragraph).replace(/\n/g, '<br>')}</p>`)
    .join('\n')
}

type Send = Parameters<AuthEmailSink['send']>[0]

const INVITE = WORKSPACE_INVITE
const BOOTSTRAP = BOOTSTRAP_INVITE
const TOKEN = INVITE.inviteToken
const EXPIRES = INVITE.expiresAt

describe('DefaultAuthEmailProvider.sendWorkspaceInvitation', () => {
  let send: jest.Mock<Promise<unknown>, [Send]>
  let provider: DefaultAuthEmailProvider

  beforeEach(() => {
    send = jest.fn<Promise<unknown>, [Send]>().mockResolvedValue(undefined)
    provider = new DefaultAuthEmailProvider({ send })
    jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  const sent = (): Send => {
    const call = send.mock.calls.at(-1)
    if (call === undefined) throw new Error('the sink was not called')
    return call[0]
  }

  it('is implemented, so the module can enable workspace invitations with the default provider', () => {
    expect(typeof provider.sendWorkspaceInvitation).toBe('function')
  })

  it('sends the inviter, workspace, role, token and expiry to the invitee', async () => {
    await provider.sendWorkspaceInvitation('tenant-1', 'invitee@example.com', INVITE)

    const text =
      'Ada invited you to the workspace Platform as admin.\n\n' +
      `Sign in and use this token to accept: ${TOKEN}\n\n` +
      'It expires on 2026-12-31T23:59:59.000Z.\n\n' +
      'If you were not expecting this invitation, ignore this message.'
    expect(sent()).toEqual({
      tenantId: 'tenant-1',
      to: 'invitee@example.com',
      subject: 'Ada invited you to Platform',
      html: html(text),
      text,
      kind: 'workspaceInvitation',
      containsCredential: true
    })
  })

  it('asks an invitee with no account to create one', async () => {
    await provider.sendWorkspaceInvitation('t', 'new@example.com', {
      ...INVITE,
      accountExists: false
    })

    expect(sent().text).toContain(`Create your account and use this token to accept: ${TOKEN}`)
    expect(sent().text).not.toContain('Sign in and use')
  })

  it('invites to set up the workspace as its owner for a bootstrap invitation, naming the sender', async () => {
    await provider.sendWorkspaceInvitation('t', 'o@example.com', BOOTSTRAP)

    expect(sent().subject).toBe('Ada invited you to set up Platform')
    expect(sent().text.split('\n\n')[0]).toBe(
      'Ada invited you to set up the workspace Platform as its owner.'
    )
    expect(sent().text).not.toContain('as owner')
  })

  it('names no sender for a bootstrap invitation when the platform gave none', async () => {
    for (const inviterName of ['', '   ']) {
      await provider.sendWorkspaceInvitation('t', 'o@example.com', { ...BOOTSTRAP, inviterName })

      expect(sent().subject).toBe('You have been invited to set up Platform')
      expect(sent().text.split('\n\n')[0]).toBe(
        'You have been invited to set up the workspace Platform as its owner.'
      )
    }
  })

  it('keeps the sign-in and sign-up wording for a bootstrap invitation', async () => {
    await provider.sendWorkspaceInvitation('t', 'o@example.com', {
      ...BOOTSTRAP,
      accountExists: false
    })

    expect(sent().text).toContain(`Create your account and use this token to accept: ${TOKEN}`)
  })

  it.each([
    ['a member invitation', INVITE],
    ['a bootstrap invitation', BOOTSTRAP]
  ])('escapes every HTML metacharacter of the text the sender chose in %s', async (_name, base) => {
    await provider.sendWorkspaceInvitation('t', 'u@example.com', {
      ...base,
      inviterName: `<b>"A"</b> & 'B'`,
      workspaceName: '<script>x</script>'
    })

    expect(sent().html).toContain('&lt;b&gt;&quot;A&quot;&lt;/b&gt; &amp; &#39;B&#39;')
    expect(sent().html).toContain('&lt;script&gt;x&lt;/script&gt;')
    expect(sent().html).not.toContain('<script>')
    expect(sent().html).not.toContain('<b>')
  })

  it('strips CR and LF from the subject', async () => {
    await provider.sendWorkspaceInvitation('t', 'u@example.com', {
      ...INVITE,
      inviterName: 'Ada\r\nBcc: x@example.com'
    })

    expect(sent().subject).toBe('Ada Bcc: x@example.com invited you to Platform')
  })

  it('swallows a delivery failure and logs only its own label', async () => {
    const logError = jest.spyOn(Logger.prototype, 'error')
    send.mockRejectedValue(new Error(`550 refused: ${TOKEN}`))

    await expect(
      provider.sendWorkspaceInvitation('t', 'u@example.com', INVITE)
    ).resolves.toBeUndefined()

    const logged = JSON.stringify(logError.mock.calls)
    expect(logged).toContain('workspaceInvitation')
    expect(logged).not.toContain(TOKEN)
  })

  it('re-throws the channel error under the policy for this message and no other', async () => {
    const failure = new Error('channel down')
    send.mockRejectedValue(failure)
    const strict = new DefaultAuthEmailProvider(
      { send },
      { onDeliveryError: { workspaceInvitation: 'rethrow' } }
    )

    await expect(strict.sendWorkspaceInvitation('t', 'u@example.com', INVITE)).rejects.toBe(failure)
    await expect(
      strict.sendInvitation('t', 'u@example.com', {
        inviterName: 'A',
        tenantName: 'T',
        inviteToken: TOKEN,
        expiresAt: EXPIRES
      })
    ).resolves.toBeUndefined()
  })

  it('uses the product copy an override supplies, still escaping and still flagging the credential', async () => {
    const custom = new DefaultAuthEmailProvider(
      { send },
      {
        messages: {
          workspaceInvitation: ({ invite }) => ({
            subject: `Join ${invite.workspaceName}`,
            text: `<i>${invite.inviteToken}</i>`
          })
        }
      }
    )

    await custom.sendWorkspaceInvitation('t', 'u@example.com', INVITE)

    expect(sent().subject).toBe('Join Platform')
    expect(sent().html).toBe(`<p>&lt;i&gt;${TOKEN}&lt;/i&gt;</p>`)
    expect(sent().containsCredential).toBe(true)
  })
})
