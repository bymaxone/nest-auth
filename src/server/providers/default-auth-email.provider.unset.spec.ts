/**
 * @fileoverview A message override that holds `undefined` is unset: the default copy is sent, as if
 * the key were absent, instead of a message with no body.
 *
 * @layer Test
 */

import { DefaultAuthEmailProvider } from './default-auth-email.provider'
import type { AuthEmailSink } from './default-auth-email.provider'

/** A sink that records what it was asked to send. */
function makeSink(): { send: jest.Mock<Promise<unknown>, [Parameters<AuthEmailSink['send']>[0]]> } {
  return { send: jest.fn<Promise<unknown>, [Parameters<AuthEmailSink['send']>[0]]>() }
}

describe('DefaultAuthEmailProvider overrides that are unset', () => {
  // Scenario: an override key holding `undefined`, such as a copy read from a missing translation.
  // Expected: the default copy is sent, with the token in it.
  it('keeps the default copy for an override that holds undefined', async () => {
    const sink = makeSink()
    sink.send.mockResolvedValue({ messageId: 'mid' })
    const messages = Object.defineProperty({}, 'passwordResetToken', {
      value: undefined,
      enumerable: true
    })
    const provider = new DefaultAuthEmailProvider(sink, { messages })

    await provider.sendPasswordResetToken('tenant-1', 'user@example.com', 'TOK')

    const sent = sink.send.mock.calls.at(-1)?.[0]
    expect(sent?.subject.length).toBeGreaterThan(0)
    expect(sent?.text).toContain('TOK')
  })
})
