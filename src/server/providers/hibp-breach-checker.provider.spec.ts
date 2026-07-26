/**
 * @fileoverview Tests for the Have I Been Pwned breach checker and the allow-all default.
 *
 * The two properties that matter here are that the password never leaves the process, and
 * that an unavailable corpus approves rather than blocks — a breach check must not become a
 * dependency of the credential path.
 */

import { createHash } from 'node:crypto'

import { Logger } from '@nestjs/common'

import { AllowAllBreachChecker, HibpBreachChecker } from './hibp-breach-checker.provider'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const PASSWORD = 'correct horse battery staple'

/** The SHA-1 of the password, upper-cased, as the range API indexes it. */
const DIGEST = createHash('sha1').update(PASSWORD, 'utf8').digest('hex').toUpperCase()
const PREFIX = DIGEST.slice(0, 5)
const SUFFIX = DIGEST.slice(5)

/** A range response containing the password's suffix among unrelated ones. */
const HIT_BODY = [`0000000000000000000000000000000000A:3`, `${SUFFIX}:42`, `FFFFF:1`].join('\r\n')

/** A range response with only unrelated suffixes. */
const MISS_BODY = ['0000000000000000000000000000000000A:3', 'FFFFF:1'].join('\r\n')

/** Stub `fetch` with a body and status. */
function stubFetch(body: string, status = 200): jest.Mock {
  const mock = jest.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    text: async () => body
  })
  globalThis.fetch = mock as unknown as typeof fetch
  return mock
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('HibpBreachChecker', () => {
  const originalFetch = globalThis.fetch
  let warn: jest.SpyInstance

  beforeEach(() => {
    warn = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
  })

  afterEach(() => {
    globalThis.fetch = originalFetch
    warn.mockRestore()
  })

  // The k-anonymity property, asserted on the wire: only the five-character prefix is sent.
  // Anything more — the whole digest, let alone the password — would defeat the entire point
  // of using a range query instead of a lookup.
  it('sends only the five-character hash prefix, never the password or the full digest', async () => {
    const fetchMock = stubFetch(MISS_BODY)

    await new HibpBreachChecker().isBreached(PASSWORD)

    const url = String(fetchMock.mock.calls[0]?.[0])
    expect(url).toBe(`https://api.pwnedpasswords.com/range/${PREFIX}`)
    expect(url).not.toContain(SUFFIX)
    expect(url).not.toContain(PASSWORD)
    // Padding hides the true response size from a network observer.
    expect(fetchMock.mock.calls[0]?.[1]).toMatchObject({ headers: { 'Add-Padding': 'true' } })
  })

  // The match itself: the suffix is compared locally against every line of the range.
  it('reports a password whose suffix appears in the range', async () => {
    stubFetch(HIT_BODY)

    await expect(new HibpBreachChecker().isBreached(PASSWORD)).resolves.toBe(true)
  })

  // A range that does not contain the suffix is a clean password, not an error.
  it('approves a password whose suffix is absent from the range', async () => {
    stubFetch(MISS_BODY)

    await expect(new HibpBreachChecker().isBreached(PASSWORD)).resolves.toBe(false)
  })

  // Suffixes come back upper-cased and the comparison must not be thrown by whitespace from
  // the CRLF line endings the service uses.
  it('matches case-insensitively and tolerates whitespace around the suffix', async () => {
    stubFetch(`  ${SUFFIX.toLowerCase()}\t:9\r\n`)

    await expect(new HibpBreachChecker().isBreached(PASSWORD)).resolves.toBe(true)
  })

  // Fail-open, the rule that keeps this from becoming a dependency: a service that is down,
  // rate-limiting, or slow must not stop someone changing their password — least of all during
  // an incident, when changing it is the urgent thing.
  it.each([
    ['a non-OK status', () => stubFetch('', 429)],
    [
      'a network failure',
      () => {
        const mock = jest.fn().mockRejectedValue(new Error('ECONNREFUSED'))
        globalThis.fetch = mock as unknown as typeof fetch
        return mock
      }
    ],
    [
      'a timeout',
      () => {
        const mock = jest
          .fn()
          .mockRejectedValue(Object.assign(new Error('timeout'), { name: 'TimeoutError' }))
        globalThis.fetch = mock as unknown as typeof fetch
        return mock
      }
    ]
  ])('approves the password on %s', async (_label, arrange) => {
    arrange()

    await expect(new HibpBreachChecker().isBreached(PASSWORD)).resolves.toBe(false)
    expect(warn).toHaveBeenCalled()
  })

  // The warning is the operator's only signal that the check silently did not happen, so it
  // must say so — and it must not carry password material.
  it.each([
    ['a refused status', () => stubFetch('', 503), 'breach check unavailable (status 503)'],
    [
      'an unreachable service',
      () => {
        globalThis.fetch = jest
          .fn()
          .mockRejectedValue(new Error('ECONNREFUSED')) as unknown as typeof fetch
      },
      'breach check unreachable'
    ]
  ])(
    'logs that the check did not happen on %s, without the password',
    async (_l, arrange, expected) => {
      arrange()

      await new HibpBreachChecker().isBreached(PASSWORD)

      const logged = warn.mock.calls.map((call) => String(call[0])).join(' ')
      // The two failures are distinguishable in the log: a refusal names the status, an
      // unreachable service cannot, and an operator triages them differently.
      expect(logged).toContain(expected)
      expect(logged).toContain('password allowed')
      expect(logged).not.toContain(PASSWORD)
      expect(logged).not.toContain(SUFFIX)
    }
  )

  // A caller-supplied timeout is honored, so a deployment can tighten the budget it is
  // willing to spend on the check.
  it('honors a caller-supplied timeout', async () => {
    stubFetch(MISS_BODY)

    await new HibpBreachChecker(50).isBreached(PASSWORD)

    const signal = (globalThis.fetch as unknown as jest.Mock).mock.calls[0]?.[1]?.signal as
      | AbortSignal
      | undefined
    expect(signal).toBeInstanceOf(AbortSignal)
  })
})

describe('AllowAllBreachChecker', () => {
  // The default when nothing is wired: the credential path behaves exactly as it did before
  // the check existed, and no network call is made. A library should not start talking to a
  // third party because it was upgraded.
  it('approves every password without reaching the network', async () => {
    const fetchMock = jest.fn()
    globalThis.fetch = fetchMock as unknown as typeof fetch

    await expect(new AllowAllBreachChecker().isBreached('hunter2')).resolves.toBe(false)
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
