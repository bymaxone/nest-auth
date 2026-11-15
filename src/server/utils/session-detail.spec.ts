/**
 * @fileoverview The per-session detail records written beside a refresh session, and the
 * User-Agent description they carry.
 *
 * The expected bytes below were captured from the code that wrote these records before they moved
 * into the step that creates the session (`SessionService.createSession` for `sd:` and
 * `TokenManagerService` for `psd:`), with the clock fixed. They are the bytes the sibling backend
 * sharing the Redis reads, so they are pinned as captured and not derived again.
 */

import {
  dashboardSessionDetail,
  parseUserAgent,
  platformSessionDetail,
  platformSessionExtra
} from './session-detail'

const NOW = 1_700_000_000_000

/** [ip, user agent, the `sd:` value the dashboard wrote for them]. */
const DASHBOARD: Array<[string, string, string]> = [
  [
    '192.168.1.1',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    '{"device":"Chrome on macOS","ip":"192.168.1.1","createdAt":1700000000000,"lastActivityAt":1700000000000}'
  ],
  [
    '2001:0db8:85a3:0000:0000:8a2e:0370:7334:extra-oversized-forwarded-value-0123456789',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
    '{"device":"Safari on iOS","ip":"2001:0db8:85a3:0000:0000:8a2e:0370:7334:extra","createdAt":1700000000000,"lastActivityAt":1700000000000}'
  ],
  [
    '10.0.0.9',
    'curl/8.4.0 — ünïcode ☃',
    '{"device":"Unknown Browser on Unknown OS","ip":"10.0.0.9","createdAt":1700000000000,"lastActivityAt":1700000000000}'
  ]
]

/** [ip, user agent, the `psd:` value the platform wrote for them]. */
const PLATFORM: Array<[string, string, string]> = [
  [
    '192.168.1.1',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    '{"device":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_","ip":"192.168.1.1","createdAt":1700000000000,"lastActivityAt":1700000000000}'
  ],
  [
    '2001:0db8:85a3:0000:0000:8a2e:0370:7334:extra-oversized-forwarded-value-0123456789',
    'curl/8.4.0 — ünïcode ☃',
    '{"device":"curl/8.4.0 — ünïcode ☃","ip":"2001:0db8:85a3:0000:0000:8a2e:0370:7334:extra","createdAt":1700000000000,"lastActivityAt":1700000000000}'
  ]
]

describe('session detail records', () => {
  it.each(DASHBOARD)(
    'writes the dashboard record for %s as it always has',
    (ip, userAgent, expected) => {
      expect(dashboardSessionDetail(ip, userAgent, NOW)).toBe(expected)
    }
  )

  it.each(PLATFORM)(
    'writes the platform record for %s as it always has',
    (ip, userAgent, expected) => {
      expect(platformSessionDetail(ip, userAgent, NOW)).toBe(expected)
    }
  )

  // Scenario: the record handed to the session-creating step for a platform session. Expected: the
  // `psd:` key for the token hash, the same bytes, and the lifetime it was given.
  it('pairs the platform record with its key and lifetime', () => {
    jest.spyOn(Date, 'now').mockReturnValue(NOW)
    const [ip, userAgent, expected] = PLATFORM[0] ?? ['', '', '']

    expect(platformSessionExtra('abc123', ip, userAgent, 604_800)).toEqual({
      key: 'psd:abc123',
      value: expected,
      ttl: 604_800
    })
    jest.restoreAllMocks()
  })
})

describe('parseUserAgent', () => {
  it.each([
    ['Edge', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/123.0'],
    ['Opera', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 OPR/123.0'],
    [
      'Safari',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15'
    ],
    [
      'Android',
      'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Chrome/112.0 Mobile Safari/537.36'
    ],
    [
      'iOS',
      'Mozilla/5.0 (iPhone; CPU iPhone OS 16_4 like Mac OS X) AppleWebKit/605.1.15 Version/16.4 Mobile Safari/604.1'
    ],
    [
      'Windows',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/112.0 Safari/537.36'
    ],
    ['Linux', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/112.0 Safari/537.36'],
    [
      'Chrome',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    ],
    ['Firefox', 'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0'],
    [
      'macOS',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15'
    ]
  ])('names %s from its token', (label, userAgent) => {
    expect(parseUserAgent(userAgent)).toContain(label)
  })

  // Scenario: a user agent that matches nothing. Expected: both defaults, spelled out.
  it('labels an unrecognised user-agent as Unknown Browser on Unknown OS', () => {
    expect(parseUserAgent('curl/7.88.1')).toBe('Unknown Browser on Unknown OS')
  })

  // Scenario: a Safari token with no Version token. Expected: not labelled Safari.
  // Why: both tokens are needed; Chrome and others carry the Safari token alone.
  it('does not label a Safari-token-only UA (no Version) as Safari', () => {
    const device = parseUserAgent('Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 Safari/605.1.15')

    expect(device).toContain('Unknown Browser')
    expect(device).not.toContain('Safari')
  })
})
