/**
 * Unit tests for `src/nextjs/helpers/dedupeSetCookieHeaders.ts`.
 *
 * Exercises every exported symbol:
 *
 *   - `parseSetCookieHeader`: attribute parsing, case-insensitivity,
 *     CRLF rejection, length bound, SameSite normalisation, unknown
 *     attributes preserved in `rawAttributes`.
 *   - `dedupeSetCookieHeaders`: `(name, domain)` keying with
 *     last-writer-wins semantics, filtering of malformed entries.
 *   - `getSetCookieHeaders`: modern `getSetCookie()` path and the
 *     legacy comma-joined fallback (including the `Expires=Wed, 09 Jun …`
 *     non-split rule).
 */

import {
  dedupeSetCookieHeaders,
  getSetCookieHeaders,
  parseSetCookieHeader
} from '../helpers/dedupeSetCookieHeaders'

describe('parseSetCookieHeader', () => {
  // Happy path: every known attribute is parsed into its typed slot.
  it('parses a fully-attributed Set-Cookie into the typed record', () => {
    const parsed = parseSetCookieHeader(
      'sid=abc; HttpOnly; Secure; SameSite=Lax; Path=/; Domain=Example.com; Max-Age=3600; Expires=Wed, 09 Jun 2021 10:18:14 GMT'
    )
    expect(parsed.name).toBe('sid')
    expect(parsed.value).toBe('abc')
    expect(parsed.httpOnly).toBe(true)
    expect(parsed.secure).toBe(true)
    expect(parsed.sameSite).toBe('lax')
    expect(parsed.path).toBe('/')
    // Domain is lowercased so dedup keys collide correctly.
    expect(parsed.domain).toBe('example.com')
    expect(parsed.maxAge).toBe(3600)
    expect(parsed.expires).toBe('Wed, 09 Jun 2021 10:18:14 GMT')
  })

  // Attribute names are case-insensitive per RFC 6265.
  it('matches attribute names case-insensitively', () => {
    const parsed = parseSetCookieHeader('sid=abc; HTTPONLY; SameSITE=Strict')
    expect(parsed.httpOnly).toBe(true)
    expect(parsed.sameSite).toBe('strict')
  })

  // SameSite=None must be preserved verbatim (browsers require this
  // value to be paired with Secure).
  it('preserves SameSite=None', () => {
    expect(parseSetCookieHeader('sid=abc; SameSite=None').sameSite).toBe('none')
  })

  // Unknown SameSite values leave the typed field undefined but the
  // raw attribute survives in rawAttributes.
  it('drops unknown SameSite values from the typed field', () => {
    const parsed = parseSetCookieHeader('sid=abc; SameSite=Extended')
    expect(parsed.sameSite).toBeUndefined()
    expect(parsed.rawAttributes.some((a) => /SameSite=Extended/i.test(a))).toBe(true)
  })

  // Unparsable Max-Age stays undefined (stays conservative).
  it('ignores a non-numeric Max-Age', () => {
    expect(parseSetCookieHeader('sid=abc; Max-Age=abc').maxAge).toBeUndefined()
  })

  // CRLF rejection — the top-level header-smuggling guard.
  it('rejects inputs containing CR or LF', () => {
    expect(parseSetCookieHeader('sid=abc\r\nX-Inject: 1').name).toBe('')
    expect(parseSetCookieHeader('sid=abc\nbogus').name).toBe('')
  })

  // Oversized inputs are dropped to prevent pathological parsing.
  it('rejects inputs longer than the 8192-byte limit', () => {
    const huge = `sid=${'a'.repeat(9000)}`
    expect(parseSetCookieHeader(huge).name).toBe('')
  })

  // No `=` in first segment → empty record (filtered by dedupe).
  it('returns an empty record for malformed input (no =)', () => {
    const parsed = parseSetCookieHeader('justatoken; Path=/')
    expect(parsed.name).toBe('')
  })

  // Inner whitespace in the cookie value is preserved. Outer
  // whitespace around the `;` separator is consumed by segment
  // trimming — the segment boundary is ambiguous otherwise.
  it('preserves inner whitespace inside the cookie value', () => {
    const parsed = parseSetCookieHeader('sid=first second; Path=/')
    expect(parsed.value).toBe('first second')
  })

  // Unknown attributes are retained verbatim in rawAttributes for
  // round-trip preservation.
  it('preserves unknown attributes in rawAttributes', () => {
    const parsed = parseSetCookieHeader('sid=abc; Priority=High; Partitioned')
    expect(parsed.rawAttributes).toContain('Priority=High')
    expect(parsed.rawAttributes).toContain('Partitioned')
  })

  // Double-semicolon → empty attribute segment → should be skipped.
  // Exercises the `if (attribute.length === 0) continue` branch.
  it('skips empty attribute segments (double semicolon)', () => {
    const parsed = parseSetCookieHeader('sid=abc;; Path=/')
    expect(parsed.name).toBe('sid')
    expect(parsed.path).toBe('/')
  })

  // Attribute without an `=` (e.g. a bare `HttpOnly` token) must
  // parse the NAME only and leave the value empty.
  it('handles attribute tokens without = (HttpOnly flag)', () => {
    const parsed = parseSetCookieHeader('sid=abc; HttpOnly')
    expect(parsed.httpOnly).toBe(true)
  })

  // SameSite without a value — leaves the typed field undefined.
  it('leaves sameSite undefined when SameSite= has no value', () => {
    const parsed = parseSetCookieHeader('sid=abc; SameSite=')
    expect(parsed.sameSite).toBeUndefined()
  })
})

describe('parseSetCookieHeader — RFC 6265 token character coverage', () => {
  // The token alphabet includes unusual but valid characters:
  // `!#$%&'*+-.^_` + backtick + `|~`. Exercising a cookie whose name
  // uses these chars guarantees `isCookieNameChar` (used by the
  // legacy splitter) has exercised every switch-case branch.
  it('accepts cookie names with tilde, backtick, and pipe characters', () => {
    const parsed = parseSetCookieHeader('foo~name`|=value; Path=/')
    expect(parsed.name).toBe('foo~name`|')
    expect(parsed.value).toBe('value')
  })

  // The `isCookieNameChar` switch is also exercised indirectly by
  // `getSetCookieHeaders`' legacy splitter — this drives the same
  // branches via that path so the coverage tool sees every case hit.
  it('splits legacy cookies with tilde/backtick/pipe characters in the name', () => {
    const { getSetCookieHeaders } = jest.requireActual(
      '../helpers/dedupeSetCookieHeaders'
    ) as typeof import('../helpers/dedupeSetCookieHeaders')
    const headers = {
      get: (name: string) =>
        name.toLowerCase() === 'set-cookie' ? 'a~=1; Path=/, b|=2; Path=/, c`=3; Path=/' : null
    }
    expect(getSetCookieHeaders(headers)).toHaveLength(3)
  })

  // A/Z uppercase cookie names in the legacy splitter — exercises
  // the A-Z range branch inside `isCookieNameChar`.
  it('splits legacy cookies whose names use uppercase ASCII', () => {
    const { getSetCookieHeaders } = jest.requireActual(
      '../helpers/dedupeSetCookieHeaders'
    ) as typeof import('../helpers/dedupeSetCookieHeaders')
    const headers = {
      get: (name: string) =>
        name.toLowerCase() === 'set-cookie' ? 'Access=1; Path=/, Refresh=2; Path=/api' : null
    }
    expect(getSetCookieHeaders(headers)).toHaveLength(2)
  })

  // Digit-first cookie name — exercises the 0-9 range branch.
  it('splits legacy cookies whose names start with a digit', () => {
    const { getSetCookieHeaders } = jest.requireActual(
      '../helpers/dedupeSetCookieHeaders'
    ) as typeof import('../helpers/dedupeSetCookieHeaders')
    const headers = {
      get: (name: string) =>
        name.toLowerCase() === 'set-cookie' ? '1session=a; Path=/, 2session=b; Path=/' : null
    }
    expect(getSetCookieHeaders(headers)).toHaveLength(2)
  })

  // Comma followed by a non-token (no `=`) — exercises the
  // `tokenLength === 0 → false` tail of the lookahead.
  it('does not split at a comma when the lookahead has no following =', () => {
    const { getSetCookieHeaders } = jest.requireActual(
      '../helpers/dedupeSetCookieHeaders'
    ) as typeof import('../helpers/dedupeSetCookieHeaders')
    const headers = { get: () => 'sid=abc, trailing' }
    expect(getSetCookieHeaders(headers)).toEqual(['sid=abc, trailing'])
  })

  // Comma immediately followed by a non-token character (double
  // quote) so `isCookieNameChar` returns false on the very first
  // lookahead iteration — this exercises the `tokenLength === 0`
  // branch of `looksLikeCookieStart`.
  it('does not split at a comma when the immediate following char is not a token char', () => {
    const { getSetCookieHeaders } = jest.requireActual(
      '../helpers/dedupeSetCookieHeaders'
    ) as typeof import('../helpers/dedupeSetCookieHeaders')
    const headers = { get: () => 'sid=abc, "quoted"' }
    expect(getSetCookieHeaders(headers)).toEqual(['sid=abc, "quoted"'])
  })

  // Every remaining RFC 6265 token character `!#$%&'*+-.^_` — each
  // one is a separate `switch` case in `isCookieNameChar`. Parsing
  // a cookie whose NAME contains every such character exercises
  // them all in one go.
  it('accepts every RFC 6265 token character in a cookie name', () => {
    const parsed = parseSetCookieHeader(`!#$%&'*+-.^_=value; Path=/`)
    expect(parsed.name).toBe(`!#$%&'*+-.^_`)
    expect(parsed.value).toBe('value')
  })

  // Same token characters via the legacy splitter so the
  // `isCookieNameChar` switch is entered from the splitter path.
  // Each cookie after the FIRST sits immediately after a comma, so
  // the lookahead enters `isCookieNameChar` with the cookie's first
  // character — this exercises every specific `case` branch of the
  // switch, which is what the branch coverage report asks for.
  it('splits legacy cookies whose names start with each RFC 6265 token character', () => {
    const { getSetCookieHeaders } = jest.requireActual(
      '../helpers/dedupeSetCookieHeaders'
    ) as typeof import('../helpers/dedupeSetCookieHeaders')
    const headers = {
      get: (name: string) =>
        name.toLowerCase() === 'set-cookie'
          ? `sid=start; Path=/, !a=1; Path=/, #b=2; Path=/, $c=3; Path=/, %d=4; Path=/, &e=5; Path=/, 'f=6; Path=/, *g=7; Path=/, +h=8; Path=/, -i=9; Path=/, .j=10; Path=/, ^k=11; Path=/, _l=12; Path=/`
          : null
    }
    expect(getSetCookieHeaders(headers)).toHaveLength(13)
  })
})

describe('dedupeSetCookieHeaders', () => {
  // Last-writer-wins on (name, domain).
  it('keeps the LAST writer for duplicate (name, domain) pairs', () => {
    const result = dedupeSetCookieHeaders([
      'sid=first; Domain=example.com; Path=/',
      'sid=second; Domain=example.com; Path=/'
    ])
    expect(result).toHaveLength(1)
    expect(result[0]).toContain('sid=second')
  })

  // Different domains → different keys → both retained.
  it('retains cookies with different Domain attributes', () => {
    const result = dedupeSetCookieHeaders([
      'sid=tenant-a; Domain=a.example.com; Path=/',
      'sid=tenant-b; Domain=b.example.com; Path=/'
    ])
    expect(result).toHaveLength(2)
  })

  // Different names → both retained.
  it('retains cookies with different names', () => {
    const result = dedupeSetCookieHeaders(['access=1; Path=/', 'refresh=2; Path=/api/auth'])
    expect(result).toHaveLength(2)
  })

  // Domain-less cookie uses '' as domain component — distinct from a
  // cookie with an explicit Domain attribute.
  it('distinguishes domain-less cookies from domain-bearing ones', () => {
    const result = dedupeSetCookieHeaders([
      'sid=noDomain; Path=/',
      'sid=withDomain; Domain=example.com; Path=/'
    ])
    expect(result).toHaveLength(2)
  })

  // Malformed entries are dropped silently (empty name → filtered).
  it('drops malformed entries', () => {
    const result = dedupeSetCookieHeaders(['valid=1; Path=/', 'not-a-cookie', 'another=2; Path=/'])
    expect(result).toHaveLength(2)
  })

  // Preserves original ordering of the winners (by last-seen index).
  it('preserves the relative order of winners by last-occurrence index', () => {
    const result = dedupeSetCookieHeaders(['a=1; Path=/', 'b=1; Path=/', 'a=2; Path=/'])
    // `a` last occurs at index 2, `b` at index 1. Sorted ascending:
    // b (idx 1) before a (idx 2).
    expect(result[0]).toContain('b=1')
    expect(result[1]).toContain('a=2')
  })

  // Empty input → empty output.
  it('returns an empty array for an empty input', () => {
    expect(dedupeSetCookieHeaders([])).toEqual([])
  })
})

describe('getSetCookieHeaders', () => {
  // Modern path: uses `getSetCookie()` when available.
  it('uses getSetCookie() when present', () => {
    const headers = {
      get: () => null,
      getSetCookie: () => ['a=1; Path=/', 'b=2; Path=/']
    }
    expect(getSetCookieHeaders(headers)).toEqual(['a=1; Path=/', 'b=2; Path=/'])
  })

  // Legacy path: no getSetCookie → fall back to `get('set-cookie')`
  // with the comma-split heuristic.
  it('falls back to get("set-cookie") when getSetCookie is absent', () => {
    const headers = {
      get: (name: string) =>
        name.toLowerCase() === 'set-cookie' ? 'a=1; Path=/, b=2; Path=/' : null
    }
    expect(getSetCookieHeaders(headers)).toEqual(['a=1; Path=/', 'b=2; Path=/'])
  })

  // No set-cookie header at all → empty array.
  it('returns an empty array when no set-cookie header is present', () => {
    const headers = { get: () => null }
    expect(getSetCookieHeaders(headers)).toEqual([])
  })

  // Empty set-cookie header → empty array.
  it('returns an empty array for an empty set-cookie header value', () => {
    const headers = { get: () => '' }
    expect(getSetCookieHeaders(headers)).toEqual([])
  })

  // Expires comma inside the value must NOT be treated as a separator.
  // This is the critical correctness case for the legacy splitter.
  it('does not split at a comma inside an Expires attribute value', () => {
    const headers = {
      get: (name: string) =>
        name.toLowerCase() === 'set-cookie'
          ? 'sid=abc; Expires=Wed, 09 Jun 2021 10:18:14 GMT; Path=/, sid=xyz; Path=/api'
          : null
    }
    const result = getSetCookieHeaders(headers)
    expect(result).toHaveLength(2)
    expect(result[0]).toContain('Expires=Wed, 09 Jun 2021 10:18:14 GMT')
    expect(result[1]).toContain('sid=xyz')
  })

  // OWS (horizontal tab) after the comma is also a valid separator.
  it('treats comma + horizontal tab as a separator', () => {
    const headers = {
      get: (name: string) =>
        name.toLowerCase() === 'set-cookie' ? 'a=1; Path=/,\tb=2; Path=/' : null
    }
    expect(getSetCookieHeaders(headers)).toHaveLength(2)
  })

  // A comma followed by non-token garbage is NOT a separator.
  it('does not split at a comma followed by non-token garbage', () => {
    const headers = {
      get: () => 'sid=abc,xyz; Path=/'
    }
    expect(getSetCookieHeaders(headers)).toEqual(['sid=abc,xyz; Path=/'])
  })

  // Oversized combined value is rejected to prevent O(N²) blowups.
  it('returns an empty array when the combined value exceeds the hard cap', () => {
    const huge = 'a=' + 'x'.repeat(8192 * 64 + 1)
    const headers = { get: () => huge }
    expect(getSetCookieHeaders(headers)).toEqual([])
  })
})
