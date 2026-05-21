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
    // CR-only (bare \r, no \n) must also be rejected — pins the CR half of the
    // smuggling guard independently of LF. The \r\n and \n cases above both
    // leave LF detection sufficient, so neither catches a dropped CR check.
    expect(parseSetCookieHeader('sid=abc\rX-Inject: 1').name).toBe('')
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

  // A cookie with NO security attributes must report httpOnly/secure
  // as `false`, not `true`. Pins the `let httpOnly = false` /
  // `let secure = false` initialisers (a flipped default would silently
  // mark every cookie as HttpOnly+Secure).
  it('reports httpOnly and secure as false when neither attribute is present', () => {
    const parsed = parseSetCookieHeader('sid=abc; Path=/')
    expect(parsed.httpOnly).toBe(false)
    expect(parsed.secure).toBe(false)
  })

  // The cookie VALUE is everything after the first `=`. When the
  // segment has NO `=` the value must be the empty string — pins the
  // `firstEquals >= 0 ? … : ''` value branch (both the conditional and
  // the `''` literal). A mutated branch would echo the whole token or a
  // sentinel string into `value`.
  it('returns an empty value when the name/value segment has no =', () => {
    expect(parseSetCookieHeader('justatoken; Path=/').value).toBe('')
  })

  // A leading `=` means an empty name and a value taken from index 1.
  // `firstEquals === 0` must still slice the value (`>= 0`, not `> 0`).
  it('extracts the value when the cookie starts with = (empty name)', () => {
    const parsed = parseSetCookieHeader('=value; Path=/')
    expect(parsed.name).toBe('')
    expect(parsed.value).toBe('value')
  })

  // The cookie NAME is trimmed even when internal trailing whitespace
  // precedes the `=` (`sid =abc` → `sid`). Pins the `.trim()` on the
  // name slice; without it the name would carry a trailing space and
  // break the dedup key.
  it('trims trailing whitespace from the cookie name before the =', () => {
    expect(parseSetCookieHeader('sid =abc').name).toBe('sid')
  })

  // `attributeSegments` is `segments.slice(1)` — it must EXCLUDE the
  // name/value segment. Pins the `.slice(1)`; including index 0 would
  // leak `sid=abc` into rawAttributes and treat it as an attribute.
  it('excludes the name/value segment from rawAttributes', () => {
    const parsed = parseSetCookieHeader('sid=abc; Path=/; HttpOnly')
    expect(parsed.rawAttributes).toEqual(['Path=/', 'HttpOnly'])
  })

  // A bare `Path` flag (no `=`) yields an empty Path value — pins the
  // flag-attribute `['', …]` value in `splitAttribute`. A sentinel
  // there would surface as a bogus Path string.
  it('treats a valueless Path attribute as an empty-string path', () => {
    expect(parseSetCookieHeader('sid=abc; Path').path).toBe('')
  })

  // The attribute NAME is trimmed before the case-insensitive match
  // (`Path =/` → `path`). Without the trim the lookup key keeps the
  // trailing space, no case matches, and Path is dropped.
  it('trims the attribute name before matching (space before =)', () => {
    expect(parseSetCookieHeader('sid=abc; Path =/').path).toBe('/')
  })

  // The attribute VALUE is trimmed (`Path= /` → `/`). Without the trim
  // the Path would carry a leading space.
  it('trims the attribute value (space after =)', () => {
    expect(parseSetCookieHeader('sid=abc; Path= /').path).toBe('/')
  })

  // A raw header EXACTLY at the 8192-byte limit must still parse — the
  // guard is `length > MAX`, not `>=`. Pins the boundary so the limit
  // is inclusive of 8192.
  it('parses a header whose length is exactly the 8192-byte limit', () => {
    const raw = `sid=${'a'.repeat(8188)}` // 4 ("sid=") + 8188 = 8192
    expect(raw.length).toBe(8192)
    expect(parseSetCookieHeader(raw).name).toBe('sid')
  })

  // The empty/rejected record (CRLF input here) must report the exact
  // default field values. Pins `value: ''`, `httpOnly: false`,
  // `secure: false`, and `rawAttributes: []` in `emptyParsedCookie`.
  it('returns a fully-empty record for a CRLF-rejected input', () => {
    const parsed = parseSetCookieHeader('sid=abc\r\nX-Inject: 1')
    expect(parsed.name).toBe('')
    expect(parsed.value).toBe('')
    expect(parsed.httpOnly).toBe(false)
    expect(parsed.secure).toBe(false)
    expect(parsed.rawAttributes).toEqual([])
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

  // A domain-LESS cookie (no Domain attribute → `domain === undefined`)
  // and a cookie with an explicit empty `Domain=` (→ `domain === ''`)
  // collapse to the SAME dedup key `name|`, because `domain ?? ''`
  // maps both `undefined` and `''` to `''`. They therefore dedupe to a
  // single winner. Pins the `?? ''` fallback literal in `buildDedupKey`
  // — a sentinel fallback would split the key and keep both cookies.
  it('collapses a domain-less cookie and an explicit empty Domain= to one key', () => {
    const result = dedupeSetCookieHeaders(['sid=1; Path=/', 'sid=2; Domain=; Path=/'])
    expect(result).toHaveLength(1)
    expect(result[0]).toContain('sid=2')
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

  // A combined value EXACTLY at the `8192 * 64` hard cap must still be
  // processed — the guard is `length > cap`, not `>=`. Pins the
  // boundary so the cap is inclusive.
  it('still splits a combined value exactly at the hard cap', () => {
    const exact = 'a=' + 'x'.repeat(8192 * 64 - 2) // 2 + (cap - 2) = cap
    expect(exact.length).toBe(8192 * 64)
    const headers = { get: () => exact }
    expect(getSetCookieHeaders(headers)).toHaveLength(1)
  })

  // The split segment is trimmed (`slice(cursor, index).trim()`). With
  // OWS before the comma the first cookie must come out trimmed
  // (`a=1 ,` → `a=1`). Pins the `.trim()` on the comma-split push.
  it('trims surrounding whitespace from each split cookie', () => {
    const headers = { get: () => 'a=1 , b=2; Path=/' }
    const result = getSetCookieHeaders(headers)
    expect(result).toHaveLength(2)
    expect(result[0]).toBe('a=1')
    expect(result[1]).toBe('b=2; Path=/')
  })

  // A whitespace-only header is NOT empty (length > 0, so it passes the
  // early `combined.length === 0` guard) but splits to a single blank
  // entry that the final `.filter(entry => entry.length > 0)` removes.
  // Pins the trailing filter (and its `length > 0` predicate); without
  // it the result would contain an empty string.
  it('drops a whitespace-only header to an empty array via the length filter', () => {
    const headers = { get: () => '   ' }
    expect(getSetCookieHeaders(headers)).toEqual([])
  })

  // A multi-character cookie name AFTER a comma must trigger a split.
  // The forward token scan (`index + tokenLength`) has to walk the
  // whole name to reach the `=`; a backward scan (`index - tokenLength`)
  // would re-read prior characters, mis-measure the token, and miss the
  // split. Pins the `+` in the lookahead's bounds expression.
  it('splits at a comma preceding a multi-character cookie name', () => {
    const headers = { get: () => 'a=1, bb=2; Path=/' }
    expect(getSetCookieHeaders(headers)).toHaveLength(2)
  })

  // A comma followed immediately by `=` (no token name) must NOT split:
  // `tokenLength === 0` short-circuits to `false` before the `=`
  // lookahead. Pins the `if (tokenLength === 0) return false` guard;
  // without it the `=` would be read as the cookie-start delimiter and
  // force a spurious split.
  it('does not split when a comma is immediately followed by =', () => {
    const headers = { get: () => 'sid=abc,=x' }
    expect(getSetCookieHeaders(headers)).toEqual(['sid=abc,=x'])
  })
})

describe('getSetCookieHeaders — isCookieNameChar range boundaries', () => {
  // Each case puts the boundary character at the START of the SECOND
  // cookie (immediately after `, `) so the legacy splitter's lookahead
  // enters `isCookieNameChar` with exactly that code point. Token
  // characters force a split (length 2); non-token characters suppress
  // it (length 1). These pin every range comparison in
  // `isCookieNameChar`.

  /** Build a header whose second cookie name starts with `firstChar`. */
  function headerWithSecondName(firstChar: string): { get: () => string } {
    return { get: () => `sid=1; Path=/, ${firstChar}x=2; Path=/` }
  }

  // '0' (0x30) is the lower bound of the digit range — it must be a
  // token char. Kills `code >= 0x30` → `code > 0x30`.
  it('splits when the second cookie name starts with "0" (digit lower bound)', () => {
    expect(getSetCookieHeaders(headerWithSecondName('0'))).toHaveLength(2)
  })

  // '9' (0x39) is the upper bound of the digit range. Kills
  // `code <= 0x39` → `code < 0x39`.
  it('splits when the second cookie name starts with "9" (digit upper bound)', () => {
    expect(getSetCookieHeaders(headerWithSecondName('9'))).toHaveLength(2)
  })

  // '/' (0x2f) sits just BELOW the digit range and is NOT a token
  // char, so no split. Kills the `code >= 0x30 && code <= 0x39` →
  // `true && code <= 0x39` conditional (which would wrongly accept it).
  it('does not split when the second cookie name starts with "/" (below digit range)', () => {
    expect(getSetCookieHeaders(headerWithSecondName('/'))).toHaveLength(1)
  })

  // 'A' (0x41) is the lower bound of the uppercase range. Kills
  // `code >= 0x41` → `code > 0x41`.
  it('splits when the second cookie name starts with "A" (uppercase lower bound)', () => {
    expect(getSetCookieHeaders(headerWithSecondName('A'))).toHaveLength(2)
  })

  // 'Z' (0x5a) is the upper bound of the uppercase range. Kills
  // `code <= 0x5a` → `code < 0x5a`.
  it('splits when the second cookie name starts with "Z" (uppercase upper bound)', () => {
    expect(getSetCookieHeaders(headerWithSecondName('Z'))).toHaveLength(2)
  })

  // '[' (0x5b) sits just ABOVE the uppercase range and is NOT a token
  // char, so no split. Kills the `code >= 0x41 && code <= 0x5a` →
  // `code >= 0x41 && true` conditional.
  it('does not split when the second cookie name starts with "[" (above uppercase range)', () => {
    expect(getSetCookieHeaders(headerWithSecondName('['))).toHaveLength(1)
  })

  // 'z' (0x7a) is the upper bound of the lowercase range. Kills
  // `code <= 0x7a` → `code < 0x7a`.
  it('splits when the second cookie name starts with "z" (lowercase upper bound)', () => {
    expect(getSetCookieHeaders(headerWithSecondName('z'))).toHaveLength(2)
  })

  // '{' (0x7b) sits just ABOVE the lowercase range and is NOT a token
  // char, so no split. Kills the `code >= 0x61 && code <= 0x7a` →
  // `code >= 0x61 && true` conditional.
  it('does not split when the second cookie name starts with "{" (above lowercase range)', () => {
    expect(getSetCookieHeaders(headerWithSecondName('{'))).toHaveLength(1)
  })
})
