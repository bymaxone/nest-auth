/**
 * Unit tests for `src/nextjs/helpers/routeHandlerUtils.ts`.
 *
 * Covers the six exported helpers individually — each is small but
 * their error branches are never taken in the main handler tests,
 * so this suite exercises them in isolation. Every case below is
 * a single `it` with a dedicated comment explaining WHY the case
 * exists, because each line is its own slice of the security
 * surface (CRLF smuggling, cookie attribute smuggling, leading-
 * slash rules, etc.).
 */

import {
  assertSafeCookieName,
  assertSafeCookiePath,
  isSafeSameOriginPath,
  isSafeUpstreamPath,
  serializeClearCookie,
  trimTrailingSlash
} from '../helpers/routeHandlerUtils'

describe('serializeClearCookie', () => {
  // Canonical cookie-clear shape. The `Max-Age=0` is what actually expires the
  // cookie; `HttpOnly`/`Secure`/`SameSite=Strict` are reapplied so the overwrite
  // matches the attributes the NestJS server originally set — RFC 6265bis
  // requires the clear's `SameSite` to be at least as strict as the original
  // or the browser may drop the overwrite and leave a stale cookie behind.
  it('produces a Max-Age=0 string with HttpOnly/Secure/SameSite=Strict', () => {
    expect(serializeClearCookie('access_token', '/')).toBe(
      'access_token=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict'
    )
  })

  // The `Path` attribute is forwarded verbatim. The helper does NOT
  // validate it — the caller is expected to have run
  // `assertSafeCookiePath` at factory time — but we confirm the
  // value round-trips into the serialised string.
  it('embeds the provided path verbatim', () => {
    expect(serializeClearCookie('refresh_token', '/api/auth')).toContain('Path=/api/auth')
  })
})

describe('isSafeSameOriginPath — accepted inputs', () => {
  // Ordinary absolute pathname — the happy-path shape used by every
  // same-origin redirect destination (`/auth/login`, `/dashboard`,
  // …).
  it('returns true for a plain absolute pathname', () => {
    expect(isSafeSameOriginPath('/dashboard')).toBe(true)
  })

  // Root path `/` is the minimal valid same-origin pathname and
  // must pass so the final `safeRelativePath(x, '/')` fallback
  // works.
  it('returns true for the root pathname "/"', () => {
    expect(isSafeSameOriginPath('/')).toBe(true)
  })

  // Query and fragment characters are allowed — they land inside
  // a pathname passed to `new URL(path, origin)` which parses them
  // as search/hash without escaping the origin.
  it('returns true for a path carrying query and fragment', () => {
    expect(isSafeSameOriginPath('/deep/path?x=1')).toBe(true)
  })
})

describe('isSafeSameOriginPath — rejected inputs', () => {
  // Protocol-relative URL `//host/path` — the primary open-redirect
  // vector the helper exists to block. `new URL('//evil.com', …)`
  // resolves to `https://evil.com`.
  it('returns false for a protocol-relative URL', () => {
    expect(isSafeSameOriginPath('//evil.com')).toBe(false)
  })

  // No leading slash — would resolve against the base URL and
  // could escape the same-origin assumption on some inputs.
  it('returns false for a relative path without leading slash', () => {
    expect(isSafeSameOriginPath('relative')).toBe(false)
  })

  // Empty string — technically starts with nothing, not `/`;
  // redirecting to an empty path would surprise the browser.
  it('returns false for an empty string', () => {
    expect(isSafeSameOriginPath('')).toBe(false)
  })

  // CR byte embedded in the path — forbidden by RFC 6265 and the
  // classic response-splitting / header-smuggling vector.
  it('returns false for a path containing CR (\\r)', () => {
    expect(isSafeSameOriginPath('/path\r')).toBe(false)
  })

  // LF byte — same smuggling risk as CR; rejected together.
  it('returns false for a path containing LF (\\n)', () => {
    expect(isSafeSameOriginPath('/path\n')).toBe(false)
  })

  // NUL byte — downstream parsers sometimes terminate on NUL,
  // producing a truncated path. Reject at the boundary.
  it('returns false for a path containing NUL (\\0)', () => {
    expect(isSafeSameOriginPath('/path\0')).toBe(false)
  })

  // Backslash — on some runtimes the URL parser normalises `\` to
  // `/`, which can smuggle a protocol-relative `\\evil.com` past
  // the leading-slash check. Reject proactively.
  it('returns false for a path containing a backslash', () => {
    expect(isSafeSameOriginPath('/path\\back')).toBe(false)
  })

  // Defensive: callers are typed against `string`, but a JS-only
  // consumer could slip a non-string through. The helper must not
  // throw — it must return `false`.
  it('returns false for a non-string input', () => {
    expect(isSafeSameOriginPath(123 as unknown as string)).toBe(false)
  })
})

describe('isSafeUpstreamPath — accepted inputs', () => {
  // The canonical upstream refresh endpoint — this is the default
  // path composed into `apiBase` when consumers omit `refreshPath`.
  it('returns true for the default refresh pathname "/auth/refresh"', () => {
    expect(isSafeUpstreamPath('/auth/refresh')).toBe(true)
  })

  // Multi-segment path — proves the helper does not reject deeper
  // namespaces (e.g., versioned APIs like `/v2/auth/refresh`).
  it('returns true for a deep multi-segment path', () => {
    expect(isSafeUpstreamPath('/a/b/c')).toBe(true)
  })

  // Root — used only as a degenerate configuration but must pass
  // the validator since the `/` prefix rule is the sole allow
  // condition.
  it('returns true for the root pathname "/"', () => {
    expect(isSafeUpstreamPath('/')).toBe(true)
  })
})

describe('isSafeUpstreamPath — rejected inputs', () => {
  // Empty — concatenating onto `apiBase` would produce the
  // `apiBase` root, which is almost never what the consumer
  // intended.
  it('returns false for an empty string', () => {
    expect(isSafeUpstreamPath('')).toBe(false)
  })

  // No leading slash — `apiBase + "auth/refresh"` would glue into
  // `https://api.example.comauth/refresh`, silently wrong.
  it('returns false for a path without leading slash', () => {
    expect(isSafeUpstreamPath('auth/no-leading-slash')).toBe(false)
  })

  // Dot-segments — allow redirecting the request to an unintended
  // upstream route (`/auth/../admin`). Rejected outright.
  it('returns false for a path with parent traversal "../"', () => {
    expect(isSafeUpstreamPath('/a/../b')).toBe(false)
  })

  // `?` — the caller supplies a PATHNAME, not a full URL. Letting
  // `?` through would permit an attacker-configured query to ride
  // on the refresh call.
  it('returns false for a path containing a query string "?"', () => {
    expect(isSafeUpstreamPath('/a?x=1')).toBe(false)
  })

  // `#` — same rationale as `?`: fragment characters belong on
  // URLs, not pathnames.
  it('returns false for a path containing a fragment "#"', () => {
    expect(isSafeUpstreamPath('/a#frag')).toBe(false)
  })

  // Backslash — URL normalisation in some runtimes turns `\` into
  // `/`, potentially re-interpreting the path structure.
  it('returns false for a path containing a backslash', () => {
    expect(isSafeUpstreamPath('/a\\b')).toBe(false)
  })

  // CR — header-smuggling byte, same policy as the same-origin
  // path validator.
  it('returns false for a path containing CR (\\r)', () => {
    expect(isSafeUpstreamPath('/a\r')).toBe(false)
  })

  // LF — paired with CR in the smuggling guard.
  it('returns false for a path containing LF (\\n)', () => {
    expect(isSafeUpstreamPath('/a\n')).toBe(false)
  })

  // NUL — same rationale as the same-origin validator.
  it('returns false for a path containing NUL (\\0)', () => {
    expect(isSafeUpstreamPath('/a\0')).toBe(false)
  })

  // Defensive non-string guard.
  it('returns false for a non-string input', () => {
    expect(isSafeUpstreamPath(123 as unknown as string)).toBe(false)
  })
})

describe('assertSafeCookieName', () => {
  // Plain alphanumeric name with underscore — the most common
  // cookie-name shape, expected to pass unchanged.
  it('accepts a plain alphanumeric RFC 6265 token', () => {
    expect(() => assertSafeCookieName('access_token', 'factory', 'label')).not.toThrow()
  })

  // Full set of RFC 6265 token punctuation characters — confirms
  // the regex accepts every legal token codepoint, not just the
  // common letter+digit subset.
  it('accepts a name containing every RFC 6265 token punctuation character', () => {
    expect(() => assertSafeCookieName("a!#$%&'*+-.^_`|~", 'factory', 'label')).not.toThrow()
  })

  // Space is a separator per RFC 7230, not a token character.
  // Allowing it would break server-side cookie parsers that split
  // on whitespace.
  it('rejects a name containing a space', () => {
    expect(() => assertSafeCookieName('bad name', 'factory', 'access')).toThrow(
      /invalid cookie name "bad name" for access/
    )
  })

  // `=` is the name/value separator in a `Set-Cookie` header — a
  // cookie name containing it would confuse every HTTP parser.
  it('rejects a name containing "="', () => {
    expect(() => assertSafeCookieName('bad=name', 'factory', 'label')).toThrow()
  })

  // `;` is the attribute separator — same hazard as `=`. Permitting
  // it would open cookie-attribute-smuggling at the serialisation
  // step.
  it('rejects a name containing ";"', () => {
    expect(() => assertSafeCookieName('bad;name', 'factory', 'label')).toThrow()
  })

  // Empty string — not a valid token per the regex, and a cookie
  // with no name cannot be stored by the browser.
  it('rejects an empty name', () => {
    expect(() => assertSafeCookieName('', 'factory', 'label')).toThrow()
  })

  // CR in the name — classic header-smuggling attempt; must be
  // caught at the validator, not at the Fetch API boundary.
  it('rejects a name containing CR (\\r)', () => {
    expect(() => assertSafeCookieName('name\r', 'factory', 'label')).toThrow()
  })

  // LF in the name — paired with CR.
  it('rejects a name containing LF (\\n)', () => {
    expect(() => assertSafeCookieName('name\n', 'factory', 'label')).toThrow()
  })

  // Observability: the error message carries both the factory name
  // and the config label so consumers can pinpoint which cookie
  // slot is misconfigured.
  it('includes the factory and label in the error message', () => {
    expect(() =>
      assertSafeCookieName('bad name', 'createLogoutHandler', 'cookieNames.access')
    ).toThrow(/createLogoutHandler: invalid cookie name "bad name" for cookieNames\.access/)
  })
})

describe('assertSafeCookiePath — accepted inputs', () => {
  // Root path is the most common cookie scope (`Path=/`).
  it('accepts the root path "/"', () => {
    expect(() => assertSafeCookiePath('/', 'factory', 'label')).not.toThrow()
  })

  // The default scope for the refresh cookie in the NestJS auth
  // module — a realistic production value.
  it('accepts the default refresh-cookie path "/api/auth"', () => {
    expect(() => assertSafeCookiePath('/api/auth', 'factory', 'label')).not.toThrow()
  })

  // Dashes are part of the RFC-permitted path character set and
  // appear in common cookie scopes.
  it('accepts a path containing dashes', () => {
    expect(() => assertSafeCookiePath('/path/with-dashes', 'factory', 'label')).not.toThrow()
  })
})

describe('assertSafeCookiePath — rejected inputs', () => {
  // No leading slash — a `Path=` value without a leading slash is
  // treated by browsers as relative to the request path, leaking
  // the cookie to unintended routes.
  it('rejects a path without leading slash', () => {
    expect(() => assertSafeCookiePath('api/auth', 'factory', 'refreshCookiePath')).toThrow(
      /invalid cookie path "api\/auth" for refreshCookiePath/
    )
  })

  // `;` ends the `Path` attribute — embedding one would let a
  // misconfigured consumer smuggle extra attributes (e.g.,
  // `/api;Secure` → path `/api` plus an injected `Secure` flag).
  it('rejects a path containing ";"', () => {
    expect(() => assertSafeCookiePath('/api;Secure', 'factory', 'label')).toThrow()
  })

  // CR — header-splitting vector.
  it('rejects a path containing CR (\\r)', () => {
    expect(() => assertSafeCookiePath('/api\r', 'factory', 'label')).toThrow()
  })

  // LF — header-splitting vector.
  it('rejects a path containing LF (\\n)', () => {
    expect(() => assertSafeCookiePath('/api\n', 'factory', 'label')).toThrow()
  })

  // NUL — truncation vector in some downstream parsers.
  it('rejects a path containing NUL (\\0)', () => {
    expect(() => assertSafeCookiePath('/api\0', 'factory', 'label')).toThrow()
  })

  // Empty string — no leading slash, degenerate; silently accepting
  // would attach cookies to `/` only in some browsers and nowhere
  // in others.
  it('rejects an empty path', () => {
    expect(() => assertSafeCookiePath('', 'factory', 'label')).toThrow()
  })
})

describe('trimTrailingSlash', () => {
  // Single trailing slash is the normal input — the helper's
  // primary reason to exist. Consumers configure `apiBase` with or
  // without a slash; this call centralises the removal.
  it('removes a single trailing slash', () => {
    expect(trimTrailingSlash('https://x/')).toBe('https://x')
  })

  // No trailing slash — the helper must be idempotent: calling it
  // twice must produce the same result.
  it('is a no-op when no trailing slash is present', () => {
    expect(trimTrailingSlash('https://x')).toBe('https://x')
  })

  // Double trailing slash — only ONE slash is trimmed. This keeps
  // the helper's behaviour predictable and leaves a second call
  // (or a stricter validator) to decide how to treat the remaining
  // slash.
  it('only removes ONE trailing slash (double-slash case)', () => {
    expect(trimTrailingSlash('https://x//')).toBe('https://x/')
  })

  // Empty string — defensive input that must not throw.
  it('handles an empty string', () => {
    expect(trimTrailingSlash('')).toBe('')
  })
})
