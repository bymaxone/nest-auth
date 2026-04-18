/**
 * Unit tests for `src/nextjs/helpers/buildRefreshUrl.ts`.
 *
 * Exercises every branch of the URL composer and the two
 * construction-time validators (`assertValidApiBase`,
 * `assertValidUpstreamPath`). The handlers that depend on these
 * helpers already exercise the happy paths — this file is the
 * authoritative coverage for the edge-case and error paths.
 */

import {
  DEFAULT_REFRESH_PATH,
  assertValidApiBase,
  assertValidUpstreamPath,
  buildRefreshUrl
} from '../helpers/buildRefreshUrl'

describe('buildRefreshUrl', () => {
  // Default path: when `refreshPath` is omitted the DEFAULT_REFRESH_PATH
  // (`/auth/refresh`) is appended to the api base.
  it('uses DEFAULT_REFRESH_PATH when refreshPath is omitted', () => {
    expect(buildRefreshUrl('https://api.example.com')).toBe(
      `https://api.example.com${DEFAULT_REFRESH_PATH}`
    )
  })

  // Explicit refreshPath overrides the default — used by consumers
  // who mount the NestJS module under a non-default route prefix.
  it('honours an explicit refreshPath override', () => {
    expect(buildRefreshUrl('https://api.example.com', '/custom/refresh')).toBe(
      'https://api.example.com/custom/refresh'
    )
  })

  // Trailing slash on apiBase: the function trims it so consumers do
  // not have to normalise their own config.
  it('trims a trailing slash on apiBase', () => {
    expect(buildRefreshUrl('https://api.example.com/', '/refresh')).toBe(
      'https://api.example.com/refresh'
    )
  })

  // No trailing slash: the URL is composed without introducing one.
  it('does not insert a slash when apiBase has none', () => {
    expect(buildRefreshUrl('https://api.example.com', '/refresh')).toBe(
      'https://api.example.com/refresh'
    )
  })
})

describe('assertValidApiBase', () => {
  // Happy path: `http://` is accepted.
  it('accepts a well-formed http URL', () => {
    expect(() => assertValidApiBase('http://api.example.com', 'factory')).not.toThrow()
  })

  // Happy path: `https://` is accepted.
  it('accepts a well-formed https URL', () => {
    expect(() => assertValidApiBase('https://api.example.com', 'factory')).not.toThrow()
  })

  // Empty string: misconfiguration surfaces loudly at factory time.
  it('throws on an empty string', () => {
    expect(() => assertValidApiBase('', 'factory')).toThrow(
      /factory: apiBase must be a non-empty string/
    )
  })

  // Non-string (defensive): the TS type says string, but runtime
  // JS callers may slip through — the guard handles that case.
  it('throws on a non-string apiBase', () => {
    expect(() => assertValidApiBase(123 as unknown as string, 'factory')).toThrow(
      /factory: apiBase must be a non-empty string/
    )
  })

  // Relative URL: common misconfiguration (consumer forgets to set
  // the full origin). Must be rejected.
  it('throws on a relative URL', () => {
    expect(() => assertValidApiBase('/api', 'factory')).toThrow(
      /apiBase "\/api" must be an absolute URL/
    )
  })

  // Non-HTTP scheme: defensive rejection. A `ftp://` base would
  // silently work with `fetch` in some runtimes.
  it('throws on a non-HTTP scheme', () => {
    expect(() => assertValidApiBase('ftp://example.com', 'factory')).toThrow(
      /must be an absolute URL/
    )
  })

  // The factory-name prefix is echoed in the error for observability.
  it('includes the factory name in the error message', () => {
    expect(() => assertValidApiBase('', 'createLogoutHandler')).toThrow(/createLogoutHandler:/)
  })
})

describe('assertValidUpstreamPath', () => {
  // Undefined path: accepted (optional override). Exercises the
  // early-return guard.
  it('is a no-op when path is undefined', () => {
    expect(() => assertValidUpstreamPath(undefined, 'factory', 'refreshPath')).not.toThrow()
  })

  // Happy path: an absolute-within-origin path starting with `/`.
  it('accepts a normal absolute path', () => {
    expect(() => assertValidUpstreamPath('/auth/refresh', 'factory', 'refreshPath')).not.toThrow()
  })

  // Missing leading slash: rejected.
  it('throws when the path does not start with /', () => {
    expect(() => assertValidUpstreamPath('auth/refresh', 'factory', 'refreshPath')).toThrow(
      /refreshPath/
    )
  })

  // Dot-segment: `..` would redirect the request to a different
  // upstream route.
  it('throws when the path contains ..', () => {
    expect(() => assertValidUpstreamPath('/auth/../admin', 'factory', 'refreshPath')).toThrow(
      /refreshPath/
    )
  })

  // Query string: the `?` character is rejected because the caller
  // supplies a pathname, not a URL.
  it('throws when the path contains a query string', () => {
    expect(() => assertValidUpstreamPath('/auth?x=1', 'factory', 'refreshPath')).toThrow(
      /refreshPath/
    )
  })

  // Fragment: same rationale as query string.
  it('throws when the path contains a fragment', () => {
    expect(() => assertValidUpstreamPath('/auth#frag', 'factory', 'refreshPath')).toThrow(
      /refreshPath/
    )
  })

  // CR/LF/NUL: defence against HTTP smuggling via crafted paths.
  it('throws when the path contains CR/LF/NUL bytes', () => {
    expect(() => assertValidUpstreamPath('/auth\r\n', 'factory', 'refreshPath')).toThrow()
    expect(() => assertValidUpstreamPath('/auth\0', 'factory', 'refreshPath')).toThrow()
  })
})
