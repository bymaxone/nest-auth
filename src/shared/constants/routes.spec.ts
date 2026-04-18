import {
  AUTH_PROXY_ROUTES,
  AUTH_REFRESH_SKIP_PATH_SUFFIXES,
  buildAuthRefreshSkipSuffixes
} from './routes'

/**
 * Coverage suite for {@link buildAuthRefreshSkipSuffixes}.
 *
 * The factory composes the pathname-suffix list that `createAuthFetch`
 * consults before attempting a transparent refresh. A regression in
 * either the prefix-normalization branch or the empty-prefix branch
 * would silently break 401 handling on non-default deployments, so
 * both branches are exercised explicitly here.
 */
describe('buildAuthRefreshSkipSuffixes', () => {
  // Default call (no argument) must match the backwards-compat
  // constant exported for the canonical `'auth'` prefix, guaranteeing
  // that existing consumers who imported `AUTH_REFRESH_SKIP_PATH_SUFFIXES`
  // before the factory existed keep receiving the same values.
  it('returns the default-prefix suffixes identical to AUTH_REFRESH_SKIP_PATH_SUFFIXES', () => {
    expect(buildAuthRefreshSkipSuffixes()).toEqual(AUTH_REFRESH_SKIP_PATH_SUFFIXES)
  })

  // Non-default NestJS prefixes are the whole reason the factory
  // exists — a `routePrefix: 'authentication'` deployment must
  // receive suffixes like `/authentication/login` instead of
  // `/auth/login`, or 401s will spuriously trigger refreshes.
  it('composes suffixes using the supplied routePrefix', () => {
    const suffixes = buildAuthRefreshSkipSuffixes('authentication')

    expect(suffixes).toContain('/authentication/login')
    expect(suffixes).toContain('/authentication/platform/refresh')
    expect(suffixes).not.toContain('/auth/login')
  })

  // Layered deployments mount the auth module under a prefix like
  // `'api/v1/auth'`. Leading/trailing slashes are normalized so
  // consumers can pass either `'api/v1/auth'`, `'/api/v1/auth'`, or
  // `'/api/v1/auth/'` and receive the same suffix list.
  it('normalizes leading and trailing slashes in the prefix', () => {
    const bare = buildAuthRefreshSkipSuffixes('api/v1/auth')
    const leading = buildAuthRefreshSkipSuffixes('/api/v1/auth')
    const both = buildAuthRefreshSkipSuffixes('/api/v1/auth/')

    expect(bare).toEqual(leading)
    expect(bare).toEqual(both)
    expect(bare).toContain('/api/v1/auth/login')
  })

  // The empty-prefix branch is reachable when a consumer mounts auth
  // at the root (`routePrefix: ''` or `'/'`). Every controller path
  // must then appear at the root (`/login`, `/refresh`, …) — without
  // this branch, the normalized-prefix concatenation would emit a
  // leading `//` that would never match real URLs.
  it('emits root-relative suffixes when the prefix is empty', () => {
    const emptyString = buildAuthRefreshSkipSuffixes('')
    const slash = buildAuthRefreshSkipSuffixes('/')
    const slashes = buildAuthRefreshSkipSuffixes('///')

    for (const suffixes of [emptyString, slash, slashes]) {
      expect(suffixes).toContain('/login')
      expect(suffixes).toContain('/refresh')
      expect(suffixes).toContain('/platform/login')
      // Proxy endpoints are never prefixed — they must remain
      // exactly as declared regardless of the server routePrefix.
      expect(suffixes).toContain(AUTH_PROXY_ROUTES.clientRefresh)
      expect(suffixes).toContain(AUTH_PROXY_ROUTES.silentRefresh)
      // No suffix must ever start with a double-slash — that would
      // indicate a normalization bug that leaves the list unmatched.
      for (const s of suffixes) {
        expect(s.startsWith('//')).toBe(false)
      }
    }
  })

  // Proxy endpoints are never prefixed by the NestJS `routePrefix` —
  // they are browser-facing Next.js routes. Assert the suffix list
  // always carries the exact proxy paths regardless of the prefix.
  it('always includes the unprefixed proxy refresh endpoints', () => {
    const custom = buildAuthRefreshSkipSuffixes('mycompany/auth')

    expect(custom).toContain(AUTH_PROXY_ROUTES.clientRefresh)
    expect(custom).toContain(AUTH_PROXY_ROUTES.silentRefresh)
  })
})
