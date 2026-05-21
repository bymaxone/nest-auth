/**
 * Unit tests for `src/nextjs/internal/constants.ts`.
 *
 * These constants drive the `createAuthProxy` pipeline. The
 * IDENTITY_HEADERS_BASELINE list in particular is a security control —
 * the proxy strips these inbound header names so a client can never spoof
 * an identity the proxy itself is responsible for stamping. Emptying the
 * list would silently disable that protection, so its exact contents are
 * pinned here.
 */

import {
  DEFAULT_MAX_REFRESH_ATTEMPTS,
  IDENTITY_HEADERS_BASELINE,
  REASON_EXPIRED,
  REASON_PARAM,
  REFRESH_ATTEMPT_PARAM
} from './constants'

describe('nextjs internal constants', () => {
  // Pins the full IDENTITY_HEADERS_BASELINE list. Each name MUST be present so
  // that buildSanitizedRequestHeaders strips a client-sent value before the
  // request reaches a downstream server component. An emptied array would let
  // any of these identity headers be spoofed end to end.
  it('IDENTITY_HEADERS_BASELINE should contain exactly the four identity header names', () => {
    expect(IDENTITY_HEADERS_BASELINE).toEqual([
      'x-user-id',
      'x-user-role',
      'x-tenant-id',
      'x-tenant-domain'
    ])
  })

  // Asserts each individual header name independently so a single-element
  // removal (not just a full empty) is also caught, and pins the length.
  it('IDENTITY_HEADERS_BASELINE should include every spoofable identity header', () => {
    expect(IDENTITY_HEADERS_BASELINE).toHaveLength(4)
    expect(IDENTITY_HEADERS_BASELINE).toContain('x-user-id')
    expect(IDENTITY_HEADERS_BASELINE).toContain('x-user-role')
    expect(IDENTITY_HEADERS_BASELINE).toContain('x-tenant-id')
    expect(IDENTITY_HEADERS_BASELINE).toContain('x-tenant-domain')
  })

  // Pins the silent-refresh retry ceiling — a regression here would change how
  // many redirect attempts the proxy makes before falling back to loginPath.
  it('DEFAULT_MAX_REFRESH_ATTEMPTS should be 2', () => {
    expect(DEFAULT_MAX_REFRESH_ATTEMPTS).toBe(2)
  })

  // Pins the query-parameter names and reason value that break the refresh
  // redirect loop. These appear in generated URLs and are matched downstream,
  // so they are behaviorally significant, not cosmetic.
  it('should expose the refresh-loop query parameter and reason constants', () => {
    expect(REFRESH_ATTEMPT_PARAM).toBe('_r')
    expect(REASON_PARAM).toBe('reason')
    expect(REASON_EXPIRED).toBe('expired')
  })
})
