/**
 * Unit tests for `src/nextjs/helpers/isBackgroundRequest.ts`.
 *
 * The proxy suite exercises this helper indirectly with the canonical
 * `'1'` header value. This file pins the helper directly so the
 * `value.length > 0` non-empty guard is observable: a PRESENT but
 * EMPTY header (`''`) must NOT be treated as a background request,
 * which distinguishes the live code from `length >= 0` / `true`
 * mutations that would classify every present header as background.
 */

import { isBackgroundRequest } from '../helpers/isBackgroundRequest'
import type { RequestWithHeaders } from '../helpers/isBackgroundRequest'

/**
 * Build a {@link RequestWithHeaders} whose `headers.get(name)` returns
 * the configured value for an exact (already-lowercased) header name,
 * mirroring the lowercase lookups the helper performs. A `Map` backs
 * the lookup so there is no dynamic object indexing.
 */
function makeRequest(entries: ReadonlyArray<readonly [string, string]>): RequestWithHeaders {
  const values = new Map<string, string>(entries)
  return {
    headers: {
      get(name: string): string | null {
        return values.has(name) ? (values.get(name) ?? null) : null
      }
    }
  }
}

describe('isBackgroundRequest', () => {
  // No background headers present → ordinary navigation, returns false.
  // Establishes the negative baseline the positive cases contrast with.
  it('returns false when none of the background headers are present', () => {
    expect(isBackgroundRequest(makeRequest([]))).toBe(false)
  })

  // RSC header with a non-empty value → React Server Component fetch.
  // The proxy uses this to answer 401 instead of redirecting.
  it('returns true for a non-empty RSC header', () => {
    expect(isBackgroundRequest(makeRequest([['rsc', '1']]))).toBe(true)
  })

  // Next-Router-Prefetch with a non-empty value → speculative prefetch.
  // The header name is load-bearing; pin the exact lookup key.
  it('returns true for a non-empty Next-Router-Prefetch header', () => {
    expect(isBackgroundRequest(makeRequest([['next-router-prefetch', '1']]))).toBe(true)
  })

  // Next-Router-State-Tree with a non-empty value → partial-render
  // state fetch. Confirms the third lookup key is wired.
  it('returns true for a non-empty Next-Router-State-Tree header', () => {
    expect(isBackgroundRequest(makeRequest([['next-router-state-tree', '1']]))).toBe(true)
  })

  // Edge case: RSC header PRESENT but EMPTY (`''`). RFC allows empty
  // header values, and an empty value carries no background signal.
  // The non-empty guard (`value.length > 0`) must return false here —
  // kills `length >= 0` (always true) and the `true` literal mutation.
  it('returns false when the RSC header is present but empty', () => {
    expect(isBackgroundRequest(makeRequest([['rsc', '']]))).toBe(false)
  })

  // Edge case: same empty-value rule for Next-Router-Prefetch — the
  // header existing with no value is not a prefetch signal.
  it('returns false when Next-Router-Prefetch is present but empty', () => {
    expect(isBackgroundRequest(makeRequest([['next-router-prefetch', '']]))).toBe(false)
  })

  // Edge case: same empty-value rule for Next-Router-State-Tree.
  it('returns false when Next-Router-State-Tree is present but empty', () => {
    expect(isBackgroundRequest(makeRequest([['next-router-state-tree', '']]))).toBe(false)
  })

  // All three present but empty → still not a background request. Guards
  // against any single mutated branch flipping the disjunction to true.
  it('returns false when every background header is present but empty', () => {
    expect(
      isBackgroundRequest(
        makeRequest([
          ['rsc', ''],
          ['next-router-prefetch', ''],
          ['next-router-state-tree', '']
        ])
      )
    ).toBe(false)
  })
})
