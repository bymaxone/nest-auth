/**
 * @fileoverview The list of request headers an API key may not be read from.
 *
 * The option specs are table-driven from `LIBRARY_READ_HEADERS`, so on their own they would follow
 * the constant down if a name were deleted from it. This pins the list by name, and keeps the
 * property the comparison depends on. That every header the sources read is on the list is checked
 * by `test/e2e/request-headers.e2e-spec.ts`, which parses the sources and so cannot run here.
 */
import { LIBRARY_READ_HEADERS } from './constants/request-headers'

describe('LIBRARY_READ_HEADERS', () => {
  // The list is pinned by name, so dropping a header from it is a decision made in a test edit and
  // never a quiet deletion: the table-driven option specs would follow the constant down.
  it('names exactly the headers the library reads or derives a field from', () => {
    expect([...LIBRARY_READ_HEADERS]).toEqual([
      'authorization',
      'proxy-authorization',
      'cookie',
      'set-cookie',
      'user-agent',
      'origin',
      'sec-fetch-site',
      'x-forwarded-for',
      'x-forwarded-host',
      'x-real-ip',
      'x-original-forwarded-for',
      'host'
    ])
  })

  // The list is lowercase and free of duplicates, because it is compared against lowercased input.
  it('is lowercase and unique', () => {
    expect(LIBRARY_READ_HEADERS.map((h) => h.toLowerCase())).toEqual([...LIBRARY_READ_HEADERS])
    expect(new Set(LIBRARY_READ_HEADERS).size).toBe(LIBRARY_READ_HEADERS.length)
  })
})
