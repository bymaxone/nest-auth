/**
 * Unit tests — normalizeEmail
 *
 * Verifies the canonical email-normalization helper that the auth services call
 * at their boundary (independent of the DTO `@Transform`, which the controllers'
 * non-transforming `ValidationPipe` discards). Canonicalization is trim + lowercase;
 * deriving the brute-force key, user lookup, and stored identity from this value is
 * what closes the case-rotation lockout bypass.
 *
 * Pure-function tests — no mocks, no async, no I/O.
 */

import { normalizeEmail } from './normalize-email'

// ---------------------------------------------------------------------------
// normalizeEmail
// ---------------------------------------------------------------------------

describe('normalizeEmail', () => {
  // Verifies the canonical case documented in the JSDoc: surrounding whitespace is
  // stripped and mixed casing is lowercased so every casing collapses to one value.
  it('trims surrounding whitespace and lowercases the address', () => {
    expect(normalizeEmail('  USER@Example.COM  ')).toBe('user@example.com')
  })

  // Verifies an already-canonical address is returned unchanged (idempotence), so
  // normalizing twice never diverges from normalizing once.
  it('leaves an already-canonical address unchanged', () => {
    expect(normalizeEmail('user@example.com')).toBe('user@example.com')
  })

  // Verifies inner-tab / internal whitespace is preserved (only the ends are trimmed),
  // pinning that trim() — not a broader whitespace strip — is the contract.
  it('trims only the ends, not internal characters', () => {
    expect(normalizeEmail('\tUser@Example.com\n')).toBe('user@example.com')
  })
})
