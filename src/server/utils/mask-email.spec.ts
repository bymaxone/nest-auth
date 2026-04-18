/**
 * Unit tests — maskEmail
 *
 * Verifies the email-masking helper used to safely include user identifiers in
 * log lines. The function preserves the first character of the local part and
 * the full domain, replacing the rest with `***`. Strings without a usable `@`
 * separator collapse to a fully redacted `***` to guarantee that no raw input
 * ever leaks through the logger.
 *
 * Pure-function tests — no mocks, no async, no I/O. Each branch of the source
 * (`atIndex <= 0` redaction path and the masked-construction path) is exercised
 * directly through the public API.
 */

import { maskEmail } from './mask-email'

// ---------------------------------------------------------------------------
// maskEmail — happy paths and redaction edge cases
// ---------------------------------------------------------------------------

describe('maskEmail', () => {
  // Verifies the canonical case: a typical address keeps only the first letter
  // of the local part plus the full domain, matching the example documented in
  // the source JSDoc.
  it('masks a standard email address', () => {
    expect(maskEmail('john.doe@example.com')).toBe('j***@example.com')
  })

  // Confirms the masking still works when the local part is a single character —
  // the implementation must not depend on having a multi-character local part to
  // build the `<first>***@<domain>` shape.
  it('masks a single-character local part', () => {
    expect(maskEmail('a@example.com')).toBe('a***@example.com')
  })

  // Exercises the `atIndex === -1` branch: with no `@` separator there is no
  // domain to preserve, so the entire string must be redacted to avoid leaking
  // the raw value (which could be a token, hash, or unrelated identifier).
  it('returns *** for a string with no @ symbol', () => {
    expect(maskEmail('nodomain')).toBe('***')
  })

  // Exercises the `atIndex === 0` branch: a leading `@` means the local part is
  // empty, so there is no first character to keep — the value is fully redacted
  // to stay consistent with the no-separator case.
  it('returns *** when @ is the first character', () => {
    expect(maskEmail('@nodomain.com')).toBe('***')
  })

  // Ensures that `slice(atIndex + 1)` returns the full domain including any
  // sub-labels and dots, so multi-level domains are preserved verbatim and not
  // truncated at the first dot.
  it('masks a subdomain email address', () => {
    expect(maskEmail('user@mail.example.org')).toBe('u***@mail.example.org')
  })
})
