/**
 * @fileoverview Unit tests for {@link redactSecrets}.
 *
 * The function exists because a mail relay was measured quoting a rejected message's body back in
 * its error, putting a live OTP into an operator's log. These cases pin the behaviour that closes
 * that, and the two shapes that would silently reopen it: a secret appearing more than once, and
 * a secret embedded in surrounding text rather than standing alone.
 */
import { redactSecrets } from './redact-secrets'

describe('redactSecrets', () => {
  // The measured case, reduced: a 550 that quotes the body containing the code this library
  // issued. If this line ever prints the digits again, a credential is in the log pipeline.
  it('removes a code the relay quoted back inside a rejection', () => {
    const line = redactSecrets(
      '550 5.7.1 Message rejected by policy: "Your code is 699647. It expires in 10 minutes."',
      ['699647']
    )

    expect(line).not.toContain('699647')
    expect(line).toBe(
      '550 5.7.1 Message rejected by policy: "Your code is <redacted>. It expires in 10 minutes."'
    )
  })

  // Bodies state a code once and repeat it in a link or a footer, and a relay quotes the whole
  // body. Replacing only the first occurrence would leak every later one, which is why this
  // asserts on a string carrying the same secret twice rather than once.
  it('removes every occurrence, not only the first', () => {
    const line = redactSecrets('code 123456 ... confirm?otp=123456', ['123456'])

    expect(line).not.toContain('123456')
    expect(line).toBe('code <redacted> ... confirm?otp=<redacted>')
  })

  // A secret is redacted wherever it sits, including glued to punctuation or other characters.
  // A word-boundary-based matcher would pass the standalone case and miss this one, which is the
  // shape a quoted URL actually produces.
  it('removes a secret embedded in surrounding text', () => {
    const line = redactSecrets('https://app.example.com/accept?token=abcdef0123456789&x=1', [
      'abcdef0123456789'
    ])

    expect(line).toBe('https://app.example.com/accept?token=<redacted>&x=1')
  })

  // More than one credential can be in flight for a single message, and each must be removed
  // independently of the others' presence.
  it('removes several secrets from one string', () => {
    expect(redactSecrets('a=111111 b=222222', ['111111', '222222'])).toBe(
      'a=<redacted> b=<redacted>'
    )
  })

  // The common path: nothing to hide, text returned untouched. Guards against a rewrite that
  // mangles ordinary diagnostics an operator depends on.
  it('returns the text unchanged when no secret occurs in it', () => {
    expect(redactSecrets('535 authentication failed', ['699647'])).toBe('535 authentication failed')
    expect(redactSecrets('ECONNREFUSED', [])).toBe('ECONNREFUSED')
  })

  // An empty secret must be skipped rather than matched. `''` splits a string into its characters,
  // so joining on the marker would rewrite every gap between them and destroy the line — the one
  // input that turns a redaction helper into a corruption helper.
  it('skips an empty secret instead of splitting the text apart', () => {
    expect(redactSecrets('535 auth failed', [''])).toBe('535 auth failed')
    expect(redactSecrets('535 auth failed', ['', '535'])).toBe('<redacted> auth failed')
  })

  // Two secrets where one is a prefix of the other. Replacing sequentially lets the shorter match
  // first, consume its prefix and leave the remaining `4` behind — a fragment of a live
  // credential sitting in the log. The longest-first ordering is what prevents that, and this is
  // the case that proves it rather than the ordering being decorative.
  it('leaves no fragment when one secret is a prefix of another', () => {
    expect(redactSecrets('1234', ['123', '1234'])).toBe('<redacted>')
    expect(redactSecrets('1234', ['1234', '123'])).toBe('<redacted>')
  })

  // Two secrets that overlap without either containing the other, which no ordering fixes. A scan
  // taking the longest match at each position consumes `1234` at 0, resumes at 4, matches nothing
  // and emits `<redacted>5` — the tail of the SECOND secret left in the log. Collecting the ranges
  // against the original text and merging the overlap is what covers it. Found by the
  // nest-notification seat, which had the identical defect and measured this exact case.
  it('leaves no fragment when two secrets overlap without nesting', () => {
    const line = redactSecrets('12345', ['1234', '2345'])

    expect(line).not.toContain('5')
    expect(line).toBe('<redacted>')
  })

  // Occurrences of a single secret can overlap themselves. Stepping past a whole match when
  // searching for the next would skip the second one and leave it in place.
  it('finds occurrences of one secret that overlap each other', () => {
    expect(redactSecrets('aaa', ['aa'])).toBe('<redacted>')
  })

  // Two secrets far apart stay two separate redactions — merging is for overlap, not for
  // everything, and collapsing them would tell an operator one credential appeared where two did.
  it('keeps disjoint occurrences as separate redactions', () => {
    expect(redactSecrets('a 111111 b 222222 c', ['111111', '222222'])).toBe(
      'a <redacted> b <redacted> c'
    )
  })

  // Ranges are collected in the order the SECRETS are declared, which has nothing to do with the
  // order they appear in the text — a caller passing `[token, otp]` may well hit the otp first.
  // Merging walks the list assuming ascending starts, so without the sort the second range is
  // compared against a later one, swallows it, and the earlier secret is emitted verbatim. This
  // asserts the leaking case rather than the tidy one: unsorted, the output is `aaa <redacted>`.
  it('redacts secrets declared in the opposite order to their positions', () => {
    const line = redactSecrets('aaa bbb', ['bbb', 'aaa'])

    expect(line).not.toContain('aaa')
    expect(line).toBe('<redacted> <redacted>')
  })

  // Adjacent but non-overlapping occurrences: `aaa` ends exactly where `bbb` begins. Two
  // credentials were present, so two markers are written. Only genuine OVERLAP collapses into one
  // region — touching is not overlapping, and reporting a single redaction here would tell an
  // operator that one credential appeared where two did. Both are fully removed either way, so
  // this pins a rendering choice rather than a safety property.
  it('writes one marker per occurrence when two secrets merely touch', () => {
    expect(redactSecrets('aaabbb', ['aaa', 'bbb'])).toBe('<redacted><redacted>')
  })

  // A secret that occurs inside the replacement marker, which is a stricter problem than it first
  // looks. Two things must hold. The scan must not match `cted` inside a `<redacted>` it just
  // wrote — a replace-one-at-a-time loop does, producing `<reda<redacted>>`. AND the marker itself
  // must not be emitted at all, because writing `<redacted>` would publish the secret `cted` that
  // it contains, failing the one promise this function makes. Deletion is the fallback.
  //
  // The first revision of this test asserted `'error <redacted> here'` and passed — while the
  // string it asserted still contained `cted`. A test can sanction the bug it was written for.
  it('emits no marker when the marker itself would contain a secret', () => {
    const line = redactSecrets('error xyz here', ['xyz', 'cted'])

    expect(line).not.toContain('xyz')
    expect(line).not.toContain('cted')
    expect(line).toBe('error  here')
  })

  // The secret is matched as a literal. Exported means a caller may treat any string as secret,
  // and an unescaped `(` would throw on an unbalanced group while an unescaped `.` would redact
  // text that is not the secret at all.
  it('treats a secret containing regex syntax as a literal', () => {
    expect(redactSecrets('token a.c and abc', ['a.c'])).toBe('token <redacted> and abc')
    expect(() => redactSecrets('x', ['(unclosed'])).not.toThrow()
    expect(redactSecrets('say (unclosed here', ['(unclosed'])).toBe('say <redacted> here')
  })

  // Over-redaction is the accepted trade. A four-digit OTP — the shortest this library permits —
  // colliding with a message id costs an operator one obscured number; the opposite mistake
  // publishes a working credential.
  it('redacts an incidental collision rather than risk missing the secret', () => {
    expect(redactSecrets('queued as 1234ABC', ['1234'])).toBe('queued as <redacted>ABC')
  })
})
