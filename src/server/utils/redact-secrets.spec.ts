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

  // A secret that occurs inside the replacement marker. Replacing one secret at a time rescans
  // text this function already rewrote, so `cted` matches inside the `<redacted>` an earlier pass
  // inserted and the line comes out as `<reda<redacted>>`. One pass over the original cannot.
  it('does not match its own replacement marker', () => {
    expect(redactSecrets('error xyz here', ['xyz', 'cted'])).toBe('error <redacted> here')
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
