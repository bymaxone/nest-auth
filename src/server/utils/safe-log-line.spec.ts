/**
 * @fileoverview Unit tests for {@link safeLogLine}.
 *
 * The function exists for the seam between separately-sanitised fields. Every case here is one
 * shape of that seam, or the guarantee that an ordinary line is passed through untouched — because
 * a check that withheld too eagerly would cost operators their diagnostics to buy nothing.
 */
import { safeLogLine } from './safe-log-line'

describe('safeLogLine', () => {
  // The measured case from the provider: a device string of `foo": Error: bar` is reconstructed
  // when a subject of `foo` and a description of `Error: bar` are joined by the template's `": `.
  // Neither field contains the secret; the line does.
  it('withholds a line whose composition rebuilt a secret across the seam', () => {
    const device = 'foo": Error: bar'
    const line = `delivery failed for "foo": Error: bar`

    expect(line).toContain(device)
    expect(safeLogLine(line, [device])).not.toContain(device)
  })

  // The composition joins NUMBERS as well as text, and the punctuation between them is no barrier
  // to anyone reading the record. This line contains neither the literal `4550` nor anything
  // resembling it, and stripping every non-digit yields exactly that — a live four-digit reset
  // code, assembled from a consumer's user id and a relay's status, neither of which is a leak on
  // its own. It is the same arithmetic that took the enhanced SMTP code out of the description,
  // one level up.
  it('withholds a line whose digits reassemble a numeric value', () => {
    const line = 'sendPasswordResetOtp failed for user u4: <error>: 550'

    expect(line).not.toContain('4550')
    expect(line.replace(/\D/g, '')).toContain('4550')
    // The line is WITHHELD, not merely free of the literal — asserting the absence would pass on a
    // build that never noticed, because the literal was never there to begin with.
    expect(safeLogLine(line, ['4550'])).toContain('withheld')
  })

  // Only all-digit values get that treatment. A token is hex and an address has letters, so
  // normalising them would compare fragments rather than values — `a1b2` would match any line
  // holding a `1` and a `2` in order — and withhold diagnoses for no reason at all.
  it('does not normalise a value that is not all digits', () => {
    const line = 'sendPasswordResetToken failed for user 1234: <error>: 550'

    expect(safeLogLine(line, ['a1b2'])).toBe(line)
  })

  // The common path. A check that fired on ordinary text would remove the diagnosis operators
  // depend on, which is a worse trade than the leak it prevents.
  it('passes an ordinary line through unchanged', () => {
    const line = 'delivery failed for "Your password reset code": Error: 535 auth failed'

    expect(safeLogLine(line, ['699647'])).toBe(line)
    expect(safeLogLine(line, [])).toBe(line)
  })

  // An empty secret occurs in every string, so testing it naively would withhold every line. It
  // has nothing to hide, which is why it is skipped rather than matched.
  it('does not withhold on an empty secret', () => {
    const line = '535 authentication failed'

    expect(safeLogLine(line, [''])).toBe(line)
  })

  // The placeholder has to say what happened. A blank or dropped line reads as "nothing was
  // logged", which sends an operator looking for a delivery that did fail; this reads as a
  // finding about their channel.
  it('names the reason when it withholds', () => {
    const withheld = safeLogLine('code 424242 leaked', ['424242'])

    expect(withheld).toContain('withheld')
    expect(withheld).toContain('must not be logged')
  })

  // The placeholder is text, so the rule it enforces applies to it. A secret of `withheld` occurs
  // inside the placeholder itself — and a device string is arbitrary, so this is reachable — which
  // would have the guard publish the very value it detected. The last line out has to satisfy the
  // contract too.
  it('does not publish a secret through its own placeholder', () => {
    const line = safeLogLine('x withheld', ['withheld'])

    expect(line).not.toContain('withheld')
  })

  // More than one value can be in flight, and any of them surviving is enough to withhold.
  it('withholds when any one of several secrets survives', () => {
    expect(safeLogLine('a 111111 b', ['999999', '111111'])).not.toContain('111111')
  })
})
