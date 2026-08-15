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

  // More than one value can be in flight, and any of them surviving is enough to withhold.
  it('withholds when any one of several secrets survives', () => {
    expect(safeLogLine('a 111111 b', ['999999', '111111'])).not.toContain('111111')
  })
})
