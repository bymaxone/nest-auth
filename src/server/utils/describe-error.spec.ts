/**
 * @fileoverview Unit tests for {@link describeError}, the form that KEEPS the channel's own words.
 *
 * It has no caller inside this library — every internal path publishes nothing the channel wrote,
 * because a relay may quote what it rejected in transfer encoding and no substring match sees
 * through that. It is exported for consumers whose provider throws errors carrying values they can
 * name literally, which is a real case this library cannot cover on their behalf. Public API with
 * no internal user is exactly the shape that rots unnoticed, so it is tested directly here rather
 * than through whatever happens to call it.
 *
 * {@link describeChannelStatus}'s per-message behaviour is exercised end to end through
 * `DefaultAuthEmailProvider`, where its contract is what the log line actually reads. What lives
 * here instead is its INVARIANT, asserted over adversarial input rather than over the fixtures a
 * test happened to choose — see the suite at the bottom for why that distinction earned a suite.
 */
import { describeChannelStatus, describeError } from './describe-error'

describe('describeError', () => {
  // The common shape, and the reason this form exists at all: where nothing withheld was rendered,
  // the relay's own words ARE the diagnosis an operator acts on.
  it('keeps the name and the message', () => {
    expect(describeError(new Error('relay unreachable'), [])).toBe('Error: relay unreachable')
  })

  // An error name is whatever constructed it — a mail client is free to build one out of the
  // server's reply. This form publishes it, which is the trade this form makes.
  it('keeps a name that is not an identifier', () => {
    const named = new Error('relay unreachable')
    named.name = 'Smtp Error (timeout)'

    expect(describeError(named, [])).toBe('Smtp Error (timeout): relay unreachable')
  })

  // A message can be absent — `new Error()`, or one whose entire content was control characters
  // and got replaced. The name then stands alone rather than trailing a colon with nothing after
  // it, so the line still reads as a diagnosis.
  it('reports the name alone when the message is empty', () => {
    expect(describeError(new Error(), [])).toBe('Error')
  })

  // The likeliest exposure of the set, and it needs no quoted body: an SMTP rejection NAMES the
  // recipient it refused. A caller that names the address gets it stripped.
  it('strips a value the transport named', () => {
    const line = describeError(new Error('550 user@example.com: recipient rejected'), [
      'user@example.com'
    ])

    expect(line).not.toContain('user@example.com')
    expect(line).toContain('<redacted>')
    expect(line).toContain('550')
  })

  // A channel reports "send failed BECAUSE the relay said", and what matters lands one level down.
  // Reading only the top-level message would leave it out entirely.
  it('walks the cause chain and separates the links', () => {
    const inner = new Error('550 rejected')
    const outer = new Error('send failed', { cause: inner })

    expect(describeError(outer, [])).toBe('Error: send failed <- Error: 550 rejected')
  })

  // `cause: null` is legal and explicit — a channel that says "no underlying error" rather than
  // omitting the field. Treating it as a link would append `<non-error: object>` to every such
  // chain, reporting the ABSENCE of a cause as a malformed one.
  it('treats an explicitly null cause as the end of the chain', () => {
    expect(describeError(new Error('channel down', { cause: null }), [])).toBe(
      'Error: channel down'
    )
  })

  // A cycle in the chain must not turn one failure into an unbounded record. The depth cap is what
  // guarantees termination; without it this test hangs rather than fails.
  it('stops walking a self-referential cause chain', () => {
    const looped = new Error('outer')
    Object.defineProperty(looped, 'cause', { value: looped })

    expect(describeError(looped, []).match(/outer/g)).toHaveLength(3)
  })

  // Untrusted input in a line-oriented pipeline: a CR/LF in the remote's text closes the record and
  // opens a forged one. The whole field is REPLACED rather than having the character stripped —
  // stripping would splice the forged record onto the real one and publish it as a single line,
  // which is the attack rather than the fix. What survives is the name, and a marker saying why
  // the rest is missing.
  it('replaces a message carrying a control character', () => {
    const line = describeError(new Error('rejected\nLOG [AuthService] login: success'), [])

    expect(line).not.toContain('\n')
    expect(line).not.toContain('login: success')
    expect(line).toBe('Error: <malformed>')
  })

  // A bound on VOLUME. Truncated rather than dropped, so the diagnosis survives: the second
  // assertion is what keeps this from passing on a build that omits the channel's text altogether.
  //
  // The length is asserted EXACTLY. `slice` on an overflowing input lands on the limit itself, so
  // there is no slack to leave, and a threshold with slack is a threshold that does not test the
  // bound — `< 210` passes on a build that relaxed the cap to 205.
  it('caps how much channel text reaches the line', () => {
    const line = describeError(new Error('x'.repeat(5_000)), [])

    expect(line.length).toBe(200)
    expect(line).toContain('xxx')
  })

  // The cap is applied ONCE to the finished description, not per link — three links each bounded
  // to the budget would return three times it.
  it('caps the whole chain, not each link', () => {
    const deep = new Error('a'.repeat(300), {
      cause: new Error('b'.repeat(300), { cause: new Error('c'.repeat(300)) })
    })

    expect(describeError(deep, []).length).toBe(200)
  })

  // The COMPOSITION of two clean parts can spell a value neither contains: `name` and `message`
  // are stripped separately and then joined as `name: message`, so a declared value of
  // `Error: boom` matches neither half and appears in full in the join. The end-to-end pass over
  // the finished description is what covers it.
  it('removes a value formed by joining two clean parts', () => {
    expect(describeError(new Error('boom'), ['Error: boom'])).not.toContain('Error: boom')
  })

  // A thrown non-Error has no contract at all — a string, an object, a rejected promise's value.
  // Its type is the most that can be said without stringifying something whose `toString` belongs
  // to whoever threw it.
  it.each([
    ['a string', 'boom', '<non-error: string>'],
    ['an object', { code: 550 }, '<non-error: object>'],
    ['undefined', undefined, '<non-error: undefined>'],
    ['null', null, '<non-error: object>']
  ])('reports the type of %s rather than its content', (_why, thrown, expected) => {
    expect(describeError(thrown, [])).toBe(expected)
  })

  // Every field belongs to whoever constructed the error, and any of them can be an accessor that
  // throws. An exception raised here would propagate out of the CALLER's `catch` block and turn a
  // failure the caller meant to absorb into an unhandled rejection with no log line at all —
  // strictly worse than the leak this function exists to prevent.
  it('reports a link whose message throws rather than propagating', () => {
    const hostile = new Error('x')
    Object.defineProperty(hostile, 'message', {
      get() {
        throw new Error('nope')
      }
    })

    expect(describeError(hostile, [])).toBe('<malformed-error>')
  })

  // `cause` throwing is a different failure from `message` throwing: there is nothing further to
  // walk, but the link itself still has a description to report. Collapsing the two would discard
  // a diagnosis this function could have produced.
  it('treats a throwing cause as the end of the chain', () => {
    const outer = new Error('send failed')
    Object.defineProperty(outer, 'cause', {
      get() {
        throw new Error('nope')
      }
    })

    expect(describeError(outer, [])).toBe('Error: send failed')
  })

  // `instanceof` invokes the prototype lookup, and a `Proxy` can install a trap that throws — so
  // even asking "is this an Error?" runs code belonging to whoever threw it. A value whose own
  // classification is hostile is treated as a non-error, which is what it has earned.
  it('treats a value whose classification throws as a non-error', () => {
    const hostile = new Proxy(new Error('x'), {
      getPrototypeOf() {
        throw new Error('nope')
      }
    })

    expect(describeError(hostile, [])).toBe('<non-error: object>')
  })
})

/**
 * The output grammar, asserted as a property.
 *
 * Every earlier attempt to bound what this function publishes was a rule that had to predict the
 * form the secret would take — strip these values, cap the length, validate the name's shape, allow
 * a status matching this grammar. Each held for the case that motivated it and fell to the next
 * one, and the last of them fell to a credential the relay had merely grouped: an OTP of `424242`
 * quoted as `424-242` parsed as the reply `424`, so the output varied with the secret.
 *
 * The rule that finally has no exception is that the output is drawn from a fixed alphabet this
 * file owns. That is checkable, and checking it is worth more than the prose saying so — the prose
 * had drifted in thirteen places across nine files, and three separate sweeps for the wording each
 * left members of the family alive. A test does not care how the claim is worded.
 *
 * The `<non-error: …>` arm is here because this suite found it: the first grammar written from what
 * the documentation described omitted it, and three inputs failed. The word after the colon is a
 * `typeof`, so it is one of a fixed set and identical for every value of that type — `typeof` a
 * quoted OTP is `string` whatever the digits are. It passes the same independence test the status
 * failed, which is why it stays and the status did not.
 */
const OPAQUE_GRAMMAR =
  /^(<(error|malformed-error)>|<non-error: [a-z]+>)( <- (<(error|malformed-error)>|<non-error: [a-z]+>))*$/

describe('describeChannelStatus invariant', () => {
  /** A hostile value whose own accessors run code when the description reads them. */
  const boobyTrapped = {
    get name(): string {
      throw new Error('name getter is hostile')
    },
    get message(): string {
      throw new Error('message getter is hostile')
    }
  }
  Object.setPrototypeOf(boobyTrapped, Error.prototype)

  // Each input is a form that defeated one of the removed rules, plus the shapes that never had a
  // rule at all. The assertion is the same for all of them, which is the point: the guarantee does
  // not depend on recognising which attack an input is.
  const adversarial: ReadonlyArray<readonly [string, unknown]> = [
    ['a plain failure', new Error('relay unreachable')],
    ['an SMTP reply', new Error('550 5.7.1 message rejected by policy')],
    ['a grouped credential at the head', new Error('424-242 is your code, quoted back')],
    ['a space-grouped credential', new Error('424 242 is your code, quoted back')],
    ['a base64 body', new Error(Buffer.from('Your code is 123456.').toString('base64'))],
    ['a name built from the reply', Object.assign(new Error('rejected'), { name: 'E424242' })],
    ['a unicode line separator', new Error('550 rejected\u2028injected: 424242')],
    ['a cause chain', new Error('send failed', { cause: new Error('550 424-242 quoted') })],
    [
      'a chain past the depth cap',
      new Error('a', {
        cause: new Error('b', { cause: new Error('c', { cause: new Error('550 424242') }) })
      })
    ],
    ['a hostile accessor', boobyTrapped],
    ['a thrown string', '550 424-242 is your code'],
    ['a thrown null', null],
    ['a thrown number', 424242]
  ]

  // One assertion for every input above: whatever was thrown, the line is drawn only from the
  // alphabet this file owns. A failure here means something the channel authored found a way out.
  it.each(adversarial)('publishes only the opaque grammar for %s', (_label, thrown) => {
    const line = describeChannelStatus(thrown)

    expect(line).toMatch(OPAQUE_GRAMMAR)
  })

  // Stronger than the grammar, and true only since the drop path stopped reading the message: on
  // this policy `describeOneLink` reads NOTHING that can throw — the name is a constant and the
  // message is never touched — so no error can drive it into the `<malformed-error>` arm. That
  // matters beyond tidiness: while the message was read and discarded, a relay could pick which
  // stand-in the log showed by throwing from its own getter, which is a choice a channel does not
  // get to make about this library's output.
  it.each(adversarial)('cannot be driven into the malformed arm by %s', (_label, thrown) => {
    expect(describeChannelStatus(thrown)).not.toContain('<malformed-error>')
  })

  // The claim that keeps decaying in prose, made checkable. Documentation in three files has said
  // some version of "reads only X" about this function, and each time the code moved the sentences
  // did not. Accessor invocation is observable, so this asserts it instead of describing it: under
  // this policy the error's `name` and `message` are never touched, and the only field read is
  // `cause`, walked to count the links.
  it('reads no field of the error but its cause', () => {
    const touched: string[] = []
    const probe = new Error('550 5.7.1 rejected: "Your code is 424242."')
    for (const field of ['name', 'message', 'stack'] as const) {
      Object.defineProperty(probe, field, {
        get() {
          touched.push(field)
          return 'x'
        }
      })
    }

    expect(describeChannelStatus(probe)).toBe('<error>')
    expect(touched).toEqual([])
  })

  // The same probe under the OTHER policy, so the assertion above cannot pass by the function
  // having stopped working. `describeError` is the form that publishes the channel's words, so it
  // must still read the two it publishes — and `stack` is asserted here too, because "neither
  // reads `stack`" is half of the documented claim and testing only the other half is how a
  // sentence half-decays without anything noticing. A stack carries file paths and frames from
  // whichever dependency constructed the error; none of that belongs in a log line.
  it('reads the two fields it publishes and never the stack', () => {
    const touched: string[] = []
    const probe = new Error('rejected')
    for (const field of ['name', 'message', 'stack'] as const) {
      Object.defineProperty(probe, field, {
        get() {
          touched.push(field)
          return 'x'
        }
      })
    }

    describeError(probe, [])

    expect(touched).toContain('name')
    expect(touched).toContain('message')
    expect(touched).not.toContain('stack')
  })

  // The independence test, run rather than described. Two different secrets rendered into the same
  // position must produce the SAME line — output that varies with the secret is derivation, which
  // is exactly what took the status out. A grammar check alone would not catch it: `424` and `551`
  // both match a reply-code pattern.
  //
  // The value is asserted as well as the sameness. "All three agree" is satisfied by a build that
  // returns the empty string for everything, which would agree perfectly and diagnose nothing —
  // the same vacuity as an absence assertion, one level up.
  it('produces a line that does not vary with the secret', () => {
    const lines = ['424242', '551234', '999999'].map((otp) =>
      describeChannelStatus(new Error(`${otp.slice(0, 3)}-${otp.slice(3)} is your code`))
    )

    expect(new Set(lines)).toEqual(new Set(['<error>']))
  })
})
