/**
 * Unit tests — ownerFragment
 *
 * The reuse-detection line is the strongest evidence of compromise this library produces, and
 * `userId` is the only field an on-call can act on. These pin both halves: that a resolvable
 * owner is named, and that an unresolvable one is SAID to be unresolvable rather than left blank.
 */

import { ownerFragment } from './owner-fragment'

describe('ownerFragment', () => {
  // The ordinary case: a family with at least one live member names its owner.
  it('names the owner when the family still had a member to read', () => {
    expect(ownerFragment('user-1')).toBe('userId=user-1')
  })

  // The case that motivated this. `revokeFamily` answers `''` on the second and later replay of
  // an already-revoked family — the consumed marker outlives the sessions it points at, so reuse
  // is detected again while every record that could name the owner is gone. An empty `userId=`
  // reads as a defect in the logger, which makes a reader distrust the tool instead of the event.
  //
  // Asserted whole, not by substring. A `toContain('unknown')` pair passed the wording this
  // replaced — which claimed the family had been "already revoked", a cause `readFamilyOwner`
  // cannot distinguish from expiry or from a record that will not parse. Substrings survive a
  // rewrite that changes what the line MEANS, so the exact fragment is the assertion, and the
  // literal is written out here rather than imported: a test that reads the value from the code
  // it is checking pins nothing.
  it('says the owner is unknown, and what was observed, when no member named one', () => {
    expect(ownerFragment('')).toBe(
      'userId=<unknown: no live session remains in this family to name it>'
    )
  })

  // The owner comes off a stored record whose contents belong to the consumer, so it is guarded
  // like any other value this library did not author — the line is a record in a line-oriented
  // pipeline, and a newline in it would open a forged one.
  it('replaces an owner that could break the log record', () => {
    expect(ownerFragment('u1\nLOG forged')).toBe('userId=<malformed>')
  })
})
