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
  it('says the owner is unknown, and why, when no member survived', () => {
    const line = ownerFragment('')

    expect(line).toContain('unknown')
    expect(line).toContain('already revoked')
    // Never the bare field, which is the shape being fixed.
    expect(line).not.toBe('userId=')
  })

  // The owner comes off a stored record whose contents belong to the consumer, so it is guarded
  // like any other value this library did not author — the line is a record in a line-oriented
  // pipeline, and a newline in it would open a forged one.
  it('replaces an owner that could break the log record', () => {
    expect(ownerFragment('u1\nLOG forged')).toBe('userId=<malformed>')
  })
})
