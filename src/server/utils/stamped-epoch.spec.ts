/**
 * @fileoverview Tests for readStampedEpoch, the defensive reader behind the bulk-revocation
 * comparison in the JWT guards.
 */

import { readStampedEpoch } from './stamped-epoch'

describe('readStampedEpoch', () => {
  // The ordinary case: a token stamped by this library carries its generation through intact,
  // so a bumped user's newer tokens keep working.
  it('returns the stamped generation unchanged', () => {
    expect(readStampedEpoch({ epoch: 5 })).toBe(5)
    expect(readStampedEpoch({ epoch: 1 })).toBe(1)
  })

  // A token carrying no claim reads as the lowest generation: it passes while the user has
  // never been bumped and stops the moment they are — the fail-closed direction.
  it('reads an absent claim as generation zero', () => {
    expect(readStampedEpoch({})).toBe(0)
    expect(readStampedEpoch({ epoch: undefined })).toBe(0)
    expect(readStampedEpoch({ epoch: 0 })).toBe(0)
  })

  // The reason this helper exists. The comparison it feeds is `stamped < stored`, and
  // JavaScript answers `false` when the left side is not a number — so a token carrying a
  // string, NaN, or an object as its epoch would sail straight past a bulk revocation. Every
  // unusable shape must collapse to the lowest generation instead.
  it('reads an unusable claim as generation zero', () => {
    for (const epoch of ['zzz', '3', Number.NaN, Number.POSITIVE_INFINITY, 1.5, null, {}, []]) {
      expect(readStampedEpoch({ epoch })).toBe(0)
    }
  })

  // A negative generation is below every stored value by construction; clamping it to zero
  // keeps the comparison meaningful rather than letting a crafted `-1` behave like "older than
  // possible" in some other arithmetic downstream.
  it('clamps a negative generation to zero', () => {
    expect(readStampedEpoch({ epoch: -1 })).toBe(0)
    expect(readStampedEpoch({ epoch: -9_999 })).toBe(0)
  })
})
