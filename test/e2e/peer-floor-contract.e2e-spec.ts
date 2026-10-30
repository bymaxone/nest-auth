/**
 * @fileoverview Pins the lowest version each optional peer dependency admits above its advisories.
 *
 * A `peerDependencies` range is a statement about which installs this package supports. A floor
 * below a published advisory tells a consumer that a vulnerable install is a supported one, and
 * nothing in their tooling contradicts it: the install resolves cleanly. The scheduled
 * `peer-advisory-drift` workflow finds such a floor after an advisory is published; this suite
 * holds the floors already known, so lowering one in a change fails here instead of waiting for
 * the next scheduled run.
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

/** Repository root, from this suite's location under `test/e2e/`. */
const REPO_ROOT = join(__dirname, '../..')

/**
 * The lowest version a peer range may admit, per package, with the advisories that set it.
 *
 * Add a row when an advisory raises a floor; never lower one.
 */
const PEER_FLOORS: ReadonlyArray<{ name: string; floor: string; advisories: string }> = [
  {
    name: 'next',
    floor: '16.4.1',
    advisories: 'GHSA-673q-mjm6-r5xr, GHSA-2464-fhr4-w9xw (critical, patched in 16.4.1)'
  }
]

/**
 * Compares two plain `major.minor.patch` versions.
 *
 * @param a - The first version.
 * @param b - The second version.
 * @returns A negative number when `a` is lower, zero when equal, a positive number when higher.
 */
function compareVersions(a: string, b: string): number {
  const left = a.split('.').map(Number)
  const right = b.split('.').map(Number)
  for (let i = 0; i < 3; i++) {
    const difference = (left[i] ?? 0) - (right[i] ?? 0)
    if (difference !== 0) return difference
  }
  return 0
}

/**
 * Reads the lowest version a caret range admits.
 *
 * @param range - A range of the form `^x.y.z`.
 * @returns The `x.y.z` the caret starts from.
 */
function lowestAdmitted(range: string): string {
  const match = /^\^(\d+\.\d+\.\d+)$/.exec(range)
  if (match === null) throw new Error(`peer range ${range} is not a caret range`)
  return match[1] as string
}

describe('peer dependency floors', () => {
  const manifest = JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf8')) as {
    peerDependencies: Record<string, string>
  }

  // Scenario: a peer whose lower versions carry a published advisory. Expected: the declared range
  // starts at or above the patched version. Why: the range is what a consumer is told they may
  // install, so a lower floor declares the vulnerable install supported.
  it.each(PEER_FLOORS)('admits no $name version below $floor ($advisories)', ({ name, floor }) => {
    const declared = manifest.peerDependencies[name]

    expect(declared).toBeDefined()
    expect(compareVersions(lowestAdmitted(declared as string), floor)).toBeGreaterThanOrEqual(0)
  })
})
