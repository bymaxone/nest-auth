/**
 * Tests for the scaling helper the linear-time specs share: it must accept work that grows linearly
 * and reject work that grows quadratically, because a check that cannot fail proves nothing.
 */

import { expectLinearScaling } from './_scaling'

/** Work that touches each of `size` elements once. */
function linear(size: number): number {
  let sum = 0
  for (let index = 0; index < size; index += 1) sum += index
  return sum
}

/** Work that touches every pair of `size` elements. */
function quadratic(size: number): number {
  let sum = 0
  for (let outer = 0; outer < size; outer += 1) {
    for (let inner = 0; inner < size; inner += 1) sum += inner
  }
  return sum
}

describe('expectLinearScaling', () => {
  // Scenario: work that is linear in its input. Expected: accepted.
  it('accepts work that grows linearly', async () => {
    await expect(expectLinearScaling(linear, 20_000, 400_000)).resolves.toBeUndefined()
  })

  // Scenario: work that is quadratic in its input. Expected: rejected, naming both timings.
  it('rejects work that grows quadratically', async () => {
    await expect(expectLinearScaling(quadratic, 500, 10_000)).rejects.toThrow(
      /grew faster than linearly/
    )
  })

  // Scenario: async work, as the Next.js reader is. Expected: awaited, so the timing includes it.
  it('awaits asynchronous work', async () => {
    await expect(
      expectLinearScaling(async (size) => linear(size), 20_000, 400_000)
    ).resolves.toBeUndefined()
  })
})
