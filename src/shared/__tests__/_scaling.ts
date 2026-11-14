/**
 * Test helper: does a piece of work grow linearly with its input?
 *
 * A wall-clock bound ("under 250 ms") measures the machine as much as the code, and fails on a
 * loaded one. What a linear-time claim says is about growth, so this times the same work on a small
 * and on a large input and compares the two: a loaded machine slows both and the ratio holds. Each
 * size is timed best-of-several, which discards the runs a busy machine interrupted.
 */

/** How many times each size is timed; the fastest run stands for it. */
const RUNS = 5

/** The smallest time, in milliseconds, a measurement is trusted to resolve. */
const RESOLUTION_MS = 0.05

/** How far above exact linear growth the large run may be before the work counts as superlinear. */
const SLACK = 5

/**
 * The fastest of several timings of `work` on an input of `size`.
 *
 * @param work - The work under test; it checks its own result.
 * @param size - The input size handed to it.
 * @returns The fastest run, in milliseconds.
 */
async function fastest(work: (size: number) => unknown, size: number): Promise<number> {
  let best = Infinity
  for (let run = 0; run < RUNS; run += 1) {
    const started = performance.now()
    await work(size)
    best = Math.min(best, performance.now() - started)
  }
  return best
}

/**
 * Asserts that `work` grows no faster than linearly between two input sizes.
 *
 * Linear work takes about `large / small` times as long on the larger input; quadratic work takes
 * about its square. The bound sits `SLACK` times above the first and far below the second.
 *
 * @param work - The work under test on an input of the given size; it checks its own result.
 * @param small - The smaller size.
 * @param large - The larger size.
 * @throws When the large run took more than `SLACK * (large / small)` times the small one.
 */
export async function expectLinearScaling(
  work: (size: number) => unknown,
  small: number,
  large: number
): Promise<void> {
  const smallMs = Math.max(await fastest(work, small), RESOLUTION_MS)
  const largeMs = await fastest(work, large)
  const limit = smallMs * (large / small) * SLACK
  if (largeMs >= limit) {
    throw new Error(
      `work grew faster than linearly: ${smallMs.toFixed(3)} ms on ${small} became ` +
        `${largeMs.toFixed(3)} ms on ${large}, more than the ${limit.toFixed(3)} ms linear growth allows`
    )
  }
}
