/**
 * Runs a list of writes to completion and reports what failed (layer: Utils).
 *
 * A revocation is a set of writes that each close one way back in: the blacklist entry, the refresh
 * session, its rotation grace pointer. Stopping at the first refusal leaves the others undone, and
 * swallowing a refusal reports a revocation that did not happen. This runs every write, in order,
 * whatever the earlier ones did, and hands back the failures so the caller can finish its other
 * work and then raise the first.
 */

/**
 * Attempts every write in order and returns the errors the failing ones raised.
 *
 * Sequential on purpose: the order is the order the failures are reported in, and a caller that
 * raises the first one raises the same error however long each write took.
 *
 * @param writes - The writes to attempt, each started only after the previous one has settled.
 * @returns The errors raised, in the order the writes ran; empty when every write succeeded.
 */
export async function settleWrites(
  writes: ReadonlyArray<() => Promise<unknown>>
): Promise<unknown[]> {
  const failures: unknown[] = []
  for (const write of writes) {
    try {
      await write()
    } catch (err: unknown) {
      failures.push(err)
    }
  }
  return failures
}

/**
 * Raises the first of a list of failures, or does nothing when the list is empty.
 *
 * @param failures - The errors {@link settleWrites} returned.
 * @throws The first error in the list.
 */
export function raiseFirst(failures: readonly unknown[]): void {
  const [first] = failures
  if (failures.length > 0) throw first
}
