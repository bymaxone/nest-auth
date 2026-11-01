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

/**
 * A write that runs `first` and, only if it succeeded, every follow-up, raising the first failure.
 *
 * For a write whose follow-ups prune what points at its target: an index member naming a credential
 * must outlive a failed deletion of that credential, or the sweep that revokes by index can no
 * longer find the session that is still alive. A failure of `first` therefore skips the follow-ups,
 * while a failing follow-up does not stop the ones after it.
 *
 * @param first - The write the follow-ups depend on.
 * @param followUps - Writes attempted, in order, once `first` has succeeded.
 * @returns A write to hand to {@link settleWrites}; it raises the error `first` raised, or else the
 *   first follow-up's.
 */
export function settleAfter(
  first: () => Promise<unknown>,
  followUps: ReadonlyArray<() => Promise<unknown>>
): () => Promise<void> {
  return async (): Promise<void> => {
    await first()
    raiseFirst(await settleWrites(followUps))
  }
}
