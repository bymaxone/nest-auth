/**
 * @fileoverview Reads the token-epoch claim defensively for the bulk-revocation check.
 *
 * @layer Util
 */

/**
 * Reads the `epoch` claim of a verified access token as a usable generation number.
 *
 * Anything that is not a non-negative integer reads as `0` — the lowest possible generation —
 * so it can only ever make the token *more* likely to be rejected, never less.
 *
 * That matters because the comparison this feeds is `stamped < stored`, and JavaScript's
 * relational operators quietly answer `false` for a non-numeric left side: a token carrying
 * `epoch: "abc"`, `epoch: NaN`, or `epoch: {}` would otherwise sail past a bulk revocation.
 * The guard cannot assume the claim came from this library's signer — any other holder of the
 * deployment secret (a sibling service, an older version) could emit one.
 *
 * A token with no `epoch` at all is the legitimate legacy case and also reads as `0`: it is
 * accepted while the user has never been bumped, and rejected the moment they are.
 *
 * @param payload - The verified token payload.
 * @returns The stamped generation, or `0` when the claim is absent or unusable.
 */
export function readStampedEpoch(payload: { epoch?: unknown }): number {
  const { epoch } = payload
  return typeof epoch === 'number' && Number.isInteger(epoch) ? Math.max(0, epoch) : 0
}
