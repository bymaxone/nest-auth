/**
 * How a reuse-detection line names the account, including when it cannot name one.
 *
 * @layer Utility
 */
import { logSafe } from './log-safe'

/**
 * Stands in for the account when the family was already torn down.
 *
 * Says what is unknown AND why, because the two together are the finding. A family being revoked
 * a second time means the replay is repeat traffic against a lineage that is already dead — which
 * is information, where an empty field is not.
 */
const UNKNOWN_OWNER = 'userId=<unknown: every session in this family was already revoked>'

/**
 * Builds the `userId=` fragment of the reuse-detection log line.
 *
 * `revokeFamily` resolves the owner by reading the first LIVE member of the family. On the second
 * and later replay of an already-revoked family there is none: the consumed marker outlives the
 * sessions it points at, so reuse is detected again while every record that could name the owner
 * is gone. The line then read `userId=` — an empty field on the strongest evidence of compromise
 * this library produces, and precisely on REPEAT attack traffic, where `userId` is the only field
 * an on-call can act on.
 *
 * An empty field reads as a defect in the logger, so the reader distrusts the tool instead of the
 * event. Naming the absence keeps the line about the compromise.
 *
 * The owner goes through {@link logSafe} because it comes from a stored record whose contents are
 * the consumer's, and the placeholder is text this file wrote — so every value this returns is
 * safe to interpolate, which is what lets it stand as a guard in its own right.
 *
 * @param ownerId - Whatever `revokeFamily` could resolve; `''` when no member record survived.
 * @returns The fragment, naming the account or naming the absence of one.
 */
export function ownerFragment(ownerId: string): string {
  return ownerId === '' ? UNKNOWN_OWNER : `userId=${logSafe(ownerId)}`
}
