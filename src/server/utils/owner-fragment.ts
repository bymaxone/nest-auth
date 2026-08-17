/**
 * How a reuse-detection line names the account, including when it cannot name one.
 *
 * @layer Utility
 */
import { logSafe } from './log-safe'

/**
 * Stands in for the account when no member of the family could name it.
 *
 * Says what is unknown AND what was measured, because the two together are the finding: a family
 * with no readable member is a lineage that is already dead, so the replay is repeat traffic
 * against it. That is information; an empty field is not.
 *
 * It names the OBSERVATION, not a cause. `readFamilyOwner` answers `''` for three different
 * reasons — every member record gone, a member whose JSON will not parse, a member carrying no
 * `userId` — and only the first is the already-revoked case, which even then cannot be told apart
 * from ordinary TTL expiry. An earlier wording said _"every session in this family was already
 * revoked"_, which reads as a diagnosis the caller has no basis for and would send an on-call
 * looking for a revocation during what may be store corruption.
 */
const UNKNOWN_OWNER = 'userId=<unknown: no live session remains in this family to name it>'

/**
 * Builds the `userId=` fragment of the reuse-detection log line.
 *
 * `revokeFamily` resolves the owner by reading the first readable member of the family. On the
 * second and later replay of an already-revoked family there is none: the consumed marker
 * outlives the sessions it points at, so reuse is detected again while every record that could
 * name the owner is gone. That is the common way it happens, not the only one — see
 * {@link UNKNOWN_OWNER}. The line then read `userId=` — an empty field on the strongest evidence
 * of compromise
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
