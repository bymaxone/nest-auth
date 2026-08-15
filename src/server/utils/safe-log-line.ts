/**
 * Last check on a log line composed from separately-sanitised parts.
 *
 * @layer Utility
 */
import { redactSecrets } from './redact-secrets'

/**
 * Emitted in place of a line whose composition reconstructed a value that must not be logged.
 *
 * Says what happened rather than going silent: an operator who sees this learns that a line was
 * suppressed and why, which is a finding about their channel, not a gap in their logging.
 */
const WITHHELD =
  'delivery details withheld: the composed line matched a value that must not be logged'

/**
 * Returns `line`, or a withheld placeholder when any secret survived into it.
 *
 * **Why a check and not another redaction.** Sanitising each field separately leaves the seams
 * between them: two parts that individually contain nothing can spell a secret across the text a
 * template puts between them. A device string of `foo": Error: bar` reappears in full when a
 * subject of `foo` and a description of `Error: bar` are joined by `": `. Redacting the assembled
 * line would close that too — and it was tried. It makes every per-field redaction redundant with
 * the final one, so removing any single one changes nothing observable, and the mutation gate
 * reported exactly that: one surviving mutant per redaction, each masked by the others. The tests
 * passed while proving none of them.
 *
 * A check has neither problem. It closes the seam, and it *fails* if a per-field redaction is
 * removed, because the value then survives and the line becomes the placeholder. Every guard stays
 * individually observable, which is the property that makes the suite evidence rather than
 * decoration.
 *
 * @param line - The fully composed line.
 * @param secrets - Values that must not appear in it.
 * @returns The line, or the withheld placeholder.
 */
export function safeLogLine(line: string, secrets: readonly string[]): string {
  if (!secrets.some((secret) => secret.length > 0 && line.includes(secret))) return line

  // The placeholder is text like any other, so it is subject to the rule it enforces: a secret of
  // `withheld` — and a device string is arbitrary — occurs inside it, which would have this guard
  // publish the value it just detected. `redactSecrets` strips it, and collapses to an empty line
  // when the collision cannot be resolved, which is the correct end for a line that cannot be
  // written safely at all.
  return redactSecrets(WITHHELD, secrets)
}
