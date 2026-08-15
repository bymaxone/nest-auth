/**
 * Removes known secret values from text that is about to be logged or rethrown.
 *
 * @layer Utility
 */

/**
 * Written in place of every secret occurrence.
 *
 * Deliberately visible rather than a silent deletion: an operator reading `<redacted>` learns
 * that the channel echoed something this library recognised as a credential, which is itself a
 * finding about their mail relay.
 */
const REDACTED = '<redacted>'

/**
 * Replaces every occurrence of each secret in `value` with `<redacted>`.
 *
 * The case this exists for is a mail channel that rejects a message by **quoting the body back**.
 * A policy, DLP or anti-spam relay answering `550` with the offending content puts whatever the
 * message contained into the error it raises — and for this library that content is a
 * password-reset OTP, an email-verification OTP or an invitation token. The error then flows to a
 * log line and the credential is in the operator's log pipeline in clear text, valid until it
 * expires. Measured against a real relay rather than hypothesised.
 *
 * Matching is exact and case-sensitive, which is what the credentials this library issues call
 * for: OTPs are digits and tokens are lower-case hex, so they survive an echo byte-for-byte.
 * Over-redaction is accepted without hesitation — a message id that happens to contain a four
 * digit OTP is written as `<redacted>` and nothing of value is lost, whereas the reverse mistake
 * publishes a live credential.
 *
 * **This cannot find a secret the channel re-encoded.** A relay that returns the body base64'd
 * defeats substring matching, because the encoding is block-aligned and the secret has no
 * standalone representation inside it. That residual case is why the caller must also bound how
 * much channel text it logs, rather than treating this function as sufficient on its own.
 *
 * Empty secrets are skipped: an empty string matches at every position, so the scan would emit a
 * marker between every character and never advance past one. An empty string also has nothing to
 * hide, so skipping it is correct rather than merely defensive.
 *
 * @param value - Text about to be logged.
 * @param secrets - Values that must not appear in it.
 * @returns `value` with every occurrence of every secret replaced.
 */
export function redactSecrets(value: string, secrets: readonly string[]): string {
  const present = [...secrets]
    // Length rather than `=== ''`: this is a guard against a degenerate pattern, not a comparison
    // of one credential against another, and writing it as a length check says so in the code
    // instead of relying on a reader to infer it.
    .filter((secret) => secret.length > 0)
    // Longest first, so `1234` is preferred over `123` where both are in flight. Without it the
    // shorter match wins, consumes its prefix and leaves the remaining `4` — a fragment of a live
    // credential — sitting in the log. Sorted on a copy: `secrets` is the caller's array and
    // reordering it under them would be a side effect they never asked for.
    .sort((a, b) => b.length - a.length)

  // Scanned once, left to right, emitting into a separate buffer. Two properties come from that
  // shape and neither is available to a replace-one-secret-at-a-time loop.
  //
  // It never revisits what it wrote. Replacing sequentially rescans text this function already
  // rewrote, so a later secret can match INSIDE a `<redacted>` an earlier pass inserted — `cted`
  // does, since the marker contains it — and the line comes out as `<reda<redacted>>`.
  //
  // And it matches literally, with no pattern to escape. Building a regular expression from a
  // caller-supplied secret would need every metacharacter escaped first, and an escape that
  // missed one would either redact text that is not the secret or throw on an unbalanced group.
  let out = ''
  let index = 0

  // Stryker disable next-line EqualityOperator: `<=` is equivalent here and no test can separate
  // it. The extra iteration it allows lands on `index === value.length`, where `startsWith` is
  // false for every non-empty secret and `charAt` returns the empty string, so the buffer is
  // unchanged and the loop exits on the next check. Same output, one wasted comparison.
  while (index < value.length) {
    const matched = present.find((secret) => value.startsWith(secret, index))

    if (matched === undefined) {
      out += value.charAt(index)
      index += 1
      continue
    }
    out += REDACTED
    index += matched.length
  }
  return out
}
