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
 * @example
 * ```typescript
 * // A relay rejected the message and quoted the body back:
 * redactSecrets('550 rejected: "Your code is 699647."', ['699647'])
 * // => '550 rejected: "Your code is <redacted>."'
 * ```
 *
 * @param value - Text about to be logged.
 * @param secrets - Values that must not appear in it.
 * @returns `value` with every occurrence of every secret replaced.
 */
export function redactSecrets(value: string, secrets: readonly string[]): string {
  // Length rather than `=== ''`: this is a guard against a degenerate pattern, not a comparison
  // of one credential against another, and writing it as a length check says so in the code
  // instead of relying on a reader to infer it.
  const present = secrets.filter((secret) => secret.length > 0)

  // The marker is written INTO the output, so it is subject to the same contract as everything
  // else in it: if a secret occurs inside `<redacted>` — `cted` does — then emitting the marker
  // publishes that secret, and the function fails the one promise it makes. Deleting instead is
  // the honest fallback. The operator loses the "something was here" signal in a case that needs
  // a credential to be a substring of the word "redacted"; this library's own OTPs (digits) and
  // tokens (lower-case hex) cannot be, but the function is exported and a caller's may.
  const marker = present.some((secret) => REDACTED.includes(secret)) ? '' : REDACTED

  // Every occurrence of every secret, located against the ORIGINAL text before anything is
  // rewritten. That ordering is the whole design, and two defects live in the alternatives.
  //
  // Replacing one secret at a time rescans text this function already produced, so a later secret
  // can match INSIDE a marker an earlier pass inserted — `cted` does — giving `<reda<redacted>>`.
  //
  // And scanning left to right taking the longest match at each position still loses. Consider
  // `['1234', '2345']` over `12345`: the scan takes `1234` at 0, resumes at 4, finds no match,
  // and emits `<redacted>5` — the tail of the SECOND secret surviving in the log. No ordering
  // fixes it, because the two overlap without either containing the other. Collecting the ranges
  // first and merging the overlap into one redaction is what covers it.
  const ranges: Array<{ start: number; end: number }> = []

  for (const secret of present) {
    // `from + 1`, not `from + secret.length`: occurrences of one secret can overlap each other
    // (`aa` inside `aaa`), and stepping past the whole match would skip the second one.
    for (let from = value.indexOf(secret); from !== -1; from = value.indexOf(secret, from + 1)) {
      ranges.push({ start: from, end: from + secret.length })
    }
  }

  // Ascending by start, because the merge below walks the list once and compares each range only
  // against the one before it. Collection order follows the SECRETS array, which has nothing to do
  // with where they appear — pass `[token, otp]` for a body that mentions the otp first and the
  // unsorted list makes the merge swallow the earlier range, emitting that secret verbatim.
  ranges.sort((a, b) => a.start - b.start)

  // Overlapping and nested ranges collapse into one redaction. Emitting a marker per range would
  // write two for a single overlapping region and, worse, leave the gap between them intact.
  const merged: Array<{ start: number; end: number }> = []

  for (const range of ranges) {
    const last = merged.at(-1)

    if (last !== undefined && range.start <= last.end) {
      last.end = Math.max(last.end, range.end)
      continue
    }
    merged.push({ ...range })
  }

  let out = ''
  let cursor = 0

  for (const range of merged) {
    out += value.slice(cursor, range.start) + marker
    cursor = range.end
  }
  return out + value.slice(cursor)
}
