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
 * standalone representation inside it. Bounding the text does NOT cover that gap — the encoding
 * runs from the body's start, so the credential is in the first sentence and survives any cap
 * that leaves enough to decode. The caller's answer is to not log channel free text at all while
 * a credential is in flight; this function handles what it can see.
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
  //
  // Sorted longest-first, once, so the scan below can return on its first match — and so a secret
  // that is a PREFIX of another cannot claim the position first, consume its own length and leave
  // the remainder of the longer one in the log. Sorting in place is safe here precisely because
  // `filter` already returned a new array; `secrets` itself is never reordered under the caller.
  const present = secrets.filter((secret) => secret.length > 0).sort((a, b) => b.length - a.length)

  // The marker is written INTO the output, so it is subject to the same contract as everything
  // else in it: if a secret occurs inside `<redacted>` — `cted` does — then emitting the marker
  // publishes that secret, and the function fails the one promise it makes. Deleting instead is
  // the honest fallback. The operator loses the "something was here" signal in a case that needs
  // a credential to be a substring of the word "redacted"; this library's own OTPs (digits) and
  // tokens (lower-case hex) cannot be, but the function is exported and a caller's may.
  const marker = present.some((secret) => REDACTED.includes(secret)) ? '' : REDACTED

  // One left-to-right pass over the ORIGINAL text, extending each redaction over any secret that
  // starts inside it. Three designs were wrong before this one and each failure is worth naming,
  // because each looked correct.
  //
  // Replacing one secret at a time rescans text this function already produced, so a later secret
  // matches INSIDE a marker an earlier pass inserted — `cted` is in `<redacted>` — giving
  // `<reda<redacted>>`.
  //
  // Taking the longest match at each position and resuming past it loses overlaps that nest in
  // neither direction. Over `12345` with `['1234','2345']` it takes `1234`, resumes at index 4,
  // matches nothing, and emits `<redacted>5` — the tail of the second credential, in the log.
  // The inner extension below is exactly what covers that case.
  //
  // Collecting every occurrence into an array and merging the ranges is correct but allocates one
  // object per occurrence and then sorts them. This runs inside a `catch` whose entire purpose is
  // to absorb a failure, and the text is channel-controlled: a rejection quoting a body with the
  // code repeated thousands of times would have this function allocating proportionally to the
  // provocation. Extending in place holds the same guarantees with no per-occurrence allocation
  // and no sort.
  let out = ''
  let index = 0

  // `<=` here is equivalent and no test separates the two. The extra iteration it allows lands on
  // `index === value.length`, where `startsWith` is false for every non-empty secret and `charAt`
  // returns the empty string, so the buffer is unchanged and the loop exits on the next check.
  // Same output, one wasted comparison.
  //
  // The directive sits on its own line immediately above the target. It was measured to bind from
  // the end of a multi-line comment too, but `next-line` counting past a wrapped explanation is a
  // documented way to silently disable nothing, and adjacency costs a line.
  // Stryker disable next-line EqualityOperator
  while (index < value.length) {
    const matched = longestMatchAt(value, present, index)

    if (matched === 0) {
      out += value.charAt(index)
      index += 1
      continue
    }

    let end = index + matched

    // Extend while any secret STARTS inside the region already claimed. `1234` claims `[0,4)` and
    // `2345` starts at 1, so the region grows to `[0,5)` and the whole run is redacted as one.
    //
    // From `index` rather than `index + 1`, which costs one redundant test per region — the match
    // at `index` is already known — and buys a loop bound with no arithmetic in it to get wrong.
    for (let inner = index; inner < end; inner += 1) {
      end = Math.max(end, inner + longestMatchAt(value, present, inner))
    }
    out += marker
    index = end
  }

  // Replacing text can CREATE an occurrence that was not in the input. The marker is written into
  // the output and then sits next to whatever followed the region, so a secret spanning that seam
  // — `'<redacted>X'` declared as a secret, over the input `'xyzX'` with `'xyz'` also declared —
  // appears in a result assembled entirely from pieces that individually contained none.
  //
  // Checking the finished string is the only test that covers every way a seam can arise, because
  // it asks the question the contract actually makes rather than enumerating the mechanisms. When
  // it fails there is no safe partial answer to return — a second pass could synthesise a third
  // occurrence — so the diagnostic is abandoned entirely. That costs an operator the line, in a
  // case that requires a caller to declare a secret containing this function's own marker.
  if (present.some((secret) => out.includes(secret))) return ''

  return out
}

/**
 * Length of the longest secret occurring at exactly this position.
 *
 * Returns on the first match because `secrets` arrives sorted longest-first, which is what makes
 * the first match the longest. Comparing lengths per candidate instead would do the same work and
 * add a comparison whose boundary is invisible in the result: two secrets of equal length produce
 * the same number whichever one wins.
 *
 * @param value - The text being scanned.
 * @param secrets - Non-empty secrets, ordered longest first.
 * @param at - Index to test.
 * @returns The match length, or `0` when no secret starts here.
 */
function longestMatchAt(value: string, secrets: readonly string[], at: number): number {
  for (const secret of secrets) {
    if (value.startsWith(secret, at)) return secret.length
  }
  return 0
}
