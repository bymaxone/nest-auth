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
 * Empty secrets are skipped: splitting on `''` would explode the text into characters and rejoin
 * it with the marker between every one. An empty string also has nothing to hide, so skipping it
 * is correct rather than merely defensive.
 *
 * @param value - Text about to be logged.
 * @param secrets - Values that must not appear in it.
 * @returns `value` with every occurrence of every secret replaced.
 */
export function redactSecrets(value: string, secrets: readonly string[]): string {
  let out = value

  for (const secret of secrets) {
    // Length rather than `=== ''`: this is a guard against a degenerate separator, not a
    // comparison of one credential against another, and writing it as a length check says so
    // in the code instead of relying on a reader to infer it.
    if (secret.length === 0) continue
    out = out.split(secret).join(REDACTED)
  }
  return out
}
