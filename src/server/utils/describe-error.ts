/**
 * Renders a thrown value into one bounded, secret-free line fit for a log.
 *
 * @layer Utility
 */
import { logSafe } from './log-safe'
import { redactSecrets } from './redact-secrets'

/**
 * How much of an error's text may reach a log line.
 *
 * A bound rather than a formatting preference. {@link redactSecrets} removes the credentials the
 * caller knows it put in flight, but it cannot find one that was re-encoded on the way back, so
 * the second lock is to refuse to relay an unbounded quantity of foreign text into the log at
 * all. The diagnosis an operator actually needs — `535 authentication failed`, `ECONNREFUSED` —
 * is short and comes first; a rejection that quotes an entire message body is exactly the long
 * one.
 */
const ERROR_TEXT_LIMIT = 200

/**
 * How far down the `cause` chain the description walks.
 *
 * Chains are how a client reports "the call failed BECAUSE the remote said". The useful context
 * is near the top, and the depth is capped so a self-referential or pathological chain cannot
 * turn one failure into an unbounded log record.
 */
const ERROR_CAUSE_DEPTH = 3

/**
 * Describes a thrown value in one line, with known credentials stripped out.
 *
 * Reads an allowlist of `name` and `message` and nothing else. That is the point rather than an
 * omission: a thrown value carries whatever threw it decided to put in it — a mail client hangs
 * the server's full reply on `response`, and `stack` embeds the message — so an allowlist is the
 * only shape whose contents a caller can reason about. Each piece is redacted against the secrets
 * in flight, joined, length-capped and passed through {@link logSafe}, because text that came
 * back from a remote is untrusted input and a CR/LF in it would forge a second log record.
 *
 * The case this exists for: a mail relay rejecting a message by **quoting the body back**. The
 * body holds the one-time code this library just issued, so the error is the credential, and a
 * log line built from it publishes a working credential until it expires.
 *
 * @param error - Whatever was thrown.
 * @param secrets - Credentials that were in flight and must not survive into the line. Required
 *   rather than defaulted: a caller that has nothing to hide says so by passing an empty array,
 *   which is one keystroke, whereas a default lets a call site that *does* hold a credential
 *   forget to name it and read as correct. This is the parameter whose omission is the bug.
 * @returns A single-line description safe to log.
 */
export function describeError(error: unknown, secrets: readonly string[]): string {
  const parts: string[] = []
  let current: unknown = error

  for (
    let depth = 0;
    depth < ERROR_CAUSE_DEPTH && current !== undefined && current !== null;
    depth++
  ) {
    if (!(current instanceof Error)) {
      // A thrown non-Error has no contract at all — a string, an object, a rejected promise's
      // value. Its type is the most that can be said about it without stringifying something
      // whose `toString` belongs to whoever threw it.
      parts.push(`<non-error: ${typeof current}>`)
      break
    }

    // `name` and `message` are typed `string` but are ordinary writable properties: a subclass,
    // or a value revived from JSON, can leave either holding something else. Coercing here keeps
    // a malformed error from throwing a TypeError inside the caller's catch block, which would
    // turn a handled failure into an unhandled rejection — a worse outcome than a poor log line.
    const name = logSafe(redactSecrets(String(current.name), secrets))
    const message = logSafe(redactSecrets(String(current.message), secrets))
    // Capped once, on the composed piece, rather than on each half: two bounds let one link of
    // the chain contribute twice the intended budget, and the pair says nothing the single bound
    // does not. An empty message leaves the name standing alone rather than trailing a colon.
    const described = message === '' ? name : `${name}: ${message}`

    parts.push(described.slice(0, ERROR_TEXT_LIMIT))
    current = current.cause
  }

  // The loop guard stops the walk when a `cause` is absent, which is the same test that skips the
  // body entirely when the THROWN value is itself `undefined` or `null` — legal from a channel
  // (`Promise.reject()` is a valid rejection). Without this, that case returns an empty string
  // and the caller emits `delivery failed for "X": ` with a dangling colon and no diagnosis at
  // all. Reported rather than swallowed: "something rejected with nothing" is itself the finding.
  if (parts.length === 0) return `<non-error: ${typeof error}>`

  return parts.join(' <- ')
}
