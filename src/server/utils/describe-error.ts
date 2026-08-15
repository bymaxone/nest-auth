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
 * A bound on VOLUME, and explicitly not on disclosure — the earlier version of this comment
 * called it a second lock against a re-encoded body, and that was wrong. A relay returning the
 * body base64'd encodes it from its start, so the credential sits in the first sentence and
 * survives any cap that leaves enough text to decode: the whole reset-code body is 96 base64
 * characters. Confidentiality on a credential path comes from dropping the free text entirely and
 * keeping only a parsed status code; this limit is what stops a bounce filling a log file.
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
 * Written when reading an error's own fields is what fails.
 *
 * A description that cannot be produced still has to be a description — the caller is inside a
 * `catch` block and needs a line, not a second exception.
 */
/**
 * What to do with the channel's own free text.
 *
 * `'redact'` keeps it with the named values stripped. Right only where the BODY renders nothing
 * that must be withheld, which leaves the recipient as the one value at risk — and a bounce names
 * the recipient in plain text (`550 user@example.com: recipient rejected`), where redaction
 * reaches it. There is no encoded body to see through, because the body held nothing to hide.
 *
 * `'drop'` keeps only a parsed status code. Required whenever the body renders a value that must
 * not be logged — a credential, but personal data too: an IP is not a credential and is still not
 * something to publish. The standard is what the body renders, not how bad it would be. Because
 * redaction cannot see through an encoding and a bound on length does not help: a relay returning
 * the body base64'd encodes it from the start, so the code sits in the first sentence and survives
 * any cap that leaves enough to decode. Measured — the whole reset-code body is 96 base64
 * characters, and the first 200 of that line decode straight back to the OTP.
 */
export type ChannelTextPolicy = 'redact' | 'drop'

const MALFORMED = '<malformed-error>'

/**
 * Classifies a thrown value without letting the classification itself throw.
 *
 * `instanceof` invokes the prototype lookup, and a `Proxy` can install a `getPrototypeOf` trap
 * that throws — so even asking "is this an Error?" runs code belonging to whoever threw it. That
 * exception would escape from inside the caller's `catch` block, which is the one thing this
 * module exists to prevent. A value whose own classification is hostile is treated as a non-error,
 * which is what it has earned.
 *
 * @param value - The thrown value.
 * @returns `true` only when the value is an `Error` and asking did not throw.
 */
function isError(value: unknown): value is Error {
  try {
    return value instanceof Error
  } catch {
    return false
  }
}

/**
 * Renders one link of the chain, and never throws while doing it.
 *
 * `name`, `message` and `cause` look like plain properties but any of them can be an accessor
 * that throws, and `String()` on an object runs a `toString`/`Symbol.toPrimitive` that can throw
 * too. All of them belong to whoever constructed the error, which for a mail channel means a
 * third-party client. An exception raised here would propagate out of the caller's `catch` block
 * and turn a delivery failure the swallow policy promises to absorb into an unhandled rejection
 * with **no log line at all** — strictly worse than the leak this function exists to prevent.
 *
 * @param error - The link being described.
 * @param secrets - Credentials that must not survive into the line.
 * @param channelText - `'drop'` reduces BOTH channel-controlled fields to a validated shape: the
 *   message to its status code (see {@link statusOf}), the name to an identifier (see
 *   {@link nameOf}).
 * @returns One redacted, control-character-free line. NOT length-bounded: the cap is applied
 *   once to the finished description, because capping each part would let a chain of parts
 *   return a multiple of the budget.
 */
function describeOneLink(
  error: Error,
  secrets: readonly string[],
  channelText: ChannelTextPolicy
): string {
  try {
    const name = nameOf(error, secrets, channelText)
    const raw = String(error.message)

    // WITH a credential in flight, the channel's free text does not reach the line at all — only
    // a status code parsed out of it. Redaction cannot save that text: a relay that returns the
    // body RE-ENCODED defeats substring matching, and the length cap does not help either, because
    // the encoding is of the body FROM ITS START and the code sits in the first sentence. Measured:
    // the whole reset-code body is 96 base64 characters, so the first 200 of the line decode
    // straight back to the OTP. A bound on volume was never a bound on disclosure, and describing
    // it as a second lock — as this file did — was the mistake.
    const detail = channelText === 'drop' ? statusOf(raw) : logSafe(redactSecrets(raw, secrets))

    return detail === '' ? name : `${name}: ${detail}`
  } catch {
    return MALFORMED
  }
}

/**
 * A JavaScript error name, as a shape rather than as free text.
 *
 * An identifier: `Error`, `TypeError`, `SmtpRejection`, `AggregateError`. Two properties are being
 * bought, and the second is why the bound is a specific number rather than a generous one.
 *
 * The character class excludes what a quoted body is made of — spaces, quotes, colons, and the
 * `+/=` of base64 — so a rejection that echoes the message cannot pass as a name whatever encoding
 * it arrived in.
 *
 * The length of 48 is chosen so that **no credential this library issues can occupy a valid name**:
 * every token is 64 hex characters, which does not fit, and every OTP is digits, which cannot even
 * start one. It is still far above any real name — `MongoNetworkTimeoutError` is 24 — so nothing
 * legitimate is lost. That invariant is what lets the drop policy be stated as a guarantee rather
 * than as a hope about what a channel happens to write.
 */
const ERROR_NAME_SHAPE = /^[A-Za-z_$][A-Za-z0-9_$]{0,47}$/

/** Stands in for a name that did not look like one. */
const OPAQUE_NAME = '<error>'

/**
 * The error's name, validated by shape when the channel's free text is not trusted.
 *
 * `name` is as much the channel's to write as `message` is — an error class built around a relay
 * reply (`name = \`SmtpRejection: ${response}\``) is a normal thing for a mail client to do, and
 * this module's own history is the proof that "it is only the error's own field, not the body" is
 * the assumption that fails. Dropping the message while letting the name through would have moved
 * the leak one field over and left every argument for the drop intact: redaction still misses a
 * re-encoded body, and the line cap still bounds volume rather than disclosure.
 *
 * So under `'drop'` the name is kept only when it looks like a name. Redaction runs FIRST, so a
 * name that did contain a credential no longer matches the shape and becomes opaque rather than
 * being published with a marker in it.
 *
 * Under `'redact'` nothing secret was in flight, the message's own text is already allowed
 * through, and constraining the name would cost diagnosis to buy nothing.
 *
 * @param error - The link whose name is wanted.
 * @param secrets - Credentials that must not survive into it.
 * @param channelText - Whether the channel's free text is trusted on this path.
 * @returns The name, or an opaque stand-in.
 */
function nameOf(error: Error, secrets: readonly string[], channelText: ChannelTextPolicy): string {
  const name = logSafe(redactSecrets(String(error.name), secrets))

  if (channelText === 'redact') return name
  return ERROR_NAME_SHAPE.test(name) ? name : OPAQUE_NAME
}

/**
 * The SMTP status code at the head of a message, or the empty string.
 *
 * Structured and independently validated, which is what makes it safe to keep when free text is
 * not: three digits, optionally followed by an enhanced `X.Y.Z` code, matched at the very start
 * and returned from the PATTERN's own capture rather than by slicing the input. Nothing a relay
 * writes after that can ride along, whatever it encoded it in.
 *
 * It is also the half of a bounce an operator actually acts on — `550` is a refusal, `421` is a
 * transient outage, `535` is a credential problem on their side. Keeping it is what makes dropping
 * the rest affordable.
 *
 * @param message - The channel's raw message.
 * @returns The status code, normalised, or `''` when the message does not begin with one.
 */
function statusOf(message: string): string {
  const match = /^(\d{3})(?:\s+(\d\.\d\.\d))?/.exec(message)

  if (match === null) return ''
  return match[2] === undefined ? `${match[1]}` : `${match[1]} ${match[2]}`
}

/**
 * Reads the next link of the chain, treating a throwing accessor as the end of it.
 *
 * Separate from {@link describeOneLink} because the failures are different: a `cause` that throws
 * means there is nothing further to walk, whereas a `message` that throws still leaves a link to
 * report. Collapsing them would drop a description this function could have produced.
 *
 * @param error - The link whose cause is wanted.
 * @returns The next link, or `undefined` when there is none or it cannot be read.
 */
function readCause(error: Error): unknown {
  try {
    return error.cause
  } catch {
    return undefined
  }
}

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
 * @example
 * ```typescript
 * // A relay rejected the message and quoted the body back, wrapped by the mail client:
 * describeError(err, [otp], 'drop')
 * // => 'Error <- Error: 550'
 *
 * // The same error where nothing secret was in flight — the relay's own words are the diagnosis:
 * describeError(err, [], 'redact')
 * // => 'Error: send failed <- Error: 550 rejected: "Your code is 123456."'
 * ```
 *
 * @param error - Whatever was thrown.
 * @param secrets - Credentials that were in flight and must not survive into the line. Required
 *   rather than defaulted: a caller that has nothing to hide says so by passing an empty array,
 *   which is one keystroke, whereas a default lets a call site that *does* hold a credential
 *   forget to name it and read as correct. This is the parameter whose omission is the bug.
 * @param channelText - What to do with the free text the remote sent. `'drop'` on any path that
 *   carries a credential: the text is replaced by the status code parsed off its front, because
 *   redaction and the length cap both assume the credential appears in the line the way this
 *   library wrote it, and a relay that re-encodes the body it quotes (base64 is the ordinary
 *   case) breaks that assumption — the encoding runs from the body's first byte, so the code is
 *   inside the cap and matches no secret. `'redact'` only where nothing secret was in flight.
 *   Required for the same reason `secrets` is: a permissive default is a leak that reads as
 *   correct at the call site that forgot it.
 * @returns A single-line description safe to log.
 */
export function describeError(
  error: unknown,
  secrets: readonly string[],
  channelText: ChannelTextPolicy
): string {
  const parts: string[] = []
  let current: unknown = error

  for (
    let depth = 0;
    depth < ERROR_CAUSE_DEPTH && current !== undefined && current !== null;
    depth++
  ) {
    if (!isError(current)) {
      // A thrown non-Error has no contract at all — a string, an object, a rejected promise's
      // value. Its type is the most that can be said about it without stringifying something
      // whose `toString` belongs to whoever threw it.
      parts.push(`<non-error: ${typeof current}>`)
      break
    }

    const described = describeOneLink(current, secrets, channelText)

    parts.push(described)
    current = readCause(current)
  }

  // The loop guard stops the walk when a `cause` is absent, which is the same test that skips the
  // body entirely when the THROWN value is itself `undefined` or `null` — legal from a channel
  // (`Promise.reject()` is a valid rejection). Without this, that case returns an empty string
  // and the caller emits `delivery failed for "X": ` with a dangling colon and no diagnosis at
  // all. Reported rather than swallowed: "something rejected with nothing" is itself the finding.
  // Redacted ONCE MORE, over the finished line, and this is not belt-and-braces. Redaction runs
  // per component, and three things happen after it: `logSafe` REPLACES a control-character value
  // with `<malformed>`, a failed link becomes `<malformed-error>`, and the parts are joined with
  // a separator. Each of those writes text the per-component pass never saw, so a caller whose
  // declared secret is one of those markers — or that spans a join seam — gets it published by
  // the very function meant to remove it. `redactSecrets` also enforces its own end-to-end check,
  // so a seam it cannot resolve collapses to an empty diagnostic rather than a leaking one.
  //
  // The empty-parts answer goes through it too: `typeof` yields a short word, and "short word a
  // caller declared as secret" is exactly the case this guard exists for.
  const line = parts.length === 0 ? `<non-error: ${typeof error}>` : parts.join(' <- ')

  // Capped on the finished line, not per link. The per-link bound alone lets a three-deep chain
  // return three times the documented budget — measured at 608 characters for the limit of 200 —
  // which is the same "one bound per part multiplies" mistake the comment inside `describeOneLink`
  // warns about, made one level up. The bound exists to stop a channel relaying an unbounded
  // quantity of its own text into a log, and a chain is a channel's text just as a message is.
  return redactSecrets(line, secrets).slice(0, ERROR_TEXT_LIMIT)
}
