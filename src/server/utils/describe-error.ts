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
 * characters. Confidentiality on a credential path comes from dropping the channel's text
 * entirely, keeping nothing parsed off it; this limit is what stops a bounce filling a log file.
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
 * What to do with the channel's own free text.
 *
 * `'redact'` keeps it with the named values stripped, and it has NO caller inside this library —
 * it is reached only through the exported {@link describeError}, by a consumer who has a reason to
 * trust the text their own channel produces. It stops short of a guarantee: redaction is a
 * substring match, so it holds for a value that appears the way the caller wrote it and not for
 * one a remote transformed.
 *
 * `'drop'` publishes NOTHING the channel authored — not the message, not the name. Required
 * wherever the body rendered a value that must not be logged: a credential, but personal data too,
 * since an IP is not a credential and is still not something to publish. The standard is what the
 * body renders, not how bad it would be.
 *
 * A parsed SMTP status was kept here for a while, on the reasoning that a value rebuilt from a
 * validated grammar cannot carry body content. It can, and the test that shows it is whether the
 * output DEPENDS on the secret: an OTP of `424242` grouped as `424-242` at the head of a quoted
 * body publishes `424`, and a different code publishes different digits. That is derivation, not
 * coincidence, and no grammar separates a reply from body text shaped like one. What an operator
 * loses is the transient-versus-permanent split, which their mail provider's own dashboard has.
 */
type ChannelTextPolicy = 'redact' | 'drop'

/**
 * Written when reading an error's own fields is what fails.
 *
 * A description that cannot be produced still has to be a description — the caller is inside a
 * `catch` block and needs a line, not a second exception.
 */
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
 * @param channelText - `'drop'` publishes nothing the channel authored at all: the message is
 *   discarded and the name is replaced outright (see {@link nameOf}).
 * @returns One rendered line. NOT length-bounded: the cap is applied once to the finished
 *   description, because capping each part would let a chain of parts return a multiple of it.
 */
function describeOneLink(
  error: Error,
  secrets: readonly string[],
  channelText: ChannelTextPolicy
): string {
  try {
    const name = nameOf(error, secrets, channelText)

    // Unconditional, with no branch on the policy: the drop path passes no secrets, and
    // `redactSecrets` returns its input untouched when there is nothing to look for, so the walk
    // over remote-controlled text never happens there. Branching here instead would have made the
    // guard conditional on a policy rather than on whether anything needs guarding.
    const raw = redactSecrets(String(error.message), secrets)

    // WITH a credential in flight, the channel's free text does not reach the line at all, and
    // nothing is parsed off it. Redaction cannot save that text: a relay that returns the
    // body RE-ENCODED defeats substring matching, and the length cap does not help either, because
    // the encoding is of the body FROM ITS START and the code sits in the first sentence. Measured:
    // the whole reset-code body is 96 base64 characters, so the first 200 of the line decode
    // straight back to the OTP. A bound on volume was never a bound on disclosure, and describing
    // it as a second lock — as this file did — was the mistake.
    const detail = channelText === 'drop' ? '' : logSafe(raw)

    return detail === '' ? name : `${name}: ${detail}`
  } catch {
    return MALFORMED
  }
}

/** Stands in for a name on a path where nothing the channel wrote may be published. */
const OPAQUE_NAME = '<error>'

/**
 * The error's name, or an opaque stand-in when the channel's text is not trusted.
 *
 * `name` is as much the channel's to write as `message` is — an error class built around a relay
 * reply (`name = \`SmtpRejection: ${response}\``) is a normal thing for a mail client to do, and
 * this module's own history is the proof that "it is only the error's own field, not the body" is
 * the assumption that fails.
 *
 * **Under `'drop'` the name is never published.** Validating its SHAPE was tried and is not
 * enough: an identifier bounded in length excludes a quoted body, and does NOT exclude an encoded
 * one. `MTIzNDU2` is the base64 of the OTP `123456` — eight characters, alphanumeric, leading
 * letter, a valid identifier by any such rule, and reversible by anyone reading the log. A shape
 * test cannot tell `SmtpRejection` from a credential in transfer encoding, which is the exact
 * threat this policy exists for, so on a credential path the answer is that no name comes through
 * at all. What is lost is the error's class; what is kept is that this link exists, and one
 * `<error>` per link still tells an operator how deep the failure was reported from — a provider
 * that threw on its own reads differently from one relaying a remote's refusal.
 *
 * Under `'redact'` nothing secret was in flight, the message's own text is already allowed
 * through, and constraining the name would cost diagnosis to buy nothing.
 *
 * @param error - The link whose name is wanted.
 * @param secrets - Values that must not survive into it.
 * @param channelText - Whether the channel's free text is trusted on this path.
 * @returns The name, or the opaque stand-in.
 */
function nameOf(error: Error, secrets: readonly string[], channelText: ChannelTextPolicy): string {
  if (channelText === 'drop') return OPAQUE_NAME
  return logSafe(redactSecrets(String(error.name), secrets))
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
 * Shared walk behind {@link describeError} and {@link describeChannelStatus}.
 *
 * Reads an allowlist of `name` and `message` and nothing else. That is the point rather than an
 * omission: a thrown value carries whatever threw it decided to put in it — a mail client hangs
 * the server's full reply on `response`, and `stack` embeds the message — so an allowlist is the
 * only shape whose contents a caller can reason about.
 *
 * @param error - Whatever was thrown.
 * @param secrets - Values that must not survive into the line.
 * @param channelText - Whether the channel's own words may be published.
 * @returns A single-line description safe to log.
 */
function describe(
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

    parts.push(describeOneLink(current, secrets, channelText))
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

/**
 * Describes a thrown value in one line, with known values stripped out of the channel's own words.
 *
 * For failures where **nothing that must be withheld was rendered into the message**. There the
 * relay's explanation is the diagnosis, and the values worth naming — a recipient address, say —
 * appear the way this library wrote them, where redaction reaches them. Each piece is redacted,
 * joined, length-capped and passed through {@link logSafe}, because text that came back from a
 * remote is untrusted input and a CR/LF in it would forge a second log record.
 *
 * **When the message DID render something to withhold, use {@link describeChannelStatus} instead.**
 * Redaction cannot save that case: a relay may quote the body it rejected in transfer encoding
 * rather than verbatim, and base64 defeats substring matching outright.
 *
 * @example
 * ```typescript
 * describeError(err, [recipient])
 * // => 'Error: send failed <- Error: 550 <redacted>: recipient rejected'
 * ```
 *
 * @param error - Whatever was thrown.
 * @param secrets - Values that must not survive into the line. Required rather than defaulted: a
 *   caller with nothing to hide says so by passing an empty array, which is one keystroke, whereas
 *   a default lets a call site that *does* hold one forget to name it and read as correct.
 * @returns A single-line description safe to log.
 */
export function describeError(error: unknown, secrets: readonly string[]): string {
  return describe(error, secrets, 'redact')
}

/**
 * Describes a thrown value while publishing nothing the channel authored.
 *
 * For failures on a path that **rendered a credential, or anything else you would withhold, into
 * the message**. Nothing the channel wrote is published: not the message, not the `name` — which
 * is as much the channel's field to fill — and nothing parsed off either. What survives is the
 * SHAPE of the failure: that a throw happened, and how many links its `cause` chain has. Both are
 * facts about the error object rather than text, so neither varies with what the body rendered.
 *
 * **It takes no secrets, and that is the guarantee rather than an omission.** Redaction is a
 * substring match: it assumes the credential reaches the error the way this library wrote it, and
 * a relay may quote the body it rejected re-encoded instead. Bounding the length does not help
 * either — the encoding runs from the body's first byte, so the code is in the first sentence.
 * Measured: a reset-code body is 96 base64 characters end to end, and the first 200 of the line
 * decode straight back to the OTP. Validating the name's SHAPE does not help either: `MTIzNDU2` is
 * the base64 of the OTP `123456`, a valid identifier by any such rule. There is nothing to name
 * because nothing the channel authored comes through.
 *
 * @example
 * ```typescript
 * describeChannelStatus(err)
 * // => '<error> <- <error>'
 * ```
 *
 * @param error - Whatever was thrown.
 * @returns A single-line description carrying nothing the channel authored.
 */
export function describeChannelStatus(error: unknown): string {
  // Equivalence, stated before the directive so the directive itself stays adjacent to the line it
  // means: no test can kill a non-empty list here, and the reason is this function's own guarantee
  // rather than a gap in the suite. The line it produces is composed entirely of text this library
  // authored — the `<error>` stand-in, the `<-` join, and a status rebuilt from a pattern's own
  // capture — so there is no channel-written substring for any secret to match. That is precisely
  // why the parameter is gone from the signature: a caller has nothing to name. Where naming IS
  // load-bearing the function is `describeError`, and its list is pinned by tests.
  //
  // Stryker disable next-line ArrayDeclaration
  return describe(error, [], 'drop')
}
