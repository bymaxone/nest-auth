/**
 * @fileoverview Fails when a value this library did not author reaches a log template unguarded.
 *
 * A log line is a record in a line-oriented pipeline. A value carrying CR/LF closes the record and
 * opens a forged one, so anything interpolated into a template must either be text this library
 * wrote or pass through a guard — `logSafe` for identifiers, `maskEmail` for addresses, the
 * `describe*` helpers for a channel's own error.
 *
 * The convention already existed and was applied to `tenantId` at fourteen sites. It had never
 * been applied to any other repository-supplied field, and the omission was invisible because it
 * sat on the SAME LINES: `userId=${user.id} tenantId=${logSafe(tenantId)}` reads as deliberate
 * until you ask why one half is wrapped. Forty-eight interpolations had drifted, across six files.
 *
 * So the convention is a gate rather than a habit. Every interpolation in a logger template must
 * be either guarded or named in {@link LIBRARY_AUTHORED} below — which fails CLOSED: a new one is
 * a test failure until somebody decides which it is, and that decision is the point. Adding a name
 * to the allowlist is a claim that this library controls the value, and it belongs in review.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'

/** Source root, from this suite's location under `test/e2e/`. */
const SRC_ROOT = join(__dirname, '../../src')

/**
 * Calls whose output is safe to interpolate: each either strips control characters or replaces the
 * value outright.
 */
const GUARDS = ['logSafe', 'maskEmail', 'describeChannelStatus', 'describeError', 'safeLogLine']

/**
 * Whether the WHOLE expression is one guard call.
 *
 * Substring matching was the first version and it is not fail-closed, which was the entire claim
 * made for this suite. `${logSafe(a) || attackerValue}` contains `logSafe` and publishes
 * `attackerValue`; so do `${x + logSafe(y)}` and `${cond ? logSafe(a) : raw}`, and a helper merely
 * NAMED `logSafeish(v)` would have passed on its name alone. Three of those five shapes are things
 * a person writes without thinking about it.
 *
 * So the guard call must BE the expression: it starts at position zero and its own closing
 * parenthesis is the last character. Anything else — a fallback, a concatenation, a ternary —
 * fails and has to be rewritten so the guard wraps the whole value, which is what the rule meant
 * all along.
 *
 * @param expression - The text between `${` and `}`.
 * @returns `true` only when the expression is exactly one call to a guard.
 */
function isFullyGuarded(expression: string): boolean {
  return GUARDS.some((guard) => {
    if (!expression.startsWith(`${guard}(`)) return false

    let depth = 0
    for (let i = guard.length; i < expression.length; i++) {
      const ch = expression[i]
      if (ch === '(') depth++
      else if (ch === ')') {
        depth--
        // The call closed. Only a guard whose close is the final character wraps everything.
        if (depth === 0) return i === expression.length - 1
      }
    }
    return false
  })
}

/**
 * Expressions this library authors, so no guard applies.
 *
 * Each is a constant, an enum this library owns, a number, or a value this library computed — a
 * hash it derived, a count it took. None can carry a byte a consumer or a remote chose. A name
 * added here must satisfy that, and nothing weaker: "it is probably fine" is how the forty-eight
 * accumulated.
 */
const LIBRARY_AUTHORED = new Set([
  // Flow and plane discriminators — string-literal unions declared in this package.
  'context',
  'kind',
  'flow',
  'purpose',
  'origin',
  'label',
  'provider',
  'hookResult.action',
  // Configuration keys and values, read from options this library validates at boot.
  'name',
  'option',
  'value',
  'MAX_IDENTIFIER_LENGTH',
  // Values this library computed rather than received.
  'entry.memberHash',
  'hash.slice(0, 8)',
  'staleKeys.length',
  'response.status'
  // Nothing else. `String(err)` and `String(resolved)` are both ABSENT and both were once
  // candidates: the first is a channel's text, and the second is what a consumer-supplied
  // `maxSessionsResolver` returned — on the branch that exists precisely because the value can
  // violate its own TypeScript contract, so a JavaScript caller can return a string with CR/LF
  // in it. Allowlisting it was the "it is probably fine" this comment warns against, written by
  // the same hand that wrote the warning.
])

/**
 * Every `.ts` file under a directory, excluding specs.
 *
 * @param dir - Directory to walk.
 * @returns Absolute paths of the source files found.
 */
function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((entry) => {
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) return sourceFiles(full)
    return entry.endsWith('.ts') && !entry.endsWith('.spec.ts') ? [full] : []
  })
}

/** One interpolation found inside a logger call. */
interface Interpolation {
  file: string
  line: number
  expression: string
}

/**
 * Finds every `${...}` inside a `this.logger.*(...)` call.
 *
 * The call is followed until its parentheses balance, because a template long enough to matter is
 * usually wrapped across lines — reading only the line that names the logger would miss most of
 * them, which is how a line-based grep under-counted this family by more than half.
 *
 * @param source - File contents.
 * @param file - Path, for the failure message.
 * @returns Every interpolation inside a logger call, in file order.
 */
function interpolationsInLoggerCalls(source: string, file: string): Interpolation[] {
  const lines = source.split('\n')
  const found: Interpolation[] = []

  lines.forEach((line, index) => {
    if (!/this\.logger\.(log|warn|error|debug|verbose)\(/.test(line)) return

    // The call is collected as ONE string and scanned whole. Matching per line required `${` and
    // its `}` to sit together, so an interpolation prettier had wrapped was invisible — a false
    // negative in a gate, and the shape appears whenever a long expression meets the print width.
    let text = ''
    let depth = 0
    for (let cursor = index; cursor < lines.length; cursor++) {
      const current = lines[cursor] ?? ''
      text += current + '\n'
      depth += (current.match(/\(/g) ?? []).length - (current.match(/\)/g) ?? []).length
      if (depth <= 0) break
    }

    for (const match of text.matchAll(/\$\{([\s\S]*?)\}/g)) {
      // Whitespace collapsed so a wrapped expression compares against the allowlist as one line.
      found.push({
        file,
        line: index + 1,
        expression: (match[1] ?? '').trim().replace(/\s+/g, ' ')
      })
    }
  })

  return found
}

describe('log-injection guard (E2E)', () => {
  const everything = sourceFiles(SRC_ROOT).flatMap((file) =>
    interpolationsInLoggerCalls(readFileSync(file, 'utf8'), file.slice(SRC_ROOT.length + 1))
  )

  // The gate. Anything neither guarded nor claimed as this library's own is a finding, and the
  // failure message names it so the reviewer can make the call rather than guess at the rule.
  it('guards every interpolation that this library did not author', () => {
    const unguarded = everything.filter(
      ({ expression }) => !isFullyGuarded(expression) && !LIBRARY_AUTHORED.has(expression)
    )

    expect(unguarded.map((u) => `${u.file}:${u.line} \${${u.expression}}`)).toEqual([])
  })

  // The detector has to be able to fail, or the assertion above is decoration. It found 48 real
  // sites when written; asserting a lower bound on what it sees keeps a later refactor of the
  // walker from silently reducing it to nothing.
  it('actually inspects the logger calls it claims to', () => {
    expect(everything.length).toBeGreaterThan(80)
    expect(everything.some((i) => i.expression.includes('logSafe'))).toBe(true)
  })

  // The shapes that made the first version of this suite NOT fail-closed, which was the whole
  // claim made for it. Substring matching accepted every one of the rejected cases below while
  // the unguarded half of the expression went to the log. None of them is exotic — a fallback, a
  // concatenation and a ternary are things a person writes without thinking about it, and a
  // helper whose NAME merely starts with a guard's would have passed on the name alone.
  it.each([
    ['a bare guard call', 'logSafe(user.id)', true],
    ['a guard wrapping a nested call', 'logSafe(redactSecrets(v, s))', true],
    ['a guard with a fallback beside it', 'logSafe(a) || attackerValue', false],
    ['a guard concatenated with raw text', 'x + logSafe(y)', false],
    ['a guard on one arm of a ternary', 'cond ? logSafe(a) : raw', false],
    ['a helper whose name starts with a guard', 'logSafeish(value)', false],
    ['an unguarded value', 'user.id', false]
  ])('accepts only a whole-expression guard: %s', (_why, expression, expected) => {
    expect(isFullyGuarded(expression)).toBe(expected)
  })

  // The detector's own reach, pinned against a synthetic source rather than against `src/`. A
  // fixture is the only way to test the negative here: `src/` has no wrapped interpolation today,
  // so a suite that only walks it would have passed either way and did — this shape was reported
  // by review, not caught by the gate.
  it('sees an interpolation prettier wrapped across lines', () => {
    const wrapped = [
      '    this.logger.error(',
      '      `session cap refused for ${',
      '        attackerControlledValue',
      '      }`',
      '    )'
    ].join('\n')

    const found = interpolationsInLoggerCalls(wrapped, 'synthetic.ts')

    expect(found.map((f) => f.expression)).toEqual(['attackerControlledValue'])
  })

  // `String(err)` is deliberately absent from the allowlist. An error's text belongs to whoever
  // constructed it — for a channel that is a third-party client, and PR #135 measured a relay
  // putting a live credential there. `describeError`/`describeChannelStatus` exist for it, and
  // both strip control characters; `String()` strips nothing. This pins the exclusion so nobody
  // resolves a future failure by adding the easy name to the allowlist.
  it('never treats a raw stringified error as this library’s own text', () => {
    expect(LIBRARY_AUTHORED.has('String(err)')).toBe(false)
    expect(LIBRARY_AUTHORED.has('String(error)')).toBe(false)
  })
})
