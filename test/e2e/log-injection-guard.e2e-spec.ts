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
 * until you ask why one half is wrapped. Forty-eight interpolations had drifted, across nine files.
 *
 * So the convention is a gate rather than a habit, and it fails CLOSED: a new interpolation is a
 * test failure until somebody decides which it is, and that decision is the point.
 *
 * **This reads the TypeScript AST rather than the text.** Three hand-rolled scanners preceded it
 * and each was wrong in a way a person would write by accident: one counted a comma inside a
 * message as an argument separator, one lost template mode at the `)` of an interpolated call and
 * stopped seeing a real second argument, and one matched a guard's NAME anywhere in the
 * expression so that `${logSafe(a) || attackerValue}` passed. Parentheses and quotes inside string
 * literals defeat every version of that approach, and a gate whose parser can be fooled by
 * ordinary punctuation is not a gate. The compiler already knows where the calls are.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'

import ts from 'typescript'

import { describeChannelStatus, describeError } from '../../src/server/utils/describe-error'
import { logSafe } from '../../src/server/utils/log-safe'
import { maskEmail } from '../../src/server/utils/mask-email'

/** Source root, from this suite's location under `test/e2e/`. */
const SRC_ROOT = join(__dirname, '../../src')

/**
 * Whether a string carries a character that ends a log record.
 *
 * Stated here by code point rather than imported from `logSafe`, on purpose: checking the guards
 * against the very set they use would let a weakened set pass silently, because the property and
 * the implementation would move together. This suite states what it wants independently of
 * whatever provides it.
 *
 * @param value - A guard's return value.
 * @returns `true` when the value could close the record and open a forged one.
 */
function breaksRecord(value: string): boolean {
  return [...value].some((character) => {
    const code = character.codePointAt(0) ?? 0

    return code <= 0x1f || (code >= 0x7f && code <= 0x9f) || code === 0x2028 || code === 0x2029
  })
}

/**
 * Calls whose output is safe to interpolate: each either strips control characters or replaces the
 * value outright.
 *
 * That sentence is an invariant, not a description, and the membership test below exercises every
 * name against a value carrying `\n` rather than trusting it. `maskEmail` was listed here while
 * copying the domain verbatim, which made `a@example.com\nforged` a masked address that still
 * closed the record — the allowlist asserted a property the member did not have.
 *
 * `safeLogLine` is deliberately absent. It is a check on a fully composed line, not a field guard:
 * it takes the values that must not appear and answers whether the line reconstructed one, and
 * `safeLogLine(raw, [])` returns `raw` untouched. Every call site wraps the whole template with it
 * — it appears inside a `${...}` nowhere in `src/` — so removing it from this set costs nothing
 * and closes the shape where it would have been read as a boundary it never enforced.
 */
const GUARDS = new Set(['logSafe', 'maskEmail', 'describeChannelStatus', 'describeError'])

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
 * Whether a node is a call to one of the {@link GUARDS}.
 *
 * The check is on the AST, so `logSafeish(v)` is a different identifier rather than a string that
 * happens to start the same way, and `logSafe(a) || attacker` is a `BinaryExpression` rather than
 * something containing the substring `logSafe`. Both defeated the text-matching version.
 *
 * @param node - The interpolated expression.
 * @returns `true` only when the whole expression is one call to a guard.
 */
function isGuardCall(node: ts.Expression): boolean {
  return (
    ts.isCallExpression(node) &&
    ts.isIdentifier(node.expression) &&
    GUARDS.has(node.expression.text)
  )
}

/** One interpolation found inside a logger call. */
interface Interpolation {
  file: string
  line: number
  expression: string
  guarded: boolean
}

/** One `this.logger.*` call, as the compiler sees it. */
interface LoggerCall {
  node: ts.CallExpression
  line: number
}

/**
 * Every `this.logger.<level>(...)` call in a file.
 *
 * Matched structurally: a call whose callee is a property access on `this.logger`. A local named
 * `logger` or a differently-shaped call is not one of ours and is not reported — the rule is about
 * what THIS library writes to ITS logger.
 *
 * @param source - Parsed file.
 * @returns Each matching call with the 1-based line it starts on.
 */
function loggerCalls(source: ts.SourceFile): LoggerCall[] {
  const found: LoggerCall[] = []
  const LEVELS = new Set(['log', 'warn', 'error', 'debug', 'verbose'])

  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
      const level = node.expression.name.text
      const target = node.expression.expression
      if (
        LEVELS.has(level) &&
        ts.isPropertyAccessExpression(target) &&
        target.name.text === 'logger' &&
        target.expression.kind === ts.SyntaxKind.ThisKeyword
      ) {
        found.push({
          node,
          line: source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1
        })
      }
    }
    ts.forEachChild(node, visit)
  }

  visit(source)
  return found
}

/**
 * Every `${...}` inside the arguments of a logger call.
 *
 * Taken from `TemplateExpression.templateSpans`, so the literal text between them is never
 * examined — a `)` or a `,` or a quote inside the message is data to the compiler and cannot be
 * mistaken for syntax. That is the whole reason this reads the AST.
 *
 * @param source - Parsed file.
 * @param file - Path, for the failure message.
 * @returns Every interpolation, with whether it is a guard call.
 */
function interpolationsInLoggerCalls(source: ts.SourceFile, file: string): Interpolation[] {
  const found: Interpolation[] = []

  for (const call of loggerCalls(source)) {
    const visit = (node: ts.Node): void => {
      if (ts.isTemplateExpression(node)) {
        for (const span of node.templateSpans) {
          found.push({
            file,
            line: call.line,
            expression: span.expression.getText(source).replace(/\s+/g, ' '),
            guarded: isGuardCall(span.expression)
          })
        }
      }
      ts.forEachChild(node, visit)
    }
    for (const argument of call.node.arguments) visit(argument)
  }

  return found
}

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

/**
 * Parse one file for inspection.
 *
 * @param path - File to read.
 * @returns The parsed source, with positions available for line reporting.
 */
function parse(path: string): ts.SourceFile {
  return ts.createSourceFile(path, readFileSync(path, 'utf8'), ts.ScriptTarget.ESNext, true)
}

describe('log-injection guard (E2E)', () => {
  const files = sourceFiles(SRC_ROOT)
  const everything = files.flatMap((file) =>
    interpolationsInLoggerCalls(parse(file), file.slice(SRC_ROOT.length + 1))
  )

  // The gate. Anything neither guarded nor claimed as this library's own is a finding, and the
  // failure message names it so the reviewer can make the call rather than guess at the rule.
  it('guards every interpolation that this library did not author', () => {
    const unguarded = everything.filter(
      ({ expression, guarded }) => !guarded && !LIBRARY_AUTHORED.has(expression)
    )

    expect(unguarded.map((u) => `${u.file}:${u.line} \${${u.expression}}`)).toEqual([])
  })

  // The detector has to be able to fail, or the assertions above are decoration. It found 48 real
  // sites when written; asserting a lower bound keeps a later refactor of the walker from silently
  // reducing it to nothing.
  it('actually inspects the logger calls it claims to', () => {
    expect(everything.length).toBeGreaterThan(80)
    expect(everything.some((i) => i.guarded)).toBe(true)
  })

  // The shapes that made earlier versions of this suite NOT fail-closed, which was the whole claim
  // made for it. Each rejected case below was ACCEPTED by the text-matching version while the
  // unguarded half went to the log, and each is something a person writes without thinking: a
  // fallback, a concatenation, a ternary, a helper whose name merely starts with a guard's.
  //
  // The last two are the ones a hand-rolled scanner cannot get right at all — punctuation inside a
  // string literal is data, and only a parser knows that.
  it.each([
    ['a bare guard call', '`${logSafe(user.id)}`', true],
    ['a guard wrapping a nested call', '`${logSafe(redactSecrets(v, s))}`', true],
    ['a guard with a fallback beside it', '`${logSafe(a) || attackerValue}`', false],
    ['a guard concatenated with raw text', '`${x + logSafe(y)}`', false],
    ['a guard on one arm of a ternary', '`${cond ? logSafe(a) : raw}`', false],
    ['a helper whose name starts with a guard', '`${logSafeish(value)}`', false],
    ['an unguarded value', '`${user.id}`', false],
    ["a guard whose argument is the string '('", "`${logSafe('(') && (attacker + ')')}`", false],
    ['an unmatched ) in the literal text before it', '`oops) ${attackerValue}`', false]
  ])('classifies %s', (_why, template, expectedGuarded) => {
    const source = ts.createSourceFile(
      'synthetic.ts',
      `class C { m() { this.logger.error(${template}) } }`,
      ts.ScriptTarget.ESNext,
      true
    )
    const found = interpolationsInLoggerCalls(source, 'synthetic.ts')

    expect(found).toHaveLength(1)
    expect(found[0]?.guarded).toBe(expectedGuarded)
  })

  // An interpolation prettier wrapped across lines is one node to the compiler, so the shape that
  // defeated the line-based scanner cannot defeat this one. Kept because the regression is cheap
  // to reintroduce and `src/` has no example to catch it.
  it('sees an interpolation wrapped across lines', () => {
    const source = ts.createSourceFile(
      'synthetic.ts',
      [
        'class C { m() {',
        '  this.logger.error(`cap refused for ${',
        '    attackerValue',
        '  }`)',
        '} }'
      ].join('\n'),
      ts.ScriptTarget.ESNext,
      true
    )

    expect(interpolationsInLoggerCalls(source, 'synthetic.ts').map((i) => i.expression)).toEqual([
      'attackerValue'
    ])
  })

  // A second argument is counted, not scanned. The two shapes below both defeated the character
  // counter: a comma inside the message read as a separator, and a template whose interpolation
  // contained a call made it lose track and miss a real one.
  it.each([
    ['a comma inside the message', 'this.logger.warn(`refused, not satisfied ${f(x)}`)', 1],
    ['a real second argument after a template', 'this.logger.error(`for ${f(id)}`, delErr)', 2],
    ['two plain-string arguments', "this.logger.error('unhandled exception', exception)", 2]
  ])('counts the arguments of %s', (_why, code, expected) => {
    const source = ts.createSourceFile(
      'synthetic.ts',
      `class C { m() { ${code} } }`,
      ts.ScriptTarget.ESNext,
      true
    )

    expect(loggerCalls(source)[0]?.node.arguments.length).toBe(expected)
  })

  // `String(err)` is deliberately absent from the allowlist. An error's text belongs to whoever
  // constructed it — for a channel that is a third-party client, and PR #135 measured a relay
  // putting a live credential there. `describeError`/`describeChannelStatus` exist for it, and
  // both strip control characters; `String()` strips nothing. This pins the exclusion so nobody
  // resolves a future failure by adding the easy name to the allowlist.
  it('never treats a raw stringified error as this library’s own text', () => {
    expect(LIBRARY_AUTHORED.has('String(err)')).toBe(false)
    expect(LIBRARY_AUTHORED.has('String(error)')).toBe(false)
    expect(LIBRARY_AUTHORED.has('String(resolved)')).toBe(false)
  })

  // The allowlist's own claim, exercised rather than asserted in prose. `maskEmail` sat in this
  // set while copying the domain verbatim, so a masked address still carried the newline that
  // closes the record: the list said "safe to interpolate" and one member was not. Feeding every
  // guard a value that breaks a record is the check that would have caught it, and it holds
  // whoever adds the next name to the same standard — including the shape that hid this one, a
  // guard that sanitises the part it is named for and passes the rest through.
  it.each([
    ['logSafe', (value: string) => logSafe(value)],
    ['maskEmail', (value: string) => maskEmail(value)],
    ['describeChannelStatus', (value: string) => describeChannelStatus(new Error(value))],
    ['describeError', (value: string) => describeError(new Error(value), [])]
  ])('%s never returns a value that can break a log record', (name, guard) => {
    expect(GUARDS.has(name)).toBe(true)

    for (const injection of [
      'a@example.com\nforged',
      'a@example.com\r\nforged',
      'a@example.com\u0085forged',
      'a@example.com\u2028forged'
    ]) {
      expect(breaksRecord(guard(injection))).toBe(false)
    }
  })

  // The counterpart to the exclusion documented on GUARDS: `safeLogLine` answers a question about
  // a whole line and enforces no boundary of its own — `safeLogLine(raw, [])` is `raw`. Listing it
  // as a field guard would let `${safeLogLine(x, [])}` pass the gate carrying anything.
  it('does not accept the composed-line check as a field guard', () => {
    expect(GUARDS.has('safeLogLine')).toBe(false)
  })
})
