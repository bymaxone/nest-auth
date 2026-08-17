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
import { ownerFragment } from '../../src/server/utils/owner-fragment'

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
const GUARDS = new Set([
  'logSafe',
  'maskEmail',
  'describeChannelStatus',
  'describeError',
  'ownerFragment'
])

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
  // Every level Nest 11's `Logger` exposes. `fatal` was missing and nothing here uses it yet,
  // which is exactly why it is easy to leave out and exactly why it belongs: the first
  // `this.logger.fatal(...)` anyone writes would be invisible to a gate that claims to walk them
  // all. A level list is the kind of thing that has to be complete rather than sufficient.
  const LEVELS = new Set(['log', 'warn', 'error', 'debug', 'verbose', 'fatal'])

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
 * **The walk stops at a guard.** A guard's argument is not part of the emitted line — its OUTPUT
 * is, and the guard sanitises whatever it was handed. Descending anyway made
 * ``logSafe(`id=${user.id}`)`` report twice: the outer interpolation as guarded and the inner
 * `user.id` as bare, failing a line whose emitted value cannot carry a control character. The
 * rule is about what reaches the record, so the subtree a guard consumes is not scanned.
 *
 * @param source - Parsed file.
 * @param file - Path, for the failure message.
 * @returns Every interpolation, with whether it is a guard call.
 */
function interpolationsInLoggerCalls(source: ts.SourceFile, file: string): Interpolation[] {
  const found: Interpolation[] = []

  for (const call of loggerCalls(source)) {
    const visit = (node: ts.Node): void => {
      if (ts.isCallExpression(node) && isGuardCall(node)) return

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

  // A message can be guarded and the call still hand the logger the error object, whose `stack`
  // this library never chose to publish and whose text is unbounded. Every thrower on these paths
  // is code this library does not own — a hook, an OAuth plugin, a repository, and in the
  // exception filter's case literally anything the surrounding application threw.
  //
  // The cost is real and was accepted deliberately: an operator loses the stack trace for a hook
  // or plugin failure. That stack belongs to the consumer's own code, which can log it where the
  // audience is known — a library's log line reaches a wider one, which is the same argument that
  // took the recipient address out of the delivery-failure line.
  //
  // Stated as a SHAPE rather than as an argument count. Counting was the first version and it was
  // a proxy for the rule, not the rule: `this.logger.error(err)` has one argument, so it passed
  // both this check and the interpolation check — the template walk only inspects template spans,
  // and a bare identifier is not one — while handing Nest the whole error object. Arity is also
  // wrong in the other direction, since a second argument that is plain context is harmless.
  //
  // What the rule actually says is that every argument must be text this library composed. A
  // template or a string literal is; an identifier, an object literal and a call are not. Read
  // structurally, so no scanner can be confused by a comma in a message — the name-based version
  // missed `auth-exception.filter.ts` entirely, whose parameter is called `exception` rather than
  // `err`, and that is the most exposed site of the set, being where a re-thrown mail-channel
  // error lands under `onDeliveryError: 'rethrow'`.
  //
  // The cost is real and was accepted deliberately: an operator loses the stack trace for a hook
  // or plugin failure. That stack belongs to the consumer's own code, which can log it where the
  // audience is known — a library's log line reaches a wider one, which is the same argument that
  // took the recipient address out of the delivery-failure line.
  it('passes the logger nothing but text it composed', () => {
    const composed = (node: ts.Expression): boolean =>
      ts.isTemplateExpression(node) ||
      ts.isNoSubstitutionTemplateLiteral(node) ||
      ts.isStringLiteral(node) ||
      // `'a' + describeChannelStatus(e)` — a concatenation is composed when both halves are.
      (ts.isBinaryExpression(node) &&
        node.operatorToken.kind === ts.SyntaxKind.PlusToken &&
        composed(node.left) &&
        composed(node.right)) ||
      // `safeLogLine(line, secrets)` returns either `line` or a constant this library wrote, so
      // its output is composed exactly when its INPUT is. Recursing rather than accepting the
      // name keeps `safeLogLine(rawThing, [])` a failure, which is the shape that made it wrong
      // to list as a field guard in the first place.
      (ts.isCallExpression(node) &&
        ts.isIdentifier(node.expression) &&
        node.expression.text === 'safeLogLine' &&
        node.arguments[0] !== undefined &&
        composed(node.arguments[0])) ||
      isGuardCall(node)

    const raw = files.flatMap((file) =>
      loggerCalls(parse(file))
        .filter((call) => !call.node.arguments.every(composed))
        .map((call) => `${file.slice(SRC_ROOT.length + 1)}:${call.line}`)
    )

    expect(raw).toEqual([])
  })

  // `describeError(x, [])` publishes the thrower's `name` and `message` with an empty list
  // asserting there is nothing to remove. No call site in this library can make that assertion:
  // every thrower on these paths is consumer code, and a consumer error that quotes its own input
  // carries whatever this library handed it — a repository given `findByEmail(dto.email,
  // tenantId)`, a hook given the IP and user agent, a `maxSessionsResolver` given the full
  // `AuthUser` including the password hash.
  //
  // It read as a defence and was the absence of one, which is the worse half: a reader sees a
  // redaction helper and stops asking. Twenty sites had it. `describeChannelStatus` is the form
  // for a thrower whose contents you cannot name, and a non-empty list stays legal because naming
  // values IS a claim a caller can make about what it passed in.
  // A second rule rides along on the same walk: the list must name values AS THE THROWER RECEIVED
  // THEM. `describeError(err, [logSafe(user.id)])` redacted a DIFFERENT string from the one the
  // repository was handed — `logSafe` returns `<malformed>` for exactly the ids worth worrying
  // about — so the list named a value that could not appear in the error. A transformed name is
  // the same mistake as an empty list wearing a longer sleeve, and both are call shapes rather
  // than judgement, so both are checked here.
  it.each([
    [
      'never asks for redaction while naming nothing to redact',
      (list: ts.ArrayLiteralExpression) => list.elements.length === 0
    ],
    [
      'never names a transformed value in a redaction list',
      (list: ts.ArrayLiteralExpression) => list.elements.some((e) => ts.isCallExpression(e))
    ]
  ])('%s', (_why, offends) => {
    const offenders = files.flatMap((file) => {
      const source = parse(file)
      const found: string[] = []
      const visit = (node: ts.Node): void => {
        const list = node
        if (
          ts.isCallExpression(list) &&
          ts.isIdentifier(list.expression) &&
          list.expression.text === 'describeError' &&
          list.arguments[1] !== undefined &&
          ts.isArrayLiteralExpression(list.arguments[1]) &&
          offends(list.arguments[1])
        ) {
          const line = source.getLineAndCharacterOfPosition(list.getStart(source)).line + 1
          found.push(`${file.slice(SRC_ROOT.length + 1)}:${line}`)
        }
        ts.forEachChild(node, visit)
      }
      visit(source)
      return found
    })

    expect(offenders).toEqual([])
  })

  // The shape the arity check could not see, and the reason it was replaced. Held synthetically
  // because `src/` has no example — which is what made the gap invisible rather than harmless.
  it.each([
    ['a bare error as the only argument', 'this.logger.error(err)'],
    ['an error wrapped in an object', 'this.logger.error({ err })'],
    ['a call this library did not author', 'this.logger.error(inspect(err))']
  ])('rejects %s', (_why, code) => {
    const source = ts.createSourceFile(
      'synthetic.ts',
      `class C { m() { ${code} } }`,
      ts.ScriptTarget.ESNext,
      true
    )
    const call = loggerCalls(source)[0]

    expect(call?.node.arguments.every((a) => ts.isTemplateExpression(a) || isGuardCall(a))).toBe(
      false
    )
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

  // `fatal` is the sixth level Nest 11's `Logger` exposes and the gate did not know it. Nothing in
  // `src/` uses it, which is why the omission was invisible and why only a synthetic fixture can
  // hold it: the first real `this.logger.fatal(...)` would otherwise be the test case.
  it('sees an interpolation at every level the logger exposes', () => {
    for (const level of ['log', 'warn', 'error', 'debug', 'verbose', 'fatal']) {
      const source = ts.createSourceFile(
        'synthetic.ts',
        `class C { m() { this.logger.${level}(\`for \${attackerValue}\`) } }`,
        ts.ScriptTarget.ESNext,
        true
      )

      expect(interpolationsInLoggerCalls(source, 'synthetic.ts').map((i) => i.expression)).toEqual([
        'attackerValue'
      ])
    }
  })

  // A guard's ARGUMENT is not what reaches the record — its output is, and the guard sanitises
  // whatever it was handed. Before the walk stopped at a guard this reported twice: the outer
  // interpolation as guarded and the inner `user.id` as bare, failing a line that cannot carry a
  // control character. A false positive on a correct line is how a gate gets weakened by whoever
  // hits it next.
  it('does not scan inside a guard, whose argument never reaches the record', () => {
    const source = ts.createSourceFile(
      'synthetic.ts',
      'class C { m() { this.logger.error(`${logSafe(`id=${user.id}`)}`) } }',
      ts.ScriptTarget.ESNext,
      true
    )

    const found = interpolationsInLoggerCalls(source, 'synthetic.ts')

    expect(found).toHaveLength(1)
    expect(found[0]?.guarded).toBe(true)
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
    ['describeError', (value: string) => describeError(new Error(value), [])],
    ['ownerFragment', (value: string) => ownerFragment(value)]
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
