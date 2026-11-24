/**
 * @fileoverview Every promise a decision awaits, and every promise a decision returns, carries the language's own constructor.
 *
 * `await` of a native promise reads its `constructor`, and when that is not `Promise` it resolves a new promise with it, which reads
 * `then`. A host that replaces `Promise.prototype.constructor` while the library waits (a hook, a repository, a plugin runs host
 * code between the call and the `await`) decides what that `await` yields, a refusal included; the same goes for the caller of the
 * library, which awaits what a guard or a service returns after the last check ran. So the awaited promise is pinned before it
 * is awaited (`pinned(...)`, or `awaiting(...)` which also checks the root), and the decisions that return a promise are decorated
 * with `@Pinned()`. The rules are here because a list in a comment is the one a later edit forgets.
 *
 * @layer Test
 */

import { readdirSync, readFileSync } from 'node:fs'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { isAbsolute, join } from 'node:path'

import ts from 'typescript'

const SERVER = join(__dirname, '..')

/**
 * The server sources that are not scanned, each with the reason. Every other source under `src/server` is held to the rules below,
 * so a file added later is scanned without anyone remembering to list it: the list names what is left out, never what is checked.
 */
const EXEMPT: Record<string, string> = {
  'utils/settle.ts':
    'the primitive itself: it waits only on promises it started and pinned, and answers only boxes with no prototype',
  'redis/redis-readiness.service.ts':
    'startup only, before any request exists: it decides whether the app starts, never what a request is told',
  'services/api-key-last-used.service.ts':
    'a background flush of a usage counter: no request waits on it and no decision reads it'
}

/**
 * The sources whose public promise-returning methods are not pinned, each with the reason. A file listed here that no longer needs
 * it is reported, so the list cannot go stale.
 */
const UNPINNED_PUBLIC: Record<string, string> = {
  'redis/auth-redis.service.ts':
    'internal to the library: the host never awaits it, and every caller in the library pins what it awaits from it',
  'providers/common-password-checker.provider.ts':
    'a default provider the host replaces: the library pins the call of it at the place it awaits',
  'providers/hibp-breach-checker.provider.ts':
    'a default provider the host replaces: the library pins the call of it at the place it awaits',
  'providers/no-op-email.provider.ts':
    'a default provider the host replaces: the library pins the call of it at the place it awaits',
  'guards/ws-jwt.guard.ts':
    'onModuleInit runs at startup, before any request: Nest awaits it and it decides no request'
}

/** The `.then`, `.catch` and `.finally` calls of a source. */
function chains(text: string): string[] {
  const found: string[] = []
  const source = ts.createSourceFile('x.ts', text, ts.ScriptTarget.Latest, true)
  const visit = (node: ts.Node): void => {
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      ['then', 'catch', 'finally'].includes(node.expression.name.text)
    )
      found.push(
        `.${node.expression.name.text}() chain on ${node.expression.expression.getText(source)}`
      )
    ts.forEachChild(node, visit)
  }
  visit(source)
  return found
}

/** Every server source, as a path under `src/server`, that is not a test, a test helper or a declaration. */
function serverSources(): string[] {
  return (readdirSync(SERVER, { recursive: true }) as string[])
    .filter(
      (name) =>
        /\.ts$/.test(name) && !/\.(spec|test|d)\.ts$/.test(name) && !/(^|\/)__tests__\//.test(name)
    )
    .map((name) => name.split('\\').join('/'))
    .sort()
}

const DECISION_FILES = serverSources().filter((file) => EXEMPT[file] === undefined)

/** The methods whose returned promise is the decision itself, by file: each carries `@Pinned()`. */
const PINNED_METHODS: Record<string, string[]> = {
  'services/account-status.service.ts': [
    'assertDashboardAccountUsable',
    'assertPlatformAccountUsable'
  ],
  'services/auth-revocation.service.ts': ['isAccessTokenRevoked'],
  'services/auth-token-verifier.service.ts': ['verifyAccessToken'],
  'services/session.service.ts': ['listSessions'],
  'services/mfa-challenge.service.ts': ['admitChallenge'],
  'services/token-manager.service.ts': [
    'readSeedSession',
    'rotateFromPrimary',
    'rotateFromGrace',
    'buildRotatedResult',
    'rotatePlatformFromPrimary',
    'rotatePlatformFromGrace',
    'buildPlatformRotatedResult',
    'writePlatformSessionDetail'
  ],
  'services/workspace-access.service.ts': ['resolveAccess', 'assertStillAuthorized'],
  'services/workspace-invitation.service.ts': ['preview']
}

/**
 * The awaits whose operand is neither `pinned(...)`, `awaiting(...)` nor a call of a method the class pins itself. The pin of a
 * method covers the promise it returns and not the awaits and returns inside its body, so the body is held to the same rules: every
 * async function of the file is scanned on its own, the pinned ones included.
 */
function unpinnedAwaits(text: string): string[] {
  const found: string[] = []
  const ownPinned = pinnedNames(text)
  const source = ts.createSourceFile('x.ts', text, ts.ScriptTarget.Latest, true)
  const visit = (node: ts.Node): void => {
    if (ts.isForOfStatement(node) && node.awaitModifier !== undefined)
      found.push(`for await (${node.expression.getText(source)})`)
    if (ts.isAwaitExpression(node)) {
      const operand = node.expression
      const callee = ts.isCallExpression(operand) ? operand.expression : undefined
      const wrapped =
        callee !== undefined &&
        ((ts.isIdentifier(callee) && ['pinned', 'awaiting'].includes(callee.text)) ||
          (ts.isPropertyAccessExpression(callee) &&
            callee.expression.kind === ts.SyntaxKind.ThisKeyword &&
            (ownPinned.has(EVERY) || ownPinned.has(callee.name.text))))
      if (!wrapped) found.push(operand.getText(source))
    }
    ts.forEachChild(node, visit)
  }
  visit(source)
  return found
}

/** Marks a class decorated with `@PinnedAll()`: every own method is pinned. */
const EVERY = '*'

/** The names a class lists in `@PinnedMethods(...)`, each as written, or `EVERY` for `@PinnedAll()`. */
function pinnedNames(text: string): Set<string> {
  const found = new Set<string>()
  const source = ts.createSourceFile('x.ts', text, ts.ScriptTarget.Latest, true)
  const visit = (node: ts.Node): void => {
    if (ts.isClassDeclaration(node)) {
      for (const decorator of ts.getDecorators(node) ?? []) {
        const call = decorator.expression
        if (ts.isCallExpression(call) && call.expression.getText(source) === 'PinnedAll')
          found.add(EVERY)
        if (ts.isCallExpression(call) && call.expression.getText(source) === 'PinnedMethods')
          for (const argument of call.arguments)
            if (ts.isStringLiteral(argument)) found.add(argument.text)
      }
    }
    ts.forEachChild(node, visit)
  }
  visit(source)
  return found
}

/** A program over the decision files, so the type of every returned expression is the compiler's and not a guess from its text. */
function programOf(files: string[]): { program: ts.Program; checker: ts.TypeChecker } {
  const root = join(SERVER, '..', '..')
  const config = ts.readConfigFile(join(root, 'tsconfig.json'), ts.sys.readFile)
  const parsed = ts.parseJsonConfigFileContent(config.config, ts.sys, root)
  const program = ts.createProgram(
    files.map((file) => (isAbsolute(file) ? file : join(SERVER, file))),
    parsed.options
  )
  return { program, checker: program.getTypeChecker() }
}

function partsOf(type: ts.Type): ts.Type[] {
  return type.isUnion() ? type.types : [type]
}

/** Whether a value of this type answers `then`: a promise, or anything that declares one. */
function isPromiseLike(type: ts.Type): boolean {
  return partsOf(type).some((part) => part.getProperty('then') !== undefined)
}

/** Whether a value of this type is an object, which resolving an async function with it asks for `then`. */
function isObjectLike(type: ts.Type): boolean {
  return partsOf(type).some(
    (part) => (part.flags & (ts.TypeFlags.Object | ts.TypeFlags.NonPrimitive)) !== 0
  )
}

/**
 * Whether the expression is an object literal with `__proto__: null`, or an identifier bound to one: such an object inherits from
 * nothing, so resolving a promise with it asks no `then` of the root.
 */
function nullPrototypeBox(expression: ts.Expression, checker: ts.TypeChecker): boolean {
  let literal: ts.Node | undefined = expression
  if (ts.isIdentifier(expression)) {
    const declaration = checker.getSymbolAtLocation(expression)?.valueDeclaration
    literal =
      declaration !== undefined && ts.isVariableDeclaration(declaration)
        ? declaration.initializer
        : undefined
  }
  return (
    literal !== undefined &&
    ts.isObjectLiteralExpression(literal) &&
    literal.properties.some(
      (property) =>
        ts.isPropertyAssignment(property) &&
        property.name.getText() === '__proto__' &&
        property.initializer.kind === ts.SyntaxKind.NullKeyword
    )
  )
}

/** Whether the expression is `checked(...)` around something that is not a promise: the only wrapper a `return` may carry. */
function checkedValue(node: ts.Expression, checker: ts.TypeChecker): boolean {
  if (!ts.isCallExpression(node) || !ts.isIdentifier(node.expression)) return false
  if (node.expression.text !== 'checked') return false
  const argument = node.arguments[0]
  return argument !== undefined && !isPromiseLike(checker.getTypeAtLocation(argument))
}

interface Returns {
  bare: string[]
  unrooted: string[]
}

/**
 * The returns of every async function in a file that settle the function's promise from a value that has not been checked:
 *
 * - `bare`: a promise returned without `await`. Resolving the outer promise from it reads its `then` (16b.13).
 * - `unrooted`: an object returned from a function that waited, with no `checked(...)` around it. Resolving the function's promise
 *   from an object asks it for `then`, and a `then` planted on a prototype while the function waited answers for it (16b.11), so the
 *   root is asserted by the last statement. A controller is exempt: Nest and Express read what it returns after it has returned, which
 *   no statement of the library can precede (a known limit of the release).
 */
function scanReturns(source: ts.SourceFile, checker: ts.TypeChecker, controller: boolean): Returns {
  const found: Returns = { bare: [], unrooted: [] }
  const where = (node: ts.Node): string =>
    `${node.getText(source).slice(0, 60)} (line ${source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1})`
  const judge = (expression: ts.Expression, waited: boolean): void => {
    if (ts.isParenthesizedExpression(expression)) return judge(expression.expression, waited)
    if (ts.isConditionalExpression(expression)) {
      judge(expression.whenTrue, waited)
      judge(expression.whenFalse, waited)
      return
    }
    if (checkedValue(expression, checker)) return
    if (nullPrototypeBox(expression, checker)) return
    const type = checker.getTypeAtLocation(expression)
    if (ts.isAwaitExpression(expression)) {
      if (waited && !controller && isObjectLike(type) && !isPromiseLike(type))
        found.unrooted.push(where(expression))
      return
    }
    if (isPromiseLike(type)) found.bare.push(where(expression))
    else if (waited && !controller && isObjectLike(type)) found.unrooted.push(where(expression))
  }
  const visitFunction = (fn: ts.FunctionLikeDeclaration): void => {
    const isAsync = (ts.getModifiers(fn) ?? []).some((m) => m.kind === ts.SyntaxKind.AsyncKeyword)
    const returns: ts.Expression[] = []
    let waited = false
    const walk = (node: ts.Node): void => {
      if (ts.isAwaitExpression(node)) waited = true
      if (ts.isReturnStatement(node) && node.expression !== undefined) returns.push(node.expression)
      if (node !== fn && ts.isFunctionLike(node)) {
        visitFunction(node as ts.FunctionLikeDeclaration)
        return
      }
      ts.forEachChild(node, walk)
    }
    ts.forEachChild(fn, walk)
    if (!isAsync || fn.body === undefined) return
    if (!ts.isBlock(fn.body)) judge(fn.body, waited)
    for (const expression of returns) judge(expression, waited)
  }
  const visit = (node: ts.Node): void => {
    if (ts.isFunctionLike(node) && node.kind !== ts.SyntaxKind.Constructor) {
      visitFunction(node as ts.FunctionLikeDeclaration)
      return
    }
    ts.forEachChild(node, visit)
  }
  visit(source)
  return found
}

/**
 * The public methods of an `@Injectable` class that return a promise (`async`, or declared `Promise<...>`) and that nothing pins:
 * the class carries no `@PinnedAll()`, does not list the method in `@PinnedMethods(...)` and the method has no `@Pinned()`.
 * The host awaits what a service returns after the last statement of the service ran, so every such method is held to the pin.
 */
function unpinnedPublic(text: string): string[] {
  const found: string[] = []
  const source = ts.createSourceFile('x.ts', text, ts.ScriptTarget.Latest, true)
  const pinnedByClass = pinnedNames(text)
  const visit = (node: ts.Node): void => {
    const injectable =
      ts.isClassDeclaration(node) &&
      (ts.getDecorators(node) ?? []).some((d) => d.expression.getText(source) === 'Injectable()')
    if (injectable && !pinnedByClass.has(EVERY)) {
      for (const member of (node as ts.ClassDeclaration).members) {
        if (!ts.isMethodDeclaration(member) || member.body === undefined) continue
        const modifiers = (ts.getModifiers(member) ?? []).map((m) => m.getText(source))
        if (modifiers.includes('private') || modifiers.includes('protected')) continue
        if (member.name.getText(source).startsWith('#')) continue
        const returnsPromise =
          modifiers.includes('async') || (member.type?.getText(source) ?? '').startsWith('Promise')
        const name = member.name.getText(source)
        const own = (ts.getDecorators(member) ?? []).some(
          (d) => d.expression.getText(source) === 'Pinned()'
        )
        if (returnsPromise && !own && !pinnedByClass.has(name)) found.push(name)
      }
    }
    ts.forEachChild(node, visit)
  }
  visit(source)
  return found
}

/** The async methods named in `names`, or any async `canActivate` when `names` is `canActivate`, that neither the class nor a `@Pinned()` on the method pins. */
function undecorated(text: string, names: string[] | 'canActivate' | 'async'): string[] {
  const found: string[] = []
  const source = ts.createSourceFile('x.ts', text, ts.ScriptTarget.Latest, true)
  const pinnedByClass = pinnedNames(text)
  const seen = new Set<string>()
  const visit = (node: ts.Node): void => {
    if (ts.isMethodDeclaration(node) && node.body !== undefined) {
      const name = node.name.getText(source)
      const wanted =
        names === 'canActivate' || names === 'async'
          ? (names === 'async' || name === 'canActivate') &&
            (ts.getModifiers(node) ?? []).some((m) => m.getText(source) === 'async')
          : names.includes(name)
      if (wanted) {
        seen.add(name)
        const ownDecorator = (ts.getDecorators(node) ?? []).some(
          (decorator) => decorator.expression.getText(source) === 'Pinned()'
        )
        if (!pinnedByClass.has(EVERY) && !pinnedByClass.has(name) && !ownDecorator) found.push(name)
      }
    }
    ts.forEachChild(node, visit)
  }
  visit(source)
  if (typeof names !== 'string')
    for (const name of names) if (!seen.has(name)) found.push(`${name} (not found)`)
  return found
}

describe('the promises of a decision path carry the language constructor', () => {
  // Scenario: every await in the files of a decision path. Expected: none awaits a promise that is not pinned first.
  // Why: the call that makes the promise can run host code, which can replace the constructor before the await reads it.
  it.each(DECISION_FILES)('%s awaits only pinned promises', (file) => {
    expect(unpinnedAwaits(readFileSync(join(SERVER, file), 'utf8'))).toEqual([])
  })

  // Scenario: every server source. Expected: no `.then`, `.catch` or `.finally` chain, detached work included.
  // Why: a chain reads `then` of the promise it is called on and builds another through its species, so a throwing species makes the
  // chain itself throw, and the failure of the work it was meant to swallow is left unhandled. Detached work is an `async` function
  // with a `try` around a pinned `await` (`detached` in `utils/settle`).
  it.each(DECISION_FILES)('%s keeps no chain on a promise', (file) => {
    expect(chains(readFileSync(join(SERVER, file), 'utf8'))).toEqual([])
  })

  // Scenario: an exemption or a detached chain that names a file that is gone or has nothing to exempt. Expected: reported, so the
  // lists cannot grow stale and keep excusing what is no longer there.
  it('lists only sources that exist, each with a reason', () => {
    const all = serverSources()
    const named = Object.entries(EXEMPT)
    expect(named.filter(([file]) => !all.includes(file))).toEqual([])
    expect(named.filter(([, reason]) => reason.length < 20)).toEqual([])
  })

  // Scenario: the decisions that return a promise. Expected: each is decorated, so its caller's await reads the pinned constructor.
  it.each(Object.entries(PINNED_METHODS))(
    '%s pins its decisions in the class decorator',
    (file, names) => {
      expect(undecorated(readFileSync(join(SERVER, file), 'utf8'), names)).toEqual([])
    }
  )

  // Scenario: every injectable service. Expected: each public method that returns a promise is pinned for the host that awaits it.
  // Why: a host store call can plant a one-shot `Promise.prototype.constructor` accessor while the service waits, and the caller's
  // `await` of what the service returned is the first read of it; a method left unpinned is a decision the plant answers for.
  it.each(DECISION_FILES.filter((file) => !file.startsWith('controllers/')))(
    '%s pins every public method that returns a promise',
    (file) => {
      const found = unpinnedPublic(readFileSync(join(SERVER, file), 'utf8'))
      expect(UNPINNED_PUBLIC[file] === undefined ? found : []).toEqual([])
    }
  )

  // Scenario: a source listed as unpinned that has nothing left to excuse, or is gone. Expected: reported.
  it('lists only unpinned sources that exist and still need it', () => {
    const all = serverSources()
    const named = Object.entries(UNPINNED_PUBLIC)
    expect(named.filter(([file]) => !all.includes(file))).toEqual([])
    expect(named.filter(([, reason]) => reason.length < 20)).toEqual([])
    expect(
      Object.keys(UNPINNED_PUBLIC).filter(
        (file) => unpinnedPublic(readFileSync(join(SERVER, file), 'utf8')).length === 0
      )
    ).toEqual([])
  })

  // Scenario: every guard that is async. Expected: its `canActivate` is decorated, whichever guards exist.
  it.each(DECISION_FILES.filter((file) => file.startsWith('guards/')))(
    '%s pins an async canActivate',
    (file) => {
      expect(undecorated(readFileSync(join(SERVER, file), 'utf8'), 'canActivate')).toEqual([])
    }
  )

  // Scenario: every controller. Expected: each async route handler is pinned by the class, so a handler that returns what a service
  // decided never resolves its own promise from a promise that is not pinned. Why: the response of login, refresh, the OAuth callback
  // and the MFA verify carries a decision, and an `async` handler resolving from `p` reads `p.then`.
  it.each(DECISION_FILES.filter((file) => file.startsWith('controllers/')))(
    '%s pins every async handler',
    (file) => {
      expect(undecorated(readFileSync(join(SERVER, file), 'utf8'), 'async')).toEqual([])
    }
  )

  // Scenario: every async function of the decision files. Expected: none returns a promise it has not awaited through `pinned`, and
  // none returns an object after waiting without `checked(...)` around it.
  // Why: a bare `return p` resolves the function's own promise from `p`, which reads `p.then`; an object returned after an await is
  // read for `then` too, and a `then` planted while the function waited forges it (a revoked token accepted, a non-member made owner).
  describe('returns', () => {
    // Scenario: an async function that returns a pinned, awaited or checked promise without `await`. Expected: each is reported as a
    // bare return, and the same function with `return await` is not (C8). Why: `return pinned(p)` resolves the function's own promise
    // from `p`, which reads `p.then`; a wrapper around the promise does not change what the return reads.
    describe('the rule for a return of a promise', () => {
      const fixture = [
        'declare function pinned<T>(p: Promise<T>): Promise<T>',
        'declare function awaiting<T>(p: Promise<T>): Promise<T>',
        'declare function checked<T>(v: T): T',
        'declare const work: Promise<string>',
        'export async function a(): Promise<string> { return pinned(work) }',
        'export async function b(): Promise<string> { return awaiting(work) }',
        'export async function c(): Promise<string> { return checked(work) }',
        'export async function d(): Promise<string> { return await pinned(work) }'
      ].join('\n')

      it('reports a wrapper around a promise that is returned without await', () => {
        const file = join(mkdtempSync(join(tmpdir(), 'scan-')), 'fixture.ts')
        writeFileSync(file, fixture)
        const { program, checker } = programOf([file])
        const source = program.getSourceFile(file) as ts.SourceFile

        const found = scanReturns(source, checker, false).bare

        expect(found).toEqual([
          'pinned(work) (line 5)',
          'awaiting(work) (line 6)',
          'checked(work) (line 7)'
        ])
      })
    })

    let scanned: Map<string, Returns>

    beforeAll(() => {
      const { program, checker } = programOf(DECISION_FILES)
      scanned = new Map(
        DECISION_FILES.map((file) => {
          const source = program.getSourceFile(join(SERVER, file)) as ts.SourceFile
          return [
            file,
            scanReturns(
              source,
              checker,
              file.startsWith('controllers/') || file.endsWith('.controller.ts')
            )
          ]
        })
      )
    }, 180_000)

    it.each(DECISION_FILES)('%s returns no promise it has not awaited', (file) => {
      expect(scanned.get(file)?.bare).toEqual([])
    })

    it.each(DECISION_FILES)(
      '%s checks the root last on an object it returns after an await',
      (file) => {
        expect(scanned.get(file)?.unrooted).toEqual([])
      }
    )
  })

  // Scenario: a method listed in `@PinnedMethods` that does not exist. Expected: reported, so a rename cannot leave a name that pins nothing.
  it.each(Object.entries(PINNED_METHODS))('%s lists only methods that exist', (file, names) => {
    const text = readFileSync(join(SERVER, file), 'utf8')
    const missing = undecorated(text, names).filter((entry) => entry.endsWith('(not found)'))
    expect(missing).toEqual([])
  })

  // Scenario: the scanners on text that breaks each rule. Expected: both report it, so a green scan is not a scanner that finds nothing.
  it('reports an await that is not pinned and a decision that is not decorated', () => {
    const broken = `@PinnedMethods('other')
    class A {
      async canActivate() { return await this.read() }
      async decide() { return await pinned(this.read()) }
      async other() { return await awaiting(this.read()) }
    }`

    expect(unpinnedAwaits(broken)).toEqual(['this.read()'])
    expect(undecorated(broken, 'canActivate')).toEqual(['canActivate'])
    expect(undecorated(broken, ['decide', 'other', 'missing'])).toEqual([
      'decide',
      'missing (not found)'
    ])
  })
  // Scenario: a method that awaits a method the class pins itself. Expected: accepted at the call, and the body of that method is
  // scanned on its own, so an unpinned await inside it is reported there.
  it('scans the body of a method the class pins, though a call of it needs no wrapper', () => {
    const own = `@PinnedMethods('inner')
    class A {
      async outer() { return await this.inner() }
      async inner() { return await this.read() }
    }`

    expect(unpinnedAwaits(own)).toEqual(['this.read()'])
  })

  // Scenario: functions that return a promise bare, an object after an await with no check, and the safe forms.
  // Expected: only the first two are reported, with the line.
  it('reports a bare promise return and an unchecked object return after an await', () => {
    const text = `declare function pinned<T>(v: T): T
    declare function checked<T>(v: T): T
    declare function read(): Promise<{ a: number }>
    export class A {
      async bare() { return read() }
      async fine() { return checked(await pinned(read())) }
      async object() { const x = await pinned(read()); return x }
      async rooted() { const x = await pinned(read()); return checked(x) }
      async noWait() { return { a: 1 } }
      async arrow() { const f = async () => read(); return checked(await pinned(f())) }
    }`
    const host = ts.createCompilerHost({})
    const read = host.getSourceFile.bind(host)
    host.getSourceFile = (name, ...rest) =>
      name === 'x.ts'
        ? ts.createSourceFile(name, text, ts.ScriptTarget.Latest, true)
        : read(name, ...rest)
    const program = ts.createProgram(
      ['x.ts'],
      { strict: true, target: ts.ScriptTarget.ES2022 },
      host
    )
    const found = scanReturns(
      program.getSourceFile('x.ts') as ts.SourceFile,
      program.getTypeChecker(),
      false
    )

    expect(found.bare.map((entry) => entry.replace(/ \(line.*/, ''))).toEqual(['read()', 'read()'])
    expect(found.unrooted.map((entry) => entry.replace(/ \(line.*/, ''))).toEqual(['x'])
  })
})
