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
import { join } from 'node:path'

import ts from 'typescript'

const SERVER = join(__dirname, '..')

/** The sources whose awaits are on a decision path: the guards, the services that make a verdict and the reads they wait for. */
const DECISION_FILES = [
  ...readdirSync(join(SERVER, 'guards')).flatMap((name) =>
    /\.ts$/.test(name) && !/\.(spec|test)\.ts$/.test(name) ? [`guards/${name}`] : []
  ),
  ...readdirSync(join(SERVER, 'controllers')).flatMap((name) =>
    /\.controller\.ts$/.test(name) ? [`controllers/${name}`] : []
  ),
  'services/account-status.service.ts',
  'services/auth-revocation.service.ts',
  'services/auth-token-verifier.service.ts',
  'services/session.service.ts',
  'services/workspace-access.service.ts',
  'services/workspace-invitation.service.ts',
  'oauth/oauth.service.ts',
  'utils/host-read.ts',
  'redis/redis-outage.ts',
  'redis/auth-redis.service.ts',
  'services/workspace-invitation.store.ts',
  'utils/settle-writes.ts',
  'services/mfa-challenge.service.ts',
  'services/mfa-record.service.ts',
  'services/brute-force.service.ts',
  'services/token-manager.service.ts',
  'services/api-key-verifier.service.ts',
  'services/auth.service.ts',
  'services/workspace-invitation-accept.service.ts',
  'oauth/oauth.controller.ts'
]

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
    if (ts.isAwaitExpression(node)) {
      const operand = node.expression
      const callee = ts.isCallExpression(operand) ? operand.expression : undefined
      const wrapped =
        callee !== undefined &&
        ((ts.isIdentifier(callee) && ['pinned', 'awaiting'].includes(callee.text)) ||
          (ts.isPropertyAccessExpression(callee) &&
            callee.expression.kind === ts.SyntaxKind.ThisKeyword &&
            ownPinned.has(callee.name.text)))
      if (!wrapped) found.push(operand.getText(source))
    }
    ts.forEachChild(node, visit)
  }
  visit(source)
  return found
}

/** The names a class lists in `@PinnedMethods(...)`, each as written. */
function pinnedNames(text: string): Set<string> {
  const found = new Set<string>()
  const source = ts.createSourceFile('x.ts', text, ts.ScriptTarget.Latest, true)
  const visit = (node: ts.Node): void => {
    if (ts.isClassDeclaration(node)) {
      for (const decorator of ts.getDecorators(node) ?? []) {
        const call = decorator.expression
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

const WRAPPERS = ['pinned', 'awaiting', 'checked']

/** A program over the decision files, so the type of every returned expression is the compiler's and not a guess from its text. */
function programOf(files: string[]): { program: ts.Program; checker: ts.TypeChecker } {
  const root = join(SERVER, '..', '..')
  const config = ts.readConfigFile(join(root, 'tsconfig.json'), ts.sys.readFile)
  const parsed = ts.parseJsonConfigFileContent(config.config, ts.sys, root)
  const program = ts.createProgram(
    files.map((file) => join(SERVER, file)),
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

/** Whether the expression is a call of one of the wrappers that pin or check what is returned. */
function wrapperOf(node: ts.Expression): boolean {
  return (
    ts.isCallExpression(node) &&
    ts.isIdentifier(node.expression) &&
    WRAPPERS.includes(node.expression.text)
  )
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
    if (wrapperOf(expression)) return
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
        if (!pinnedByClass.has(name) && !ownDecorator) found.push(name)
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

  // Scenario: the decisions that return a promise. Expected: each is decorated, so its caller's await reads the pinned constructor.
  it.each(Object.entries(PINNED_METHODS))(
    '%s pins its decisions in the class decorator',
    (file, names) => {
      expect(undecorated(readFileSync(join(SERVER, file), 'utf8'), names)).toEqual([])
    }
  )

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
