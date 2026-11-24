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
  'utils/settle-writes.ts'
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
  'services/workspace-access.service.ts': ['resolveAccess', 'assertStillAuthorized'],
  'services/workspace-invitation.service.ts': ['preview']
}

/** The awaits whose operand is neither `pinned(...)`, `awaiting(...)` nor a call of a method the class pins itself. */
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

/** The async methods named in `names`, or any async `canActivate` when `names` is `canActivate`, that the class does not pin. */
function undecorated(text: string, names: string[] | 'canActivate'): string[] {
  const found: string[] = []
  const source = ts.createSourceFile('x.ts', text, ts.ScriptTarget.Latest, true)
  const pinnedByClass = pinnedNames(text)
  const seen = new Set<string>()
  const visit = (node: ts.Node): void => {
    if (ts.isMethodDeclaration(node) && node.body !== undefined) {
      const name = node.name.getText(source)
      const wanted =
        names === 'canActivate'
          ? name === 'canActivate' &&
            (ts.getModifiers(node) ?? []).some((m) => m.getText(source) === 'async')
          : names.includes(name)
      if (wanted) {
        seen.add(name)
        if (!pinnedByClass.has(name)) found.push(name)
      }
    }
    ts.forEachChild(node, visit)
  }
  visit(source)
  if (names !== 'canActivate')
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
})
