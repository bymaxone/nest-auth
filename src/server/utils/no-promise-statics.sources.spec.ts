/**
 * @fileoverview No source of the server combines or races promises through a static of `Promise`.
 *
 * `Promise.all`, `Promise.race`, `Promise.allSettled` and `Promise.any` are properties of a global that anything running in the
 * process can replace after the library loaded, and the root guard does not compare them (a monitor or a test double of a host
 * wraps them). A replaced one answers what a decision reads: a membership the store never returned, a profile the plugin never
 * fetched, the order sessions are evicted in. The sources wait with `await` alone, through `utils/settle`.
 *
 * @layer Test
 */

import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

import ts from 'typescript'

/** The statics that combine or race promises. */
const BANNED = ['all', 'allSettled', 'any', 'race', 'reject', 'resolve', 'try', 'withResolvers']

/** The name of the function or method that holds `node`, or `<module>` at the top level of a file. */
function holderOf(node: ts.Node): string {
  for (let up: ts.Node | undefined = node.parent; up !== undefined; up = up.parent) {
    if (
      (ts.isMethodDeclaration(up) ||
        ts.isFunctionDeclaration(up) ||
        ts.isGetAccessorDeclaration(up)) &&
      up.name !== undefined
    )
      return up.name.getText()
    if (ts.isConstructorDeclaration(up)) return 'constructor'
    if (ts.isVariableDeclaration(up) && ts.isIdentifier(up.name)) return up.name.text
  }
  return '<module>'
}

/** What a site is keyed by: the function that holds it and the read itself, so a second read in another function is a new site. */
function anchorOf(node: ts.Node, read: string): string {
  return `${holderOf(node)}: ${read}`
}

/** The `.ts` sources of the server that are not tests. */
function sourceFiles(dir = join(__dirname, '..')): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name)
    if (entry.isDirectory()) return entry.name === '__tests__' ? [] : sourceFiles(path)
    return /\.ts$/.test(entry.name) && !/\.(spec|test)\.ts$/.test(entry.name) ? [path] : []
  })
}

/** Every place `text` reads one of the banned statics of `Promise`: a property, an element, or a destructuring of the global. */
function staticsRead(text: string): string[] {
  const found: string[] = []
  const isPromise = (node: ts.Node): boolean => ts.isIdentifier(node) && node.text === 'Promise'
  const visit = (node: ts.Node): void => {
    if (ts.isPropertyAccessExpression(node) && isPromise(node.expression)) {
      if (BANNED.includes(node.name.text)) found.push(anchorOf(node, `Promise.${node.name.text}`))
    } else if (ts.isElementAccessExpression(node) && isPromise(node.expression)) {
      const key = node.argumentExpression
      if (!ts.isStringLiteralLike(key)) found.push(anchorOf(node, 'Promise[computed]'))
      else if (BANNED.includes(key.text)) found.push(anchorOf(node, `Promise.${key.text}`))
    } else if (
      ts.isVariableDeclaration(node) &&
      node.initializer !== undefined &&
      isPromise(node.initializer) &&
      ts.isObjectBindingPattern(node.name)
    ) {
      found.push(anchorOf(node, 'Promise destructured'))
    }
    ts.forEachChild(node, visit)
  }
  visit(ts.createSourceFile('probe.ts', text, ts.ScriptTarget.Latest, true))
  return found
}

/** Every `new Promise(...)` in `text`: the global binding is read there, and a host can replace it after load. */
function constructed(text: string): string[] {
  const found: string[] = []
  const visit = (node: ts.Node): void => {
    if (
      ts.isNewExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === 'Promise'
    )
      found.push(anchorOf(node, 'new Promise'))
    ts.forEachChild(node, visit)
  }
  visit(ts.createSourceFile('probe.ts', text, ts.ScriptTarget.Latest, true))
  return found
}

/** The methods of a promise that a host can replace on `Promise.prototype`: a source that calls one lets that replacement answer. */
const METHODS = ['catch', 'finally', 'then']

/** Every property access of `catch`, `finally` or `then` in `text`, which covers a call, `.then.call` and `.then[...]`. */
function methodsRead(text: string): string[] {
  const found: string[] = []
  const visit = (node: ts.Node): void => {
    if (ts.isPropertyAccessExpression(node) && METHODS.includes(node.name.text))
      found.push(anchorOf(node, `.${node.name.text}`))
    else if (
      ts.isElementAccessExpression(node) &&
      ts.isStringLiteralLike(node.argumentExpression) &&
      METHODS.includes(node.argumentExpression.text)
    )
      found.push(anchorOf(node, `.${node.argumentExpression.text}`))
    ts.forEachChild(node, visit)
  }
  visit(ts.createSourceFile('probe.ts', text, ts.ScriptTarget.Latest, true))
  return found
}

/** A call site argued not to be a decision: the file, the function that holds it, the read, how many times, and why. */
interface Exemption {
  file: string
  site: string
  count: number
  reason: string
}

/**
 * The calls of a method of a promise, by site (file and the function that holds it). Each is a handler that logs a failure, a
 * cleanup nobody waits on, or an adapter of a value that is not a decision; an answer read from a host's promise by one of these
 * is never what an access, a session or a token is decided on. A new call, in a file listed here or not, is a new finding until
 * it is argued here.
 */
const EXEMPT_METHODS: Exemption[] = [
  {
    file: 'guards/api-key.guard.ts',
    site: 'audit: .catch',
    count: 1,
    reason: 'The detached audit hook: its failure is logged and the guard has decided already.'
  },
  {
    file: 'observability/auth-health-probe.ts',
    site: '#ask: .then',
    count: 1,
    reason:
      'The health probe shares one PING between callers; it reports status and decides no access.'
  },
  {
    file: 'observability/auth-health-probe.ts',
    site: 'within: .finally',
    count: 1,
    reason: "Clears the probe's deadline timer; it reports status and decides no access."
  },
  {
    file: 'observability/auth-health-probe.ts',
    site: 'within: .then',
    count: 1,
    reason: "Bounds the probe's PING with a deadline; it reports status and decides no access."
  },
  {
    file: 'observability/auth-tracing.ts',
    site: 'attempt: .catch',
    count: 1,
    reason:
      'A tracing call that is fire-and-forget with its failure swallowed; nothing is decided on it.'
  },
  {
    file: 'redis/redis-outage.ts',
    site: 'isThenable: .then',
    count: 1,
    reason:
      'The read of `then` that tells a promise-like from a plain value; the wait itself uses await.'
  },
  {
    file: 'services/auth.service.ts',
    site: 'dropCachedAccountFacts: .catch',
    count: 1,
    reason: 'A cache invalidation after the decision; its failure is logged.'
  },
  {
    file: 'services/auth.service.ts',
    site: 'emitLogout: .catch',
    count: 1,
    reason: 'The detached logout hook; its failure is logged and the logout is done.'
  },
  {
    file: 'services/auth.service.ts',
    site: 'fireAndForget: .catch',
    count: 1,
    reason: 'The helper that detaches a hook and logs its failure; nothing reads its answer.'
  },
  {
    file: 'services/auth.service.ts',
    site: 'issueTokensForUserId: .catch',
    count: 1,
    reason: 'A last-login write detached from the token issue; its failure is logged.'
  },
  {
    file: 'services/auth.service.ts',
    site: 'login: .catch',
    count: 1,
    reason: 'A last-login write detached from the login; the login was decided before it.'
  },
  {
    file: 'services/auth.service.ts',
    site: 'refresh: .catch',
    count: 1,
    reason: 'A detached session-detail rotation; its failure is logged and the refresh is decided.'
  },
  {
    file: 'services/auth.service.ts',
    site: 'revokeSessionMetadata: .catch',
    count: 1,
    reason: 'A detached revocation of session detail; its failure is logged.'
  },
  {
    file: 'services/invitation.service.ts',
    site: 'withdrawRecord: .catch',
    count: 1,
    reason:
      'Withdraws a written record after a failure; the failure is logged and nothing is decided.'
  },
  {
    file: 'services/password-reset.service.ts',
    site: 'sendToken: .catch',
    count: 1,
    reason: 'A best-effort delete of a spent token whose failure is logged; the reset was decided.'
  },
  {
    file: 'services/platform-auth.service.ts',
    site: 'emitPlatformLogout: .catch',
    count: 1,
    reason: 'The detached logout hook; its failure is logged and the logout is done.'
  },
  {
    file: 'services/platform-auth.service.ts',
    site: 'login: .catch',
    count: 1,
    reason: 'A last-login write detached from the login; the login was decided before it.'
  },
  {
    file: 'services/session.service.ts',
    site: 'createSession: .catch',
    count: 1,
    reason: 'The detached new-session notification; its failure is logged.'
  },
  {
    file: 'services/session.service.ts',
    site: 'createSession: .then',
    count: 1,
    reason: 'Adapts the user read for the notification; no access is decided on it.'
  },
  {
    file: 'services/session.service.ts',
    site: 'listSessions: .catch',
    count: 2,
    reason: 'Detached prunes of the index; each only logs a failure and decides nothing.'
  },
  {
    file: 'services/token-manager.service.ts',
    site: 'emitReuseDetected: .catch',
    count: 1,
    reason: 'A detached reuse-detection hook whose rejection is logged; the refresh was decided.'
  },
  {
    file: 'utils/captured-builtins.ts',
    site: 'intrinsicThen: .then',
    count: 1,
    reason:
      "Takes the then of the language's own promises once, at load; nothing is awaited through it."
  },
  {
    file: 'utils/run-detached.ts',
    site: 'runDetached: .catch',
    count: 1,
    reason: 'Detaches a hook and logs its rejection; nothing waits for or reads its answer.'
  }
]

/**
 * The statics of `Promise` the sources read, by site: each wraps a call in `Promise.resolve(...)` to detach a hook and log its
 * failure. Each one is fire-and-forget, nothing waits for the promise or reads its answer, so a replaced `resolve` cannot answer
 * a decision.
 */
const EXEMPT_STATICS: Exemption[] = [
  {
    file: 'guards/api-key.guard.ts',
    site: 'audit: Promise.resolve',
    count: 1,
    reason: 'Wraps the detached audit hook so its failure can be logged; nothing waits for it.'
  },
  {
    file: 'observability/auth-tracing.ts',
    site: 'attempt: Promise.resolve',
    count: 1,
    reason: 'Wraps a fire-and-forget tracing call; nothing waits for it or reads its answer.'
  },
  {
    file: 'services/auth.service.ts',
    site: 'emitLogout: Promise.resolve',
    count: 1,
    reason: 'Wraps the detached logout hook; nothing waits for it or reads its answer.'
  },
  {
    file: 'services/auth.service.ts',
    site: 'fireAndForget: Promise.resolve',
    count: 1,
    reason: 'Wraps a detached hook; nothing waits for it or reads its answer.'
  },
  {
    file: 'services/platform-auth.service.ts',
    site: 'emitPlatformLogout: Promise.resolve',
    count: 1,
    reason: 'Wraps the detached logout hook; nothing waits for it or reads its answer.'
  },
  {
    file: 'services/token-manager.service.ts',
    site: 'emitReuseDetected: Promise.resolve',
    count: 1,
    reason: 'Wraps the detached reuse hook; nothing waits for it or reads its answer.'
  },
  {
    file: 'utils/run-detached.ts',
    site: 'runDetached: Promise.resolve',
    count: 1,
    reason: 'Wraps the detached hook; nothing waits for it or reads its answer.'
  }
]

/** The sites a scan found, as the table that argues them: `file :: site` to the count. */
function tally(scan: (text: string) => string[]): Record<string, number> {
  const counted: Record<string, number> = {}
  for (const file of sourceFiles()) {
    for (const site of scan(readFileSync(file, 'utf8'))) {
      const key = `${file.slice(join(__dirname, '..').length + 1)} :: ${site}`
      counted[key] = (counted[key] ?? 0) + 1
    }
  }
  return counted
}

/** The table as `file :: site` to count. */
function argued(table: Exemption[]): Record<string, number> {
  return Object.fromEntries(table.map(({ file, site, count }) => [`${file} :: ${site}`, count]))
}

describe('the statics of Promise in the sources of the server', () => {
  // Scenario: each way to read a banned static in a snippet. Expected: found. Why: the scan below is only worth what it can see.
  it.each([
    ['Promise.all([a, b])', ['<module>: Promise.all']],
    ['await Promise.race([a, b])', ['<module>: Promise.race']],
    ['Promise.allSettled(list)', ['<module>: Promise.allSettled']],
    ['Promise.any(list)', ['<module>: Promise.any']],
    ["Promise['all'](list)", ['<module>: Promise.all']],
    ['Promise[name](list)', ['<module>: Promise[computed]']],
    ['Promise.resolve(x)', ['<module>: Promise.resolve']],
    ['await Promise.reject(e)', ['<module>: Promise.reject']],
    ['const { all } = Promise', ['<module>: Promise destructured']]
  ])('finds %s', (text, expected) => {
    expect(staticsRead(text)).toEqual(expected)
  })

  // Scenario: what the sources may do with `Promise`. Expected: not found. Why: a constructor combines nothing.
  it.each([
    'new Promise((resolve) => resolve(1))',
    'const all = [a, b]; all.map(f)',
    'items.all(f)',
    '// Promise.all(list)'
  ])('does not find %s', (text) => {
    expect(staticsRead(text)).toEqual([])
  })

  // Scenario: every source of the server read as syntax. Expected: the statics read are exactly the argued ones, and none combines
  // or races. Why: see the file header.
  it('reads a static only where it is argued not to be a decision', () => {
    expect(sourceFiles().length).toBeGreaterThan(100)
    expect(tally(staticsRead)).toEqual(argued(EXEMPT_STATICS))
  })

  // Scenario: a second static read in a file that already has an argued one, in the same function and in another. Expected: the
  // site is a new key or a higher count, so the table above no longer equals what is read. Why: a file-wide allowance would let it in.
  it.each([
    [
      'the same function',
      'function audit() { Promise.resolve(a); Promise.resolve(b) }',
      { 'audit: Promise.resolve': 2 }
    ],
    [
      'another function',
      'function audit() { Promise.resolve(a) }\nfunction other() { Promise.resolve(b) }',
      { 'audit: Promise.resolve': 1, 'other: Promise.resolve': 1 }
    ]
  ])('does not let a second static into a file that has one (%s)', (_label, text, expected) => {
    const counted: Record<string, number> = {}
    for (const found of staticsRead(text)) counted[found] = (counted[found] ?? 0) + 1

    expect(counted).toEqual(expected)
    expect(counted).not.toEqual({ 'audit: Promise.resolve': 1 })
  })

  // Scenario: a promise built with the global `Promise`, in a snippet and then across the sources. Expected: found in the snippet, and
  // none in the sources. Why: the global binding is replaceable after load, so the library builds promises from the one taken at
  // load (`IntrinsicPromise`); a site that needs the global must be argued in a table, and none is.
  it('builds no promise with the global constructor', () => {
    expect(constructed('function wait() { return new Promise((r) => r(1)) }')).toEqual([
      'wait: new Promise'
    ])
    expect(constructed('new IntrinsicPromise((r) => r(1))')).toEqual([])
    expect(tally(constructed)).toEqual({})
  })

  // Scenario: each way to read a method of a promise in a snippet. Expected: found, including through `call` and an element.
  it.each([
    ['p.catch(() => undefined)', ['<module>: .catch']],
    ['p.then(a, b)', ['<module>: .then']],
    ['p.finally(f)', ['<module>: .finally']],
    ['Promise.prototype.then.call(p, a)', ['<module>: .then']],
    ["p['then'](a)", ['<module>: .then']]
  ])('finds the method in %s', (text, expected) => {
    expect(methodsRead(text)).toEqual(expected)
  })

  // Scenario: every source of the server. Expected: the calls of these methods are exactly the ones argued above.
  it('calls a method of a promise only where it is argued not to be a decision', () => {
    expect(tally(methodsRead)).toEqual(argued(EXEMPT_METHODS))
    for (const { reason } of [...EXEMPT_METHODS, ...EXEMPT_STATICS])
      expect(reason.length).toBeGreaterThan(30)
  })
})
