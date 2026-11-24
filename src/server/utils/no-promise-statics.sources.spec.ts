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
const BANNED = ['all', 'allSettled', 'any', 'race', 'try', 'withResolvers']

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
      if (BANNED.includes(node.name.text)) found.push(node.name.text)
    } else if (ts.isElementAccessExpression(node) && isPromise(node.expression)) {
      const key = node.argumentExpression
      if (!ts.isStringLiteralLike(key)) found.push('[computed]')
      else if (BANNED.includes(key.text)) found.push(key.text)
    } else if (
      ts.isVariableDeclaration(node) &&
      node.initializer !== undefined &&
      isPromise(node.initializer) &&
      ts.isObjectBindingPattern(node.name)
    ) {
      found.push('[destructured]')
    }
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
      found.push(node.name.text)
    else if (
      ts.isElementAccessExpression(node) &&
      ts.isStringLiteralLike(node.argumentExpression) &&
      METHODS.includes(node.argumentExpression.text)
    )
      found.push(node.argumentExpression.text)
    ts.forEachChild(node, visit)
  }
  visit(ts.createSourceFile('probe.ts', text, ts.ScriptTarget.Latest, true))
  return found
}

/**
 * The sources that call a method of a promise, by file, with how many calls and why none of them is a decision. Each is a handler
 * that logs a failure, a cleanup nobody waits on, or an adapter of a value that is not a decision; an answer read from a host's
 * promise by one of these is never what an access, a session or a token is decided on. A new call in a file is a new finding until
 * it is argued here.
 */
const EXEMPT_METHODS: Record<string, { count: number; reason: string }> = {
  'guards/api-key.guard.ts': {
    count: 1,
    reason: 'A detached hook run whose failure is only logged; no decision reads its answer.'
  },
  'observability/auth-health-probe.ts': {
    count: 3,
    reason:
      'The health probe shares one PING and clears its cache; it reports status and decides no access.'
  },
  'observability/auth-tracing.ts': {
    count: 1,
    reason:
      'A tracing call that is fire-and-forget with its failure swallowed; nothing is decided on it.'
  },
  'redis/redis-outage.ts': {
    count: 1,
    reason:
      'The read of `then` that tells a promise-like from a plain value; the wait itself uses await.'
  },
  'services/auth.service.ts': {
    count: 7,
    reason:
      'Cleanups, hooks and detail writes whose failure is logged; the login decision never reads them.'
  },
  'services/invitation.service.ts': {
    count: 1,
    reason:
      'Withdrawing a written record after a failure; the failure is logged and nothing is decided.'
  },
  'services/otp.service.ts': {
    count: 1,
    reason: 'Releasing a resend cooldown after a failed send; a failed release is logged only.'
  },
  'services/password-reset.service.ts': {
    count: 1,
    reason:
      'A best-effort delete of a spent token whose failure is logged; the reset was already decided.'
  },
  'services/platform-auth.service.ts': {
    count: 2,
    reason:
      'A last-login write and a logout hook that are detached, logged on failure and never decide access.'
  },
  'services/session.service.ts': {
    count: 4,
    reason:
      'Detached prunes and the new-session notification; each only logs a failure and decides nothing.'
  },
  'services/token-manager.service.ts': {
    count: 1,
    reason:
      'A detached reuse-detection hook whose rejection is logged; the refresh was decided already.'
  },
  'utils/run-detached.ts': {
    count: 1,
    reason:
      'The helper that detaches a hook and logs its rejection; nothing waits for or reads its answer.'
  }
}

describe('the statics of Promise in the sources of the server', () => {
  // Scenario: each way to read a banned static in a snippet. Expected: found. Why: the scan below is only worth what it can see.
  it.each([
    ['Promise.all([a, b])', ['all']],
    ['await Promise.race([a, b])', ['race']],
    ['Promise.allSettled(list)', ['allSettled']],
    ['Promise.any(list)', ['any']],
    ["Promise['all'](list)", ['all']],
    ['Promise[name](list)', ['[computed]']],
    ['const { all } = Promise', ['[destructured]']]
  ])('finds %s', (text, expected) => {
    expect(staticsRead(text)).toEqual(expected)
  })

  // Scenario: what the sources may do with `Promise`. Expected: not found. Why: a constructor, `resolve` and `reject` combine nothing.
  it.each([
    'new Promise((resolve) => resolve(1))',
    'Promise.resolve(run()).catch(() => undefined)',
    'Promise.reject(new Error("x"))',
    'const all = [a, b]; all.map(f)',
    'items.all(f)',
    '// Promise.all(list)'
  ])('does not find %s', (text) => {
    expect(staticsRead(text)).toEqual([])
  })

  // Scenario: every source of the server read as syntax. Expected: none reads one of the statics. Why: see the file header.
  it('reads none of them in any source', () => {
    const files = sourceFiles()
    const reads = files.flatMap((file) =>
      staticsRead(readFileSync(file, 'utf8')).map((name) => `${file}: Promise.${name}`)
    )

    expect(files.length).toBeGreaterThan(100)
    expect(reads).toEqual([])
  })

  // Scenario: each way to read a method of a promise in a snippet. Expected: found, including through `call` and an element.
  it.each([
    ['p.catch(() => undefined)', ['catch']],
    ['p.then(a, b)', ['then']],
    ['p.finally(f)', ['finally']],
    ['Promise.prototype.then.call(p, a)', ['then']],
    ["p['then'](a)", ['then']]
  ])('finds the method in %s', (text, expected) => {
    expect(methodsRead(text)).toEqual(expected)
  })

  // Scenario: every source of the server. Expected: the calls of these methods are exactly the ones argued above.
  it('calls a method of a promise only where it is argued not to be a decision', () => {
    const counted: Record<string, number> = {}
    for (const file of sourceFiles()) {
      const count = methodsRead(readFileSync(file, 'utf8')).length
      if (count > 0) counted[file.slice(join(__dirname, '..').length + 1)] = count
    }
    const argued = Object.fromEntries(
      Object.entries(EXEMPT_METHODS).map(([file, { count }]) => [file, count])
    )

    expect(counted).toEqual(argued)
    for (const { reason } of Object.values(EXEMPT_METHODS))
      expect(reason.length).toBeGreaterThan(30)
  })
})
