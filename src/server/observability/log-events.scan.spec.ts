/**
 * @fileoverview The code that writes log events and the catalog agree: every `logEvent` call names a catalog code
 * and passes only the fields the catalog lists for it, and every catalog code is written by at least one call.
 *
 * It reads the sources as text and imports only node modules and `typescript`, so it executes nothing under
 * `src` and the mutation run, which instruments that code, has no use for it.
 *
 * @layer Test
 */

import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

import * as ts from 'typescript'

const ROOT = join(__dirname, '..')

/** The catalog read from its source: each code with the field names it lists. */
function catalog(): Map<string, string[]> {
  const file = ts.createSourceFile(
    'log-events.ts',
    readFileSync(join(__dirname, 'log-events.ts'), 'utf8'),
    ts.ScriptTarget.Latest,
    true
  )
  const entries = new Map<string, string[]>()
  const visit = (node: ts.Node): void => {
    if (
      ts.isVariableDeclaration(node) &&
      node.name.getText(file) === 'AUTH_LOG_EVENTS' &&
      node.initializer !== undefined
    ) {
      let literal = node.initializer
      while (ts.isAsExpression(literal) || ts.isSatisfiesExpression(literal))
        literal = literal.expression
      if (!ts.isObjectLiteralExpression(literal)) return
      for (const property of literal.properties) {
        if (
          !ts.isPropertyAssignment(property) ||
          !ts.isObjectLiteralExpression(property.initializer)
        )
          continue
        const fields = property.initializer.properties.find(
          (member) => ts.isPropertyAssignment(member) && member.name.getText(file) === 'fields'
        )
        const list =
          fields !== undefined &&
          ts.isPropertyAssignment(fields) &&
          ts.isArrayLiteralExpression(fields.initializer)
            ? fields.initializer.elements.map((element) => element.getText(file).replace(/'/g, ''))
            : []
        entries.set(property.name.getText(file), list)
      }
    }
    ts.forEachChild(node, visit)
  }
  visit(file)
  return entries
}

/** Every non-test source file of the server. */
function sources(dir: string = ROOT): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name)
    if (entry.isDirectory()) return entry.name === '__tests__' ? [] : sources(path)
    return entry.name.endsWith('.ts') && !entry.name.endsWith('.spec.ts') ? [path] : []
  })
}

/** The helpers of the logger module that write a fixed event. */
const HELPERS: Record<string, string> = {
  logHook: 'AUTH_HOOK_FAILED',
  logDelivery: 'AUTH_DELIVERY_FAILED',
  logUnhandled: 'AUTH_UNHANDLED_EXCEPTION'
}

/** The events the code writes: each call's code and the field names it passes. */
function writtenCalls(): Array<{ code: string; fields: string[] }> {
  const calls: Array<{ code: string; fields: string[] }> = []
  const call = /logEvent\(\s*[\w.]+,\s*'(AUTH_[A-Z_]+)'(?:,\s*\{([^}]*)\})?/g
  for (const file of sources()) {
    if (file.endsWith('log-event.ts') || file.endsWith('log-events.ts')) continue
    const text = readFileSync(file, 'utf8')
    for (const match of text.matchAll(call)) {
      const fields = [...(match[2] ?? '').matchAll(/(?:^|,)\s*(\w+)\s*(?::|(?=,|$))/g)].map(
        (m) => m[1] as string
      )
      calls.push({ code: match[1] as string, fields })
    }
    // The helpers write one event each, with the fields their signature names, so a call of one writes that code.
    for (const [helper, code] of Object.entries(HELPERS)) {
      if (new RegExp(`\\b${helper}\\(`).test(text)) calls.push({ code, fields: [] })
    }
    for (const match of text.matchAll(/logStore\(\s*[\w.]+,\s*'(AUTH_[A-Z_]+)'/g)) {
      calls.push({ code: match[1] as string, fields: [] })
    }
  }
  return calls
}

describe('the code that writes log events', () => {
  // Scenario: the catalog read as text. Expected: the codes this suite expects, so an empty parse cannot make the
  // next row pass by listing nothing.
  it('reads the whole catalog', () => {
    const codes = [...catalog().keys()]

    expect(codes.length).toBeGreaterThanOrEqual(17)
    expect(codes).toContain('AUTH_LOGIN_LOCKED')
    expect(catalog().get('AUTH_REFRESH_REUSE_DETECTED')).toEqual(['plane', 'familyId'])
  })

  // Scenario: every call that writes an event. Expected: it names a catalog code and passes only fields the
  // catalog lists for it, and every catalog code is written by at least one call.
  it('is what the catalog lists, and nothing else', () => {
    const entries = catalog()
    const calls = writtenCalls()

    expect(calls.length).toBeGreaterThan(0)
    for (const { code, fields } of calls) {
      expect([...entries.keys()]).toContain(code)
      for (const field of fields) expect(entries.get(code)).toContain(field)
    }
    expect(new Set(calls.map((call) => call.code))).toEqual(new Set(entries.keys()))
  })

  // Scenario: every direct logger call in the library. Expected: the only ones are the operator-guidance
  // sentences below, each a plain string that names no value, and each of them is still there. Why: every other
  // line is an event, so a new free-text line (where `userId=...` or a quoted error would come back) fails here
  // until someone decides it is an event or adds a guidance sentence to this list on purpose.
  const GUIDANCE = [
    { file: 'redis/redis-readiness.service.ts', starts: 'The Redis client has no commandTimeout' },
    {
      file: 'services/auth-token-verifier.service.ts',
      starts: 'verifyAccessToken: enforceTenantBinding'
    },
    {
      file: 'services/workspace-denied-events.service.ts',
      starts: 'access.denied events are not being emitted'
    },
    {
      file: 'services/workspace-denied-events.service.ts',
      starts: 'The suppressed count of access.denied was not an integer'
    }
  ]

  /** Every call of a source whose callee is `<something>logger.<level>`, with the text of its arguments. */
  function directLoggerCalls(text: string): string[] {
    const source = ts.createSourceFile('probe.ts', text, ts.ScriptTarget.Latest, true)
    const levels = new Set(['log', 'warn', 'error', 'debug', 'verbose', 'fatal'])
    const found: string[] = []
    const visit = (node: ts.Node): void => {
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        levels.has(node.expression.name.text) &&
        /logger$/i.test(node.expression.expression.getText(source))
      ) {
        found.push(node.arguments.map((argument) => argument.getText(source)).join(', '))
      }
      ts.forEachChild(node, visit)
    }
    visit(source)
    return found
  }

  /** The guidance sentences a source writes, and the direct logger calls in it that are not one of them. */
  function judge(relative: string, text: string): { unexpected: string[]; guidance: string[] } {
    const result: { unexpected: string[]; guidance: string[] } = { unexpected: [], guidance: [] }
    for (const args of directLoggerCalls(text)) {
      const literal = args.replace(/^\s*['"`]/, '')
      const entry = GUIDANCE.find(
        (item) => item.file === relative && literal.startsWith(item.starts)
      )
      if (entry === undefined) result.unexpected.push(args.trim())
      else result.guidance.push(entry.starts)
    }
    return result
  }

  it('has no direct logger call but the named guidance sentences', () => {
    const unexpected: string[] = []
    const seen: string[] = []

    for (const file of sources()) {
      const found = judge(file.slice(ROOT.length + 1), readFileSync(file, 'utf8'))
      unexpected.push(...found.unexpected.map((args) => `${file.slice(ROOT.length + 1)}: ${args}`))
      seen.push(...found.guidance)
    }

    expect(unexpected).toEqual([])
    expect(seen.sort()).toEqual(GUIDANCE.map((entry) => entry.starts).sort())
  })

  // The rule has to be able to fail: a text line with an interpolation, a plain line, and a guidance sentence
  // written from another file each count as unexpected, and the sentence in its own file does not.
  it.each([
    ['services/x.ts', 'this.logger.warn(`login userId=${id}`)', 1],
    ['services/x.ts', "logger.error('something failed')", 1],
    ['services/x.ts', "this.logger.log('The Redis client has no commandTimeout, so ...')", 1],
    [
      'redis/redis-readiness.service.ts',
      "this.logger.warn('The Redis client has no commandTimeout, so ...')",
      0
    ]
  ])('judges %s: %s as having %i unexpected call(s)', (file, text, count) => {
    expect(judge(file, text).unexpected).toHaveLength(count)
  })
})
