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

/** The events the code writes: each call's code and the field names it passes. */
function writtenCalls(): Array<{ code: string; fields: string[] }> {
  const calls: Array<{ code: string; fields: string[] }> = []
  const call = /logEvent\(\s*[\w.]+,\s*'(AUTH_[A-Z_]+)'(?:,\s*\{([^}]*)\})?/g
  for (const file of sources()) {
    if (file.endsWith('log-event.ts') || file.endsWith('log-events.ts')) continue
    for (const match of readFileSync(file, 'utf8').matchAll(call)) {
      const fields = [...(match[2] ?? '').matchAll(/(?:^|,)\s*(\w+)\s*(?::|(?=,|$))/g)].map(
        (m) => m[1] as string
      )
      calls.push({ code: match[1] as string, fields })
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

  // Scenario: a logger call that is not an event. Expected: none of them names a user, a tenant or an address
  // as `key=value` text or through a masked address. Why: the events carry identity only through declared
  // fields on success and audit events, and a free-text line is where `userId=...` would come back.
  it('has no plain-text logger call that names an identity', () => {
    const call = /(?:this\.)?logger\.(?:log|warn|error|debug|verbose)\(/g
    const identity = /maskEmail\(|\b(?:userId|tenantId|email|adminId|inviterUserId|revokerUserId)=/
    const found: string[] = []

    for (const file of sources()) {
      const text = readFileSync(file, 'utf8')
      for (const match of text.matchAll(call)) {
        let depth = 1
        let end = match.index + match[0].length
        while (depth > 0 && end < text.length) {
          depth += (text[end] === '(' ? 1 : 0) - (text[end] === ')' ? 1 : 0)
          end += 1
        }
        if (identity.test(text.slice(match.index, end))) found.push(file)
      }
    }

    expect(found).toEqual([])
  })
})
