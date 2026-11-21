/**
 * @fileoverview No assertion reads a dotted key as a name: `toHaveProperty('a.b')` is a nested PATH, so a
 * negative assertion on a dotted span attribute or metric name can never fail.
 *
 * It parses the specs as text with the TypeScript compiler and imports nothing under `src`, so the mutation run
 * has no use for it.
 *
 * @layer Test
 */

import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

import * as ts from 'typescript'

const ROOTS = [join(__dirname, '..'), join(__dirname, '../../test')]

/** Every spec file under a directory. */
function specs(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name)
    if (entry.isDirectory()) return entry.name === 'node_modules' ? [] : specs(path)
    return /spec\.tsx?$/.test(entry.name) ? [path] : []
  })
}

/** The string keys a source passes to `toHaveProperty` as a bare string, which Jest reads as a path. */
function dottedKeys(text: string): string[] {
  const source = ts.createSourceFile('probe.ts', text, ts.ScriptTarget.Latest, true)
  const found: string[] = []
  const visit = (node: ts.Node): void => {
    const [key] = ts.isCallExpression(node) ? node.arguments : []
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.name.text === 'toHaveProperty' &&
      key !== undefined &&
      (ts.isStringLiteral(key) || ts.isNoSubstitutionTemplateLiteral(key)) &&
      key.text.includes('.')
    ) {
      found.push(key.text)
    }
    ts.forEachChild(node, visit)
  }
  visit(source)
  return found
}

describe('toHaveProperty keys', () => {
  // Scenario: every spec of the library. Expected: no bare string key with a dot. Why: Jest splits it into a
  // path, so `.not.toHaveProperty('bymax.auth.plane')` passes whatever the object holds. The array form
  // `toHaveProperty(['bymax.auth.plane'])` names the key.
  it('never passes a dotted string as a key', () => {
    const found = ROOTS.flatMap((root) => specs(root)).flatMap((file) =>
      dottedKeys(readFileSync(file, 'utf8')).map((key) => `${file}: ${key}`)
    )

    expect(found).toEqual([])
  })

  // The rule has to be able to fail: a dotted string is reported in either quote form, and the array form, a
  // plain key and a key given with a value are not.
  it.each([
    ["expect(x).not.toHaveProperty('bymax.auth.plane')", 1],
    ['expect(x).toHaveProperty(`a.b`, 1)', 1],
    ["expect(x).not.toHaveProperty(['bymax.auth.plane'])", 0],
    ["expect(x).toHaveProperty('x-request-id', 'r')", 0],
    ["expect(x).toHaveProperty('plane')", 0]
  ])('judges %s as having %i dotted key(s)', (text, count) => {
    expect(dottedKeys(text)).toHaveLength(count)
  })
})
