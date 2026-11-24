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
const BANNED = ['all', 'allSettled', 'any', 'race']

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
})
