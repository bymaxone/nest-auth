/**
 * @fileoverview Scans the server's production sources for the shape that turns a host hook's
 * synchronous throw into a failed request: `Promise.resolve(call(...))` outside a `try`.
 *
 * `Promise.resolve(f())` evaluates `f()` before `Promise.resolve` exists, so a hook declared `void`
 * that throws synchronously escapes, and `.catch` never sees it. A completed login, logout or reset
 * would then answer as a failure. `runDetached` catches both a rejection and a throw; any other
 * `Promise.resolve(call)` must sit inside a `try` of its own.
 *
 * @layer Test
 */

import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

import ts from 'typescript'

const SERVER = join(__dirname)
const HELPER = join(SERVER, 'utils', 'run-detached.ts')

/** Production TypeScript under `dir`: no specs, no test harnesses, no declaration files. */
function productionFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return name === '__tests__' ? [] : productionFiles(path)
    return /\.ts$/.test(name) && !/\.(?:spec|d)\.ts$/.test(name) ? [path] : []
  })
}

/** Whether a node sits inside the `try` block (not the `catch`) of a try statement. */
function insideTry(node: ts.Node): boolean {
  for (let child = node, parent = node.parent; parent; child = parent, parent = parent.parent) {
    if (ts.isTryStatement(parent) && parent.tryBlock === child) return true
    if (ts.isFunctionLike(parent)) return false
  }
  return false
}

/** Whether an expression contains a call, which is what Promise.resolve would evaluate first. */
function containsCall(node: ts.Node): boolean {
  return ts.isCallExpression(node) || ts.forEachChild(node, containsCall) === true
}

/** The lines of every `Promise.resolve(<a call>)` in `text` that a synchronous throw would escape. */
function unprotectedLines(name: string, text: string): number[] {
  const file = ts.createSourceFile(name, text, ts.ScriptTarget.Latest, true)
  const found: number[] = []
  const visit = (node: ts.Node): void => {
    if (
      ts.isCallExpression(node) &&
      node.expression.getText(file) === 'Promise.resolve' &&
      node.arguments.some(containsCall) &&
      !insideTry(node)
    ) {
      found.push(file.getLineAndCharacterOfPosition(node.getStart(file)).line + 1)
    }
    ts.forEachChild(node, visit)
  }
  visit(file)
  return found
}

/** `file:line` of every unprotected `Promise.resolve(<a call>)` in a production file. */
function unprotected(path: string): string[] {
  return unprotectedLines(path, readFileSync(path, 'utf8')).map(
    (line) => `${relative(SERVER, path)}:${line}`
  )
}

describe('detached hooks', () => {
  it('has no Promise.resolve(call) outside a try, except the helper that catches both ways', () => {
    const sites = productionFiles(SERVER)
      .filter((path) => path !== HELPER)
      .flatMap(unprotected)

    expect(sites).toEqual([])
  })

  // The scan must see the shape it exists for.
  it('recognises the unprotected shape and the protected one', () => {
    const count = (text: string): number => unprotectedLines('x.ts', text).length

    expect(count('void Promise.resolve(hook(a)).catch(log)')).toBe(1)
    expect(count('try { void Promise.resolve(hook(a)).catch(log) } catch { log() }')).toBe(0)
    expect(count('try {} catch { void Promise.resolve(hook(a)) }')).toBe(1)
    expect(count('const p = Promise.resolve(value)')).toBe(0)
  })
})
