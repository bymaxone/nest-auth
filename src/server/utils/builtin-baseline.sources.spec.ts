/**
 * @fileoverview The list of built-ins the library baselines is complete for the sources: every function of a namespace
 * (`Object.keys`, `Reflect.get`, `JSON.parse`) and every global binding the sources name is on the list, or is exempt with its
 * reason, so a source that starts calling another one fails here and not in a process that was refused.
 *
 * The sources are read as syntax, not as text: a name in a comment or in a string is not a call.
 *
 * @layer Test
 */

import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'

import ts from 'typescript'

import { BASELINED_GLOBALS, BASELINED_STATICS } from './builtin-baseline'

/** The globals the sources may name without the library comparing them, each with the reason. */
const EXEMPT: Record<string, string> = {
  Promise: 'a decision never depends on it, and the test doubles of a host replace it',
  Date: 'a decision never depends on its functions, and the test doubles of a host replace it',
  AbortSignal: 'bounds how long a request to another service may wait, and decides nothing',
  Intl: 'only validates a locale tag, decides nothing, and a fake clock replaces it together with Date',
  setTimeout: 'schedules, decides nothing, and fake timers replace it',
  clearTimeout: 'schedules, decides nothing, and fake timers replace it',
  setInterval: 'schedules, decides nothing, and fake timers replace it',
  clearInterval: 'schedules, decides nothing, and fake timers replace it',
  setImmediate: 'schedules, decides nothing, and fake timers replace it',
  queueMicrotask: 'schedules, decides nothing',
  globalThis: 'the object the bindings are read from'
}

/** Global names that are namespaces or constructors, found on the runtime, plus the lowercase functions the sources use. */
const LOWER = ['parseInt', 'parseFloat', 'isNaN', 'isFinite', 'structuredClone', 'queueMicrotask']
const RUNTIME = Reflect.ownKeys(globalThis)
  .filter((key): key is string => typeof key === 'string')
  .filter((key) => /^[A-Z]/.test(key) || LOWER.includes(key))
  .filter((key) =>
    ['function', 'object'].includes(typeof (globalThis as Record<string, unknown>)[key])
  )

/** The `.ts` sources of the server that are not tests. */
function sourceFiles(dir = join(__dirname, '..')): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return sourceFiles(path)
    return /\.ts$/.test(name) && !/\.(spec|test)\.ts$/.test(name) ? [path] : []
  })
}

/** Whether `node` names a value, not a property key, a declaration or a type. */
function isValueReference(node: ts.Identifier): boolean {
  const parent = node.parent
  if (ts.isPropertyAccessExpression(parent) && parent.name === node) return false
  if (ts.isTypeReferenceNode(parent) || ts.isExpressionWithTypeArguments(parent)) return false
  if (ts.isImportSpecifier(parent) || ts.isExportSpecifier(parent) || ts.isImportClause(parent))
    return false
  if (
    (ts.isPropertyAssignment(parent) ||
      ts.isPropertySignature(parent) ||
      ts.isPropertyDeclaration(parent) ||
      ts.isMethodDeclaration(parent) ||
      ts.isBindingElement(parent) ||
      ts.isVariableDeclaration(parent) ||
      ts.isParameter(parent) ||
      ts.isFunctionDeclaration(parent) ||
      ts.isClassDeclaration(parent) ||
      ts.isInterfaceDeclaration(parent) ||
      ts.isTypeAliasDeclaration(parent) ||
      ts.isEnumDeclaration(parent) ||
      ts.isTypeParameterDeclaration(parent)) &&
    parent.name === node
  )
    return false
  return true
}

/** What the sources use: the globals named as values, and the `Namespace.member` accesses. */
function usage(): { globals: Map<string, string>; members: Map<string, string> } {
  const globals = new Map<string, string>()
  const members = new Map<string, string>()
  for (const path of sourceFiles()) {
    const file = ts.createSourceFile(path, readFileSync(path, 'utf8'), ts.ScriptTarget.Latest, true)
    const visit = (node: ts.Node): void => {
      if (ts.isIdentifier(node) && RUNTIME.includes(node.text) && isValueReference(node))
        globals.set(node.text, path)
      if (
        ts.isPropertyAccessExpression(node) &&
        ts.isIdentifier(node.expression) &&
        RUNTIME.includes(node.expression.text)
      )
        members.set(`${node.expression.text}.${node.name.text}`, path)
      ts.forEachChild(node, visit)
    }
    visit(file)
  }
  return { globals, members }
}

describe('the list of built-ins the library baselines, against the sources', () => {
  const { globals, members } = usage()

  // Scenario: every global the sources name as a value. Expected: each is a baselined binding or exempt. Why: a binding the
  // sources call and the library does not compare is one a replacement can answer for unseen.
  it('lists every global binding the sources name, or exempts it with a reason', () => {
    const unlisted = [...globals.keys()].filter(
      (name) => !(BASELINED_GLOBALS as readonly string[]).includes(name) && !(name in EXEMPT)
    )

    expect(unlisted).toEqual([])
  })

  // Scenario: every `Namespace.member` the sources access where the member is a function of that namespace. Expected: it is in
  // the list of that namespace. Why: `Object.keys` is a call; the list is what the guard compares.
  it('lists every function of a namespace the sources call', () => {
    const unlisted = [...members.keys()].filter((access) => {
      const [namespace = '', member = ''] = access.split('.')
      if (namespace in EXEMPT || member === 'prototype') return false
      const holder = (globalThis as Record<string, unknown>)[namespace] as Record<string, unknown>
      if (typeof holder[member] !== 'function') return false
      const listed = (BASELINED_STATICS as Record<string, readonly string[]>)[namespace] ?? []
      return !listed.includes(member)
    })

    expect(unlisted).toEqual([])
  })

  // Scenario: each name on the list. Expected: the sources still use it (or the library's own guard files do). Why: a list that
  // keeps names nothing calls any more costs a comparison on every entry for no decision.
  it('keeps no namespace function that no source calls', () => {
    const stale = Object.entries(BASELINED_STATICS).flatMap(([namespace, list]) =>
      list
        .filter((member) => !members.has(`${namespace}.${member}`))
        .map((member) => `${namespace}.${member}`)
    )

    expect(stale).toEqual([])
  })

  // Scenario: the exemptions. Expected: none is also baselined, and each has a reason. Why: an exemption is a decision.
  it('exempts no baselined binding, and says why for each exemption', () => {
    for (const [name, reason] of Object.entries(EXEMPT)) {
      expect((BASELINED_GLOBALS as readonly string[]).includes(name)).toBe(false)
      expect(reason.length).toBeGreaterThan(10)
    }
  })
})
