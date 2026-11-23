/**
 * @fileoverview The list of built-ins the library baselines is exactly what the sources use: every function of a namespace
 * (`Object.keys`, `Reflect.get`), every function or accessor read or called on an instance (`some`, `has`, `set`, `size`,
 * `origin`) and every global binding the sources name is on the list, or is exempt with its reason, and nothing else is on it.
 * A source that starts calling another one fails here and not in a process that was refused, and a polyfill of a function no
 * source uses never makes the guard refuse.
 *
 * The sources are read as syntax, not as text: a name in a comment or in a string is not a call.
 *
 * @layer Test
 */

import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'

import ts from 'typescript'

import {
  BASELINED_GLOBALS,
  BASELINED_HOLDERS,
  BASELINED_ITERATORS,
  BASELINED_PROTOTYPES,
  BASELINED_STATICS
} from './builtin-baseline'

/** The globals the sources may name without the library comparing them, each with the reason. */
const EXEMPT: Record<string, string> = {
  Promise: 'a decision never depends on its functions, and the test doubles of a host replace it',
  Date: 'the clock source (the binding, Date.now, Date.parse) is what the test doubles of a host replace; the methods of a date, which decide expiry, are compared',
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

/** The modules that take the copies at load, which is what makes them safe; they name the built-ins by definition. */
const CAPTURING = [
  'utils/captured-builtins.ts',
  'crypto/captured-crypto.ts',
  'utils/builtin-baseline.ts'
]

/** Global names that are namespaces or constructors, found on the runtime, plus the lowercase functions the sources use. */
const LOWER = ['parseInt', 'parseFloat', 'isNaN', 'isFinite', 'structuredClone', 'queueMicrotask']
const RUNTIME = Reflect.ownKeys(globalThis)
  .filter((key): key is string => typeof key === 'string')
  .filter((key) => /^[A-Z]/.test(key) || LOWER.includes(key))
  .filter((key) =>
    ['function', 'object'].includes(typeof (globalThis as Record<string, unknown>)[key])
  )

/** The `.ts` sources of the server that are not tests (the helpers of the specs under `__tests__` are not sources). */
function sourceFiles(dir = join(__dirname, '..')): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return name === '__tests__' ? [] : sourceFiles(path)
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

/** What a source uses, as the three maps the checks read. */
interface Usage {
  globals: Map<string, string>
  members: Map<string, string>
  names: Map<string, string>
}

/** Whether `node` is the call of a mutant switch that a mutation run adds, `stryMutAct_9fa48("12")`. */
function isMutantSwitch(node: ts.Expression): boolean {
  return (
    ts.isCallExpression(node) &&
    ts.isIdentifier(node.expression) &&
    node.expression.text.startsWith('stryMutAct_')
  )
}

/**
 * Records what the code of `text` uses into `into`. A mutation run rewrites the sources the specs read: each mutant is a branch
 * of a switch whose last branch is the original code, and the instrumentation adds functions of its own. Only the original code
 * is read, so the mutants it adds (`endsWith` for `startsWith`, `every` for `some`) are not taken for what the library uses.
 */
function scan(text: string, path: string, into: Usage): void {
  const file = ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true)
  const visit = (node: ts.Node): void => {
    if (ts.isFunctionDeclaration(node) && node.name?.text.startsWith('stry') === true) return
    if (ts.isConditionalExpression(node) && isMutantSwitch(node.condition))
      return visit(node.whenFalse)
    if (ts.isIfStatement(node) && isMutantSwitch(node.expression)) {
      if (node.elseStatement !== undefined) visit(node.elseStatement)
      return
    }
    if (ts.isIdentifier(node) && RUNTIME.includes(node.text) && isValueReference(node))
      into.globals.set(node.text, path)
    if (ts.isPropertyAccessExpression(node)) {
      const target = node.expression
      if (ts.isIdentifier(target) && RUNTIME.includes(target.text))
        into.members.set(`${target.text}.${node.name.text}`, path)
      else into.names.set(node.name.text, path)
    }
    ts.forEachChild(node, visit)
  }
  visit(file)
}

/** What the sources use: the globals named as values, the `Namespace.member` accesses and every other property name. */
function usage(): Usage {
  const found: Usage = { globals: new Map(), members: new Map(), names: new Map() }
  for (const path of sourceFiles()) {
    if (CAPTURING.some((file) => path.endsWith(file))) continue
    scan(readFileSync(path, 'utf8'), path, found)
  }
  return found
}

/** The functions and accessors the sources use, found on each prototype of the baseline, as the module lists them. */
function expectedOn(holder: object, names: Map<string, string>): string[] {
  return Reflect.ownKeys(holder)
    .filter(
      (key): key is string => typeof key === 'string' && key !== 'constructor' && names.has(key)
    )
    .filter((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(holder, key)
      return (
        descriptor !== undefined &&
        (descriptor.configurable === true || descriptor.writable === true) &&
        (typeof descriptor.value === 'function' || typeof descriptor.get === 'function')
      )
    })
}

describe('the list of built-ins the library baselines, against the sources', () => {
  const { globals, members, names } = usage()

  // Scenario: every global the sources name as a value. Expected: each is a baselined binding or exempt, and `JSON` is neither.
  // Why: a binding the sources call and the library does not compare is one a replacement can answer for unseen, and `JSON` is
  // captured, so a source that names it directly reads the live one.
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

  // Scenario: each name on the list of a namespace. Expected: the sources still use it. Why: a list that keeps names nothing
  // calls any more costs a comparison on every entry for no decision, and refuses a process for a patch nothing depends on.
  it('keeps no namespace function that no source calls', () => {
    const stale = Object.entries(BASELINED_STATICS).flatMap(([namespace, list]) =>
      list
        .filter((member) => !members.has(`${namespace}.${member}`))
        .map((member) => `${namespace}.${member}`)
    )

    expect(stale).toEqual([])
  })

  // Scenario: every prototype of the baseline, the functions and accessors the sources call or read by name, found on it.
  // Expected: the list of that prototype holds exactly those, none missing and none more. Why: a function the sources call and
  // the list lacks is one a replacement can answer for unseen; one the list has and nothing calls is a false refusal.
  it.each(Object.keys(BASELINED_PROTOTYPES))('lists exactly what the sources use of %s', (name) => {
    const holder = BASELINED_HOLDERS[name] as object
    const listed = [
      ...((BASELINED_PROTOTYPES as Record<string, readonly string[]>)[name] ?? [])
    ].sort()

    expect(listed).toEqual(expectedOn(holder, names).sort())
  })

  // Scenario: every prototype that the sources use and the list has no entry for. Expected: the sources use nothing of it.
  // Why: the other half of the check above, for a prototype the list does not name at all.
  it('has no prototype the sources use a function of that the list leaves out', () => {
    const left = Object.entries(BASELINED_HOLDERS)
      .filter(([name]) => !(name in BASELINED_PROTOTYPES) && !(name in BASELINED_ITERATORS))
      .flatMap(([name, holder]) => expectedOn(holder, names).map((key) => `${name}.${key}`))

    expect(left).toEqual([])
  })

  // Scenario: the exemptions. Expected: none is also baselined, and each has a reason. Why: an exemption is a decision.
  it('exempts no baselined binding, and says why for each exemption', () => {
    for (const [name, reason] of Object.entries(EXEMPT)) {
      expect((BASELINED_GLOBALS as readonly string[]).includes(name)).toBe(false)
      expect(reason.length).toBeGreaterThan(10)
    }
  })

  // Scenario: a source as a mutation run rewrites it: the call behind a chain of mutant switches whose last branch is the original,
  // a block inside a switch of its own, and the instrumentation functions. Expected: only the original code is read, so `startsWith`
  // is used and the `endsWith` and `every` that are mutants of it are not. Why: the same specs run under the mutation run and
  // must find the same list.
  it('reads the original code of a source that a mutation run rewrote', () => {
    const found: Usage = { globals: new Map(), members: new Map(), names: new Map() }
    const instrumented = [
      'function stryNS_9fa48() { return globalThis.Function }',
      'export function f(a: string, b: string[]): boolean {',
      '  if (stryMutAct_9fa48("1")) {} else {',
      '    stryCov_9fa48("2")',
      '    return stryMutAct_9fa48("3") ? a.endsWith("x") : stryMutAct_9fa48("4") ? b.every(Boolean) : (stryCov_9fa48("5"), a.startsWith("x"))',
      '  }',
      '}'
    ].join('\n')

    scan(instrumented, 'fixture.ts', found)

    expect([...found.names.keys()].sort()).toEqual(['startsWith'])
    expect(found.globals.has('Function')).toBe(false)
  })
})
