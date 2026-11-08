/**
 * @fileoverview Reads the method signatures of a repository port from its TypeScript source, so a
 * suite can judge what the DECLARATION requires rather than what its documentation says.
 *
 * A regex over a key name matches the JSDoc, the `@param` line and the prose paragraph above the
 * signature, all of which can be perfect while the declaration is wrong; the AST cannot be fooled
 * that way.
 *
 * @layer Test
 */
import { readFileSync } from 'node:fs'

import ts from 'typescript'

/** A method declared on a repository port, reduced to what this suite judges. */
export interface PortMethod {
  /** The method's name, for the failure message. */
  name: string
  /** Its parameters, in declaration order. */
  params: { name: string; type: string }[]
}

/** What {@link readPort} learned about one port and the types declared beside it. */
export interface ParsedPort {
  /** The port's method signatures, in declaration order. */
  methods: PortMethod[]
  /** Every interface read, mapped to its REQUIRED properties and the TYPE of each. */
  localTypes: Map<string, Map<string, string>>
  /**
   * Members of the port that are not method signatures (a function-typed property, an index
   * signature). A suite that judges only methods would not see them, so they are reported.
   */
  otherMembers: string[]
  /** Interfaces the port itself extends; their members are not read, so they are reported. */
  inherits: string[]
}

/** Parses a TypeScript file. */
function parse(path: string): ts.SourceFile {
  return ts.createSourceFile(path, readFileSync(path, 'utf8'), ts.ScriptTarget.Latest, true)
}

/**
 * The REQUIRED properties of an interface and the TYPE of each.
 *
 * The type is kept, not merely the name: a payload declaring `tenantId: string | undefined` passes
 * a name-only check while permitting exactly the tenant-blind call the rule exists to refuse.
 */
function requiredProperties(
  statement: ts.InterfaceDeclaration,
  source: ts.SourceFile
): Map<string, string> {
  const required = new Map<string, string>()
  for (const member of statement.members) {
    if (ts.isPropertySignature(member) && member.questionToken === undefined && member.name) {
      required.set(member.name.getText(source), member.type?.getText(source) ?? 'unknown')
    }
  }
  return required
}

/** The method signatures of an interface. */
function methodsOf(statement: ts.InterfaceDeclaration, source: ts.SourceFile): PortMethod[] {
  const methods: PortMethod[] = []
  for (const member of statement.members) {
    if (!ts.isMethodSignature(member) || !member.name) continue
    methods.push({
      name: member.name.getText(source),
      params: member.parameters.map((parameter) => ({
        name: parameter.name.getText(source),
        // The `?` is part of the contract: an optional tenant is exactly the shape this suite
        // exists to reject, so it has to survive into the compared string.
        type: (parameter.questionToken ? '?:' : '') + (parameter.type?.getText(source) ?? 'unknown')
      }))
    })
  }
  return methods
}

/** The members of an interface that are not method signatures, named for the failure message. */
function nonMethodMembers(statement: ts.InterfaceDeclaration, source: ts.SourceFile): string[] {
  return statement.members
    .filter((member) => !ts.isMethodSignature(member))
    .map((member) => member.name?.getText(source) ?? ts.SyntaxKind[member.kind])
}

/** The names an interface extends. */
function parentsOf(statement: ts.InterfaceDeclaration, source: ts.SourceFile): string[] {
  return (statement.heritageClauses ?? []).flatMap((clause) =>
    clause.types.map((type) => type.expression.getText(source))
  )
}

/**
 * Folds inherited members down. `UpdatePasswordParams extends TenantScopedUserRef` declares no
 * `tenantId` of its own, and a rule that only read own members would report it as unscoped.
 *
 * Iterated to a FIXED POINT because a single sweep is order-dependent: with `Child extends Parent`
 * and `Parent extends Base`, a file declaring `Child` first would process it before `Parent` has
 * received `Base.tenantId`. Bounded by the number of interfaces, since each pass either adds a
 * property or stops.
 */
function foldHeritage(
  localTypes: Map<string, Map<string, string>>,
  heritage: Map<string, string[]>
): void {
  for (let changed = true; changed;) {
    changed = false
    for (const [name, parents] of heritage) {
      const own = localTypes.get(name)
      if (!own) continue
      for (const parent of parents) {
        for (const [prop, type] of localTypes.get(parent) ?? []) {
          if (!own.has(prop)) {
            own.set(prop, type)
            changed = true
          }
        }
      }
    }
  }
}

/**
 * Parses one interface declaration into its method signatures.
 *
 * @param file - Absolute path of the `.ts` file to read.
 * @param interfaceName - The interface to pull methods from.
 * @param siblings - Further files whose interface declarations the payload types may extend, so a
 *   parent declared beside the port's neighbour still folds into the child.
 * @returns The port's methods, the types declared alongside it, and anything on the port a
 *   method-only reading would miss.
 * @throws {@link Error} when the file declares no such interface or it declares no methods — a
 *   rename must fail loudly rather than leave this suite silently checking nothing.
 */
export function readPort(file: string, interfaceName: string, siblings: string[] = []): ParsedPort {
  const port: ParsedPort = {
    methods: [],
    localTypes: new Map(),
    otherMembers: [],
    inherits: []
  }
  const heritage = new Map<string, string[]>()
  let found = false

  for (const path of [file, ...siblings]) {
    const source = parse(path)
    for (const statement of source.statements.filter(ts.isInterfaceDeclaration)) {
      port.localTypes.set(statement.name.text, requiredProperties(statement, source))
      heritage.set(statement.name.text, parentsOf(statement, source))
      if (path !== file || statement.name.text !== interfaceName) continue
      found = true
      port.methods = methodsOf(statement, source)
      port.otherMembers = nonMethodMembers(statement, source)
      port.inherits = parentsOf(statement, source)
    }
  }

  if (!found) throw new Error(`${interfaceName} is not declared in ${file}`)
  if (port.methods.length === 0) throw new Error(`${interfaceName} declares no methods in ${file}`)
  foldHeritage(port.localTypes, heritage)
  return port
}
