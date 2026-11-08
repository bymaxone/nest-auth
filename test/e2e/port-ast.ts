/**
 * @fileoverview Reads the method signatures of a repository port from its TypeScript source, so a
 * suite can judge what the DECLARATION requires rather than what its documentation says.
 *
 * A regex over a key name matches the JSDoc, the `@param` line and the prose paragraph above the
 * signature, all of which can be perfect while the declaration is wrong; the AST cannot be fooled
 * that way. *
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

/**
 * Parses one interface declaration into its method signatures.
 *
 * @param file - Absolute path of the `.ts` file to read.
 * @param interfaceName - The interface to pull methods from.
 * @param siblings - Further files whose interface declarations the payload types may extend, so
 *   a parent declared beside the port's neighbour still folds into the child.
 * @returns Every method signature declared on it, and every type declared alongside it.
 * @throws {@link Error} when the file declares no such interface — a rename must fail loudly
 *   rather than leave this suite silently checking nothing.
 */
export function readPort(
  file: string,
  interfaceName: string,
  siblings: string[] = []
): { methods: PortMethod[]; localTypes: Map<string, Map<string, string>> } {
  const methods: PortMethod[] = []
  /**
   * Every interface in the file, mapped to its REQUIRED properties and the TYPE of each.
   *
   * The type, not merely the name. An earlier version stored names only, so a payload declaring
   * `tenantId: string | undefined` satisfied the rule below while permitting exactly the
   * tenant-blind call the rule exists to refuse — the same defect the direct-parameter arm had
   * already been written to catch, reintroduced one indirection away.
   */
  const localTypes = new Map<string, Map<string, string>>()
  /** `extends` edges, resolved after the whole file is read so declaration order cannot matter. */
  const heritage = new Map<string, string[]>()
  let found = false

  for (const path of [file, ...siblings]) {
    const text = readFileSync(path, 'utf8')
    const source = ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true)
    for (const statement of source.statements) {
      if (!ts.isInterfaceDeclaration(statement)) continue

      const required = new Map<string, string>()
      for (const member of statement.members) {
        if (ts.isPropertySignature(member) && member.questionToken === undefined && member.name) {
          required.set(member.name.getText(source), member.type?.getText(source) ?? 'unknown')
        }
      }
      localTypes.set(statement.name.text, required)
      heritage.set(
        statement.name.text,
        (statement.heritageClauses ?? []).flatMap((clause) =>
          clause.types.map((t) => t.expression.getText(source))
        )
      )

      if (path !== file || statement.name.text !== interfaceName) continue
      found = true

      for (const member of statement.members) {
        if (!ts.isMethodSignature(member) || !member.name) continue
        methods.push({
          name: member.name.getText(source),
          params: member.parameters.map((parameter) => ({
            name: parameter.name.getText(source),
            // The `?` is part of the contract, not decoration: an optional tenant is exactly the
            // shape this suite exists to reject, so it has to survive into the compared string.
            type:
              (parameter.questionToken ? '?:' : '') + (parameter.type?.getText(source) ?? 'unknown')
          }))
        })
      }
    }
  }

  if (!found) throw new Error(`${interfaceName} is not declared in ${file}`)
  if (methods.length === 0) throw new Error(`${interfaceName} declares no methods in ${file}`)

  // Fold inherited members down. `UpdatePasswordParams extends TenantScopedUserRef` declares no
  // `tenantId` of its own, and a rule that only read own-members would report it as unscoped —
  // failing on the shape that is actually correct, which is the way a gate loses its audience.
  //
  // Iterated to a FIXED POINT rather than in one pass. A single sweep is order-dependent: with
  // `Child extends Parent` and `Parent extends Base`, a file declaring `Child` first processes it
  // before `Parent` has received `Base.tenantId`, so a valid payload is reported as unscoped. The
  // loop below cannot care about declaration order, which is what the comment above it claims.
  // Bounded by the number of interfaces, since each pass either adds a property or stops.
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

  return { methods, localTypes }
}
