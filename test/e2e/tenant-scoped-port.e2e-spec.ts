/**
 * @fileoverview Fails when a method on the dashboard user port can name an account without a tenant.
 *
 * `IUserRepository` is the dashboard plane's port, and this library may not assume the consumer's
 * ids are unique across tenants — a host that numbers users per tenant gives every tenant a user
 * `1`. So every call that names an account has to carry the tenant, or the implementation cannot
 * scope the row it reads or writes, however carefully it was written.
 *
 * The rule was already documented, in prose, on the port itself. It did not hold: `findById` took
 * the tenant as OPTIONAL and all twelve of this library's own call sites omitted it, none of them
 * the "internal admin flow" the JSDoc named as the reason for the option; six mutators took no
 * tenant at all while their JSDoc said implementations must scope the write; and `updateMfa` typed
 * its tenant `string | undefined` under a sentence promising it was "never omitted for a dashboard
 * account". Three different shapes of the same defect, each invisible next to the others, because
 * a signature that merely PERMITS a tenant-blind call reads exactly like one that requires a tenant
 * until you check which.
 *
 * Prose does not close by grep. This suite states the rule as something the compiler and the test
 * run agree on: it reads the declaration, not the documentation, so a method added tomorrow fails
 * until somebody gives it a tenant.
 *
 * It reads the TypeScript AST rather than the text for the same reason the log-injection gate does
 * — a regex over `tenantId` matches the JSDoc, the `@param` line and the prose paragraph above the
 * signature, all of which can be perfect while the declaration is wrong. That is precisely the
 * failure being guarded against.
 *
 * The platform arm is the mirror: `IPlatformUserRepository` serves admins who belong to no tenant,
 * so a `tenantId` parameter there means somebody copied a dashboard method onto the wrong plane.
 * Without it this suite would pass a port that had been made tenant-scoped everywhere, including
 * the one place where a tenant is meaningless.
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import ts from 'typescript'

/** Interfaces directory, from this suite's location under `test/e2e/`. */
const INTERFACES = join(__dirname, '../../src/server/interfaces')

/** A method declared on a repository port, reduced to what this suite judges. */
interface PortMethod {
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
 * @returns Every method signature declared on it, and every type declared alongside it.
 * @throws {@link Error} when the file declares no such interface — a rename must fail loudly
 *   rather than leave this suite silently checking nothing.
 */
function readPort(
  file: string,
  interfaceName: string
): { methods: PortMethod[]; localTypes: Map<string, Set<string>> } {
  const text = readFileSync(file, 'utf8')
  const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true)

  const methods: PortMethod[] = []
  /** Every interface in the file, mapped to the property names it declares as REQUIRED. */
  const localTypes = new Map<string, Set<string>>()
  let found = false

  for (const statement of source.statements) {
    if (!ts.isInterfaceDeclaration(statement)) continue

    const required = new Set<string>()
    for (const member of statement.members) {
      if (ts.isPropertySignature(member) && member.questionToken === undefined && member.name) {
        required.add(member.name.getText(source))
      }
    }
    localTypes.set(statement.name.text, required)

    if (statement.name.text !== interfaceName) continue
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

  if (!found) throw new Error(`${interfaceName} is not declared in ${file}`)
  if (methods.length === 0) throw new Error(`${interfaceName} declares no methods in ${file}`)

  return { methods, localTypes }
}

/**
 * Reads the method signatures of the README's example repository.
 *
 * The example is not illustration — it is the implementation a consumer pastes into their project
 * and then edits around, so a tenant-blind signature there ships the defect into every deployment
 * that follows the docs. It is also the one copy of the port that no compiler checks, which is
 * exactly why it drifted: the version this replaced wrote `update({ where: { id } })` on six
 * mutators, a query that crosses tenants by construction.
 *
 * @param file - Absolute path of the README.
 * @param className - The example class to read, matched on `implements`.
 * @returns Every method it declares.
 * @throws {@link Error} when no fenced block declares that class — the example being renamed or
 *   dropped must fail here rather than leave this arm asserting over an empty list.
 */
function readReadmeExample(file: string, className: string): PortMethod[] {
  const text = readFileSync(file, 'utf8')
  // Fenced TypeScript blocks only. Prose elsewhere in the README may name these methods, and this
  // arm compares declarations, not mentions.
  const blocks = [...text.matchAll(/```(?:ts|typescript)\n([\s\S]*?)```/g)].map(
    (match) => match[1] ?? ''
  )

  const methods: PortMethod[] = []
  let found = false

  for (const [index, block] of blocks.entries()) {
    const source = ts.createSourceFile(`readme-${index}.ts`, block, ts.ScriptTarget.Latest, true)

    for (const statement of source.statements) {
      if (!ts.isClassDeclaration(statement) || statement.name?.text !== className) continue
      found = true

      for (const member of statement.members) {
        if (!ts.isMethodDeclaration(member) || !member.name) continue
        methods.push({
          name: member.name.getText(source),
          params: member.parameters.map((parameter) => ({
            name: parameter.name.getText(source),
            type:
              (parameter.questionToken ? '?:' : '') + (parameter.type?.getText(source) ?? 'unknown')
          }))
        })
      }
    }
  }

  if (!found) throw new Error(`${className} is not declared in any fenced block of ${file}`)

  return methods
}

const USER_PORT = join(INTERFACES, 'user-repository.interface.ts')
const PLATFORM_PORT = join(INTERFACES, 'platform-user-repository.interface.ts')
const README = join(__dirname, '../../README.md')

/** The dashboard port, parsed once and shared by the arms that compare against it. */
const userPort = readPort(USER_PORT, 'IUserRepository')

describe('tenant-scoped port', () => {
  describe('IUserRepository', () => {
    const { methods, localTypes } = userPort

    // The suite is only as good as its subject. A port that parsed to nothing — a rename, a move
    // to a barrel, a refactor into type aliases — would make every assertion below vacuously
    // true, which is the failure mode a gate must not have.
    //
    // Named rather than counted. A `length > n` guard picks an arbitrary n and then passes a parse
    // that found some other interface with enough members; naming the methods this suite exists to
    // judge is the same guard without the arbitrary number, and it also fails when one is deleted.
    it('parses the methods it exists to judge', () => {
      const SUBJECTS = [
        'findById',
        'updatePassword',
        'updateMfa',
        'updateLastLogin',
        'updateStatus',
        'updateEmailVerified',
        'updateEmail',
        'linkOAuth'
      ]
      const parsed = methods.map((method) => method.name)

      expect(SUBJECTS.filter((name) => !parsed.includes(name))).toEqual([])
    })

    // The rule itself. A method either takes the tenant directly, or takes a payload object whose
    // type requires one; there is no third way to name an account inside a single tenant.
    //
    // Reported as a list rather than one assertion per method so a failure names EVERY method that
    // drifted. The three shapes of this defect were each hidden by the others sitting on adjacent
    // lines, and a gate that stops at the first one reproduces exactly that.
    it('names every account through a tenant', () => {
      const unscoped = methods
        .filter((method) => {
          const direct = method.params.find((parameter) => parameter.name === 'tenantId')

          // A `tenantId` typed anything but `string` — `string | undefined`, or `tenantId?: string`
          // — lets a caller pass nothing: a tenant-blind call with a tenant-shaped signature in
          // front of it.
          if (direct) return direct.type !== 'string'

          // No `tenantId` parameter: the only acceptable alternative is a payload type that
          // requires one, which is how `create` and `createWithOAuth` carry it.
          return !method.params.some((parameter) => localTypes.get(parameter.type)?.has('tenantId'))
        })
        .map((method) => method.name)

      expect(unscoped).toEqual([])
    })

    // Ordering is not cosmetic here. A method taking a bare `string` id and a bare `string` tenant
    // type checks with the two transposed, and then writes to whatever row the consumer's query
    // finds for `(tenantId, id)` — a defect with no compiler symptom and no runtime symptom until
    // the wrong account changes. One consistent position is what makes a transposition visible
    // when reading the call, and consistency only pays if nothing is allowed to differ.
    //
    // Scoped to methods that name the account by an id, because that is where the ambiguity lives.
    // `findByOAuthId` names it by a `(provider, providerId)` pair and puts the tenant after both;
    // there is no id for it to be confused with, so pinning it to index 1 would be a rule invented
    // for the gate's convenience rather than for the risk.
    it('takes the tenant immediately after the account id', () => {
      const misplaced = methods
        .filter((method) => {
          const idAt = method.params.findIndex(
            (parameter) => parameter.name === 'id' || parameter.name === 'userId'
          )

          return idAt !== -1 && method.params[idAt + 1]?.name !== 'tenantId'
        })
        .map((method) => method.name)

      expect(misplaced).toEqual([])
    })
  })

  describe("the README's example implementation", () => {
    const example = readReadmeExample(README, 'PrismaUserRepository')

    // Same vacuity guard as above: an example that parsed to nothing would make the comparison
    // below trivially true.
    it('parses an example with methods to compare', () => {
      expect(example.length).toBe(userPort.methods.length)
    })

    // Signature-for-signature, not merely "has a tenant somewhere". A consumer copies this class
    // and edits the bodies; if a parameter list here disagrees with the port, their edit starts
    // from a shape that either fails to compile or — worse, on two same-typed neighbours —
    // compiles with the id and the tenant transposed.
    it('declares the same parameters as the port', () => {
      const port = new Map(userPort.methods.map((method) => [method.name, method.params]))
      const drifted = example
        .filter((method) => JSON.stringify(port.get(method.name)) !== JSON.stringify(method.params))
        .map((method) => method.name)

      expect(drifted).toEqual([])
    })
  })

  describe('IPlatformUserRepository', () => {
    const { methods } = readPort(PLATFORM_PORT, 'IPlatformUserRepository')

    // A platform admin belongs to no tenant. A `tenantId` here is a dashboard method that landed
    // on the wrong plane, which would send the write to a scope the platform repository has no
    // column for.
    it('takes no tenant on any method', () => {
      const scoped = methods
        .filter((method) => method.params.some((parameter) => parameter.name === 'tenantId'))
        .map((method) => method.name)

      expect(scoped).toEqual([])
    })
  })
})
