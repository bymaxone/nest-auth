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
): { methods: PortMethod[]; localTypes: Map<string, Map<string, string>> } {
  const text = readFileSync(file, 'utf8')
  const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true)

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

/**
 * Type-checks one snippet against the real port and returns its errors.
 *
 * An in-memory `ts.Program` so the probe never touches disk, reading the actual interface file
 * through the default host — the point is to measure what a consumer's `tsc` measures, not what a
 * hand-rolled matcher believes about it.
 *
 * @param source - TypeScript to compile. Imports resolve relative to the repository.
 * @returns One message per diagnostic; empty when the snippet type-checks.
 */
function compileErrors(source: string): string[] {
  const NAME = join(__dirname, '__port-probe__.ts')
  const options: ts.CompilerOptions = {
    strict: true,
    noEmit: true,
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.ESNext,
    moduleResolution: ts.ModuleResolutionKind.Bundler,
    skipLibCheck: true
  }
  const host = ts.createCompilerHost(options, true)
  const original = host.getSourceFile.bind(host)
  host.getSourceFile = (fileName, languageVersion, onError, shouldCreate) =>
    fileName === NAME
      ? ts.createSourceFile(fileName, source, languageVersion, true)
      : original(fileName, languageVersion, onError, shouldCreate)
  host.fileExists = (fileName) => fileName === NAME || ts.sys.fileExists(fileName)
  host.readFile = (fileName) => (fileName === NAME ? source : ts.sys.readFile(fileName))

  const program = ts.createProgram([NAME], options, host)
  return program
    .getSemanticDiagnostics()
    .concat(program.getSyntacticDiagnostics())
    .map((d) => ts.flattenDiagnosticMessageText(d.messageText, ' '))
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
      /** A payload type counts only when it REQUIRES `tenantId` and types it exactly `string`. */
      const carriesTenant = (type: string): boolean =>
        localTypes.get(type)?.get('tenantId') === 'string'

      const unscoped = methods
        .filter((method) => {
          const direct = method.params.find((parameter) => parameter.name === 'tenantId')

          // A `tenantId` typed anything but `string` — `string | undefined`, or `tenantId?: string`
          // — lets a caller pass nothing: a tenant-blind call with a tenant-shaped signature in
          // front of it.
          if (direct) return direct.type !== 'string'

          // No `tenantId` parameter: the only acceptable alternative is a payload type that
          // requires one, typed `string`. Requiring the TYPE and not merely the property is the
          // point — `tenantId: string | undefined` is a required property that still permits
          // nothing being passed, so a name-only check would wave through the defect this arm
          // rejects two lines above when it appears directly.
          return !method.params.some((parameter) => carriesTenant(parameter.type))
        })
        .map((method) => method.name)

      expect(unscoped).toEqual([])
    })

    // Every account-naming method takes ONE parameter, and it is an object.
    //
    // This replaces an arm that pinned the tenant to the position after the id. That arm was
    // guarding a transposition — two bare `string`s next to each other type check swapped — and
    // the object form removes the hazard rather than policing it, so the old rule now has nothing
    // to say. What matters instead is that the shape stays an object, which is what the arm below
    // depends on: revert any one of these to positional strings and a stale implementation starts
    // compiling again.
    it('names an account through a single payload object', () => {
      // Both halves, because either one alone passes the shape this arm exists to refuse. Testing
      // only for a `string` parameter waves through two parameters, and a positional alias like
      // `id: UserId` — a branded string is still a positional string. Testing only the count
      // waves through `findById(id: string)`. The type must also RESOLVE to a payload declared in
      // this file, which is what makes it an object rather than a rename.
      const positional = methods
        .filter(
          (method) => method.params.length !== 1 || !localTypes.has(method.params[0]?.type ?? '')
        )
        .map((method) => method.name)

      expect(positional).toEqual([])
    })

    // The property none of the arms above can see, and the only one that closes the defect.
    //
    // Every rule so far reads the DECLARATION. None of them can tell you whether a consumer's
    // pre-upgrade implementation still satisfies it — and for the positional form the answer was
    // yes. TypeScript's structural typing accepts an implementation with FEWER parameters, so
    // `findById(id)` satisfied `findById(id: string, tenantId: string)` and ignored the tenant on
    // a clean build; the scoping this port exists to require simply did not bind. The write side
    // was worse: the library called `updatePassword(id, tenantId, hash)`, a stale two-parameter
    // implementation bound `passwordHash = tenantId`, and the tenant id went into the credential
    // column.
    //
    // So this arm compiles a stale implementation against the real port and requires the compiler
    // to REFUSE it. It is the only assertion here that can fail if somebody reverts the shape,
    // because a positional signature looks equally correct in every other check.
    //
    // Written with the real `tsc` rather than a string match on the error, so it measures what a
    // consumer's build measures.
    it('refuses a pre-upgrade implementation', () => {
      // The signatures a consumer had BEFORE the tenant was added — one parameter on `findById`,
      // two on `updatePassword`. Not the intermediate positional shape: that one is refused for
      // the trivial reason that an object is not a string, and pinning it would leave the actual
      // defect — fewer-parameter assignability — undemonstrated.
      const probe = `
        import type { IUserRepository } from '${USER_PORT.replace(/\\/g, '/').replace(/\.ts$/, '')}'
        declare const stale: {
          findById(id: string): Promise<never>
          updatePassword(id: string, passwordHash: string): Promise<void>
        }
        const port: Pick<IUserRepository, 'findById' | 'updatePassword'> = stale
        void port
      `
      expect(compileErrors(probe).length).toBeGreaterThan(0)
    })

    // The hazard itself, pinned so the arm above is legible.
    //
    // TypeScript accepts an implementation declaring FEWER parameters than the signature. That is
    // not a quirk of our port — it is the language rule that made the positional form unsafe, and
    // it is the reason the object shape was chosen rather than a reordering. This arm compiles the
    // same stale implementation against a local copy of the OLD positional signatures and requires
    // it to be ACCEPTED.
    //
    // If TypeScript ever tightened this, the arm goes red and tells the next reader that the
    // justification in `TenantScopedUserRef`'s JSDoc has expired — which is more useful than the
    // arm quietly continuing to pass for a reason nobody would re-derive.
    it('shows why the positional form could not bind: fewer parameters are accepted', () => {
      const probe = `
        interface OldPositionalPort {
          findById(id: string, tenantId: string): Promise<never>
          updatePassword(id: string, tenantId: string, passwordHash: string): Promise<void>
        }
        declare const stale: {
          findById(id: string): Promise<never>
          updatePassword(id: string, passwordHash: string): Promise<void>
        }
        const port: OldPositionalPort = stale
        void port
      `
      expect(compileErrors(probe)).toEqual([])
    })

    // The same probe with the CURRENT shape must compile, or the arm above would pass for the
    // wrong reason — a broken harness, a bad import path, a typo in the probe — and report the
    // port as safe while measuring nothing. A negative test needs its positive twin.
    it('accepts an implementation on the current shape', () => {
      const probe = `
        import type {
          IUserRepository,
          TenantScopedUserRef,
          UpdatePasswordParams
        } from '${USER_PORT.replace(/\\/g, '/').replace(/\.ts$/, '')}'
        declare const fresh: {
          findById(params: TenantScopedUserRef): Promise<never>
          updatePassword(params: UpdatePasswordParams): Promise<void>
        }
        const port: Pick<IUserRepository, 'findById' | 'updatePassword'> = fresh
        void port
      `
      expect(compileErrors(probe)).toEqual([])
    })
  })

  describe("the README's example implementation", () => {
    const example = readReadmeExample(README, 'PrismaUserRepository')

    // Same vacuity guard as above: an example that parsed to nothing would make the comparison
    // below trivially true.
    it('parses an example with methods to compare', () => {
      expect(example.length).toBe(userPort.methods.length)
    })

    // Type-for-type, not merely "has a tenant somewhere". A consumer copies this class and edits
    // the bodies; if a parameter type here disagrees with the port, their edit starts from a shape
    // that does not compile.
    //
    // The parameter NAME is deliberately excluded, and that is a change from when both sides were
    // positional. An implementation destructures — `{ id, tenantId }: TenantScopedUserRef` — while
    // the interface names the whole object `params`. Neither the compiler nor a reader cares, so
    // requiring them to match would fail the example for being written the way an implementation
    // is actually written. The type is what has to agree, because the type is what is checked.
    it('declares the same parameter types as the port', () => {
      const types = (method: PortMethod): string => method.params.map((p) => p.type).join(', ')
      const port = new Map(userPort.methods.map((method) => [method.name, types(method)]))
      const drifted = example
        .filter((method) => port.get(method.name) !== types(method))
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
