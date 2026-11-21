/**
 * @fileoverview The README names what the server entry exports and the options it reads: every export, every
 * option and every closed value of a log discriminator appears in a code span, and the reference table lists
 * nothing that is no longer exported.
 *
 * It reads the sources and the README with the TypeScript compiler and imports nothing under `src` at run time,
 * so the mutation run has no use for it.
 *
 * @layer Test
 */

import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import * as ts from 'typescript'

const ROOT = join(__dirname, '../..')
const README = readFileSync(join(ROOT, 'README.md'), 'utf8')

/** Whether the README text holds the name as a whole word inside a code span. */
function mentions(readme: string, name: string): boolean {
  const escaped = name.replace(/[$()*+.?[\\\]^{|}-]/g, '\\$&')
  return new RegExp('`[^`\\n]*(?<![\\w$])' + escaped + '(?![\\w$])[^`\\n]*`').test(readme)
}

/** The names of a list that the README does not mention. */
function unmentioned(readme: string, names: readonly string[]): string[] {
  return names.filter((name) => !mentions(readme, name))
}

/** Every name the server entry exports, by name only. */
function serverExports(): string[] {
  const file = join(ROOT, 'src/server/index.ts')
  const source = ts.createSourceFile(file, readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true)
  const names = new Set<string>()
  for (const statement of source.statements) {
    if (ts.isExportDeclaration(statement)) {
      if (statement.exportClause === undefined)
        throw new Error('export * is not supported by this spec')
      if (ts.isNamedExports(statement.exportClause)) {
        for (const element of statement.exportClause.elements) names.add(element.name.text)
      }
    } else if (
      (ts.isVariableStatement(statement) ||
        ts.isFunctionDeclaration(statement) ||
        ts.isClassDeclaration(statement)) &&
      statement.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword) ===
        true
    ) {
      if (ts.isVariableStatement(statement)) {
        for (const declaration of statement.declarationList.declarations)
          names.add(declaration.name.getText(source))
      } else if (statement.name !== undefined) names.add(statement.name.text)
    }
  }
  return [...names]
}

/** A compiler program over the files whose types this spec reads. */
function programOf(files: string[]): ts.Program {
  return ts.createProgram(
    files.map((file) => join(ROOT, file)),
    {
      strict: true,
      target: ts.ScriptTarget.ES2022,
      module: ts.ModuleKind.CommonJS,
      skipLibCheck: true,
      moduleResolution: ts.ModuleResolutionKind.Node10,
      experimentalDecorators: true,
      emitDecoratorMetadata: true
    }
  )
}

/** The option names of the module options: every property declared in this package, at any depth. */
function optionNames(): string[] {
  const file = join(ROOT, 'src/server/interfaces/auth-module-options.interface.ts')
  const program = programOf(['src/server/interfaces/auth-module-options.interface.ts'])
  const checker = program.getTypeChecker()
  const source = program.getSourceFile(file)
  const names = new Set<string>()
  const seen = new Set<ts.Type>()
  const walk = (type: ts.Type): void => {
    if (seen.has(type)) return
    seen.add(type)
    for (const property of checker.getPropertiesOfType(type)) {
      const declaration = property.valueDeclaration
      if (
        declaration === undefined ||
        !declaration.getSourceFile().fileName.includes('/src/server/')
      )
        continue
      names.add(property.name)
      const inner = checker.getNonNullableType(
        checker.getTypeOfSymbolAtLocation(property, declaration)
      )
      walk(inner)
      if (inner.isUnion()) inner.types.forEach(walk)
    }
  }
  source?.forEachChild((node) => {
    if (ts.isInterfaceDeclaration(node) && node.name.text === 'BymaxAuthModuleOptions')
      walk(checker.getTypeAtLocation(node.name))
  })
  return [...names]
}

/** The string members of the closed unions the log helpers use for their discriminators. */
function discriminators(): Record<string, string[]> {
  const file = join(ROOT, 'src/server/observability/log-event.ts')
  const program = programOf(['src/server/observability/log-event.ts'])
  const checker = program.getTypeChecker()
  const found: Record<string, string[]> = {}
  program.getSourceFile(file)?.forEachChild((node) => {
    if (
      !ts.isTypeAliasDeclaration(node) ||
      !['HookStep', 'StoreOperation', 'DeliveryKind'].includes(node.name.text)
    )
      return
    const values: string[] = []
    const visit = (type: ts.Type): void => {
      if (type.isUnion()) type.types.forEach(visit)
      else if (type.isStringLiteral()) values.push(type.value)
    }
    visit(checker.getTypeAtLocation(node.name))
    found[node.name.text] = values
  })
  return found
}

/** The part of the README between a heading and the next heading of the same or a higher level. */
function section(readme: string, heading: string): string {
  const start = readme.indexOf(heading)
  if (start === -1) return ''
  const level = heading.match(/^#+/)?.[0].length ?? 1
  const rest = readme.slice(start + heading.length)
  const next = rest.search(new RegExp(`\\n#{1,${level}} `))
  return next === -1 ? rest : rest.slice(0, next)
}

/** The names a README section lists in code spans. */
function listed(text: string): string[] {
  return [...text.matchAll(/`([A-Za-z_$][\w$]*)`/g)].map((match) => match[1] as string)
}

describe('the README against the server entry', () => {
  jest.setTimeout(120_000)

  // Scenario: every export of src/server/index.ts. Expected: each is named in a code span of the README. Why: a
  // host cannot find what the documentation never names, and the README is where an export is first looked for.
  it('names every export of the server entry', () => {
    const names = serverExports()

    expect(names.length).toBeGreaterThan(200)
    expect(unmentioned(README, names)).toEqual([])
  })

  // Scenario: the reference table of the exports the other sections do not describe. Expected: every name in it is
  // still exported. Why: a name left behind after a removal documents something that no longer exists.
  it('lists nothing in the reference table that the server entry no longer exports', () => {
    const exported = new Set(serverExports())
    const table = section(README, '### Every other server export')

    expect(listed(table).length).toBeGreaterThan(100)
    expect(listed(table).filter((name) => !exported.has(name))).toEqual([])
  })

  // Scenario: every option of the module options, at any depth. Expected: each name is in a code span. Why: an
  // option the README never names is one a host finds only by reading the types.
  it('names every option of the module options', () => {
    const names = optionNames()

    expect(names.length).toBeGreaterThan(100)
    expect(unmentioned(README, names)).toEqual([])
  })

  // Scenario: the closed values of the log discriminators. Expected: the Log events section names each, and names
  // nothing the types no longer hold. Why: an operator filtering on `operation` or `hook` learns the set there.
  it('lists the discriminators of the log events both ways', () => {
    const text = section(README, '#### Discriminators')
    const sets = discriminators()

    expect(Object.keys(sets).sort()).toEqual(['DeliveryKind', 'HookStep', 'StoreOperation'])
    for (const values of Object.values(sets)) expect(unmentioned(text, values)).toEqual([])
    const known = new Set(Object.values(sets).flat())
    expect(
      listed(text).filter(
        (name) =>
          !known.has(name) &&
          ![
            'hook',
            'operation',
            'kind',
            'AUTH_HOOK_FAILED',
            'AUTH_STORE_FAILED',
            'AUTH_STORE_DEGRADED',
            'AUTH_DELIVERY_FAILED'
          ].includes(name)
      )
    ).toEqual([])
  })

  // The rule has to be able to fail: a missing name is reported, a name that is only part of a longer identifier or
  // is outside a code span is not a mention, and a name in a span among other text is.
  it.each([
    ['`Alpha`, `Beta`', 'Beta', true],
    ['`Alpha`', 'Beta', false],
    ['`AlphaBeta`', 'Beta', false],
    ['Beta is described in prose', 'Beta', false],
    ['`jwt.accessExpiresIn`', 'accessExpiresIn', true],
    ['`a$b`', 'a', false]
  ])('judges %s for %s as mentioned: %s', (readme, name, expected) => {
    expect(mentions(readme, name)).toBe(expected)
  })
})
