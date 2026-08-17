/**
 * @fileoverview Fails when the README claims something about this package's own surface that the
 * package does not answer.
 *
 * The README is the first thing a consumer reads and the only part of this repository nothing
 * compiles. Two claims drifted in one session, and neither was caught by a test:
 *
 * - `AUTH_SECURITY_SCHEMES` was declared but never re-exported, so the README told a platform-only
 *   deployment to write `bymaxAuthAccessCookie` as a bare string literal — in a section whose whole
 *   subject is that literals drift from configuration.
 * - `AUTH_ERROR_STATUS` shipped only from the server entry while the README invited a typed client,
 *   an API document and a frontend test to use it — the three cases that must not pull the NestJS
 *   peer dependencies — one paragraph after correctly saying `AUTH_ERROR_CODES` comes from
 *   `/shared`.
 *
 * Both were *prose* contradicting a passing suite, which is the failure mode a coverage number
 * cannot see: the code was right, the tests were right, and the page a consumer reads was wrong.
 * The same shape as the mutation-plan contract and the Stryker config contract — a document is
 * either derived from the thing it describes or it is a second copy that drifts.
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import ts from 'typescript'

import { AUTH_SECURITY_SCHEMES } from '../../src/server/openapi/auth-openapi-fragment'

/**
 * Recorded when a barrel uses `export * from`, which names nothing this suite can collect.
 *
 * Not a name a barrel could export — so it can only appear because a star export did.
 */
const STAR_EXPORT_MARKER = '*'

/** The README, read once. */
const README = readFileSync(join(__dirname, '../../README.md'), 'utf8')

/** Where each documented subpath's public surface actually comes from. */
const BARRELS: Readonly<Record<string, string>> = {
  '@bymax-one/nest-auth': '../../src/server/index.ts',
  '@bymax-one/nest-auth/shared': '../../src/shared/index.ts',
  '@bymax-one/nest-auth/client': '../../src/client/index.ts',
  '@bymax-one/nest-auth/react': '../../src/react/index.ts',
  '@bymax-one/nest-auth/nextjs': '../../src/nextjs/index.ts'
}

/**
 * Every `import { … } from '@bymax-one/nest-auth…'` the README shows, by subpath.
 *
 * An import statement is the unambiguous form of the claim: prose can hedge, an import cannot.
 * A reader copies it verbatim, so a name that is not there is a broken build on their side and a
 * green suite on ours.
 *
 * @returns Each documented subpath mapped to the symbol names the README imports from it.
 */
function documentedImports(): Map<string, Set<string>> {
  const found = new Map<string, Set<string>>()
  const pattern = /import\s+(?:type\s+)?\{([^}]*)\}\s+from\s+'(@bymax-one\/nest-auth[^']*)'/g

  for (const match of README.matchAll(pattern)) {
    const [, names, subpath] = match
    if (names === undefined || subpath === undefined) continue
    const set = found.get(subpath) ?? new Set<string>()
    for (const raw of names.split(',')) {
      const name = raw.trim().replace(/^type\s+/, '')
      if (name !== '') set.add(name)
    }
    found.set(subpath, set)
  }

  return found
}

/**
 * Every name a barrel actually exports, read from its export declarations.
 *
 * The first version of this searched the barrel's SOURCE TEXT for the identifier, which is not a
 * check: a name mentioned in a comment, in a JSDoc paragraph, or in an internal import satisfies
 * it without being exported. `src/client/index.ts` carries the sharpest instance — a comment
 * reading _"Constants like `AUTH_ERROR_CODES` and `AUTH_ROUTES` stay [in shared]"_, so a README
 * that documented importing either FROM `/client` would have passed on the strength of the very
 * sentence saying it does not export them. Across the five barrels, 77 capitalised tokens appear
 * in text without being exports.
 *
 * Reading the declarations instead means the test fails when an export is deleted, and keeps
 * failing however much prose still names it. Every barrel here uses named clauses
 * (`export { X } from`, `export type { X } from`) or direct declarations — none uses `export *`,
 * which would need following into the re-exported module; that is asserted below rather than
 * assumed, because a future `export *` would silently shrink what this sees.
 *
 * @param file - Absolute path to the barrel.
 * @returns The exported names, type-only exports included — a consumer importing a type gets the
 *   same failure from a missing one.
 */
function barrelExports(file: string): Set<string> {
  const source = ts.createSourceFile(file, readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true)
  const names = new Set<string>()

  for (const statement of source.statements) {
    if (ts.isExportDeclaration(statement)) {
      // `export * from './x'` — nothing named to collect, and following it is out of scope here.
      // The suite asserts none exists rather than quietly under-reporting.
      if (statement.exportClause === undefined) {
        names.add(STAR_EXPORT_MARKER)
        continue
      }
      if (ts.isNamedExports(statement.exportClause)) {
        for (const element of statement.exportClause.elements) names.add(element.name.text)
      }
      continue
    }

    // `export const X`, `export class X`, `export function X`, `export type X`, `export interface X`
    const modifiers = ts.canHaveModifiers(statement) ? ts.getModifiers(statement) : undefined
    if (!modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword)) continue

    if (ts.isVariableStatement(statement)) {
      for (const declaration of statement.declarationList.declarations) {
        names.add(declaration.name.getText(source))
      }
    } else if (
      (ts.isClassDeclaration(statement) ||
        ts.isFunctionDeclaration(statement) ||
        ts.isInterfaceDeclaration(statement) ||
        ts.isTypeAliasDeclaration(statement) ||
        ts.isEnumDeclaration(statement)) &&
      statement.name
    ) {
      names.add(statement.name.text)
    }
  }

  return names
}

/**
 * Collapses a Markdown passage to one line, so a claim survives being rewrapped.
 *
 * Prettier reflows this README on every commit, which moves the line break inside any sentence
 * long enough to matter. A pattern anchored to the original wrapping would stop matching the day
 * a neighbouring word changed length — silently, and in the direction of passing.
 *
 * Blockquote markers go too: the paragraph this exists for lives inside a `>` block, where the
 * continuation line begins `> ` and would otherwise sit in the middle of the flattened sentence.
 *
 * @param markdown - The document, or any part of it.
 * @returns The same text with every run of whitespace and blockquote marker reduced to one space.
 */
function flatten(markdown: string): string {
  return markdown.replace(/\s*\n\s*>?\s*/g, ' ')
}

describe('README contract (E2E)', () => {
  // Every subpath the README imports from is one this package actually publishes. A typo here
  // sends a reader to a path that does not resolve, which no amount of correct symbol names fixes.
  it('imports only from subpaths this package publishes', () => {
    const unknown = [...documentedImports().keys()].filter((sub) => BARRELS[sub] === undefined)

    expect(unknown).toEqual([])
  })

  // The claim itself: every symbol the README tells a consumer to import IS exported from the
  // barrel it names. This is what would have caught `AUTH_ERROR_STATUS` had the README shown the
  // import rather than describing it in prose.
  it('imports only symbols the named barrel exports', () => {
    const broken: string[] = []

    for (const [subpath, names] of documentedImports()) {
      const barrel = BARRELS[subpath]
      if (barrel === undefined) continue
      const exported = barrelExports(join(__dirname, barrel))
      for (const name of names) {
        if (!exported.has(name)) broken.push(`${subpath}: ${name}`)
      }
    }

    expect(broken).toEqual([])
  })

  // `export *` would make the arm above under-report — it names nothing, so every symbol behind
  // it would read as missing (a false failure) or, if this suite were made lenient, as present
  // (a false pass). Neither is acceptable, so the shape itself is what is pinned: if a barrel
  // ever needs one, this test is the prompt to teach `barrelExports` to follow it.
  it('uses no star export in any barrel', () => {
    const starring = Object.entries(BARRELS)
      .filter(([, barrel]) => barrelExports(join(__dirname, barrel)).has(STAR_EXPORT_MARKER))
      .map(([subpath]) => subpath)

    expect(starring).toEqual([])
  })

  // A README may say a symbol is not public. That claim is checkable against the same barrels the
  // arm above reads, and it needs to be: this file's own subject shipped an export of
  // `AUTH_SECURITY_SCHEMES` while a paragraph four hundred lines away still told consumers it was
  // not public and to write the names as string literals. Two opposite instructions in one
  // document, and the export made the wrong one wrong rather than merely dated.
  //
  // Matched against the FLATTENED README, not the file. Prettier rewraps prose on every commit, so
  // a claim reads `` `X` is not part of the public\n> API `` as often as it reads on one line — a
  // pattern that stops at a newline would be defeated by reformatting alone, which is the kind of
  // gate that looks green because it went blind. Every barrel is checked, not just the entry:
  // nothing makes the server barrel the only one a stale claim can outlive.
  it('calls nothing unexported that a barrel exports', () => {
    const exported = new Set(
      Object.values(BARRELS).flatMap((barrel) => [...barrelExports(join(__dirname, barrel))])
    )
    const claimedPrivate = [
      ...flatten(README).matchAll(/`([A-Za-z_][A-Za-z0-9_]*)`[^.]{0,80}?is not part of the public/g)
    ]
      .map((match) => match[1])
      .filter((name): name is string => name !== undefined)
      .filter((name) => exported.has(name))

    expect([...new Set(claimedPrivate)]).toEqual([])
  })

  // The scheme-set table names four schemes as stable identifiers a generated client depends on.
  // They are values of `AUTH_SECURITY_SCHEMES`, so the table and the constant are two copies of
  // one list — and the table lost the platform-only row twice before anything noticed. Asserted
  // in both directions: a scheme absent from the prose is as wrong as a name the prose invented.
  it('names every security scheme, and invents none', () => {
    const declared = Object.values(AUTH_SECURITY_SCHEMES)
    const missingFromReadme = declared.filter((name) => !README.includes(name))

    expect(missingFromReadme).toEqual([])

    const invented = [...README.matchAll(/`(bymax[A-Za-z]*(?:Auth|Platform)[A-Za-z]*)`/g)]
      .map((m) => m[1])
      .filter((name): name is string => name !== undefined)
      .filter((name) => !declared.includes(name as (typeof declared)[number]))

    expect([...new Set(invented)]).toEqual([])
  })
})
