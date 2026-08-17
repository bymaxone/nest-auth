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

/** The scheme table's header cell, which is how it is found rather than by line number. */
const TABLE_HEADER = 'what the document says'

/** The README, read once. */
const README = readFileSync(join(__dirname, '../../README.md'), 'utf8')

/**
 * The subpaths a manifest publishes, as a consumer would write them.
 *
 * Narrowed rather than cast. `JSON.parse` answers `any`, and asserting the shape onto it would
 * turn a manifest without an `exports` map into `Object.keys(undefined)` — a `TypeError` from
 * inside a helper, at a point that says nothing about what is wrong. A manifest that cannot be
 * read is a real failure of this suite's subject, so it says so.
 *
 * @param file - Absolute path to `package.json`.
 * @returns Each export key rewritten from `.`-relative form to the specifier a consumer imports.
 * @throws {@link Error} when the manifest declares no `exports` map.
 */
function publishedSubpaths(file: string): string[] {
  const manifest: unknown = JSON.parse(readFileSync(file, 'utf8'))
  const exports =
    typeof manifest === 'object' && manifest !== null
      ? (manifest as { exports?: unknown }).exports
      : undefined

  if (typeof exports !== 'object' || exports === null) {
    throw new Error(`${file} declares no exports map`)
  }

  return Object.keys(exports).map((subpath) => subpath.replace(/^\./, '@bymax-one/nest-auth'))
}

/**
 * The subpaths this package actually publishes, from the manifest.
 *
 * {@link BARRELS} cannot answer this: it is a hand-kept map from subpath to source file, so it
 * agrees with `package.json#exports` only for as long as somebody keeps both in step. Dropping
 * `./react` from the exports map would leave every README import of it passing, which is the
 * drift this arm exists to catch — the manifest is the only thing a consumer's resolver reads.
 */
const PUBLISHED: ReadonlySet<string> = new Set(
  publishedSubpaths(join(__dirname, '../../package.json'))
)

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

/**
 * The rows of the scheme table, and nothing else in the document.
 *
 * The completeness check below used to search the WHOLE README, which cannot fail for the
 * regression it names: every scheme is repeated in the "four names" paragraph directly under the
 * table and again in the guard documentation, so deleting the `controllers.platform` row left
 * `bymaxPlatformAccessBearer` present three more times and the arm green. The table lost that row
 * twice before anything noticed — by a check that was already running.
 *
 * Located by content rather than by line number: the table is the one whose header names what the
 * document says, and anchoring on a line number would make the arm silently inspect prose the
 * first time a paragraph above it grew.
 *
 * @param readme - The document.
 * @returns The table's body rows joined, or `''` when the table is not found — which the caller
 *   fails on rather than reading as "no schemes missing".
 */
function schemeTable(readme: string): string {
  // Original line boundaries, NOT a pre-filtered list of table rows. Filtering first discards the
  // blank line that ends a Markdown table, which leaves the loop no way to tell where this table
  // stops — it would return this table concatenated with every later one, and the README has two
  // (the DTO refusals table and the client-method table). A scheme name appearing in either would
  // then let a deleted row here pass, which is the same too-wide subject this arm was fixed for.
  const lines = readme.split('\n').map((line) => line.trimEnd())

  const header = lines.findIndex((line) => line.startsWith('|') && line.includes(TABLE_HEADER))
  if (header === -1) return ''

  // Header, separator, then rows until the first line that is not a table row.
  const body: string[] = []
  for (const line of lines.slice(header + 2)) {
    if (!line.startsWith('|')) break
    body.push(line)
  }

  return body.join('\n')
}

describe('README contract (E2E)', () => {
  // Every subpath the README imports from is one this package actually publishes. A typo here
  // sends a reader to a path that does not resolve, which no amount of correct symbol names fixes.
  //
  // Checked against `package.json#exports` rather than against `BARRELS`. The first version asked
  // the hand-kept map, which answers "is this a subpath this suite knows a source file for" — a
  // different question, and one that stays green when the manifest drops the subpath entirely.
  it('imports only from subpaths this package publishes', () => {
    const unknown = [...documentedImports().keys()].filter((sub) => !PUBLISHED.has(sub))

    expect(unknown).toEqual([])
  })

  // `BARRELS` feeds the export arms below, so a published subpath it does not know about would be
  // skipped there in silence — `barrel === undefined` continues rather than fails. Pinning the two
  // lists against each other is what keeps that skip from being invisible.
  it('knows a source barrel for every published subpath', () => {
    const unmapped = [...PUBLISHED]
      .filter((subpath) => subpath !== '@bymax-one/nest-auth/package.json')
      .filter((subpath) => BARRELS[subpath] === undefined)

    expect(unmapped).toEqual([])
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
  it('names every security scheme in the table, and invents none anywhere', () => {
    const declared = Object.values(AUTH_SECURITY_SCHEMES)
    const table = schemeTable(README)

    // The table must be found. An empty one would make the next assertion pass by naming nothing.
    expect(table).not.toBe('')

    // Completeness is asked of the TABLE, because that is the passage whose job is to be complete.
    const missingFromTable = declared.filter((name) => !table.includes(name))

    expect(missingFromTable).toEqual([])

    // Invention is asked of the whole document, and deliberately: a scheme name the prose made up
    // sends a reader to write a literal that matches nothing, wherever the sentence sits.
    //
    // The candidate pattern must NOT require the spellings it is hunting for. An earlier version
    // read `bymax[A-Za-z]*(?:Auth|Platform)[A-Za-z]*`, so `bymaxAythAccessCookie` — a transposed
    // letter, the single likeliest way this goes wrong — did not match, was never a candidate,
    // and passed. Any backticked `bymax`-prefixed identifier is a candidate now; the four real
    // scheme names are the only ones the README carries, so nothing else is swept up.
    const invented = [...README.matchAll(/`(bymax[A-Za-z]+)`/g)]
      .map((m) => m[1])
      .filter((name): name is string => name !== undefined)
      .filter((name) => !declared.includes(name as (typeof declared)[number]))

    expect([...new Set(invented)]).toEqual([])
  })
})
