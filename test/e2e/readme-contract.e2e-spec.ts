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

import { AUTH_SECURITY_SCHEMES } from '../../src/server/openapi/auth-openapi-fragment'

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
      const source = readFileSync(join(__dirname, barrel), 'utf8')
      for (const name of names) {
        if (!new RegExp(`\\b${name}\\b`).test(source)) broken.push(`${subpath}: ${name}`)
      }
    }

    expect(broken).toEqual([])
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
