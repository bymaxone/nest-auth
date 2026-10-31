/**
 * @fileoverview Every request header the server sources read is named in `LIBRARY_READ_HEADERS`.
 *
 * `apiKeys.header` is refused when it names a header the library reads, so the list has to be
 * complete. A grep cannot tell a header read from a mention in a comment; walking the syntax tree
 * can, and a read added later without being listed fails here instead of being discovered when a
 * key ends up in a place built for something else.
 *
 * This is an end-to-end spec, beside the log-injection walker, and not a unit spec, on purpose:
 * it parses the TEXT of `src/`. Under mutation testing the unit run executes against instrumented
 * copies of those files, where every string literal is wrapped in a mutant switch, so a walker
 * looking for `headers['x']` finds almost nothing and the dry run fails. The end-to-end config is
 * never run by Stryker. Any spec that reads source text belongs here for the same reason.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'

import ts from 'typescript'

import { LIBRARY_READ_HEADERS } from '../../src/server/constants/request-headers'

/** The lowercase header names a source file reads through `<something>.headers[...]` or `.headers.x`. */
function headerReads(file: string, source: string): string[] {
  const tree = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true)
  const found = new Set<string>()
  const isHeadersBag = (node: ts.Expression): boolean =>
    (ts.isPropertyAccessExpression(node) && node.name.text === 'headers') ||
    (ts.isIdentifier(node) && node.text === 'headers')
  const visit = (node: ts.Node): void => {
    if (
      ts.isElementAccessExpression(node) &&
      isHeadersBag(node.expression) &&
      ts.isStringLiteralLike(node.argumentExpression)
    ) {
      found.add(node.argumentExpression.text.toLowerCase())
    }
    if (ts.isPropertyAccessExpression(node) && isHeadersBag(node.expression)) {
      found.add(node.name.text.toLowerCase())
    }
    ts.forEachChild(node, visit)
  }
  visit(tree)
  return [...found]
}

/** Every `.ts` source under `dir` that is not a spec. */
function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return sources(path)
    return path.endsWith('.ts') && !path.endsWith('.spec.ts') ? [path] : []
  })
}

/** The header reads in `source` that `listed` does not name. */
function unlistedReads(file: string, source: string, listed: ReadonlySet<string>): string[] {
  return headerReads(file, source).filter((name) => !listed.has(name))
}

describe('request headers the server reads (E2E)', () => {
  const listed = new Set(LIBRARY_READ_HEADERS)
  const root = join(__dirname, '../../src/server')

  // The walker has to see the reads it exists to list, or an empty result proves nothing.
  it('finds the reads it is meant to find', () => {
    const names = new Set(sources(root).flatMap((f) => headerReads(f, readFileSync(f, 'utf8'))))
    for (const known of ['user-agent', 'authorization', 'origin', 'sec-fetch-site']) {
      expect(names).toContain(known)
    }
  })

  // The invariant: nothing the sources read is missing from the list a key header is checked
  // against.
  it('lists every header a source file reads', () => {
    const missing = sources(root).flatMap((file) =>
      unlistedReads(file, readFileSync(file, 'utf8'), listed).map((name) => `${file}: ${name}`)
    )
    expect(missing).toEqual([])
  })

  // The plant: a new read that the constant does not name is reported, whatever form it takes, and
  // a mention in a comment is not. Without this, the invariant above could pass for a walker that
  // reports nothing.
  it('reports a planted read the constant omits and ignores a comment', () => {
    const planted = [
      "// headers['x-in-comment']",
      "const a = req.headers['X-Planted-Element']",
      'const b = request.headers.xplantedproperty',
      "const c = headers['authorization']"
    ].join('\n')
    expect(unlistedReads('planted.ts', planted, listed).sort()).toEqual([
      'x-planted-element',
      'xplantedproperty'
    ])
  })
})
