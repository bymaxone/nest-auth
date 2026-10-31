/**
 * @fileoverview Every request header the server sources read is named in `LIBRARY_READ_HEADERS`.
 *
 * `apiKeys.header` is refused when it names a header the library reads, so the list has to be
 * complete. A grep cannot tell a header read from a mention in a comment; walking the syntax tree
 * can, and a read added later without being listed fails here instead of being discovered when a
 * key ends up in a place built for something else.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'

import ts from 'typescript'

import { LIBRARY_READ_HEADERS } from './constants/request-headers'

/** The lowercase header names a source file reads through `<something>.headers[...]` or `.headers.x`. */
export function headerReads(file: string, source: string): string[] {
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

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return sources(path)
    return path.endsWith('.ts') && !path.endsWith('.spec.ts') ? [path] : []
  })
}

describe('request headers the server reads', () => {
  const reads = sources(__dirname).flatMap((file) =>
    headerReads(file, readFileSync(file, 'utf8')).map((name) => ({ file, name }))
  )

  // The walker has to see the reads it exists to list, or an empty result proves nothing.
  it('finds the reads it is meant to find', () => {
    const names = new Set(reads.map((r) => r.name))
    for (const known of ['user-agent', 'authorization', 'origin', 'sec-fetch-site']) {
      expect(names).toContain(known)
    }
  })

  // The invariant: nothing the sources read is missing from the list a key header is checked
  // against.
  it('lists every header a source file reads', () => {
    const listed = new Set(LIBRARY_READ_HEADERS)
    expect(reads.filter((r) => !listed.has(r.name))).toEqual([])
  })

  // The walker itself: it reports a header read in a snippet and ignores a mention.
  it('reports a planted read and ignores a comment', () => {
    const source = `// headers['x-planted-in-comment']\nconst a = req.headers['X-Planted']\nconst b = headers.accept`
    expect(headerReads('planted.ts', source).sort()).toEqual(['accept', 'x-planted'])
  })

  // The list is pinned by name, so dropping a header from it is a decision made in a test edit and
  // never a quiet deletion: the table-driven option specs would follow the constant down.
  it('names exactly the headers the library reads or derives a field from', () => {
    expect([...LIBRARY_READ_HEADERS]).toEqual([
      'authorization',
      'proxy-authorization',
      'cookie',
      'set-cookie',
      'user-agent',
      'origin',
      'sec-fetch-site',
      'x-forwarded-for',
      'x-forwarded-host',
      'x-real-ip',
      'x-original-forwarded-for'
    ])
  })

  // The list is lowercase and free of duplicates, because it is compared against lowercased input.
  it('is lowercase and unique', () => {
    expect(LIBRARY_READ_HEADERS.map((h) => h.toLowerCase())).toEqual([...LIBRARY_READ_HEADERS])
    expect(new Set(LIBRARY_READ_HEADERS).size).toBe(LIBRARY_READ_HEADERS.length)
  })
})
