/**
 * @fileoverview Every conformance file is well-formed Unicode: a parser that builds well-formed
 * strings, which the sibling library's does, rejects a lone surrogate escape and loses the whole
 * file.
 *
 * @layer Test
 */

import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

const DIR = join(__dirname, '../../conformance')
const FILES = readdirSync(DIR).filter((name) => name.endsWith('.json'))

/** Whether a string survives a UTF-8 round trip, which a lone surrogate does not. */
function wellFormed(text: string): boolean {
  return Buffer.from(text, 'utf8').toString('utf8') === text
}

/** Every string in a parsed document, keys included, with where it sits. */
function strings(value: unknown, path = '$'): Array<[string, string]> {
  if (typeof value === 'string') return [[path, value]]
  if (typeof value !== 'object' || value === null) return []
  return Object.entries(value).flatMap(([key, child]) => [
    [`${path}.<key ${JSON.stringify(key)}>`, key] as [string, string],
    ...strings(child, `${path}.${key}`)
  ])
}

describe('conformance files', () => {
  it('has files to check', () => {
    expect(FILES).toContain('wire-contract.json')
  })

  it.each(FILES)('%s holds only well-formed Unicode strings', (name) => {
    const document: unknown = JSON.parse(readFileSync(join(DIR, name), 'utf8'))

    const ill = strings(document)
      .filter(([, text]) => !wellFormed(text))
      .map(([where]) => where)

    expect(ill).toEqual([])
  })

  it('tells an ill-formed string from a well-formed one', () => {
    expect(wellFormed('a\ud800b')).toBe(false)
    expect(wellFormed('a😀b')).toBe(true)
  })
})
