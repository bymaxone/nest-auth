/**
 * @fileoverview Tests for `workspaceScopedName` and its inverse: the shared contract's vectors, the
 * property that no two argument lists share a name, and every shape the decoder must refuse.
 *
 * @layer Test
 */

import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import { decodeWorkspaceScopedName, workspaceScopedName } from './workspace-scoped'

interface Vector {
  case: string
  args: string[]
  name?: string
  refused?: string
}

const VECTORS = (
  JSON.parse(readFileSync(join(__dirname, '../../../conformance/wire-contract.json'), 'utf8')) as {
    workspaceScopedName: { vectors: Vector[] }
  }
).workspaceScopedName.vectors

/** A deterministic generator, so a failure reproduces. */
function generator(seed: number): () => number {
  let state = seed
  return () => {
    state = (state + 0x6d2b79f5) | 0
    let t = Math.imul(state ^ (state >>> 15), 1 | state)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

describe('workspaceScopedName', () => {
  describe('the shared contract vectors', () => {
    const built = VECTORS.filter((v) => v.name !== undefined)
    const refused = VECTORS.filter((v) => v.refused !== undefined)

    it.each(built.map((v) => [v.case, v] as const))('builds %s', (_name, vector) => {
      const [tenantId = '', workspaceId = '', ...parts] = vector.args

      expect(workspaceScopedName(tenantId, workspaceId, ...parts)).toBe(vector.name)
    })

    it.each(built.map((v) => [v.case, v] as const))('reads %s back', (_name, vector) => {
      const [tenantId = '', workspaceId = '', ...parts] = vector.args

      expect(decodeWorkspaceScopedName(vector.name ?? '')).toEqual({ tenantId, workspaceId, parts })
    })

    it.each(refused.map((v) => [v.case, v] as const))('refuses %s', (_name, vector) => {
      const [tenantId = '', workspaceId = '', ...parts] = vector.args

      expect(() => workspaceScopedName(tenantId, workspaceId, ...parts)).toThrow(TypeError)
    })

    it('has one vector for every kind of refusal the contract names', () => {
      expect(new Set(refused.map((v) => v.refused))).toEqual(
        new Set(['control character', 'empty tenant', 'empty workspace', 'unpaired surrogate'])
      )
    })
  })

  describe('refusals', () => {
    it.each([
      ['a part that is not a string', () => workspaceScopedName('t', 'w', 5 as never)],
      ['a tenant that is not a string', () => workspaceScopedName(undefined as never, 'w')],
      ['a C0 control in the workspace', () => workspaceScopedName('t', 'w\u0001')],
      ['the last C0 control, U+001F', () => workspaceScopedName('t', 'w', 'a\u001fb')],
      ['a lone low surrogate', () => workspaceScopedName('t', 'w', '\udc00')]
    ])('refuses %s', (_name, build) => {
      expect(build).toThrow(TypeError)
    })

    it('accepts a space, the first character after the C0 controls', () => {
      expect(workspaceScopedName('t', 'w', 'a b')).toBe('1:t1:w3:a b')
    })

    it('says what is wrong with a piece that is not a string', () => {
      expect(() => workspaceScopedName('t', 'w', 5 as never)).toThrow('part 0 must be a string')
      expect(() => workspaceScopedName(undefined as never, 'w')).toThrow(
        'tenantId must be a string'
      )
    })

    it('names the piece it refused', () => {
      expect(() => workspaceScopedName('t', 'w', 'ok', 'a\tb')).toThrow('part 1 must not contain')
      expect(() => workspaceScopedName('', 'w')).toThrow('tenantId must not be empty')
    })
  })

  it('reads the replacement character when it was written, and refuses a surrogate that merely decodes to it', () => {
    expect(decodeWorkspaceScopedName('1:a1:b3:\ufffd').parts).toEqual(['\ufffd'])
    expect(() => decodeWorkspaceScopedName('1:a1:b3:\ud800')).toThrow(TypeError)
  })

  describe('as an injective encoding', () => {
    // Every list is spelled from the pieces that break joined-string names, so a collision, if one
    // existed, would be found among a small space drawn many times over.
    it('reads back what was built, and two different lists never share a name', () => {
      const next = generator(20261111)
      const pieces = ['a', 'b', ':', '1', '2:', '/', 'é', '😀', '', '0:', '::']
      const text = (): string =>
        Array.from(
          { length: Math.floor(next() * 3) },
          () => pieces[Math.floor(next() * pieces.length)]
        ).join('')
      const seen = new Map<string, string>()
      const failures: string[] = []
      for (let i = 0; i < 20000; i++) {
        const args = [
          `t${text()}`,
          `w${text()}`,
          ...Array.from({ length: Math.floor(next() * 4) }, text)
        ]
        const [tenantId = '', workspaceId = '', ...parts] = args
        const name = workspaceScopedName(tenantId, workspaceId, ...parts)
        const canonical = JSON.stringify(args)
        if (
          JSON.stringify(Object.values(decodeWorkspaceScopedName(name))) !==
          JSON.stringify([tenantId, workspaceId, parts])
        ) {
          failures.push(`round trip: ${canonical}`)
        }
        if (seen.has(name) && seen.get(name) !== canonical) failures.push(`collision: ${canonical}`)
        seen.set(name, canonical)
      }

      expect(failures).toEqual([])
      expect(seen.size).toBeGreaterThan(5000)
    })

    it("keeps two workspaces of one tenant apart even when an id spells the other's name", () => {
      const first = workspaceScopedName('t', 'w1', 'x')
      const second = workspaceScopedName('t', 'w', '1', 'x')

      expect(first).not.toBe(second)
    })
  })

  describe('decodeWorkspaceScopedName refuses what the builder cannot have written', () => {
    it.each([
      ['an empty name', ''],
      ['one piece only', '1:a'],
      ['text with no length', 'abc'],
      ['a length with a leading zero', '01:a1:b'],
      ['a length that runs past the end', '1:a5:b'],
      ['text after the last piece', '1:a1:bx'],
      ['a length that is not a number', 'x:a1:b'],
      ['a length that cuts a character in two', '1:é1:b'],
      ['a control character in a piece', '1:a2:b\u0001'],
      ['an empty tenant', '0:1:b'],
      ['an empty workspace', '1:a0:'],
      [
        'an unpaired surrogate, which a buffer would read as the replacement character',
        '1:a1:b1:\ud800'
      ]
    ])('refuses %s', (_name, name) => {
      expect(() => decodeWorkspaceScopedName(name)).toThrow(TypeError)
    })
  })
})
