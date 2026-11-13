/**
 * @fileoverview Tests for the workspace cursor codec: the key builder's exact bytes, the round trip,
 * every input a cursor must read as none, the longest cursor a valid listing can issue, and a seeded
 * fuzz over what a caller can send.
 *
 * @layer Test
 */

import {
  WORKSPACE_CURSOR_MAX_LENGTH,
  WORKSPACE_CURSOR_PART_MAX_LENGTH,
  WORKSPACE_OWNER_ROLE_MAX_LENGTH,
  decodeWorkspaceCursor,
  encodeWorkspaceCursor,
  isWorkspaceOwnerRole,
  readWorkspacePosition,
  workspacePositionOf,
  workspaceQueryKey
} from './workspace-cursor'

const AT = new Date('2026-11-13T12:00:00.000Z')
const POSITION = workspacePositionOf(AT, '9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d')
const QUERY = workspaceQueryKey('listForUser', 'acme', 'u1')

/**
 * Cursors in the pair format, base64url of the JSON of `[query, position]`, written by an encoder
 * independent of this codec: each must decode to its position and re-encode to identical bytes.
 */
const PAIR_FORMAT_CURSORS = [
  {
    parts: ['listForUser', 'default', '3f1c2a9e-1b2c-4d5e-8f90-0123456789ab'],
    id: '9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d',
    cursor:
      'WyJbXCJsaXN0Rm9yVXNlclwiLFwiZGVmYXVsdFwiLFwiM2YxYzJhOWUtMWIyYy00ZDVlLThmOTAtMDEyMzQ1Njc4OWFiXCJdIiwiMjAyNi0xMS0xM1QxMjowMDowMC4wMDBaOWE4YjdjNmQtNWU0Zi00YTNiLThjMmQtMWUwZjlhOGI3YzZkIl0'
  },
  {
    parts: ['listForWorkspace', 'acme', '9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d'],
    id: '3f1c2a9e-1b2c-4d5e-8f90-0123456789ab',
    cursor:
      'WyJbXCJsaXN0Rm9yV29ya3NwYWNlXCIsXCJhY21lXCIsXCI5YThiN2M2ZC01ZTRmLTRhM2ItOGMyZC0xZTBmOWE4YjdjNmRcIl0iLCIyMDI2LTExLTEzVDEyOjAwOjAwLjAwMFozZjFjMmE5ZS0xYjJjLTRkNWUtOGY5MC0wMTIzNDU2Nzg5YWIiXQ'
  },
  {
    parts: ['listSoleOwned', 'acme', '3f1c2a9e-1b2c-4d5e-8f90-0123456789ab', 'owner'],
    id: '9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d',
    cursor:
      'WyJbXCJsaXN0U29sZU93bmVkXCIsXCJhY21lXCIsXCIzZjFjMmE5ZS0xYjJjLTRkNWUtOGY5MC0wMTIzNDU2Nzg5YWJcIixcIm93bmVyXCJdIiwiMjAyNi0xMS0xM1QxMjowMDowMC4wMDBaOWE4YjdjNmQtNWU0Zi00YTNiLThjMmQtMWUwZjlhOGI3YzZkIl0'
  }
]

/** A deterministic generator, so a failure reproduces. */
function generator(seed: number): () => number {
  let state = seed
  return () => {
    state = (state * 1664525 + 1013904223) % 4294967296
    return state / 4294967296
  }
}

/** An encoder independent of the codec: base64url of the JSON of `[query, position]`. */
function independentEncode(query: string, position: string): string {
  return Buffer.from(JSON.stringify([query, position])).toString('base64url')
}

/** A cursor whose payload is the given JSON, written the way the codec writes its own. */
function cursorOf(payload: unknown): string {
  return Buffer.from(JSON.stringify(payload)).toString('base64url')
}

describe('workspaceQueryKey', () => {
  // Scenario: fixed inputs. Expected: the exact JSON text. Why: a lock name or a map key built from
  // the key must not move between releases, or two instances would hold two names for one lock.
  it.each([
    [['listForUser', 'acme', 'u1'], '["listForUser","acme","u1"]'],
    [[], '[]'],
    [['a:b', 'c'], '["a:b","c"]'],
    [['a', 'b:c'], '["a","b:c"]'],
    [['q"uote', 'back\\slash'], '["q\\"uote","back\\\\slash"]'],
    [['é€😀'], '["é€😀"]'],
    [['\uD800'], '["\\ud800"]']
  ])('writes %j as exactly %s', (parts, expected) => {
    expect(workspaceQueryKey(...parts)).toBe(expected)
  })

  // Scenario: a corpus of part lists. Expected: the same bytes as JSON.stringify of the list.
  it('is JSON.stringify of the parts, byte for byte', () => {
    const next = generator(7)
    for (let i = 0; i < 500; i++) {
      const parts = Array.from({ length: 1 + Math.floor(next() * 4) }, () =>
        String.fromCharCode(
          ...Array.from({ length: Math.floor(next() * 6) }, () => next() * 0xffff)
        )
      )
      expect(workspaceQueryKey(...parts)).toBe(JSON.stringify(parts))
    }
  })

  // Scenario: two lists whose parts glue into the same text. Expected: two different keys.
  it('keeps two lists that join to the same text apart', () => {
    expect(workspaceQueryKey('a:b', 'c')).not.toBe(workspaceQueryKey('a', 'b:c'))
    expect(workspaceQueryKey('ab', '')).not.toBe(workspaceQueryKey('a', 'b'))
  })
})

describe('workspacePositionOf and readWorkspacePosition', () => {
  // Scenario: a position made from an instant and an id. Expected: the 24-character ISO instant
  // followed by the id, and read back to the same two values.
  it('writes the instant then the id and reads both back', () => {
    expect(POSITION).toBe('2026-11-13T12:00:00.000Z9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d')
    expect(readWorkspacePosition(POSITION)).toEqual({
      at: AT,
      id: '9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d'
    })
  })

  // Scenario: positions whose first 24 characters are not a canonical instant. Expected: none.
  it.each([
    ['empty', ''],
    ['too short', '2026-11-13'],
    ['not a date', 'nope-nope-nope-nope-nope-nope'],
    ['a non-canonical spelling', '2026-11-13T12:00:00Z0000000x'],
    ['a rolled-over date', '2026-02-31T00:00:00.000Zid']
  ])('reads %s as none', (_label, position) => {
    expect(readWorkspacePosition(position)).toBeUndefined()
  })

  // Scenario: an id that is empty. Expected: still a position (the id is whatever follows).
  it('accepts an empty id', () => {
    expect(readWorkspacePosition(workspacePositionOf(AT, ''))).toEqual({ at: AT, id: '' })
  })
})

describe('encodeWorkspaceCursor and decodeWorkspaceCursor', () => {
  // Scenario: a cursor issued for a query and read back for the same query. Expected: the position.
  it('round-trips a position for the query that issued it', () => {
    expect(decodeWorkspaceCursor(encodeWorkspaceCursor(QUERY, POSITION), QUERY)).toBe(POSITION)
  })

  // Scenario: an independent encoder and this one on the same input. Expected: identical bytes.
  it('writes the same bytes as an independent encoder', () => {
    expect(encodeWorkspaceCursor(QUERY, POSITION)).toBe(independentEncode(QUERY, POSITION))
  })

  // Scenario: cursors in the pair format. Expected: each reads as the position it carries, and this
  // encoder writes the same bytes for it.
  it.each(PAIR_FORMAT_CURSORS)('reads and rewrites a pair-format cursor for $parts', (entry) => {
    const query = workspaceQueryKey(...entry.parts)
    const position = workspacePositionOf(AT, entry.id)

    expect(decodeWorkspaceCursor(entry.cursor, query)).toBe(position)
    expect(encodeWorkspaceCursor(query, position)).toBe(entry.cursor)
  })

  // Scenario: no cursor at all. Expected: none, the first page.
  it('reads an absent cursor as none', () => {
    expect(decodeWorkspaceCursor(undefined, QUERY)).toBeUndefined()
  })

  // Scenario: a cursor issued for another query (another tenant, member, workspace, listing).
  // Expected: none, so the page restarts and never reads another scope.
  it.each([
    ['another tenant', workspaceQueryKey('listForUser', 'other', 'u1')],
    ['another member', workspaceQueryKey('listForUser', 'acme', 'u2')],
    ['another listing', workspaceQueryKey('listForWorkspace', 'acme', 'u1')],
    ['a different arity', workspaceQueryKey('listForUser', 'acme')]
  ])('reads a cursor for %s as none', (_label, other) => {
    expect(decodeWorkspaceCursor(encodeWorkspaceCursor(other, POSITION), QUERY)).toBeUndefined()
  })

  // Scenario: values that are not strings, as `?cursor=a&cursor=b` or a job can produce. Expected:
  // none, and no throw.
  it.each([[['a', 'b']], [42], [{}], [null], [true], [Symbol.iterator]])(
    'reads the non-string %p as none',
    (value) => {
      expect(decodeWorkspaceCursor(value, QUERY)).toBeUndefined()
    }
  )

  const valid = encodeWorkspaceCursor(QUERY, POSITION)

  // Scenario: a cursor that is not exactly what the encoder writes. Expected: none for each.
  it.each([
    ['empty', ''],
    ['noise characters spliced in', `${valid.slice(0, 6)}!!**${valid.slice(6)}`],
    ['padded', `${valid}==`],
    ['in the standard base64 alphabet', Buffer.from(valid, 'base64url').toString('base64')],
    ['truncated', valid.slice(0, -3)],
    ['extended', `${valid}AAAA`],
    ['with a flipped final character', `${valid.slice(0, -1)}${valid.endsWith('A') ? 'B' : 'A'}`],
    ['plain text', 'not a cursor'],
    ['a number in JSON', cursorOf(5)],
    ['JSON null', cursorOf(null)],
    ['a JSON object', cursorOf({ 0: QUERY, 1: POSITION, length: 2 })],
    ['an array of one', cursorOf([QUERY])],
    ['an array of three', cursorOf([QUERY, POSITION, 'x'])],
    ['an array of two with a number position', cursorOf([QUERY, 1])],
    ['an array of two with a null position', cursorOf([QUERY, null])],
    ['an array of two with a number query', cursorOf([1, POSITION])],
    ['an array of two with an array position', cursorOf([QUERY, [POSITION]])],
    ['nested arrays', cursorOf([[QUERY], [POSITION]])],
    ['an empty position', cursorOf([QUERY, ''])],
    [
      'JSON with spaces',
      Buffer.from(`[ ${JSON.stringify(QUERY)} , ${JSON.stringify(POSITION)} ]`).toString(
        'base64url'
      )
    ],
    [
      'JSON with a leading byte order mark',
      Buffer.from(`\uFEFF${JSON.stringify([QUERY, POSITION])}`).toString('base64url')
    ],
    [
      'JSON with an escaped character',
      Buffer.from(JSON.stringify([QUERY, POSITION]).replace('l', '\\u006c')).toString('base64url')
    ],
    ['a position that is not an instant', cursorOf([QUERY, 'whatever'])],
    ['a position with no id', cursorOf([QUERY, workspacePositionOf(AT, '')])],
    ['a position whose id holds a NUL', cursorOf([QUERY, workspacePositionOf(AT, 'a\u0000b')])],
    ['a position whose id holds a newline', cursorOf([QUERY, workspacePositionOf(AT, 'a\nb')])],
    [
      'a position whose id holds a C1 control',
      cursorOf([QUERY, workspacePositionOf(AT, 'a\u0085b')])
    ],
    [
      'a position whose id is 129 code points',
      cursorOf([QUERY, workspacePositionOf(AT, 'a'.repeat(129))])
    ]
  ])('reads a cursor that is %s as none', (_label, cursor) => {
    expect(decodeWorkspaceCursor(cursor, QUERY)).toBeUndefined()
  })

  // Scenario: a position holding an unpaired surrogate, and a payload that is not UTF-8. Expected:
  // none for each, since neither is text this codec ever wrote.
  it('reads an ill-formed position and an ill-formed payload as none', () => {
    const lone = Buffer.from(`["${QUERY.replaceAll('"', '\\"')}","\\ud800"]`).toString('base64url')
    const notUtf8 = Buffer.from([0x5b, 0xff, 0xfe, 0x5d]).toString('base64url')

    expect(decodeWorkspaceCursor(lone, QUERY)).toBeUndefined()
    expect(decodeWorkspaceCursor(notUtf8, QUERY)).toBeUndefined()
  })

  // Scenario: the edges of the control-character ranges. Expected: the last control character of
  // each range is refused and the character beside it is read, so the comparisons are exact.
  it.each([
    ['\u001f', false],
    ['\u0020', true],
    ['\u007e', true],
    ['\u007f', false],
    ['\u009f', false],
    ['\u00a0', true]
  ])('reads an id holding %j: %s', (character, readable) => {
    const position = workspacePositionOf(AT, `a${character}b`)

    expect(decodeWorkspaceCursor(cursorOf([QUERY, position]), QUERY)).toBe(
      readable ? position : undefined
    )
  })

  // Scenario: an id of exactly 128 code points, ASCII and emoji. Expected: read back, so the bound is
  // inclusive and counts code points.
  it.each([['a'.repeat(128)], ['😀'.repeat(128)]])('reads an id of 128 code points', (id) => {
    const position = workspacePositionOf(AT, id)

    expect(decodeWorkspaceCursor(encodeWorkspaceCursor(QUERY, position), QUERY)).toBe(position)
  })

  // Scenario: a position that moved but is well-formed. Expected: it reads as given, within the same
  // query, because the cursor is a bookmark and not a signature.
  it('reads a well-formed position another instant names, for the same query only', () => {
    const moved = workspacePositionOf(new Date('2020-01-01T00:00:00.000Z'), 'x')

    expect(decodeWorkspaceCursor(encodeWorkspaceCursor(QUERY, moved), QUERY)).toBe(moved)
    expect(
      decodeWorkspaceCursor(encodeWorkspaceCursor(workspaceQueryKey('other'), moved), QUERY)
    ).toBeUndefined()
  })
})

describe('what encode refuses', () => {
  // Scenario: a position the decoder reads as none. Expected: a RangeError at issue time, so a client
  // following nextCursor can never be sent back to the first page by a cursor the library wrote.
  it.each([
    ['an empty position', ''],
    ['a position that is not an instant', 'whatever'],
    ['a position with no id', workspacePositionOf(AT, '')],
    ['a lone high surrogate', workspacePositionOf(AT, '\uD800')],
    ['a lone low surrogate', workspacePositionOf(AT, 'a\uDC00b')],
    ['a NUL in the id', workspacePositionOf(AT, 'a\u0000b')],
    ['a DEL in the id', workspacePositionOf(AT, 'a\u007fb')],
    ['an id of 129 code points', workspacePositionOf(AT, 'a'.repeat(129))]
  ])('refuses %s', (_label, position) => {
    expect(() => encodeWorkspaceCursor(QUERY, position)).toThrow(RangeError)
  })

  // Scenario: an id over the bound. Expected: the message names it and its length in code points.
  it('names a position id that is too long', () => {
    expect(() => encodeWorkspaceCursor(QUERY, workspacePositionOf(AT, '😀'.repeat(300)))).toThrow(
      /position id is 300 code points, over 128/
    )
  })

  // Scenario: a key part that is a lone surrogate. Expected: still a cursor that reads back, because
  // the key writes it as an escape, the same text on both sides.
  it('keeps a key with an unpaired surrogate readable', () => {
    const key = workspaceQueryKey('listForUser', 'a\uD800', 'u')

    expect(decodeWorkspaceCursor(encodeWorkspaceCursor(key, POSITION), key)).toBe(POSITION)
  })
})

describe('the length bound', () => {
  /** A canonical cursor of exactly `length` characters, written without the length check. */
  function cursorOfLength(length: number): { cursor: string; query: string } {
    for (let padding = 0; padding < 8000; padding++) {
      const query = `q${'a'.repeat(padding)}`
      const cursor = cursorOf([query, POSITION])
      if (cursor.length === length) return { cursor, query }
    }
    throw new Error(`no cursor of ${length} characters`)
  }

  /** The message of the error a call throws. */
  function messageOf(call: () => unknown): string {
    try {
      call()
    } catch (error) {
      return error instanceof RangeError ? error.message : `not a RangeError: ${String(error)}`
    }
    return 'did not throw'
  }

  // Scenario: the two bounds. Expected: 4096 characters for a cursor and 128 code points for an id
  // or a key part, which the worst-case cases below fit under the first.
  it('is 4096 characters, over a 128-code-point id bound', () => {
    expect(WORKSPACE_CURSOR_MAX_LENGTH).toBe(4096)
    expect(WORKSPACE_CURSOR_PART_MAX_LENGTH).toBe(128)
  })

  // Scenario: a canonical cursor of exactly the maximum, and one just over. Expected: the maximum
  // reads, the next canonical length reads as none, and a 4097-character string reads as none.
  it('reads a cursor of 4096 characters and refuses one of 4098', () => {
    const at = cursorOfLength(4096)

    const over = cursorOfLength(4098)

    expect(decodeWorkspaceCursor(at.cursor, at.query)).toBe(POSITION)
    expect(decodeWorkspaceCursor(over.cursor, over.query)).toBeUndefined()
    expect(decodeWorkspaceCursor('A'.repeat(4097), at.query)).toBeUndefined()
  })

  // Scenario: a cursor of millions of characters. Expected: none, without parsing it.
  it('refuses a huge cursor without parsing it', () => {
    const parse = jest.spyOn(JSON, 'parse')
    const huge = Buffer.from(JSON.stringify(['q', 'x'.repeat(5_000_000)])).toString('base64url')

    expect(decodeWorkspaceCursor(huge, 'q')).toBeUndefined()
    expect(parse).not.toHaveBeenCalled()
    parse.mockRestore()
  })

  // Scenario: a key part far over the id bound makes the cursor too long. Expected: a RangeError
  // naming the key, the part and its length in code points.
  it('refuses to write a cursor over the maximum and names a key part that is too long', () => {
    const key = workspaceQueryKey('listForUser', 'x'.repeat(4000), 'u')

    expect(messageOf(() => encodeWorkspaceCursor(key, POSITION))).toMatch(
      /over the 4096 maximum.*query key part 2 is 4000 code points, over 128/
    )
  })

  // Scenario: the part is made of surrogate pairs. Expected: it is counted in code points, as the
  // request bounds count, so 3000 emoji read as 3000 and not 6000.
  it('counts a part in code points', () => {
    const key = workspaceQueryKey('listForUser', '😀'.repeat(3000), 'u')

    expect(messageOf(() => encodeWorkspaceCursor(key, POSITION))).toMatch(
      /query key part 2 is 3000 code points/
    )
  })

  // Scenario: every part is within the bound but the key has too many of them. Expected: the
  // message gives the sizes instead, since no single part is to blame.
  it('gives the sizes when no single part is over the id bound', () => {
    const key = workspaceQueryKey(...Array.from({ length: 40 }, () => 'p'.repeat(128)))

    expect(messageOf(() => encodeWorkspaceCursor(key, POSITION))).toMatch(
      /query key is \d+ characters and the position \d+/
    )
  })

  // Scenario: a query that is not a JSON list of strings, and one that is a list of non-strings.
  // Expected: still refused by size, with the sizes named.
  it.each([['x'.repeat(6000)], [JSON.stringify(Array.from({ length: 4000 }, () => 1))]])(
    'gives the sizes for a query that is not a key list of strings',
    (query) => {
      expect(messageOf(() => encodeWorkspaceCursor(query, POSITION))).toMatch(
        /query key is \d+ characters and the position/
      )
    }
  )

  // Scenario: a query that parses as JSON but is not a list. Expected: refused by size as well.
  it('gives the sizes for a query that is a JSON object', () => {
    const query = JSON.stringify({ k: 'x'.repeat(6000) })

    expect(messageOf(() => encodeWorkspaceCursor(query, POSITION))).toMatch(
      /query key is \d+ characters and the position/
    )
  })
})

describe('the longest cursor a valid listing can issue', () => {
  const quotes = '"'.repeat(128)
  const emoji = '😀'.repeat(128)
  const controls = '\u0000'.repeat(128)
  const lone = '\uD800'.repeat(128)
  const letters = 'a'.repeat(WORKSPACE_OWNER_ROLE_MAX_LENGTH)

  const costliest = ['"', '😀'].map((character) =>
    character.repeat(WORKSPACE_OWNER_ROLE_MAX_LENGTH)
  )

  // Scenario: tenant and member of 128 quote characters (each escaped twice) and a row id of 128
  // emoji (four bytes each), for each listing a repository serves, with owner roles up to the
  // longest the bound allows and made of the costliest characters, then with control characters or
  // unpaired surrogates in tenant and member. Expected: the length the bound was sized for, under
  // the maximum, and the cursor reads back.
  it.each([
    ['listForUser', ['listForUser', quotes, quotes], emoji, 2126],
    ['listForWorkspace', ['listForWorkspace', quotes, quotes], emoji, 2132],
    ['listSoleOwned with the role owner', ['listSoleOwned', quotes, quotes, 'owner'], emoji, 2142],
    [
      'listSoleOwned with a role of letters',
      ['listSoleOwned', quotes, quotes, letters],
      emoji,
      2178
    ],
    [
      'listSoleOwned with the role proprietário',
      ['listSoleOwned', quotes, quotes, 'proprietário'],
      emoji,
      2152
    ],
    [
      'listSoleOwned with a role of 32 é',
      ['listSoleOwned', quotes, quotes, 'é'.repeat(32)],
      emoji,
      2220
    ],
    [
      'listSoleOwned with a role of 32 quotes',
      ['listSoleOwned', quotes, quotes, costliest[0] ?? ''],
      emoji,
      2306
    ],
    [
      'listSoleOwned with a role of 32 emoji',
      ['listSoleOwned', quotes, quotes, costliest[1] ?? ''],
      emoji,
      2306
    ],
    [
      'listSoleOwned with control characters in tenant and member',
      ['listSoleOwned', controls, controls, costliest[0] ?? ''],
      emoji,
      3330
    ],
    [
      'listSoleOwned with unpaired surrogates in tenant and member',
      ['listSoleOwned', lone, lone, costliest[0] ?? ''],
      emoji,
      3330
    ]
  ])('%s is %i characters and fits', (_label, parts, id, length) => {
    const query = workspaceQueryKey(...parts)
    const position = workspacePositionOf(AT, id)
    const cursor = encodeWorkspaceCursor(query, position)

    expect(cursor).toHaveLength(length)
    expect(cursor.length).toBeLessThanOrEqual(WORKSPACE_CURSOR_MAX_LENGTH)
    expect(decodeWorkspaceCursor(cursor, query)).toBe(position)
  })

  // Scenario: an id of 300 emoji, past the id bound. Expected: it overflows, which is why an adapter
  // that issues such an id is refused loudly.
  it('overflows for an id past the id bound', () => {
    const query = workspaceQueryKey('listSoleOwned', quotes, quotes, letters)

    expect(() => encodeWorkspaceCursor(query, workspacePositionOf(AT, '😀'.repeat(900)))).toThrow(
      RangeError
    )
  })

  // Scenario: names an owner role may take. Expected: each is accepted, whatever its characters: a
  // space, accents, an emoji, and exactly the longest length counted in code points.
  it.each([
    'owner',
    'admin',
    'billing_admin',
    'ADMIN',
    'org:admin',
    'team lead',
    'proprietário',
    'dono_é',
    '😀',
    costliest[0] ?? '',
    costliest[1] ?? '',
    letters
  ])('accepts the owner role %s', (role) => {
    expect(isWorkspaceOwnerRole(role)).toBe(true)
  })

  // Scenario: names an owner role may not take: empty, over the length in code points, a control
  // character of either range or DEL, and an unpaired surrogate. Expected: each is refused.
  it.each([
    '',
    `${letters}a`,
    '😀'.repeat(WORKSPACE_OWNER_ROLE_MAX_LENGTH + 1),
    '\u0000',
    'a\nb',
    'a\u007fb',
    'a\u0085b',
    '\uD800',
    'a\uDC00'
  ])('refuses the owner role %j', (role) => {
    expect(isWorkspaceOwnerRole(role)).toBe(false)
  })
})

describe('fuzz', () => {
  // Scenario: random keys and positions, ill-formed and empty ones included. Expected: whatever
  // encode accepts reads back as the same position, and whatever it refuses is refused for the one
  // reason the decoder would also refuse it. Why: a cursor written but never readable makes a client
  // that follows nextCursor loop on the first page.
  /** Whether a position is one the decoder must read as none: the fuzz's own account of the rule. */
  function isUnreadablePosition(position: string): boolean {
    const id = position.slice(24)
    return (
      readWorkspacePosition(position) === undefined ||
      id === '' ||
      Array.from(id).length > 128 ||
      Array.from(id).some(
        (c) =>
          (c.codePointAt(0) ?? 0) <= 0x1f ||
          ((c.codePointAt(0) ?? 0) >= 0x7f && (c.codePointAt(0) ?? 0) <= 0x9f)
      ) ||
      /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(id)
    )
  }

  it('reads back every cursor it writes', () => {
    const next = generator(31)
    const pick = (n: number): number => Math.floor(next() * n)
    const units = [0x0, 0x20, 0x22, 0x5c, 0x61, 0x7f, 0xe9, 0x20ac, 0xd800, 0xdc00, 0xd83d, 0xde00]
    const text = (max: number): string =>
      String.fromCharCode(
        ...Array.from({ length: pick(max) }, () => units[pick(units.length)] ?? 0)
      )

    for (let i = 0; i < 20_000; i++) {
      const query = pick(2) === 0 ? text(20) : workspaceQueryKey(text(8), text(8), text(8))
      const position = pick(3) === 0 ? text(30) : workspacePositionOf(AT, text(30))
      let cursor: string | undefined
      try {
        cursor = encodeWorkspaceCursor(query, position)
      } catch {
        cursor = undefined
      }

      if (cursor !== undefined) expect(decodeWorkspaceCursor(cursor, query)).toBe(position)
      else expect(isUnreadablePosition(position)).toBe(true)
    }
  })

  const ALPHABET =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=+/!*. "[]{}\\,:\n'

  // Scenario: tens of thousands of strings, built from the cursor alphabet and from raw code units,
  // plus mutations of valid cursors. Expected: decoding never throws, and a cursor that reads is
  // exactly the canonical encoding of the position it returned, for this query and no other.
  it('never throws and accepts only the canonical encoding of its own result', () => {
    const next = generator(2026)
    const valid = encodeWorkspaceCursor(QUERY, POSITION)
    const pick = (n: number): number => Math.floor(next() * n)
    const randomText = (): string =>
      Array.from({ length: pick(40) }, () => ALPHABET[pick(ALPHABET.length)]).join('')
    const randomUnits = (): string =>
      String.fromCharCode(...Array.from({ length: pick(30) }, () => pick(0x10000)))
    const mutate = (): string => {
      const at = pick(valid.length)
      switch (pick(5)) {
        case 0:
          return valid.slice(0, at)
        case 1:
          return valid.slice(0, at) + ALPHABET[pick(ALPHABET.length)] + valid.slice(at + 1)
        case 2:
          return valid.slice(0, at) + valid.slice(at + 1)
        case 3:
          return valid + randomText()
        default:
          return valid.slice(0, at) + randomText() + valid.slice(at)
      }
    }
    const inputs = [randomText, randomUnits, mutate]

    for (let i = 0; i < 40_000; i++) {
      const cursor = inputs[i % inputs.length]?.() ?? ''
      const result = decodeWorkspaceCursor(cursor, QUERY)

      if (result !== undefined) {
        expect(encodeWorkspaceCursor(QUERY, result)).toBe(cursor)
        expect(decodeWorkspaceCursor(cursor, workspaceQueryKey('listForUser', 'acme', 'u2'))).toBe(
          undefined
        )
      }
    }
  })

  // Scenario: random payloads shaped like cursors, written canonically. Expected: a cursor reads
  // only when it is exactly [this query, a non-empty well-formed string].
  it('reads a canonically written payload only when it is the pair for this query', () => {
    const next = generator(99)
    const pick = (n: number): number => Math.floor(next() * n)
    const values: unknown[] = [QUERY, POSITION, '', 1, null, true, [], {}, ['x'], '\uD800']

    for (let i = 0; i < 2_000; i++) {
      const payload =
        pick(4) === 0
          ? values[pick(values.length)]
          : [values[pick(values.length)], values[pick(values.length)]]
      const result = decodeWorkspaceCursor(cursorOf(payload), QUERY)
      const isThePair =
        Array.isArray(payload) &&
        payload.length === 2 &&
        payload[0] === QUERY &&
        payload[1] === POSITION

      expect(result).toBe(isThePair ? POSITION : undefined)
    }
  })
})
