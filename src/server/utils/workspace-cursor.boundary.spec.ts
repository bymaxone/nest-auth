/**
 * @fileoverview Tests for the two parts of the workspace cursor codec an operator reads or a limit
 * binds: the reason an unreadable position is refused, and the exact length at which a cursor is
 * too long.
 *
 * @layer Test
 */

import {
  WORKSPACE_CURSOR_MAX_LENGTH,
  decodeWorkspaceCursor,
  encodeWorkspaceCursor,
  workspacePositionOf
} from './workspace-cursor'

const AT = new Date('2026-11-13T12:00:00.000Z')
const INSTANT = AT.toISOString()
const TAIL = 'the decoder reads it as the first page, so the cursor could never be followed'

/** The message of the `RangeError` an encode throws, or `undefined` when it does not throw. */
function refusal(query: string, position: string): string | undefined {
  try {
    encodeWorkspaceCursor(query, position)
  } catch (error) {
    if (error instanceof RangeError) return error.message
    throw error
  }
  return undefined
}

describe('the reason an unreadable position is refused', () => {
  // Scenario: a position that is not an instant followed by an id. Expected: the message names that
  // cause and then says the cursor could never be followed, so the operator who reads it knows what
  // to fix and why a cursor was refused at all.
  it.each([
    ['it is not a canonical instant followed by an id', 'not-an-instant-0000000000000000'],
    ['its id is empty', INSTANT],
    [
      'its id holds a control character or an unpaired surrogate',
      workspacePositionOf(AT, 'row\u0000id')
    ],
    [
      'its id holds a control character or an unpaired surrogate',
      workspacePositionOf(AT, 'row\ud800id')
    ]
  ])('says %s', (reason, position) => {
    expect(refusal('q', position)).toBe(
      `workspace cursor position is refused because ${reason}: ${TAIL}`
    )
  })

  // Scenario: an id over the part limit. Expected: the message carries the measured length and the
  // limit, not a fixed phrase.
  it('names the length of an id over the limit', () => {
    expect(refusal('q', workspacePositionOf(AT, 'x'.repeat(129)))).toBe(
      `workspace cursor position is refused because position id is 129 code points, over 128: ${TAIL}`
    )
  })
})

describe('the length at which a cursor is too long', () => {
  /** A query that makes the cursor of a 10-character id exactly `length` base64url characters. */
  function queryForCursorOf(length: number, id: string): string {
    // The cursor is base64url of `["<query>","<position>"]`: 7 bytes of punctuation, the query and
    // the position, three bytes to four characters, unpadded.
    const bytes = (length * 3) / 4
    return 'a'.repeat(bytes - 7 - (INSTANT.length + id.length))
  }

  // Scenario: a cursor of exactly the maximum length. Expected: issued, and read back, because the
  // limit is on a cursor LONGER than the maximum and the page query accepts exactly the maximum.
  it('issues and reads back a cursor of exactly the maximum length', () => {
    const id = 'row-000001'
    const position = workspacePositionOf(AT, id)
    const query = queryForCursorOf(WORKSPACE_CURSOR_MAX_LENGTH, id)

    const cursor = encodeWorkspaceCursor(query, position)

    expect(cursor.length).toBe(WORKSPACE_CURSOR_MAX_LENGTH)
    expect(decodeWorkspaceCursor(cursor, query)).toBe(position)
  })

  // Scenario: one byte more of query, which is the next cursor length that exists. Expected: refused,
  // with the measured length and the maximum in the message.
  it('refuses a cursor one step longer than the maximum', () => {
    const id = 'row-000001'
    const position = workspacePositionOf(AT, id)
    const query = `${queryForCursorOf(WORKSPACE_CURSOR_MAX_LENGTH, id)}a`

    const message = refusal(query, position)

    expect(message).toMatch(
      new RegExp(
        `^workspace cursor is \\d+ characters, over the ${WORKSPACE_CURSOR_MAX_LENGTH} maximum: `
      )
    )
    expect(Number(/is (\d+) characters/.exec(message ?? '')?.[1])).toBeGreaterThan(
      WORKSPACE_CURSOR_MAX_LENGTH
    )
  })
})
