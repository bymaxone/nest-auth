/**
 * @fileoverview What the library reads from and writes to its stores goes through the `JSON.parse` and `JSON.stringify` taken
 * when the module loaded, so replacing either afterwards changes nothing it serialises or parses.
 *
 * @layer Test
 */

import { parseJson, stringifyJson } from './captured-builtins'
import { serializeSession } from './serialize-session'
import {
  decodeWorkspaceCursor,
  encodeWorkspaceCursor,
  workspacePositionOf,
  workspaceQueryKey
} from './workspace-cursor'

// The test's own copies: the windows below replace methods of `JSON`, so nothing inside one may call a live one.
const define = Object.defineProperty
const getOwn = Object.getOwnPropertyDescriptor

/** Runs `run` with `key` of `JSON` replaced by `stub`, and puts it back. */
function withReplaced<T>(key: 'parse' | 'stringify', stub: unknown, run: () => T): T {
  const held = getOwn(JSON, key) as PropertyDescriptor
  define(JSON, key, { ...held, value: stub })
  try {
    return run()
  } finally {
    define(JSON, key, held)
  }
}

describe('JSON after the library loaded', () => {
  // Scenario: `JSON.stringify` replaced by a function that answers a fixed text, then a session serialised and a cursor
  // written and read back. Expected: the real serialisation. Why: a replaced `stringify` would write the attacker's text into
  // the store or the cursor a client sends back.
  it('serialises with the copy of stringify taken at load', () => {
    const key = workspaceQueryKey('listForUser', 'q', 'u')
    const position = workspacePositionOf(
      new Date('2026-11-13T12:00:00.000Z'),
      '9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d'
    )
    const session = { familyId: 'fam', familyCreatedAt: 't', userId: 'u' }
    const during = withReplaced(
      'stringify',
      () => '{"attacker":true}',
      () => ({
        session: serializeSession(session),
        cursor: decodeWorkspaceCursor(encodeWorkspaceCursor(key, position), key)
      })
    )

    expect(JSON.parse(during.session)).toEqual(session)
    expect(during.cursor).toBe(position)
  })

  // Scenario: `JSON.parse` replaced by a function that answers an administrator, then a text parsed through the captured copy and
  // a cursor read back. Expected: what the text says and the position the cursor holds. Why: a replaced `parse` that answers a
  // role or a position is a privilege escalation through a stored record or a cursor a client sends.
  it('parses with the copy of parse taken at load', () => {
    const key = workspaceQueryKey('listForUser', 'q', 'u')
    const position = workspacePositionOf(
      new Date('2026-11-13T12:00:00.000Z'),
      '9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d'
    )
    const cursor = encodeWorkspaceCursor(key, position)
    const during = withReplaced(
      'parse',
      () => ({ role: 'ADMIN' }),
      () => ({
        text: parseJson('{"role":"MEMBER"}'),
        cursor: decodeWorkspaceCursor(cursor, key)
      })
    )

    expect(during.text).toEqual({ role: 'MEMBER' })
    expect(during.cursor).toBe(position)
  })

  // Scenario: the captured functions compared with the ones `JSON` holds now. Expected: the same functions. Why: the copy is
  // the function `JSON` held at load, not a wrapper that calls whatever `JSON` holds when it runs.
  it('holds the functions JSON held at load', () => {
    expect(parseJson).toBe(JSON.parse)
    expect(stringifyJson).toBe(JSON.stringify)
  })
})
