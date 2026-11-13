/**
 * @fileoverview The keyset cursor codec of the workspace lists: the key a cursor is bound to, the
 * position of a row in a list's order, and the opaque cursor that carries both between pages.
 *
 * A repository serving `listForUser`, `listForWorkspace` or `listSoleOwned` pages by a keyset, and
 * the port requires one rule of every cursor it reads: a malformed cursor, or one issued for another
 * query, restarts from the first page and never widens the scope. That rule lives here once, so an
 * adapter does not write its own.
 *
 * @layer Utility
 */

/**
 * The longest cursor, in characters.
 *
 * Sized for the longest cursor a listing can issue from the ids the library admits: a tenant, a
 * member and a row id of up to {@link WORKSPACE_CURSOR_PART_MAX_LENGTH} code points each, whatever
 * well-formed characters they hold (JSON escapes a quote twice, which is the costliest), and an
 * owner role of up to {@link WORKSPACE_OWNER_ROLE_MAX_LENGTH} characters: 2178 characters at most.
 * The HTTP page query and the decoder both use this value, so a cursor the library issues is
 * always one it accepts.
 */
export const WORKSPACE_CURSOR_MAX_LENGTH = 4096

/**
 * The longest id, tenant or key part a cursor is sized for, in code points: the unit every request
 * bound of the library counts in, so an emoji is one.
 */
export const WORKSPACE_CURSOR_PART_MAX_LENGTH = 128

/** The longest owner role name, in characters; the role is part of the key of `listSoleOwned`. */
export const WORKSPACE_OWNER_ROLE_MAX_LENGTH = 32

/**
 * What an owner role may be named: a letter, then letters, digits and `_ . : -`, up to
 * {@link WORKSPACE_OWNER_ROLE_MAX_LENGTH} characters. None of them is escaped in JSON, which keeps
 * the longest cursor within {@link WORKSPACE_CURSOR_MAX_LENGTH}.
 */
export const WORKSPACE_OWNER_ROLE_PATTERN = /^[A-Za-z][A-Za-z0-9_.:-]{0,31}$/

/** The length of the canonical instant a position starts with, `2026-11-13T12:00:00.000Z`. */
const INSTANT_LENGTH = 24

/** A high surrogate without its low one, or a low one without its high: no UTF-8 form. */
const UNPAIRED_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/

/** Reads bytes as UTF-8 and refuses any that are not. */
const STRICT_UTF8 = new TextDecoder('utf-8', { fatal: true })

/**
 * The key of a value scoped by tenant and further parts, and the key a cursor is bound to.
 *
 * It is `JSON.stringify` of the parts, byte for byte, so `('a:b', 'c')` and `('a', 'b:c')` stay two
 * keys whatever characters a part holds, and the key is also fit for anything else that must be
 * unambiguous: a lock name, a map key. A cursor is valid "for the same tenant and member" only as
 * far as the key it is bound to tells two scopes apart.
 *
 * @param parts - The query's name, then the parts that scope it, the tenant first.
 * @returns The unambiguous key.
 */
export function workspaceQueryKey(...parts: readonly string[]): string {
  return JSON.stringify(parts)
}

/**
 * A row's position in a keyset order: its creation instant, then its id. The instant is an ISO
 * string of exactly 24 characters, so comparing the joined string orders by instant first and by id
 * among rows created in the same millisecond.
 *
 * @param at - The row's creation instant.
 * @param id - The id that breaks ties.
 * @returns The position.
 * @throws {RangeError} For an invalid date.
 */
export function workspacePositionOf(at: Date, id: string): string {
  return at.toISOString() + id
}

/**
 * Splits a position back into its instant and its id, for a store that compares them as a pair.
 *
 * @param position - A position from {@link decodeWorkspaceCursor}.
 * @returns The instant and the id, or `undefined` when the first 24 characters are not an instant
 *   in the canonical ISO form.
 */
export function readWorkspacePosition(position: string): { at: Date; id: string } | undefined {
  const instant = position.slice(0, INSTANT_LENGTH)
  const at = new Date(instant)
  if (Number.isNaN(at.getTime()) || at.toISOString() !== instant) return undefined
  return { at, id: position.slice(INSTANT_LENGTH) }
}

/**
 * Describes what in a cursor's parts is too long, so the error that refuses it says where to look.
 *
 * @param query - The key the cursor is bound to.
 * @param position - The position it carries.
 * @returns The first key part or the position's id that is over the id bound, or the two sizes.
 */
function describeOverflow(query: string, position: string): string {
  const parts = keyParts(query)
  const part = parts.find(({ length }) => length > WORKSPACE_CURSOR_PART_MAX_LENGTH)
  if (part !== undefined) {
    return `query key part ${part.index} is ${part.length} code points, over ${WORKSPACE_CURSOR_PART_MAX_LENGTH}`
  }
  const id = Array.from(position.slice(INSTANT_LENGTH)).length
  if (id > WORKSPACE_CURSOR_PART_MAX_LENGTH) {
    return `position id is ${id} code points, over ${WORKSPACE_CURSOR_PART_MAX_LENGTH}`
  }
  return `the query key is ${query.length} characters and the position ${position.length}`
}

/**
 * The parts of a key built by {@link workspaceQueryKey}, with their lengths, or none for a query
 * that is not such a key.
 *
 * @param query - The key.
 * @returns Each part's 1-based index and length in code points.
 */
function keyParts(query: string): { index: number; length: number }[] {
  try {
    const parsed: unknown = JSON.parse(query)
    if (!Array.isArray(parsed)) return []
    return parsed.map((part: unknown, index) => ({
      index: index + 1,
      length: typeof part === 'string' ? Array.from(part).length : 0
    }))
  } catch {
    return []
  }
}

/**
 * The opaque cursor for a keyset page: the query it belongs to and the position of the last row
 * returned, as base64url of the JSON of the pair.
 *
 * @param query - The key the cursor is valid for, from {@link workspaceQueryKey}.
 * @param position - The last row's position, from {@link workspacePositionOf}.
 * @returns The cursor.
 * @throws {RangeError} For a position the decoder would read as none, an empty one or one with an
 *   unpaired surrogate, and when the cursor would be longer than {@link WORKSPACE_CURSOR_MAX_LENGTH},
 *   which only an id, tenant or key part over {@link WORKSPACE_CURSOR_PART_MAX_LENGTH} code points
 *   can cause: the message names the part. It fails loudly because a cursor the page query would
 *   refuse makes the next page unreachable.
 */
export function encodeWorkspaceCursor(query: string, position: string): string {
  if (position === '' || UNPAIRED_SURROGATE.test(position)) {
    throw new RangeError(
      'workspace cursor position must be a non-empty well-formed string: the decoder reads ' +
        'anything else as the first page, so the cursor could never be followed'
    )
  }
  const cursor = Buffer.from(JSON.stringify([query, position])).toString('base64url')
  if (cursor.length > WORKSPACE_CURSOR_MAX_LENGTH) {
    throw new RangeError(
      `workspace cursor is ${cursor.length} characters, over the ${WORKSPACE_CURSOR_MAX_LENGTH} ` +
        `maximum: ${describeOverflow(query, position)}`
    )
  }
  return cursor
}

/**
 * Reads a cursor back for one query. Anything that is not exactly what {@link encodeWorkspaceCursor}
 * writes for this query reads as none, so the page restarts from the first one and never widens the
 * scope: a value that is not a string, one over {@link WORKSPACE_CURSOR_MAX_LENGTH}, an encoding
 * other than the canonical one, bytes that are not UTF-8, anything but a pair of two strings, a pair
 * issued for another query, and an empty or ill-formed position.
 *
 * The cursor is a bookmark, not a signature: a well-formed position another instant names reads as
 * given, and moves within the same scope and nowhere else, because the scope comes from the query
 * the store builds and never from the cursor. It never throws.
 *
 * @param cursor - The cursor the caller sent, of any type a request can carry.
 * @param query - The key of the query being paged, from {@link workspaceQueryKey}.
 * @returns The position to resume after, or `undefined` for the first page.
 */
export function decodeWorkspaceCursor(cursor: unknown, query: string): string | undefined {
  if (typeof cursor !== 'string' || cursor.length > WORKSPACE_CURSOR_MAX_LENGTH) return undefined
  try {
    const bytes = Buffer.from(cursor, 'base64url')
    if (bytes.toString('base64url') !== cursor) return undefined
    const parsed: unknown = JSON.parse(STRICT_UTF8.decode(bytes))
    if (!Array.isArray(parsed) || parsed.length !== 2) return undefined
    const [issuedFor, position] = parsed as unknown[]
    if (issuedFor !== query || typeof position !== 'string') return undefined
    return position !== '' && !UNPAIRED_SURROGATE.test(position) ? position : undefined
  } catch {
    return undefined
  }
}
