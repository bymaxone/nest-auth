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
 * non-control characters they hold (JSON escapes a quote twice, which is the costliest of them), and
 * an owner role of up to {@link WORKSPACE_OWNER_ROLE_MAX_LENGTH} characters: 2178 characters at most.
 * A key part a host builds from control characters or unpaired surrogates, which JSON escapes at six
 * or seven bytes each, still fits: the longest such cursor is 3543 characters.
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

/**
 * Whether a text holds a C0 or C1 control character or DEL, none of which may appear in an id.
 *
 * @param text - The text.
 * @returns `true` for the first such character found.
 */
function hasControlCharacter(text: string): boolean {
  for (const character of text) {
    const code = character.codePointAt(0) ?? 0
    if (code <= 0x1f || (code >= 0x7f && code <= 0x9f)) return true
  }
  return false
}

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
 * Describes what in a cursor's key is too long, so the error that refuses it says where to look.
 *
 * @param query - The key the cursor is bound to.
 * @param position - The position it carries.
 * @returns The first key part over the id bound, or the sizes of the key and the position.
 */
function describeOverflow(query: string, position: string): string {
  const part = keyParts(query).find(({ length }) => length > WORKSPACE_CURSOR_PART_MAX_LENGTH)
  if (part !== undefined) {
    return `query key part ${part.index} is ${part.length} code points, over ${WORKSPACE_CURSOR_PART_MAX_LENGTH}`
  }
  return `the query key is ${query.length} characters and the position ${position.length}`
}

/**
 * Says what is wrong with a position the decoder would read as none.
 *
 * A position is the canonical instant of {@link workspacePositionOf} followed by an id of 1 to
 * {@link WORKSPACE_CURSOR_PART_MAX_LENGTH} code points with no control character and no unpaired
 * surrogate. A position outside that is never one a listing issued, and an adapter binds it as a
 * query value and may log it.
 *
 * @param position - The position.
 * @returns The reason, or `undefined` for a readable position.
 */
function whyUnreadable(position: string): string | undefined {
  if (readWorkspacePosition(position) === undefined) {
    return 'it is not a canonical instant followed by an id'
  }
  const id = position.slice(INSTANT_LENGTH)
  if (id === '') return 'its id is empty'
  const length = Array.from(id).length
  if (length > WORKSPACE_CURSOR_PART_MAX_LENGTH) {
    return `position id is ${length} code points, over ${WORKSPACE_CURSOR_PART_MAX_LENGTH}`
  }
  if (hasControlCharacter(id) || UNPAIRED_SURROGATE.test(id)) {
    return 'its id holds a control character or an unpaired surrogate'
  }
  return undefined
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
  const reason = whyUnreadable(position)
  if (reason !== undefined) {
    throw new RangeError(
      `workspace cursor position is refused because ${reason}: the decoder reads it as the first ` +
        'page, so the cursor could never be followed'
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
 * scope: a value that is not a string, one over {@link WORKSPACE_CURSOR_MAX_LENGTH}, another spelling
 * of the same pair (base64url, JSON whitespace or escapes, a byte order mark, bytes that are not
 * UTF-8), anything but a pair of two strings, a pair issued for another query, and a position that
 * is not an instant followed by an id of 1 to {@link WORKSPACE_CURSOR_PART_MAX_LENGTH} code points
 * with no control character and no unpaired surrogate.
 *
 * The cursor is a bookmark, not a signature: a well-formed position another instant names reads as
 * given, and moves within the same scope and nowhere else, because the scope comes from the query
 * the store builds and never from the cursor. The cursor is also readable by the client, so the
 * key holds only what the caller already knows (their own tenant, member and workspace), never a
 * value that must stay on the server. It never throws.
 *
 * @param cursor - The cursor the caller sent, of any type a request can carry.
 * @param query - The key of the query being paged, from {@link workspaceQueryKey}.
 * @returns The position to resume after, or `undefined` for the first page.
 */
export function decodeWorkspaceCursor(cursor: unknown, query: string): string | undefined {
  if (typeof cursor !== 'string' || cursor.length > WORKSPACE_CURSOR_MAX_LENGTH) return undefined
  try {
    const parsed: unknown = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8'))
    if (!Array.isArray(parsed) || parsed.length !== 2) return undefined
    const [issuedFor, position] = parsed as unknown[]
    if (issuedFor !== query || typeof position !== 'string') return undefined
    if (whyUnreadable(position) !== undefined) return undefined
    // Only the encoder's own bytes read: whitespace, escapes, a byte order mark, invalid UTF-8 and
    // any other spelling of the same pair re-encode to something else.
    return Buffer.from(JSON.stringify([query, position])).toString('base64url') === cursor
      ? position
      : undefined
  } catch {
    return undefined
  }
}
