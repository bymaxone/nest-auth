/**
 * @fileoverview Names scoped to a workspace: the keys, rooms and prefixes a host builds for
 * storage, cache, sockets and queues, encoded so two workspaces can never share one.
 *
 * @layer Utility
 */

/** A high surrogate without its low one, or a low one without its high: no UTF-8 form. */
const UNPAIRED_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/

/**
 * Builds the name of something that belongs to one workspace.
 *
 * Each of the tenant, the workspace and the parts is written as its length in UTF-8 bytes, a colon
 * and the text, and the pieces are concatenated: `workspaceScopedName('t1', 'w1', 'room')` is
 * `2:t12:w14:room`. A length-prefixed piece is self-delimiting, so no text a part holds, a colon, a
 * slash, digits or the shape of another name, can move the boundary between two pieces: two
 * different arguments never produce one name, by construction. {@link decodeWorkspaceScopedName}
 * is its inverse.
 *
 * A part may be empty and may hold any character except a C0 control, DEL or an unpaired
 * surrogate; those are refused because the name ends up in Redis keys, socket rooms and object
 * keys, several storage backends reject or mangle controls, and an unpaired surrogate has no UTF-8
 * form of its own, so two different strings would write the same bytes. The tenant and the workspace must be non-empty.
 *
 * @param tenantId - The tenant, from the verified token.
 * @param workspaceId - The workspace, checked against the caller's membership.
 * @param parts - What follows, such as a resource kind and an id.
 * @returns The name.
 * @throws {TypeError} For a part that is not a string, an empty tenant or workspace, or a part
 *   holding a C0 control, DEL or an unpaired surrogate.
 */
export function workspaceScopedName(
  tenantId: string,
  workspaceId: string,
  ...parts: string[]
): string {
  const pieces = [tenantId, workspaceId, ...parts]
  pieces.forEach((piece, index) => assertPiece(piece, index))
  return pieces.map((piece) => `${Buffer.byteLength(piece, 'utf8')}:${piece}`).join('')
}

/**
 * Reads a name built by {@link workspaceScopedName} back into the tenant, the workspace and the
 * parts it was built from.
 *
 * @param name - A name.
 * @returns The tenant, the workspace and the parts, in order.
 * @throws {TypeError} For anything {@link workspaceScopedName} cannot have produced: a length that
 *   is not canonical, one that runs past the end or inside a character, text after the last piece,
 *   or fewer than two pieces.
 */
export function decodeWorkspaceScopedName(name: string): {
  tenantId: string
  workspaceId: string
  parts: string[]
} {
  const bytes = Buffer.from(name, 'utf8')
  const pieces: string[] = []
  let at = 0
  while (at < bytes.length) {
    const colon = bytes.indexOf(0x3a, at)
    const prefix = colon === -1 ? '' : bytes.toString('utf8', at, colon)
    if (!/^(?:0|[1-9]\d*)$/.test(prefix)) throw malformed(name)
    const end = colon + 1 + Number(prefix)
    if (end > bytes.length) throw malformed(name)
    pieces.push(bytes.toString('utf8', colon + 1, end))
    at = end
  }
  const [tenantId, workspaceId, ...parts] = pieces
  if (tenantId === undefined || workspaceId === undefined) throw malformed(name)
  if (!decodedWell(pieces)) throw malformed(name)
  return { tenantId, workspaceId, parts }
}

/** Whether a text holds a C0 control or DEL, which several backends reject or mangle. */
function hasControl(text: string): boolean {
  return Array.from(text).some((char) => {
    const code = char.charCodeAt(0)
    return code <= 0x1f || code === 0x7f
  })
}

/** Whether every decoded piece is one the builder would have accepted. */
function decodedWell(pieces: string[]): boolean {
  return pieces.every((piece, index) => !hasControl(piece) && (index > 1 || piece !== ''))
}

/** Refuses a piece the builder cannot encode. */
function assertPiece(piece: unknown, index: number): void {
  const label = index === 0 ? 'tenantId' : index === 1 ? 'workspaceId' : `part ${index - 2}`
  if (typeof piece !== 'string') throw new TypeError(`${label} must be a string`)
  if (index < 2 && piece === '') throw new TypeError(`${label} must not be empty`)
  if (hasControl(piece)) {
    throw new TypeError(`${label} must not contain a control character`)
  }
  if (UNPAIRED_SURROGATE.test(piece)) throw new TypeError(`${label} must be well-formed Unicode`)
}

/** The error for a name that was not built by {@link workspaceScopedName}. */
function malformed(name: string): TypeError {
  return new TypeError(`${JSON.stringify(name)} is not a workspace-scoped name`)
}
