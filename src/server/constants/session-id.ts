/**
 * The session identifier a dashboard or platform access token carries in its `sid` claim.
 *
 * @layer Constants
 */

/** 36 characters: lowercase hexadecimal and hyphens in 8-4-4-4-12, the shape of a stored family id. */
const SESSION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

/**
 * The `sid` for a refresh family id, or `undefined` when there is none to name.
 *
 * A session record written before families existed carries an empty id, and a value that is not
 * in the contract's shape is not an identifier this library minted. Both read as absent, so a
 * token never names a session it cannot prove, and the reader fails closed on an absent one.
 *
 * @param value - A refresh family id, or a `sid` claim read from a token.
 * @returns The value when it has the contract's shape, otherwise `undefined`.
 */
export function sessionId(value: unknown): string | undefined {
  return typeof value === 'string' && SESSION_ID.test(value) ? value : undefined
}
