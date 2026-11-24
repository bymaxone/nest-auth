import { stringifyJson } from './captured-builtins'
/**
 * The stored form of a refresh-session record.
 *
 * @layer Utils
 */

/**
 * Serializes a session record for storage, omitting an empty `familyId`.
 *
 * rust-auth skips the field when empty (`skip_serializing_if`), so emitting `"familyId":""`
 * here would make the same session serialize to different bytes on each side and break the
 * shared-Redis contract. A record with no family simply has no key.
 *
 * @param session - The record to store (the refresh-session record, with its family fields).
 * @returns The JSON string written under an `rt:`/`prt:` key.
 */
export function serializeSession<T extends { familyId: string; familyCreatedAt: string }>(
  session: T
): string {
  if (session.familyId !== '') return stringifyJson(session)
  const { familyId: _omitted, familyCreatedAt: _alsoOmitted, ...rest } = session
  return stringifyJson(rest)
}
