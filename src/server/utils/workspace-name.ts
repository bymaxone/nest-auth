/**
 * @fileoverview Normalizes and bounds a workspace display name.
 *
 * @layer Utility
 */

import { NO_CONTROL_CHARACTERS } from '../dto/no-control-characters'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'

/** Longest workspace name accepted, in characters. */
export const MAX_WORKSPACE_NAME_LENGTH = 120

/**
 * Trims a workspace name and refuses one that is blank, over-long or carries control characters.
 *
 * The name is shown to other people, so it is stored as the caller meant it, trimmed, and nothing
 * else about it is rewritten.
 *
 * @param raw - What the caller supplied.
 * @returns The trimmed name.
 * @throws {AuthException} `auth.validation` on the `name` field when it is not usable.
 */
export function normalizeWorkspaceName(raw: unknown): string {
  const name = typeof raw === 'string' ? raw.trim() : ''
  if (name === '' || name.length > MAX_WORKSPACE_NAME_LENGTH || !NO_CONTROL_CHARACTERS.test(name)) {
    throw new AuthException(AUTH_ERROR_CODES.VALIDATION, [
      {
        field: 'name',
        message: `name must be 1 to ${MAX_WORKSPACE_NAME_LENGTH} characters with no control characters`
      }
    ])
  }
  return name
}
