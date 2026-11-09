/**
 * @fileoverview Tests for workspace name normalization.
 *
 * @layer Test
 */

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import type { AuthException } from '../errors/auth-exception'
import { MAX_WORKSPACE_NAME_LENGTH, normalizeWorkspaceName } from './workspace-name'

/** The response body an exception carries. */
function bodyOf(fn: () => unknown): { error: { code: string; details: unknown } } {
  try {
    fn()
  } catch (error) {
    return (error as AuthException).getResponse() as { error: { code: string; details: unknown } }
  }
  throw new Error('expected a throw')
}

describe('normalizeWorkspaceName', () => {
  it('trims the name and keeps everything else as given', () => {
    expect(normalizeWorkspaceName('  Acme  Corp \t')).toBe('Acme  Corp')
  })

  it('accepts a name at the length bound', () => {
    const name = 'n'.repeat(MAX_WORKSPACE_NAME_LENGTH)

    expect(normalizeWorkspaceName(name)).toBe(name)
  })

  it.each([
    ['an empty name', ''],
    ['a blank name', '   '],
    ['a non-string', 42],
    ['an undefined name', undefined],
    ['a name over the bound', 'n'.repeat(MAX_WORKSPACE_NAME_LENGTH + 1)],
    ['a name with a control character', 'Ac\u0000me'],
    ['a name with a newline inside', 'Ac\nme']
  ])('refuses %s with a validation error on the name field', (_label, value) => {
    const body = bodyOf(() => normalizeWorkspaceName(value))

    expect(body.error.code).toBe(AUTH_ERROR_CODES.VALIDATION)
    expect(body.error.details).toEqual([
      { field: 'name', message: 'name must be 1 to 120 characters with no control characters' }
    ])
  })
})
