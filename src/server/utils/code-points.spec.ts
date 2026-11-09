/**
 * @fileoverview Tests for the code-point helpers, and the one table that holds every bounded
 * service-side check on user text to the rule the contract states: a length bound counts Unicode
 * code points, so an emoji counts once.
 *
 * @layer Test
 */

import type { ResolvedOptions } from '../config/resolved-options'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import type { AuthException } from '../errors/auth-exception'
import { ApiKeyService } from '../services/api-key.service'
import { PasswordService } from '../services/password.service'
import { codePointLength, exceedsCodePoints, isShorterThanCodePoints } from './code-points'
import { resolveRequestWorkspace } from './resolve-request-workspace'
import { normalizeWorkspaceName } from './workspace-name'

/** One code point, two UTF-16 units. */
const EMOJI = '\u{1F600}'

function accepted(run: () => unknown): boolean {
  try {
    run()
    return true
  } catch (error) {
    const code = ((error as AuthException).getResponse() as { error: { code: string } }).error.code
    if (code !== AUTH_ERROR_CODES.VALIDATION) throw error
    return false
  }
}

describe('the code-point helpers', () => {
  it('counts a surrogate pair once', () => {
    expect(codePointLength(`a${EMOJI}b`)).toBe(3)
    expect(`a${EMOJI}b`.length).toBe(4)
  })

  it.each([
    ['ascii at the bound', 'a'.repeat(5), 5, false],
    ['ascii over the bound', 'a'.repeat(6), 5, true],
    ['emoji at the bound, over it in units', EMOJI.repeat(5), 5, false],
    ['emoji over the bound', EMOJI.repeat(6), 5, true]
  ])('says whether %s exceeds the bound', (_label, value, max, expected) => {
    expect(exceedsCodePoints(value, max)).toBe(expected)
  })

  it.each([
    ['ascii under the floor', 'a'.repeat(4), 5, true],
    ['ascii at the floor', 'a'.repeat(5), 5, false],
    ['emoji under the floor, over it in units', EMOJI.repeat(4), 5, true],
    ['emoji at the floor', EMOJI.repeat(5), 5, false]
  ])('says whether %s falls short of the floor', (_label, value, min, expected) => {
    expect(isShorterThanCodePoints(value, min)).toBe(expected)
  })
})

describe('every bounded service check on user text counts code points', () => {
  const passwords = new PasswordService(
    {
      password: { minLength: 15, costFactor: 2 ** 14, blockSize: 8, parallelization: 1 }
    } as ResolvedOptions,
    { isBreached: jest.fn() }
  )
  // `validatedLabel` is private and reads no instance state, so it is run on the prototype.
  const label = (value: string): unknown =>
    ApiKeyService.prototype['validatedLabel'].call(ApiKeyService.prototype, value)
  const workspaceId = (value: string): unknown =>
    resolveRequestWorkspace({ params: { workspaceId: value }, headers: {} } as never, undefined)

  // One row per check: how it is run, and its bound. Each runs the boundary with an emoji, which
  // is one code point and two units, so a check that counts units fails the at-bound row and one
  // that stops counting fails the over-bound row.
  const CEILINGS: [name: string, run: (value: string) => unknown, max: number][] = [
    ['the workspace name', (value) => normalizeWorkspaceName(value), 120],
    ['the workspace id', workspaceId, 128],
    ['the API key label', label, 128]
  ]

  it.each(CEILINGS)('%s accepts its bound and refuses one code point more', (_name, run, max) => {
    expect(accepted(() => run(EMOJI.repeat(max)))).toBe(true)
    expect(accepted(() => run(EMOJI.repeat(max + 1)))).toBe(false)
  })

  it('holds the password floor to code points: 15 emoji meet it, 14 do not', () => {
    expect(accepted(() => passwords.assertLongEnough(EMOJI.repeat(15), 'password'))).toBe(true)
    expect(accepted(() => passwords.assertLongEnough(EMOJI.repeat(14), 'password'))).toBe(false)
  })
})
