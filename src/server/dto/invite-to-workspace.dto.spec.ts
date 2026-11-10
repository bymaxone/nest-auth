/**
 * @fileoverview Tests for `InviteToWorkspaceDto`: the address is normalized and the role is bounded
 * and free of control characters; whether the role exists is the service's decision.
 *
 * @layer Test
 */

import { plainToInstance } from 'class-transformer'
import { validate } from 'class-validator'

import { InviteToWorkspaceDto } from './invite-to-workspace.dto'
import { createAuthValidationPipe } from '../pipes/auth-validation.pipe'

async function failures(plain: object): Promise<string[]> {
  return (await validate(plainToInstance(InviteToWorkspaceDto, plain))).map((e) => e.property)
}

describe('InviteToWorkspaceDto', () => {
  it('accepts an address and a role', async () => {
    expect(await failures({ email: 'a@example.com', role: 'viewer' })).toEqual([])
  })

  it('trims and lowercases the address, and passes a non-string through for the validator to refuse', async () => {
    expect(
      plainToInstance(InviteToWorkspaceDto, { email: '  A@EXAMPLE.com ', role: 'r' }).email
    ).toBe('a@example.com')
    expect(await failures({ email: 42, role: 'viewer' })).toEqual(['email'])
  })

  it.each([
    ['a malformed address', { email: 'nope', role: 'viewer' }, 'email'],
    ['an empty address', { email: '', role: 'viewer' }, 'email'],
    [
      'an address over 255 characters',
      { email: `${'a'.repeat(250)}@example.com`, role: 'viewer' },
      'email'
    ],
    ['an empty role', { email: 'a@example.com', role: '' }, 'role'],
    ['a role over 64 characters', { email: 'a@example.com', role: 'r'.repeat(65) }, 'role'],
    ['a role with a control character', { email: 'a@example.com', role: 'ro\nle' }, 'role'],
    ['a role that is not a string', { email: 'a@example.com', role: 7 }, 'role']
  ])('refuses %s', async (_name, plain, property) => {
    expect(await failures(plain)).toContain(property)
  })

  it('accepts a role of exactly 64 characters', async () => {
    expect(await failures({ email: 'a@example.com', role: 'r'.repeat(64) })).toEqual([])
  })

  it.each(['kind', 'workspaceName', 'workspaceId', 'inviterUserId'])(
    'cannot be made to carry the record field %s',
    async (field) => {
      const pipe = createAuthValidationPipe()

      await expect(
        pipe.transform(
          { email: 'a@example.com', role: 'viewer', [field]: 'bootstrap' },
          { type: 'body', metatype: InviteToWorkspaceDto }
        )
      ).rejects.toThrow()
    }
  )
})
