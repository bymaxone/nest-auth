/**
 * @fileoverview Tests for `WorkspaceInvitationEmailDto`: the address is the whole payload, so its
 * validation and normalization are the whole contract.
 *
 * @layer Test
 */

import { plainToInstance } from 'class-transformer'
import { validate } from 'class-validator'

import { WorkspaceInvitationEmailDto } from './workspace-invitation-email.dto'

async function failures(plain: object): Promise<string[]> {
  return (await validate(plainToInstance(WorkspaceInvitationEmailDto, plain))).map(
    (e) => e.property
  )
}

describe('WorkspaceInvitationEmailDto', () => {
  it('accepts an address, trimmed and lowercased so it matches the index', async () => {
    const dto = plainToInstance(WorkspaceInvitationEmailDto, { email: '  A@EXAMPLE.com ' })

    expect(dto.email).toBe('a@example.com')
    expect(await validate(dto)).toEqual([])
  })

  it.each([
    ['a malformed address', 'nope'],
    ['an empty address', ''],
    ['a non-string address', 42],
    ['an address over 255 characters', `${'a'.repeat(250)}@example.com`]
  ])('refuses %s', async (_name, email) => {
    expect(await failures({ email })).toEqual(['email'])
  })
})
