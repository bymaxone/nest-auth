/**
 * @fileoverview Tests for `PreviewWorkspaceInvitationDto`: only a value of the exact length of a
 * token this library issues reaches the digest.
 *
 * @layer Test
 */

import { plainToInstance } from 'class-transformer'
import { validate } from 'class-validator'

import { PreviewWorkspaceInvitationDto } from './preview-workspace-invitation.dto'

async function failures(plain: object): Promise<string[]> {
  return (await validate(plainToInstance(PreviewWorkspaceInvitationDto, plain))).map(
    (e) => e.property
  )
}

describe('PreviewWorkspaceInvitationDto', () => {
  it('accepts a 64-character token', async () => {
    expect(await failures({ token: 'a'.repeat(64) })).toEqual([])
  })

  it.each([
    ['an empty token', ''],
    ['a token one short', 'a'.repeat(63)],
    ['a token one long', 'a'.repeat(65)],
    ['a non-string token', 7]
  ])('refuses %s', async (_name, token) => {
    expect(await failures({ token })).toEqual(['token'])
  })
})
