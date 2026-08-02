/**
 * Unit tests for RevokeInvitationDto.
 *
 * The address is the entire payload — it is the only handle the issuing side has on a
 * pending invitation — so its validation and normalization are the whole contract.
 *
 * No rendering strategy needed — pure DTO validation logic.
 */

import { plainToInstance } from 'class-transformer'
import { validate } from 'class-validator'

import { RevokeInvitationDto } from './revoke-invitation.dto'

function buildDto(overrides: Partial<RevokeInvitationDto> = {}): RevokeInvitationDto {
  const dto = new RevokeInvitationDto()
  dto.email = 'invitee@example.com'
  return Object.assign(dto, overrides)
}

describe('RevokeInvitationDto', () => {
  // Verifies a well-formed address passes with zero errors.
  it('should pass validation with a valid email', async () => {
    expect(await validate(buildDto())).toHaveLength(0)
  })

  // Verifies the field-level guards: an address that is malformed, empty, or longer than the
  // column that will hold it is rejected before the service ever derives a key from it.
  it.each([
    ['a malformed address', 'not-an-email'],
    ['an empty address', ''],
    ['an address over 255 characters', `${'a'.repeat(250)}@example.com`]
  ])('should fail on %s', async (_label, email) => {
    const errors = await validate(buildDto({ email }))
    expect(errors.some((e) => e.property === 'email')).toBe(true)
  })

  // Verifies @Transform lowercases and trims, so the lookup matches the key the invitation
  // was indexed under. Without this a revoke silently reports "nothing pending".
  it('should normalize email to lowercase and trimmed via @Transform', () => {
    const dto = plainToInstance(RevokeInvitationDto, { email: '  INVITEE@EXAMPLE.COM  ' })

    expect(dto.email).toBe('invitee@example.com')
  })

  // Verifies a non-string value passes through @Transform unchanged, leaving the rejection
  // to @IsEmail rather than throwing inside the transform.
  it('should pass a non-string email through @Transform unchanged', () => {
    const dto = plainToInstance(RevokeInvitationDto, { email: 42 })

    expect((dto as unknown as Record<string, unknown>)['email']).toBe(42)
  })
})
