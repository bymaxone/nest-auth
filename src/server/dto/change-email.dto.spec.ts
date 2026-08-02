/**
 * Unit tests for {@link ChangeEmailDto} and {@link ConfirmEmailChangeDto}.
 *
 * Pure DTO validation: the fields, their bounds, and the normalization that makes the address
 * comparable to the one login resolves an account by.
 *
 * @layer DTO
 */

import { plainToInstance } from 'class-transformer'
import { validate } from 'class-validator'

import { ChangeEmailDto } from './change-email.dto'
import { ConfirmEmailChangeDto } from './confirm-email-change.dto'

function buildDto(overrides: Partial<ChangeEmailDto> = {}): ChangeEmailDto {
  const dto = new ChangeEmailDto()
  dto.newEmail = 'new@example.com'
  dto.currentPassword = 'the-current-one'
  return Object.assign(dto, overrides)
}

describe('ChangeEmailDto', () => {
  it('should pass validation with a valid payload', async () => {
    expect(await validate(buildDto())).toHaveLength(0)
  })

  it.each([
    ['a malformed address', { newEmail: 'not-an-email' }],
    ['an empty address', { newEmail: '' }],
    ['an address over 255 characters', { newEmail: `${'a'.repeat(250)}@example.com` }]
  ])('should fail on %s', async (_label, overrides) => {
    const errors = await validate(buildDto(overrides))
    expect(errors.some((e) => e.property === 'newEmail')).toBe(true)
  })

  // The password is bounded at both ends: empty proves nothing, and an unbounded one is a
  // cheap way to make someone else pay for a key derivation.
  it.each([
    ['an empty password', { currentPassword: '' }],
    ['a password over 128 characters', { currentPassword: 'a'.repeat(129) }]
  ])('should fail on %s', async (_label, overrides) => {
    const errors = await validate(buildDto(overrides))
    expect(errors.some((e) => e.property === 'currentPassword')).toBe(true)
  })

  // Normalized so the address is stored, mailed and checked for uniqueness in the one form
  // login resolves an account by.
  it('should normalize the address to lowercase and trimmed via @Transform', () => {
    const dto = plainToInstance(ChangeEmailDto, {
      newEmail: '  NEW@Example.COM  ',
      currentPassword: 'x'
    })

    expect(dto.newEmail).toBe('new@example.com')
  })

  it('should pass a non-string address through @Transform unchanged', () => {
    const dto = plainToInstance(ChangeEmailDto, { newEmail: 42, currentPassword: 'x' })

    expect((dto as unknown as Record<string, unknown>)['newEmail']).toBe(42)
  })
})

describe('ConfirmEmailChangeDto', () => {
  function buildToken(token: string): ConfirmEmailChangeDto {
    const dto = new ConfirmEmailChangeDto()
    dto.token = token
    return dto
  }

  it('should pass validation with a 64-character token', async () => {
    expect(await validate(buildToken('a'.repeat(64)))).toHaveLength(0)
  })

  // Bounded to the exact shape `generateSecureToken(32)` produces, so a malformed value is
  // refused before it is hashed into a key lookup.
  it.each([
    ['an empty token', ''],
    ['a short token', 'a'.repeat(63)],
    ['a long token', 'a'.repeat(65)]
  ])('should fail on %s', async (_label, token) => {
    const errors = await validate(buildToken(token))
    expect(errors.some((e) => e.property === 'token')).toBe(true)
  })
})
