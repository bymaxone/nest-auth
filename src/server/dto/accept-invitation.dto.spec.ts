/**
 * Unit tests for AcceptInvitationDto.
 *
 * Uses class-validator `validate()` directly on instances built with the
 * `buildDto` helper. All boundary values for `@Length` constraints are
 * tested explicitly to confirm the min and max edges.
 *
 * No rendering strategy needed — pure DTO validation logic.
 */

import { validate } from 'class-validator'

import { AcceptInvitationDto } from './accept-invitation.dto'

/** Valid 64-character hex token matching the output of `generateSecureToken(32)`. */
const VALID_TOKEN = 'a'.repeat(64)

function buildDto(overrides: Partial<AcceptInvitationDto> = {}): AcceptInvitationDto {
  const dto = new AcceptInvitationDto()
  dto.token = VALID_TOKEN
  dto.name = 'Jane Doe'
  dto.password = 'SecureP@ss1'
  return Object.assign(dto, overrides)
}

// ---------------------------------------------------------------------------
// AcceptInvitationDto — field-level validation
// ---------------------------------------------------------------------------

describe('AcceptInvitationDto', () => {
  // Verifies that a fully valid DTO passes class-validator with zero errors.
  it('should pass validation with valid data', async () => {
    const errors = await validate(buildDto())
    expect(errors).toHaveLength(0)
  })

  // -------------------------------------------------------------------------
  // token field
  // -------------------------------------------------------------------------

  // Verifies that a token of exactly 64 characters satisfies the @Length(64, 64) constraint.
  it('should pass when token is exactly 64 characters', async () => {
    const errors = await validate(buildDto({ token: 'a'.repeat(64) }))
    expect(errors).toHaveLength(0)
  })

  // Verifies that a token shorter than 64 characters (63 chars) is rejected by @Length(64, 64).
  it('should fail when token is 63 characters (one below minimum)', async () => {
    const errors = await validate(buildDto({ token: 'a'.repeat(63) }))
    expect(errors.some((e) => e.property === 'token')).toBe(true)
  })

  // Verifies that a token longer than 64 characters (65 chars) is rejected by @Length(64, 64).
  it('should fail when token is 65 characters (one above maximum)', async () => {
    const errors = await validate(buildDto({ token: 'a'.repeat(65) }))
    expect(errors.some((e) => e.property === 'token')).toBe(true)
  })

  // Verifies that an empty token string is rejected by @IsNotEmpty.
  it('should fail when token is an empty string', async () => {
    const errors = await validate(buildDto({ token: '' }))
    expect(errors.some((e) => e.property === 'token')).toBe(true)
  })

  // -------------------------------------------------------------------------
  // name field
  // -------------------------------------------------------------------------

  // Verifies that a name of exactly 2 characters satisfies the @Length(2, 100) minimum boundary.
  it('should pass when name is exactly 2 characters (minimum boundary)', async () => {
    const errors = await validate(buildDto({ name: 'Jo' }))
    expect(errors).toHaveLength(0)
  })

  // Verifies that a name of 1 character is rejected by @Length(2, 100) (below minimum).
  it('should fail when name is 1 character (below minimum)', async () => {
    const errors = await validate(buildDto({ name: 'J' }))
    expect(errors.some((e) => e.property === 'name')).toBe(true)
  })

  // Verifies that an empty name is rejected by @IsNotEmpty.
  it('should fail when name is an empty string', async () => {
    const errors = await validate(buildDto({ name: '' }))
    expect(errors.some((e) => e.property === 'name')).toBe(true)
  })

  // Verifies that a name of exactly 100 characters satisfies the @Length(2, 100) maximum boundary.
  it('should pass when name is exactly 100 characters (maximum boundary)', async () => {
    const errors = await validate(buildDto({ name: 'a'.repeat(100) }))
    expect(errors).toHaveLength(0)
  })

  // Verifies that a name of 101 characters is rejected by @Length(2, 100) (above maximum).
  it('should fail when name is 101 characters (above maximum)', async () => {
    const errors = await validate(buildDto({ name: 'a'.repeat(101) }))
    expect(errors.some((e) => e.property === 'name')).toBe(true)
  })

  // -------------------------------------------------------------------------
  // password field
  // -------------------------------------------------------------------------

  // Verifies that a password of exactly 8 characters satisfies the @Length(8, 128) minimum boundary.
  it('should pass when password is exactly 8 characters (minimum boundary)', async () => {
    const errors = await validate(buildDto({ password: 'abcdefgh' }))
    expect(errors).toHaveLength(0)
  })

  // Verifies that a password of 7 characters is rejected by @Length(8, 128) (below minimum).
  it('should fail when password is 7 characters (below minimum)', async () => {
    const errors = await validate(buildDto({ password: 'abcdefg' }))
    expect(errors.some((e) => e.property === 'password')).toBe(true)
  })

  // Verifies that a password of exactly 128 characters satisfies the @Length(8, 128) maximum boundary.
  it('should pass when password is exactly 128 characters (maximum boundary)', async () => {
    const errors = await validate(buildDto({ password: 'a'.repeat(128) }))
    expect(errors).toHaveLength(0)
  })

  // Verifies that a password of 129 characters is rejected by @Length(8, 128) (above maximum).
  it('should fail when password is 129 characters (above maximum)', async () => {
    const errors = await validate(buildDto({ password: 'a'.repeat(129) }))
    expect(errors.some((e) => e.property === 'password')).toBe(true)
  })
})
