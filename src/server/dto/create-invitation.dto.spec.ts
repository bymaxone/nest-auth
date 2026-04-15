/**
 * Unit tests for CreateInvitationDto.
 *
 * Uses class-validator `validate()` directly on instances built with the
 * `buildDto` helper. `plainToInstance` is used only for the @Transform branch
 * tests to exercise the class-transformer pipeline.
 *
 * No rendering strategy needed — pure DTO validation logic.
 */

import { plainToInstance } from 'class-transformer'
import { validate } from 'class-validator'

import { CreateInvitationDto } from './create-invitation.dto'

function buildDto(overrides: Partial<CreateInvitationDto> = {}): CreateInvitationDto {
  const dto = new CreateInvitationDto()
  dto.email = 'invitee@example.com'
  dto.role = 'member'
  return Object.assign(dto, overrides)
}

// ---------------------------------------------------------------------------
// CreateInvitationDto — field-level validation
// ---------------------------------------------------------------------------

describe('CreateInvitationDto', () => {
  // Verifies that a fully valid DTO with required fields only passes with zero errors.
  it('should pass validation with required fields only (no tenantName)', async () => {
    const errors = await validate(buildDto())
    expect(errors).toHaveLength(0)
  })

  // Verifies that a fully valid DTO including the optional tenantName field also passes.
  it('should pass validation with optional tenantName provided', async () => {
    const errors = await validate(buildDto({ tenantName: 'Acme Corp' }))
    expect(errors).toHaveLength(0)
  })

  // -------------------------------------------------------------------------
  // email field
  // -------------------------------------------------------------------------

  // Verifies that a non-email string in the email field produces a validation error.
  it('should fail when email is not a valid email format', async () => {
    const errors = await validate(buildDto({ email: 'not-an-email' }))
    expect(errors.some((e) => e.property === 'email')).toBe(true)
  })

  // Verifies that an empty email string is rejected by @IsNotEmpty.
  it('should fail when email is an empty string', async () => {
    const errors = await validate(buildDto({ email: '' }))
    expect(errors.some((e) => e.property === 'email')).toBe(true)
  })

  // Verifies that an email exceeding 255 characters is rejected by @MaxLength(255).
  it('should fail when email exceeds 255 characters', async () => {
    const errors = await validate(buildDto({ email: `${'a'.repeat(250)}@b.com` }))
    expect(errors.some((e) => e.property === 'email')).toBe(true)
  })

  // Verifies that the @Transform decorator lowercases and trims the email when the value is a string.
  it('should normalize email to lowercase and trimmed via @Transform', () => {
    const dto = plainToInstance(CreateInvitationDto, {
      email: '  INVITEE@EXAMPLE.COM  ',
      role: 'member'
    })
    expect(dto.email).toBe('invitee@example.com')
  })

  // Verifies that a non-string email value passes through the @Transform unchanged (false branch).
  it('should pass non-string email through @Transform unchanged', () => {
    const dto = plainToInstance(CreateInvitationDto, { email: 42, role: 'member' })
    expect((dto as unknown as Record<string, unknown>)['email']).toBe(42)
  })

  // -------------------------------------------------------------------------
  // role field
  // -------------------------------------------------------------------------

  // Verifies that an empty role string is rejected by @IsNotEmpty.
  it('should fail when role is an empty string', async () => {
    const errors = await validate(buildDto({ role: '' }))
    expect(errors.some((e) => e.property === 'role')).toBe(true)
  })

  // Verifies that a role exceeding 64 characters is rejected by @MaxLength(64).
  it('should fail when role exceeds 64 characters', async () => {
    const errors = await validate(buildDto({ role: 'a'.repeat(65) }))
    expect(errors.some((e) => e.property === 'role')).toBe(true)
  })

  // Verifies that a role of exactly 64 characters is accepted (boundary value).
  it('should pass when role is exactly 64 characters', async () => {
    const errors = await validate(buildDto({ role: 'a'.repeat(64) }))
    expect(errors).toHaveLength(0)
  })

  // -------------------------------------------------------------------------
  // tenantName field (optional)
  // -------------------------------------------------------------------------

  // Verifies that omitting the optional tenantName field entirely passes validation.
  it('should pass when tenantName is omitted (field is optional)', async () => {
    const dto = buildDto()
    // Ensure the property is absent, not just undefined via assignment
    delete (dto as Partial<CreateInvitationDto>).tenantName
    const errors = await validate(dto)
    expect(errors).toHaveLength(0)
  })

  // Verifies that an empty string for tenantName is rejected by @IsNotEmpty even though the field is optional.
  it('should fail when tenantName is an empty string', async () => {
    const errors = await validate(buildDto({ tenantName: '' }))
    expect(errors.some((e) => e.property === 'tenantName')).toBe(true)
  })

  // Verifies that a tenantName exceeding 128 characters is rejected by @MaxLength(128).
  it('should fail when tenantName exceeds 128 characters', async () => {
    const errors = await validate(buildDto({ tenantName: 'a'.repeat(129) }))
    expect(errors.some((e) => e.property === 'tenantName')).toBe(true)
  })

  // Verifies that a tenantName of exactly 128 characters is accepted (boundary value).
  it('should pass when tenantName is exactly 128 characters', async () => {
    const errors = await validate(buildDto({ tenantName: 'a'.repeat(128) }))
    expect(errors).toHaveLength(0)
  })
})
