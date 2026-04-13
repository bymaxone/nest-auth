import { validate } from 'class-validator'

import { LoginDto } from './login.dto'

function buildDto(overrides: Partial<LoginDto> = {}): LoginDto {
  const dto = new LoginDto()
  dto.email = 'user@example.com'
  dto.password = 'anypassword'
  dto.tenantId = 'tenant-1'
  return Object.assign(dto, overrides)
}

describe('LoginDto', () => {
  // Verifies that a fully valid LoginDto passes class-validator with zero errors.
  it('should pass validation with valid data', async () => {
    const errors = await validate(buildDto())
    expect(errors).toHaveLength(0)
  })

  // Verifies that a non-email string in the email field produces a validation error.
  it('should fail when email is invalid', async () => {
    const errors = await validate(buildDto({ email: 'not-an-email' }))
    expect(errors.some((e) => e.property === 'email')).toBe(true)
  })

  // Verifies that a password longer than 128 characters is rejected by the @MaxLength constraint.
  it('should fail when password is longer than 128 characters', async () => {
    const errors = await validate(buildDto({ password: 'a'.repeat(129) }))
    expect(errors.some((e) => e.property === 'password')).toBe(true)
  })

  // Verifies that LoginDto deliberately has no @MinLength on password to prevent min-length enumeration.
  it('should pass validation for a short password (no MinLength restriction)', async () => {
    // Deliberate: login allows any password length to prevent min-length enumeration.
    const errors = await validate(buildDto({ password: '1' }))
    expect(errors).toHaveLength(0)
  })

  // Verifies that an empty password passes validation in LoginDto (anti-enumeration design decision).
  it('should pass validation for an empty password (anti-enumeration)', async () => {
    const errors = await validate(buildDto({ password: '' }))
    expect(errors).toHaveLength(0)
  })

  // Verifies that an empty tenantId string is rejected because @IsNotEmpty is applied.
  it('should fail when tenantId is empty', async () => {
    const errors = await validate(buildDto({ tenantId: '' }))
    expect(errors.some((e) => e.property === 'tenantId')).toBe(true)
  })
})
