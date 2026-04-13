import { validate } from 'class-validator'

import { RegisterDto } from './register.dto'

function buildDto(overrides: Partial<RegisterDto> = {}): RegisterDto {
  const dto = new RegisterDto()
  dto.email = 'user@example.com'
  dto.password = 'SecureP@ss1'
  dto.name = 'Test User'
  dto.tenantId = 'tenant-1'
  return Object.assign(dto, overrides)
}

describe('RegisterDto', () => {
  // Verifies that a fully valid DTO passes class-validator with zero errors.
  it('should pass validation with valid data', async () => {
    const errors = await validate(buildDto())
    expect(errors).toHaveLength(0)
  })

  // Verifies that a non-email string in the email field produces a validation error.
  it('should fail when email is invalid', async () => {
    const errors = await validate(buildDto({ email: 'not-an-email' }))
    expect(errors.some((e) => e.property === 'email')).toBe(true)
  })

  // Verifies that a password shorter than 8 characters is rejected by the @MinLength constraint.
  it('should fail when password is shorter than 8 characters', async () => {
    const errors = await validate(buildDto({ password: 'short' }))
    expect(errors.some((e) => e.property === 'password')).toBe(true)
  })

  // Verifies that a password longer than 128 characters is rejected by the @MaxLength constraint.
  it('should fail when password is longer than 128 characters', async () => {
    const errors = await validate(buildDto({ password: 'a'.repeat(129) }))
    expect(errors.some((e) => e.property === 'password')).toBe(true)
  })

  // Verifies that exactly 8 characters is the minimum valid password length (boundary test).
  it('should accept a password of exactly 8 characters', async () => {
    const errors = await validate(buildDto({ password: 'abcdefgh' }))
    expect(errors).toHaveLength(0)
  })

  // Verifies that exactly 128 characters is the maximum valid password length (boundary test).
  it('should accept a password of exactly 128 characters', async () => {
    const errors = await validate(buildDto({ password: 'a'.repeat(128) }))
    expect(errors).toHaveLength(0)
  })

  // Verifies that a name shorter than 2 characters is rejected by the @MinLength constraint.
  it('should fail when name is shorter than 2 characters', async () => {
    const errors = await validate(buildDto({ name: 'A' }))
    expect(errors.some((e) => e.property === 'name')).toBe(true)
  })

  // Verifies that an empty tenantId string is rejected because @IsNotEmpty is applied.
  it('should fail when tenantId is empty', async () => {
    const errors = await validate(buildDto({ tenantId: '' }))
    expect(errors.some((e) => e.property === 'tenantId')).toBe(true)
  })
})
