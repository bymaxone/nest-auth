import { plainToInstance } from 'class-transformer'
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

  // Verifies the @Transform normalizes the email so the stored identity matches the
  // canonical lowercase form used by every e-mail-keyed control.
  it('should normalize email to lowercase and trimmed via @Transform', () => {
    const dto = plainToInstance(RegisterDto, {
      email: '  NEW.User@Example.COM  ',
      password: 'password123',
      name: 'New User',
      tenantId: 'tenant-1'
    })
    expect(dto.email).toBe('new.user@example.com')
  })

  // Verifies that a non-string email value passes through the @Transform unchanged (false branch).
  it('should pass non-string email through @Transform unchanged', () => {
    const dto = plainToInstance(RegisterDto, {
      email: 42,
      password: 'password123',
      name: 'New User',
      tenantId: 'tenant-1'
    })
    expect((dto as unknown as Record<string, unknown>)['email']).toBe(42)
  })
})
