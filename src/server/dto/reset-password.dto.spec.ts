import { plainToInstance } from 'class-transformer'
import { validate } from 'class-validator'

import { ResetPasswordDto } from './reset-password.dto'

function buildDto(overrides: Partial<ResetPasswordDto> = {}): ResetPasswordDto {
  const dto = new ResetPasswordDto()
  dto.email = 'user@example.com'
  dto.newPassword = 'StrongPass1!'
  dto.tenantId = 'tenant-1'
  return Object.assign(dto, overrides)
}

describe('ResetPasswordDto', () => {
  // Verifies that providing a token as proof alongside valid required fields passes validation.
  it('should pass validation with token proof', async () => {
    const errors = await validate(buildDto({ token: 'some-reset-token' }))
    expect(errors).toHaveLength(0)
  })

  // Verifies that providing an OTP as proof alongside valid required fields passes validation.
  it('should pass validation with otp proof', async () => {
    const errors = await validate(buildDto({ otp: '123456' }))
    expect(errors).toHaveLength(0)
  })

  // Verifies that a verifiedToken of exactly 64 characters passes the @Length(64, 64) constraint.
  it('should pass validation with verifiedToken proof of exactly 64 characters', async () => {
    const errors = await validate(buildDto({ verifiedToken: 'a'.repeat(64) }))
    expect(errors).toHaveLength(0)
  })

  // Verifies that the DTO allows zero proof fields because the service enforces the exactly-one constraint.
  it('should pass validation without any proof field', async () => {
    const errors = await validate(buildDto())
    expect(errors).toHaveLength(0)
  })

  // Verifies that a non-email string in the email field produces a validation error.
  it('should fail when email is invalid', async () => {
    const errors = await validate(buildDto({ email: 'not-an-email' }))
    expect(errors.some((e) => e.property === 'email')).toBe(true)
  })

  // Verifies that a password shorter than 8 characters is rejected by the @MinLength constraint.
  it('should fail when newPassword is shorter than 8 characters', async () => {
    const errors = await validate(buildDto({ newPassword: 'short1!' }))
    expect(errors.some((e) => e.property === 'newPassword')).toBe(true)
  })

  // Verifies that a password longer than 128 characters is rejected by the @MaxLength constraint.
  it('should fail when newPassword exceeds 128 characters', async () => {
    const errors = await validate(buildDto({ newPassword: 'A1!'.padEnd(129, 'a') }))
    expect(errors.some((e) => e.property === 'newPassword')).toBe(true)
  })

  // Verifies that an empty string for token is rejected by @IsNotEmpty to prevent blank-token bypass.
  it('should fail when token is an empty string', async () => {
    const errors = await validate(buildDto({ token: '' }))
    expect(errors.some((e) => e.property === 'token')).toBe(true)
  })

  // Verifies that a token longer than 2048 characters is rejected by the @MaxLength constraint.
  it('should fail when token exceeds 2048 characters', async () => {
    const errors = await validate(buildDto({ token: 'a'.repeat(2049) }))
    expect(errors.some((e) => e.property === 'token')).toBe(true)
  })

  // Verifies that an OTP shorter than 4 characters is rejected by the @Length(4, 8) constraint.
  it('should fail when otp is shorter than 4 characters', async () => {
    const errors = await validate(buildDto({ otp: '123' }))
    expect(errors.some((e) => e.property === 'otp')).toBe(true)
  })

  // Verifies that an OTP longer than 8 characters is rejected by the @Length(4, 8) constraint.
  it('should fail when otp is longer than 8 characters', async () => {
    const errors = await validate(buildDto({ otp: '123456789' }))
    expect(errors.some((e) => e.property === 'otp')).toBe(true)
  })

  // Verifies that a verifiedToken other than exactly 64 characters is rejected by @Length(64, 64).
  it('should fail when verifiedToken is not exactly 64 characters', async () => {
    const errors = await validate(buildDto({ verifiedToken: 'a'.repeat(63) }))
    expect(errors.some((e) => e.property === 'verifiedToken')).toBe(true)
  })

  // Verifies that an empty tenantId string is rejected because @IsNotEmpty is applied.
  it('should fail when tenantId is empty', async () => {
    const errors = await validate(buildDto({ tenantId: '' }))
    expect(errors.some((e) => e.property === 'tenantId')).toBe(true)
  })

  // Verifies that a tenantId longer than 128 characters is rejected by the @MaxLength constraint.
  it('should fail when tenantId exceeds 128 characters', async () => {
    const errors = await validate(buildDto({ tenantId: 'a'.repeat(129) }))
    expect(errors.some((e) => e.property === 'tenantId')).toBe(true)
  })

  // Verifies that the @Transform decorator lowercases and trims the email when the value is a string.
  it('should normalize email to lowercase and trimmed via @Transform', () => {
    const dto = plainToInstance(ResetPasswordDto, {
      email: '  USER@EXAMPLE.COM  ',
      newPassword: 'StrongPass1!',
      tenantId: 'tenant-1'
    })
    expect(dto.email).toBe('user@example.com')
  })

  // Verifies that a non-string email value passes through the @Transform unchanged (false branch).
  it('should pass non-string email through @Transform unchanged', () => {
    const dto = plainToInstance(ResetPasswordDto, {
      email: 42,
      newPassword: 'StrongPass1!',
      tenantId: 'tenant-1'
    })
    expect((dto as unknown as Record<string, unknown>)['email']).toBe(42)
  })
})
