import { plainToInstance } from 'class-transformer'
import { validate } from 'class-validator'

import { VerifyOtpDto } from './verify-otp.dto'

function buildDto(overrides: Partial<VerifyOtpDto> = {}): VerifyOtpDto {
  const dto = new VerifyOtpDto()
  dto.email = 'user@example.com'
  dto.otp = '123456'
  dto.tenantId = 'tenant-1'
  return Object.assign(dto, overrides)
}

describe('VerifyOtpDto', () => {
  // Verifies that a fully valid VerifyOtpDto passes class-validator with zero errors.
  it('should pass validation with valid data', async () => {
    const errors = await validate(buildDto())
    expect(errors).toHaveLength(0)
  })

  // Verifies that a non-email string in the email field produces a validation error.
  it('should fail when email is invalid', async () => {
    const errors = await validate(buildDto({ email: 'not-an-email' }))
    expect(errors.some((e) => e.property === 'email')).toBe(true)
  })

  // Verifies that an email longer than 255 characters is rejected by the @MaxLength constraint.
  it('should fail when email exceeds 255 characters', async () => {
    const errors = await validate(buildDto({ email: `${'a'.repeat(250)}@b.com` }))
    expect(errors.some((e) => e.property === 'email')).toBe(true)
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

  // Verifies that exactly 4 characters is the minimum valid OTP length (boundary test).
  it('should accept an otp of exactly 4 characters', async () => {
    const errors = await validate(buildDto({ otp: '1234' }))
    expect(errors).toHaveLength(0)
  })

  // Verifies that exactly 8 characters is the maximum valid OTP length (boundary test).
  it('should accept an otp of exactly 8 characters', async () => {
    const errors = await validate(buildDto({ otp: '12345678' }))
    expect(errors).toHaveLength(0)
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
    const dto = plainToInstance(VerifyOtpDto, {
      email: '  USER@EXAMPLE.COM  ',
      otp: '123456',
      tenantId: 'tenant-1'
    })
    expect(dto.email).toBe('user@example.com')
  })

  // Verifies that a non-string email value passes through the @Transform unchanged (false branch).
  it('should pass non-string email through @Transform unchanged', () => {
    const dto = plainToInstance(VerifyOtpDto, { email: 42, otp: '123456', tenantId: 'tenant-1' })
    expect((dto as unknown as Record<string, unknown>)['email']).toBe(42)
  })
})
