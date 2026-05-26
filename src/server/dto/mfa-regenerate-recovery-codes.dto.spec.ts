import { validate } from 'class-validator'

import { MfaRegenerateRecoveryCodesDto } from './mfa-regenerate-recovery-codes.dto'

function buildDto(
  overrides: Partial<MfaRegenerateRecoveryCodesDto> = {}
): MfaRegenerateRecoveryCodesDto {
  const dto = new MfaRegenerateRecoveryCodesDto()
  dto.code = '123456'
  return Object.assign(dto, overrides)
}

describe('MfaRegenerateRecoveryCodesDto', () => {
  // Verifies that a fully valid DTO with a 6-digit TOTP passes class-validator.
  it('should pass validation with a 6-digit code', async () => {
    const errors = await validate(buildDto())
    expect(errors).toHaveLength(0)
  })

  // Verifies that an empty code is rejected (defence against unauthenticated calls
  // hitting the regenerate route with no proof factor at all).
  it('should fail validation when code is empty', async () => {
    const errors = await validate(buildDto({ code: '' }))
    expect(errors.some((e) => e.property === 'code')).toBe(true)
  })

  // Verifies that codes shorter than 6 digits are rejected at the DTO boundary
  // so they never reach the service-layer TOTP comparison.
  it('should fail validation when code has fewer than 6 digits', async () => {
    const errors = await validate(buildDto({ code: '12345' }))
    expect(errors.some((e) => e.property === 'code')).toBe(true)
  })

  // Verifies that codes longer than 6 digits are rejected — this also makes
  // recovery code submission (XXXX-XXXX-XXXX-XXXX-XXXX-XXXX format) structurally
  // impossible, matching the disable endpoint's TOTP-only posture.
  it('should fail validation when code has more than 6 digits', async () => {
    const errors = await validate(buildDto({ code: '1234567' }))
    expect(errors.some((e) => e.property === 'code')).toBe(true)
  })

  // Verifies that codes containing non-digit characters are rejected — this also
  // eliminates the formatted recovery code path.
  it('should fail validation when code contains non-digit characters', async () => {
    const errors = await validate(buildDto({ code: '12345a' }))
    expect(errors.some((e) => e.property === 'code')).toBe(true)
  })

  // Verifies that a recovery-code shape (XXXX-XXXX-XXXX-XXXX-XXXX-XXXX) is
  // rejected — recovery codes must NOT be accepted as the regenerate proof
  // factor. Pins the "TOTP only" product decision encoded in the DTO.
  it('should fail validation when code is a recovery code string', async () => {
    const errors = await validate(buildDto({ code: '1234-5678-9012-3456-7890-1234' }))
    expect(errors.some((e) => e.property === 'code')).toBe(true)
  })
})
