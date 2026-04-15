/**
 * PlatformLoginDto — unit tests
 *
 * Tests the DTO validation rules and Transform decorator for the platform admin
 * login endpoint. Uses class-validator's `validate()` and class-transformer's
 * `plainToInstance()` directly — no NestJS TestingModule is required for DTO tests.
 *
 * Each test calls plainToInstance() first so that @Transform decorators run,
 * then validate() to execute @IsEmail, @MinLength, etc.
 */

import { plainToInstance } from 'class-transformer'
import { validate } from 'class-validator'

import { PlatformLoginDto } from './platform-login.dto'

// ---------------------------------------------------------------------------
// Helper — builds a dto with optional field overrides and runs validation
// ---------------------------------------------------------------------------

async function buildAndValidate(
  plain: Record<string, unknown>
): Promise<{ dto: PlatformLoginDto; errors: Awaited<ReturnType<typeof validate>> }> {
  const dto = plainToInstance(PlatformLoginDto, plain)
  const errors = await validate(dto)
  return { dto, errors }
}

// ---------------------------------------------------------------------------
// PlatformLoginDto — email field
// ---------------------------------------------------------------------------

describe('PlatformLoginDto — email field', () => {
  // ---------------------------------------------------------------------------
  // @Transform — trim and lowercase
  // ---------------------------------------------------------------------------

  describe('@Transform (trim + toLowerCase)', () => {
    // The Transform decorator must trim leading/trailing spaces and lowercase the value
    // before validation runs. A valid uppercase email with spaces becomes a clean string.
    it('should trim and lowercase a string email with surrounding spaces', async () => {
      const { dto } = await buildAndValidate({
        email: '  Admin@Example.COM  ',
        password: 'ValidPassword123'
      })
      expect(dto.email).toBe('admin@example.com')
    })

    // When the value is not a string (e.g. a number), the Transform passes it through
    // unchanged. The subsequent @IsEmail decorator will then reject it.
    it('should pass through non-string values unchanged (e.g. 42)', async () => {
      const { dto, errors } = await buildAndValidate({
        email: 42,
        password: 'ValidPassword123'
      })
      // The raw value was preserved by the transform
      expect((dto as unknown as { email: unknown }).email).toBe(42)
      // @IsEmail must fail because 42 is not a valid email
      const emailErrors = errors.filter((e) => e.property === 'email')
      expect(emailErrors.length).toBeGreaterThan(0)
    })
  })

  // ---------------------------------------------------------------------------
  // @IsEmail
  // ---------------------------------------------------------------------------

  describe('@IsEmail', () => {
    // A properly formatted email address must pass all email-related validators.
    it('should pass validation for a valid email', async () => {
      const { errors } = await buildAndValidate({
        email: 'admin@example.com',
        password: 'ValidPassword123'
      })
      const emailErrors = errors.filter((e) => e.property === 'email')
      expect(emailErrors).toHaveLength(0)
    })

    // A string that is not a valid email (missing @ sign) must fail @IsEmail.
    it('should fail validation for an invalid email format (missing @)', async () => {
      const { errors } = await buildAndValidate({
        email: 'not-an-email',
        password: 'ValidPassword123'
      })
      const emailErrors = errors.filter((e) => e.property === 'email')
      expect(emailErrors.length).toBeGreaterThan(0)
    })

    // An email-like string missing the domain part must fail @IsEmail.
    it('should fail validation for an email missing the domain', async () => {
      const { errors } = await buildAndValidate({
        email: 'admin@',
        password: 'ValidPassword123'
      })
      const emailErrors = errors.filter((e) => e.property === 'email')
      expect(emailErrors.length).toBeGreaterThan(0)
    })
  })

  // ---------------------------------------------------------------------------
  // @IsNotEmpty
  // ---------------------------------------------------------------------------

  describe('@IsNotEmpty', () => {
    // An empty string must fail @IsNotEmpty even though it might pass @IsEmail on some
    // versions of class-validator. We check that at least one email error is present.
    it('should fail validation for an empty string email', async () => {
      const { errors } = await buildAndValidate({
        email: '',
        password: 'ValidPassword123'
      })
      const emailErrors = errors.filter((e) => e.property === 'email')
      expect(emailErrors.length).toBeGreaterThan(0)
    })
  })

  // ---------------------------------------------------------------------------
  // @MaxLength(255)
  // ---------------------------------------------------------------------------

  describe('@MaxLength(255)', () => {
    // A string exceeding 255 characters must fail the @MaxLength constraint.
    it('should fail validation for an email exceeding 255 characters', async () => {
      // 246 'a' chars + '@x.com' = 252 + local overhead → total > 255
      const longLocal = 'a'.repeat(250)
      const { errors } = await buildAndValidate({
        email: `${longLocal}@x.com`,
        password: 'ValidPassword123'
      })
      const emailErrors = errors.filter((e) => e.property === 'email')
      expect(emailErrors.length).toBeGreaterThan(0)
    })
  })
})

// ---------------------------------------------------------------------------
// PlatformLoginDto — password field
// ---------------------------------------------------------------------------

describe('PlatformLoginDto — password field', () => {
  // ---------------------------------------------------------------------------
  // @IsString
  // ---------------------------------------------------------------------------

  describe('@IsString', () => {
    // A numeric value must fail @IsString; the guard prevents non-string payloads.
    it('should fail validation when password is a number (123)', async () => {
      const { errors } = await buildAndValidate({
        email: 'admin@example.com',
        password: 123
      })
      const pwErrors = errors.filter((e) => e.property === 'password')
      expect(pwErrors.length).toBeGreaterThan(0)
    })
  })

  // ---------------------------------------------------------------------------
  // @IsNotEmpty
  // ---------------------------------------------------------------------------

  describe('@IsNotEmpty', () => {
    // An empty string must fail @IsNotEmpty. An admin must supply a non-empty password.
    it('should fail validation for an empty password string', async () => {
      const { errors } = await buildAndValidate({
        email: 'admin@example.com',
        password: ''
      })
      const pwErrors = errors.filter((e) => e.property === 'password')
      expect(pwErrors.length).toBeGreaterThan(0)
    })
  })

  // ---------------------------------------------------------------------------
  // @Matches(/\S/) — no all-whitespace passwords
  // ---------------------------------------------------------------------------

  describe('@Matches(/\\S/)', () => {
    // A 12-character all-whitespace string passes @MinLength and @IsString but must
    // fail the @Matches(/\S/) constraint that ensures at least one non-whitespace char.
    it('should fail validation for a 12-character whitespace-only password', async () => {
      const { errors } = await buildAndValidate({
        email: 'admin@example.com',
        password: '            ' // exactly 12 spaces
      })
      const pwErrors = errors.filter((e) => e.property === 'password')
      expect(pwErrors.length).toBeGreaterThan(0)
    })
  })

  // ---------------------------------------------------------------------------
  // @MinLength(12)
  // ---------------------------------------------------------------------------

  describe('@MinLength(12)', () => {
    // An 11-character password is one char below the minimum and must fail.
    it('should fail validation for an 11-character password', async () => {
      const { errors } = await buildAndValidate({
        email: 'admin@example.com',
        password: 'ShortPass01'
      })
      const pwErrors = errors.filter((e) => e.property === 'password')
      expect(pwErrors.length).toBeGreaterThan(0)
    })

    // Exactly 12 characters is the boundary value and must pass.
    it('should pass validation for a 12-character password', async () => {
      const { errors } = await buildAndValidate({
        email: 'admin@example.com',
        password: 'Exactly12Chr'
      })
      const pwErrors = errors.filter((e) => e.property === 'password')
      expect(pwErrors).toHaveLength(0)
    })
  })

  // ---------------------------------------------------------------------------
  // @MaxLength(128)
  // ---------------------------------------------------------------------------

  describe('@MaxLength(128)', () => {
    // A password exceeding 128 characters must be rejected to prevent DoS via
    // oversized payloads hitting the scrypt/bcrypt hash function.
    it('should fail validation for a password exceeding 128 characters', async () => {
      const { errors } = await buildAndValidate({
        email: 'admin@example.com',
        password: 'A'.repeat(129)
      })
      const pwErrors = errors.filter((e) => e.property === 'password')
      expect(pwErrors.length).toBeGreaterThan(0)
    })

    // Exactly 128 characters is the upper boundary value and must pass.
    it('should pass validation for a 128-character password', async () => {
      const { errors } = await buildAndValidate({
        email: 'admin@example.com',
        password: 'A'.repeat(128)
      })
      const pwErrors = errors.filter((e) => e.property === 'password')
      expect(pwErrors).toHaveLength(0)
    })
  })

  // ---------------------------------------------------------------------------
  // Happy path — both fields valid
  // ---------------------------------------------------------------------------

  describe('happy path', () => {
    // A valid email and a valid password must produce zero validation errors.
    it('should pass validation when email and password are both valid', async () => {
      const { errors } = await buildAndValidate({
        email: 'admin@example.com',
        password: 'SecurePassword42'
      })
      expect(errors).toHaveLength(0)
    })
  })
})
