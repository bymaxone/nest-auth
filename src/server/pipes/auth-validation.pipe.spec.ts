/**
 * @fileoverview Tests for the validation pipe every auth controller mounts.
 *
 * The pipe's reason to exist is its `exceptionFactory`: Nest's default answers a malformed
 * body in the framework's own shape, while everything else this library throws answers in
 * `{ error: { code, message, details } }`. These tests pin the envelope, the code, and the
 * flattening of class-validator's nested error tree into `[{ field, message }]` — the same
 * shape rust-auth serializes for `auth.validation`.
 */

import { IsInt, IsNotEmpty, IsString, Min, MinLength, ValidateNested } from 'class-validator'
import { Type } from 'class-transformer'

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { createAuthValidationPipe } from './auth-validation.pipe'

import type { ArgumentMetadata } from '@nestjs/common'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

class NestedDto {
  @IsInt()
  @Min(1)
  quantity!: number
}

class SampleDto {
  @IsString()
  @IsNotEmpty()
  @MinLength(3)
  email!: string

  @ValidateNested()
  @Type(() => NestedDto)
  nested!: NestedDto
}

const METADATA: ArgumentMetadata = { type: 'body', metatype: SampleDto }

/** The `{ error: { ... } }` body an `AuthException` carries. */
function envelopeOf(err: unknown): {
  code: string
  message: string
  details: unknown
} {
  if (!(err instanceof AuthException)) throw new Error('not an AuthException')
  return (err.getResponse() as { error: { code: string; message: string; details: unknown } }).error
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('createAuthValidationPipe', () => {
  it('answers a malformed body in the library envelope, not the framework default', async () => {
    const pipe = createAuthValidationPipe()

    const caught = await pipe
      .transform({ email: '', nested: { quantity: 3 } }, METADATA)
      .catch((err: unknown) => err)

    // Nest's own rejection would be `{ statusCode, message, error }` — a second shape a client
    // parsing `error.code` cannot read, and the one that says which field to fix.
    expect(caught).toBeInstanceOf(AuthException)
    expect(envelopeOf(caught).code).toBe(AUTH_ERROR_CODES.VALIDATION)
    expect((caught as AuthException).getStatus()).toBe(400)
  })

  it('names every offending field, nested ones by their dotted path', async () => {
    const pipe = createAuthValidationPipe()

    const caught = await pipe
      .transform({ email: '', nested: { quantity: 0 } }, METADATA)
      .catch((err: unknown) => err)

    const details = envelopeOf(caught).details as { field: string; message: string }[]
    expect(details.map((d) => d.field)).toEqual(
      expect.arrayContaining(['email', 'nested.quantity'])
    )
    // The message is what a caller acts on, so it travels rather than being replaced by a
    // generic "invalid".
    expect(details.every((d) => d.message.length > 0)).toBe(true)
  })

  it('reports every constraint a single field broke, not only the first', async () => {
    const pipe = createAuthValidationPipe()

    const caught = await pipe
      .transform({ email: '', nested: { quantity: 1 } }, METADATA)
      .catch((err: unknown) => err)

    const details = envelopeOf(caught).details as { field: string }[]
    // `''` fails both `@IsNotEmpty` and `@MinLength` — one field, two entries.
    expect(details.filter((d) => d.field === 'email').length).toBeGreaterThan(1)
  })

  it('rejects properties the DTO does not declare', async () => {
    const pipe = createAuthValidationPipe()

    const caught = await pipe
      .transform({ email: 'a@e.com', nested: { quantity: 1 }, isAdmin: true }, METADATA)
      .catch((err: unknown) => err)

    const details = envelopeOf(caught).details as { field: string }[]
    expect(details.some((d) => d.field === 'isAdmin')).toBe(true)
  })

  it('lets a caller add options without losing the envelope', async () => {
    const pipe = createAuthValidationPipe({ forbidUnknownValues: true })

    const caught = await pipe.transform({}, METADATA).catch((err: unknown) => err)

    expect(envelopeOf(caught).code).toBe(AUTH_ERROR_CODES.VALIDATION)
  })

  it('passes a valid payload through untouched', async () => {
    const pipe = createAuthValidationPipe()

    await expect(
      pipe.transform({ email: 'a@e.com', nested: { quantity: 2 } }, METADATA)
    ).resolves.toMatchObject({ email: 'a@e.com' })
  })
})
