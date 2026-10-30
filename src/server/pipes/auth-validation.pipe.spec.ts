/**
 * @fileoverview Tests for the validation pipe every auth controller mounts.
 *
 * The pipe's reason to exist is its `exceptionFactory`: Nest's default answers a malformed
 * body in the framework's own shape, while everything else this library throws answers in
 * `{ error: { code, message, details } }`. These tests pin the envelope, the code, and the
 * flattening of class-validator's nested error tree into `[{ field, message }]` — the same
 * shape rust-auth serializes for `auth.validation`.
 */

import {
  IsInt,
  IsNotEmpty,
  IsOptional,
  IsString,
  Min,
  MinLength,
  ValidateNested
} from 'class-validator'
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

describe('createAuthValidationPipe — a missing body', () => {
  class OptionalDto {
    @IsOptional()
    @IsString()
    password?: string
  }

  // Scenario: no body (undefined, then null) for a DTO whose fields are all optional.
  // Expected: an empty instance of the DTO, never the nil. Why: the base pipe validates `{}` and
  // returns the original nil, and a handler reading `dto.password` cannot run on `undefined`.
  it.each([
    ['undefined', undefined],
    ['null', null]
  ])('hands the handler an empty DTO for a %s body', async (_name, body) => {
    const pipe = createAuthValidationPipe()

    const out: unknown = await pipe.transform(body, { type: 'body', metatype: OptionalDto })

    expect(out).toBeInstanceOf(OptionalDto)
    expect(out).toEqual({})
  })

  // Scenario: no body for a DTO with a required field. Expected: the validation refusal. Why: normalising a nil body must not turn a required field into an accepted one.
  it('still refuses a missing body when a field is required', async () => {
    const pipe = createAuthValidationPipe()

    const caught = await pipe.transform(undefined, METADATA).catch((err: unknown) => err)

    expect(envelopeOf(caught).code).toBe(AUTH_ERROR_CODES.VALIDATION)
  })

  // Scenario: a missing value that is not a body (a query parameter). Expected: left missing.
  // Why: only the body is a DTO this pipe stands in for; a query value has its own meaning of
  // "absent" and is not the pipe's to invent.
  it('leaves a missing non-body value as it is', async () => {
    const pipe = createAuthValidationPipe()

    const out: unknown = await pipe.transform(undefined, { type: 'query', metatype: OptionalDto })

    expect(out).toBeUndefined()
  })

  // Scenario: a missing body on a parameter typed as a primitive, which the pipe does not
  // validate. Expected: left missing. Why: there is no DTO to build, and inventing `{}` for a
  // `string` parameter would be a wrong type.
  it('leaves a missing body alone when its type is not a DTO', async () => {
    const pipe = createAuthValidationPipe()

    const out: unknown = await pipe.transform(undefined, { type: 'body', metatype: String })

    expect(out).toBeUndefined()
  })

  // Scenario: a present body. Expected: unchanged by the normalisation. Why: only a nil body is
  // replaced; an object a client sent must reach the handler as it was validated.
  it('does not replace a body that was sent', async () => {
    const pipe = createAuthValidationPipe()

    const out: unknown = await pipe.transform(
      { password: 'x' },
      { type: 'body', metatype: OptionalDto }
    )

    expect(out).toMatchObject({ password: 'x' })
  })
})
