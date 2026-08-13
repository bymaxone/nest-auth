import { IsString, MaxLength } from 'class-validator'

import { deriveRequestSchema, readValidationMetadata } from './derive-request-schemas'
import type { ValidationEntry } from './derive-request-schemas'
import { RegisterDto } from '../dto/register.dto'
import { VerifyEmailDto } from '../dto/verify-email.dto'

/** Builds a reader over fixed entries, standing in for class-validator's storage. */
const reader =
  (...entries: ValidationEntry[]) =>
  () =>
    entries

/** A `customValidation` entry, the shape every decorator-registered validator produces. */
const validator = (
  propertyName: string,
  name: string,
  ...constraints: unknown[]
): ValidationEntry => ({ propertyName, type: 'customValidation', name, constraints })

describe('deriveRequestSchema', () => {
  // Verifies the default reader is class-validator's storage, so the production path is the one
  // the conformance artifact is generated from rather than a test seam left wired in.
  it('reads class-validator metadata by default', () => {
    expect(readValidationMetadata(VerifyEmailDto).length).toBeGreaterThan(0)
    expect(deriveRequestSchema(VerifyEmailDto).properties['otp']).toEqual({
      type: 'string',
      minLength: 6,
      maxLength: 6
    })
  })

  // Verifies the eight validators the DTOs use each reach the schema, on a real DTO rather than
  // on synthetic entries — the mapping has to hold for what the decorators actually register.
  it('maps the decorators a real DTO carries', () => {
    const schema = deriveRequestSchema(RegisterDto)

    expect(schema.properties['email']).toEqual({
      type: 'string',
      format: 'email',
      maxLength: 255
    })
    expect(schema.properties['password']).toEqual({
      type: 'string',
      minLength: 8,
      maxLength: 128
    })
    // `@IsOptional()` reaches the derivation as a conditional entry, so the property exists but
    // is not required.
    expect(schema.required).toEqual(['email', 'name', 'password'])
    expect(schema.properties['tenantId']).toBeDefined()
  })

  // Verifies the schema describes the CONJUNCTION the validators enforce. Stacked decorators
  // validate conjunctively, so `@Length(6, 6)` ∧ `@IsNotEmpty()` accepts exactly length-6
  // strings; `minLength: 6` is the only correct description of that, not a stricter option
  // chosen over a weaker one. Order-independence follows, because intersection is commutative.
  it('keeps the stricter minLength when isNotEmpty also applies', () => {
    const schema = deriveRequestSchema(
      class {},
      reader(validator('code', 'isLength', 6, 6), validator('code', 'isNotEmpty'))
    )

    expect(schema.properties['code']).toEqual({ type: 'string', minLength: 6, maxLength: 6 })
  })

  // Verifies isNotEmpty alone still establishes the empty-string floor.
  it('applies minLength 1 for isNotEmpty when nothing stricter is present', () => {
    const schema = deriveRequestSchema(class {}, reader(validator('slug', 'isNotEmpty')))

    expect(schema.properties['slug']).toEqual({ type: 'string', minLength: 1 })
  })

  // Verifies a validator nothing maps is ignored rather than guessed. Guessing produces a
  // constraint that is confidently wrong; ignoring produces a visible gap in the artifact.
  it('ignores a validator it does not map', () => {
    const schema = deriveRequestSchema(class {}, reader(validator('age', 'isInt')))

    expect(schema.properties['age']).toEqual({ type: 'string' })
  })

  // Verifies the constraint-shape guards. Decorators cannot produce these today; the seam
  // exists so they are verified rather than merely present.
  it.each([
    ['maxLength', 'notANumber'],
    ['minLength', 'notANumber'],
    ['isLength', 'notANumber']
  ])('ignores a %s constraint that is not a number', (name, value) => {
    const schema = deriveRequestSchema(class {}, reader(validator('field', name, value, value)))

    expect(schema.properties['field']).toEqual({ type: 'string' })
  })

  // Verifies `matches` only writes a pattern when the constraint really is a RegExp — a string
  // would otherwise reach the document as `pattern: undefined` or as the string itself.
  it('ignores a matches constraint that is not a RegExp', () => {
    const schema = deriveRequestSchema(class {}, reader(validator('field', 'matches', '^a$')))

    expect(schema.properties['field']).toEqual({ type: 'string' })
  })

  // Verifies a RegExp constraint yields its source, which is what OpenAPI's `pattern` takes.
  it('writes the RegExp source as pattern', () => {
    const schema = deriveRequestSchema(class {}, reader(validator('field', 'matches', /^a$/)))

    expect(schema.properties['field']).toEqual({ type: 'string', pattern: '^a$' })
  })

  // Verifies a flagged regex is refused rather than rendered. `.source` alone would publish
  // `^a$` for `/^a$/i` — a pattern stricter than the server enforces, with nothing to say so.
  // ECMA 262 has no inline modifier to rewrite the flag into, so refusal is the only honest
  // output.
  it.each(['i', 'm', 'gi'])('refuses a regex carrying the %s flag', (flags) => {
    const derive = () =>
      deriveRequestSchema(class {}, reader(validator('field', 'matches', new RegExp('^a$', flags))))

    // The whole message is asserted, not just its first clause. It names the offending pattern
    // WITH its flags (so the reader can find it), why 3.0 cannot carry it, and the two ways out.
    // Pinning only the opening phrase would let the actionable half be emptied silently.
    expect(derive).toThrow(`/^a$/${flags} carries regex flags`)
    expect(derive).toThrow('`pattern` cannot express')
    expect(derive).toThrow('Rewrite the pattern without flags')
    expect(derive).toThrow('declare this property in the declared overlay')
  })

  // Verifies grouped validators still reach the schema. Measured: reading the metadata with
  // `strictGroups: true` returns ZERO entries for a class whose validators carry `groups`, so
  // every constraint on a grouped property would vanish with nothing to say so. The schema
  // describes what a field accepts in general, which includes constraints scoped to a group.
  it('includes validators registered under a validation group', () => {
    class Grouped {
      @IsString({ groups: ['create'] })
      @MaxLength(10, { groups: ['create'] })
      scoped!: string
    }

    expect(deriveRequestSchema(Grouped).properties['scoped']).toEqual({
      type: 'string',
      maxLength: 10
    })
  })

  // Verifies an entry with no validator name is skipped without disturbing the property.
  it('tolerates an entry carrying no validator name', () => {
    const schema = deriveRequestSchema(
      class {},
      reader({ propertyName: 'field', type: 'customValidation' })
    )

    expect(schema.properties['field']).toEqual({ type: 'string' })
  })

  // Verifies a conditional entry removes the property from `required` and stops further mapping
  // for that entry — `@IsOptional()` and the single `@ValidateIf()` both arrive this way.
  it('treats a conditional entry as making the property optional', () => {
    const schema = deriveRequestSchema(
      class {},
      reader(
        validator('a', 'isString'),
        { propertyName: 'b', type: 'conditionalValidation' },
        validator('b', 'maxLength', 10)
      )
    )

    expect(schema.required).toEqual(['a'])
    expect(schema.properties['b']).toEqual({ type: 'string', maxLength: 10 })
  })

  // Verifies a DTO with no metadata yields an empty schema rather than throwing. The conformance
  // suite surfaces that as a mismatch against the committed artifact, which is where it should
  // be caught — silently accepting it here would hide a DTO that lost its decorators.
  it('returns an empty schema for a class with no metadata', () => {
    expect(deriveRequestSchema(class {}, reader())).toEqual({
      type: 'object',
      properties: {},
      required: []
    })
  })
})
