/**
 * @fileoverview Derives OpenAPI 3.0 request schemas from the DTOs' class-validator metadata.
 *
 * Not exported from the package: nothing reachable from `src/server/index.ts` imports it, so it
 * never enters the published bundle. It exists to produce and then guard
 * `conformance/openapi-request-schemas.json` — the committed artifact a document builder
 * consumes — so the schemas are a function of the decorators rather than a second description
 * of them maintained by hand.
 *
 * Why derivation is a CHECK here and not the source: three of this library's contracts are
 * invisible to a decorator, and a schema derived faithfully would document them wrong —
 * `ResetPasswordDto`'s exactly-one-of proof, the structural `@MinLength(8)` that is not the
 * deployment's `password.minLength` floor, and the conditional requirement on the OAuth
 * callback query.
 *
 * Those three are **named in the generated artifact's own header and nowhere else yet**. The
 * declared overlay that exists today (`openapi-request-descriptions.json`) covers only the
 * e-mail normalisation; expressing the three as structures — the `oneOf`, the `anyOf`, the
 * policy floor — is follow-up work on the same files. Stating it that way rather than as
 * settled is the point: a comment describing an intended state as a present one is how a reader
 * ends up trusting something that is not there.
 *
 * @layer OpenAPI
 */
import { getMetadataStorage } from 'class-validator'

/**
 * The subset of OpenAPI 3.0 a request-body schema needs here.
 *
 * 3.0 rather than 3.1 on purpose: `@nestjs/swagger`'s `DocumentBuilder` emits `3.0.0`, and a
 * 3.1 fragment merged into a 3.0 document validates as neither. The dialect is pinned in the
 * generated artifact so a future migration is one coordinated change instead of a mixture.
 */
export interface DerivedPropertySchema {
  type: 'string'
  format?: 'email'
  minLength?: number
  maxLength?: number
  pattern?: string
}

/** A whole DTO rendered as a 3.0 object schema. */
export interface DerivedObjectSchema {
  type: 'object'
  properties: Record<string, DerivedPropertySchema>
  required: string[]
}

/**
 * A DTO class with validation metadata registered against it.
 *
 * A constructor signature rather than bare `Function`, so the same type satisfies both readers:
 * `getTargetValidationMetadatas` takes any `Function`, and `plainToInstance` requires something
 * constructible. Typing it as `Function` forced a cast at the second call site, which is a type
 * error laundered rather than a type described — the DTOs really are constructible.
 */
export type DtoClass = new (...args: unknown[]) => object

/**
 * The class-validator metadata entry, narrowed to the fields this reads.
 *
 * Structurally compatible with the upstream `ValidationMetadata`, so the production reader
 * returns it with no cast: the narrowing is a restriction, not a reinterpretation.
 *
 * `name` is the discriminator and the reason this is possible at all: every decorator reports
 * `type: 'customValidation'`, so the validator's identity is recoverable only from `name`
 * (`'maxLength'`, `'isEmail'`, …). Reading `type` instead would make `@MinLength(255)` and
 * `@MaxLength(255)` indistinguishable — same shape, same constraint value, opposite meaning.
 */
export interface ValidationEntry {
  propertyName: string
  type: string
  name?: string
  constraints?: unknown[]
}

/**
 * Reads the validation entries registered against a DTO.
 *
 * A parameter rather than a direct call so the mapping can be exercised against entry shapes
 * class-validator does not currently produce. Those shapes are exactly where the guards live —
 * a constraint that is not a number, a `matches` whose argument is not a RegExp, a validator
 * name nothing maps — and they are unreachable through the decorators today. Without the seam
 * they would be untestable defensive code: uncovered, unmutated, and therefore unverified
 * precisely where being wrong would be silent.
 */
export type MetadataReader = (dto: DtoClass) => readonly ValidationEntry[]

/**
 * The production reader: class-validator's own storage.
 *
 * `strictGroups: false` is load-bearing rather than a default worth copying. Measured against a
 * class whose validators carry `groups`, `true` returns **zero** entries — every constraint on a
 * grouped property would vanish from the schema with nothing to say so. The schema documents what
 * a field accepts in general, so it must see grouped validators too; the conformance suite pins
 * this with a grouped fixture.
 */
export const readValidationMetadata: MetadataReader = (dto) =>
  getMetadataStorage().getTargetValidationMetadatas(
    dto,
    // Stryker disable next-line StringLiteral: equivalent. The schema name selects an additional
    // target registered through class-validator's schema API, which this library never uses — an
    // unknown name contributes nothing, so any value returns the same set as the empty one.
    '',
    // Stryker disable next-line BooleanLiteral: equivalent. `always` only re-admits entries that
    // group filtering excluded, and nothing is excluded here because `strictGroups` is false.
    // Measured: a grouped class returns the same two entries under either value.
    false,
    false
  )

/** class-validator's marker for a property whose validation is conditional. */
const CONDITIONAL = 'conditionalValidation'

/**
 * Applies one validator to the property schema being built.
 *
 * Unknown validators are ignored rather than guessed. A decorator this does not map produces a
 * schema missing that constraint, which the committed artifact shows and a reviewer can see —
 * whereas guessing produces a constraint that is confidently wrong.
 *
 * @param schema - The property schema accumulated so far, mutated in place.
 * @param name - The class-validator validator name (`m.name`).
 * @param constraints - The decorator's arguments, as class-validator recorded them.
 */
function applyValidator(
  schema: DerivedPropertySchema,
  name: string,
  constraints: readonly unknown[]
): void {
  const first = constraints[0]
  const second = constraints[1]

  switch (name) {
    case 'isEmail':
      schema.format = 'email'
      break
    case 'maxLength':
      if (typeof first === 'number') schema.maxLength = first
      break
    // Stryker disable next-line ConditionalExpression: equivalent. Removing this arm lets
    // `minLength` fall through to `isLength`, which additionally assigns `maxLength` from
    // `constraints[1]` — and a `@MinLength()` decorator records exactly one constraint, so that
    // second assignment is rejected by its own `typeof` guard. Both paths produce the identical
    // schema; no input distinguishes them.
    case 'minLength':
      if (typeof first === 'number') schema.minLength = first
      break
    // `@Length(min, max)` registers as `isLength`, not `length`. Found by reading the metadata
    // rather than by naming the decorator: an unmapped validator here is silent — it yields a
    // schema missing that constraint, which is why every mapping is checked against a real DTO.
    case 'isLength':
      if (typeof first === 'number') schema.minLength = first
      if (typeof second === 'number') schema.maxLength = second
      break
    case 'isNotEmpty':
      // `@IsNotEmpty()` rejects the empty string, which is `minLength: 1`. Applied only when no
      // stricter floor is present, and that is forced rather than chosen: JSON Schema keywords
      // validate conjunctively, and stacked class-validator decorators do too, so the runtime
      // accepts exactly the intersection. `@Length(6, 6)` ∧ `@IsNotEmpty()` accepts strings of
      // length 6, so `minLength: 6` is the only correct description of it. Order-independence
      // follows for free, because intersection is commutative.
      if (schema.minLength === undefined) schema.minLength = 1
      break
    case 'matches':
      if (first instanceof RegExp) {
        // A flagged regex has no faithful rendering. `pattern` is the ECMA 262 dialect (JSON
        // Schema Wright Draft 00 §5.2.3) and carries no flags slot, and ECMA 262 has no inline
        // `(?i)` modifier to rewrite them into — so emitting `.source` would silently publish a
        // stricter pattern than the server enforces. Refusing at authorship is the same choice
        // as failing on an orphan fragment key: a narrowing nobody can see becomes a build error
        // the moment someone writes the flag.
        if (first.flags !== '') {
          throw new Error(
            `[openapi] /${first.source}/${first.flags} carries regex flags, which OpenAPI 3.0 ` +
              '`pattern` cannot express. Rewrite the pattern without flags, or declare this ' +
              'property in the declared overlay.'
          )
        }
        schema.pattern = first.source
      }
      break
  }
  // No `default` clause on purpose. `default: break` is indistinguishable from its own absence,
  // so it is an equivalent mutant by construction — a branch the gate can never kill and a
  // reader can never test. Omitting it says the same thing and leaves nothing unfalsifiable.
}

/**
 * Derives the 3.0 object schema for one DTO from its live class-validator metadata.
 *
 * A property is omitted from `required` when any conditional validator sits on it. That covers
 * `@IsOptional()` exactly, and `@ValidateIf()` honestly: 3.0 cannot express "required unless
 * another field is present", so declaring it unconditionally required would be a stricter claim
 * than the server enforces. The one place that applies is named in the declared half of the
 * artifact.
 *
 * @param dto - The DTO class to read metadata from.
 * @param read - How to obtain the entries. Defaults to class-validator's storage; overridden in
 *   tests to reach the guards that decorator-produced metadata cannot.
 * @returns The object schema, with properties in declaration order and `required` sorted.
 * @throws `Error` when a mapped `@Matches()` carries regex flags, which OpenAPI 3.0 `pattern`
 *   cannot express — see `applyValidator`. A DTO with no metadata does NOT throw: it yields an
 *   empty schema, which the conformance suite surfaces as a mismatch against the committed
 *   artifact rather than silently accepting.
 */
export function deriveRequestSchema(
  dto: DtoClass,
  read: MetadataReader = readValidationMetadata
): DerivedObjectSchema {
  const entries = read(dto)

  const properties: Record<string, DerivedPropertySchema> = {}
  const conditional = new Set<string>()

  for (const entry of entries) {
    const property = entry.propertyName
    properties[property] ??= { type: 'string' }

    if (entry.type === CONDITIONAL) {
      conditional.add(property)
      continue
    }

    if (entry.name !== undefined) {
      // Stryker disable next-line ArrayDeclaration: equivalent. Every mapped validator reads
      // `constraints[0]`/`[1]` behind a `typeof === 'number'` or `instanceof RegExp` guard, so a
      // non-empty stand-in for the missing array is rejected by the same guard an empty one is —
      // no mapped name can produce a different schema from it, and an unmapped name reads nothing.
      applyValidator(properties[property], entry.name, entry.constraints ?? [])
    }
  }

  const required = Object.keys(properties)
    .filter((property) => !conditional.has(property))
    .sort()

  return { type: 'object', properties, required }
}
