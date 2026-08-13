/**
 * @fileoverview Binds `conformance/openapi-request-schemas.json` to the DTOs it describes.
 *
 * The committed artifact is generated, never hand-edited: run `pnpm gen:openapi-schemas` and
 * review the diff. This suite is what makes that safe — it regenerates from the live
 * class-validator metadata and fails when the committed copy has fallen behind, so a decorator
 * change that nobody mirrored is a red test in the repository that caused it rather than a
 * silently stale document in a consumer's `/docs`.
 *
 * It also pins the set of validators the derivation understands. An unmapped decorator is
 * SILENT — it yields a schema missing that constraint — so a new one must fail here and force a
 * mapping decision instead of thinning the published schema unnoticed.
 */
import { readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import { getMetadataStorage } from 'class-validator'

import { deriveRequestSchema } from './derive-request-schemas'
import type { DerivedObjectSchema } from './derive-request-schemas'
import { REQUEST_SCHEMA_DTOS } from './request-schema-dtos'

const ARTIFACT = join(__dirname, '../../../conformance/openapi-request-schemas.json')

/**
 * Every validator the derivation maps, plus the two that reach it as a metadata *type* rather
 * than a name (`isOptional`, and `isString` which only establishes `type: 'string'`).
 *
 * Asserted as an exact set, for the same reason the internal-only code list is pinned by name:
 * a collection nothing pins lets the checks over it pass while covering less than they claim.
 */
const KNOWN_VALIDATORS = [
  'isEmail',
  'isLength',
  'isNotEmpty',
  'isOptional',
  'isString',
  'matches',
  'maxLength',
  'minLength'
]

/** Derives the whole artifact body, keyed by DTO class name. */
function deriveAll(): Record<string, DerivedObjectSchema> {
  const schemas: Record<string, DerivedObjectSchema> = {}
  for (const dto of REQUEST_SCHEMA_DTOS) {
    schemas[dto.name] = deriveRequestSchema(dto)
  }
  return schemas
}

describe('OpenAPI request schemas — generated artifact', () => {
  // Verifies the derivation still understands every decorator the DTOs actually use. A new one
  // would otherwise produce a schema quietly missing its constraint, which no other assertion
  // here can see: the committed copy would match the (thinner) derivation and stay green.
  it('maps every validator the DTOs use, and no unknown one appears', () => {
    const names = new Set<string>()
    for (const dto of REQUEST_SCHEMA_DTOS) {
      for (const entry of getMetadataStorage().getTargetValidationMetadatas(
        dto,
        '',
        false,
        false
      )) {
        if (entry.name !== undefined) names.add(entry.name)
      }
    }

    expect([...names].sort()).toEqual(KNOWN_VALIDATORS)
  })

  // Verifies every DTO under `src/server/dto` is in the generated set. Without this the artifact
  // silently stops covering a DTO added later — the same shape as a loop over a collection
  // nothing pins.
  it('covers every DTO the library declares', () => {
    // Counted from the directory, not asserted as a literal. A hard-coded 22 would stay true
    // when a 23rd DTO file arrives without an entry, which is the case this test exists to
    // catch — a check whose title claims more than it verifies.
    const declared = readdirSync(join(__dirname, '../dto'))
      .filter((file) => file.endsWith('.dto.ts'))
      .map((file) => file.replace(/\.dto\.ts$/, ''))

    expect(REQUEST_SCHEMA_DTOS).toHaveLength(declared.length)
    expect(new Set(REQUEST_SCHEMA_DTOS.map((d) => d.name)).size).toBe(REQUEST_SCHEMA_DTOS.length)
  })

  // Verifies the committed artifact is exactly what the current decorators produce. Set
  // UPDATE_OPENAPI_SCHEMAS=1 (via `pnpm gen:openapi-schemas`) to rewrite it instead of asserting.
  it('matches the committed conformance artifact', () => {
    const derived = deriveAll()

    if (process.env['UPDATE_OPENAPI_SCHEMAS'] === '1') {
      writeFileSync(
        ARTIFACT,
        `${JSON.stringify({ $comment: ARTIFACT_COMMENT, openapi: '3.0', schemas: derived }, null, 2)}\n`,
        'utf8'
      )
    }

    const committed = JSON.parse(readFileSync(ARTIFACT, 'utf8')) as {
      $comment: string[]
      openapi: string
      schemas: Record<string, DerivedObjectSchema>
    }

    // The provenance block is compared too. It carries the "generated, do not edit" instruction
    // and the three contracts deliberately left out — the parts a reader relies on to know what
    // the file does NOT say. Left unasserted it could be edited or go stale while this test
    // stayed green, which is the failure this artifact exists to prevent, in its own header.
    expect(committed.$comment).toEqual(ARTIFACT_COMMENT)

    // The dialect is pinned in the data, so a future 3.1 migration is one coordinated change
    // rather than a mixture: a 3.1 fragment merged into `DocumentBuilder`'s 3.0 document
    // validates as neither.
    expect(committed.openapi).toBe('3.0')
    expect(committed.schemas).toEqual(derived)
  })
})

/** Written into the artifact so its provenance travels with it. */
const ARTIFACT_COMMENT = [
  'GENERATED — do not edit by hand. Run `pnpm gen:openapi-schemas` and review the diff.',
  '',
  'Request-body schemas for every DTO this library declares, derived from their class-validator',
  'decorators. OpenAPI 3.0, because @nestjs/swagger DocumentBuilder emits 3.0.0 and a 3.1',
  'fragment merged into a 3.0 document validates as neither.',
  '',
  'Three contracts are deliberately NOT here, because a decorator cannot express them and a',
  'schema derived faithfully would document them wrong. They are declared, with probes, in',
  'conformance/openapi-declared-structures.json:',
  '  - ResetPasswordDto takes email + newPassword plus exactly one of token | otp |',
  '    verifiedToken; all three are optional at the DTO layer and the service enforces the',
  '    exclusivity, so `required` cannot say it. That exactly-one-of is NECESSARY, not',
  '    sufficient: which proof is eligible depends on passwordReset.method, and an ineligible',
  '    one is refused with the same code a structural violation gets.',
  '  - The 8-character password floor is structural (the lowest NIST SP 800-63B-4 permits, and',
  '    what a decorator can express before configuration exists). The deployment floor is',
  '    password.minLength, default 15, enforced in PasswordService.',
  '  - OAuthCallbackQueryDto.code is required unless `error` is present. 3.0 cannot express a',
  '    conditional requirement per-property, so it appears optional here; the overlay declares',
  '    it as an anyOf over the pair.',
  '',
  'Normalisation is invisible too: email fields are trimmed and lowercased before the service',
  'sees them, which no keyword expresses and every client should know. It is declared in',
  'conformance/openapi-request-descriptions.json, each sentence carrying its own probe.'
]
