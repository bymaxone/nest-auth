/**
 * @fileoverview Binds `conformance/openapi-request-descriptions.json` to the behaviour it claims.
 *
 * The declared overlay carries what a decorator cannot express — today, the e-mail normalisation
 * `@Transform` performs. A generator must not invent that prose: the transform is an opaque
 * lambda, so anything "derived" from it would be a hand-maintained lookup wearing a generated
 * costume.
 *
 * So the prose is written by hand and each entry carries its own probe, which this suite runs.
 * The probe is the sentence's operational meaning rather than a test beside it: prose and
 * behaviour cannot drift, because the pair is what gets checked. It is the same move that made
 * the status table safe — put the claim in data and assert the data.
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import { plainToInstance } from 'class-transformer'

import { deriveRequestSchema } from './derive-request-schemas'
import { REQUEST_SCHEMA_DTOS } from './request-schema-dtos'

/**
 * One input carrying every distinguishing feature the known transforms act on — leading and
 * trailing padding, mixed case, an at-sign, digits and a symbol. Richer than a bare string so a
 * transform has as little room as possible to be the identity on it.
 */
const CANARY = '  MiXeD@Example.COM 42! '

interface DeclaredEntry {
  description: string
  probe: { input: string; expected: string }
}

const OVERLAY = join(__dirname, '../../../conformance/openapi-request-descriptions.json')

const declared = (
  JSON.parse(readFileSync(OVERLAY, 'utf8')) as {
    descriptions: Record<string, Record<string, DeclaredEntry>>
  }
).descriptions

/** `Dto.property` for every entry the overlay declares. */
const declaredKeys = new Set(
  Object.entries(declared).flatMap(([dto, props]) =>
    Object.keys(props).map((property) => `${dto}.${property}`)
  )
)

/** Runs one value through a DTO's transforms and returns what the service would receive. */
function transformed(dto: (typeof REQUEST_SCHEMA_DTOS)[number], property: string, value: string) {
  const plain: Record<string, string> = { [property]: value }
  const instance: object = plainToInstance(dto, plain)

  // A plain narrowing of `object` to read one dynamic key — not a reinterpretation. The DTO's
  // own type is irrelevant here: what is under test is what the transform produced.
  return (instance as Record<string, unknown>)[property]
}

describe('OpenAPI request descriptions — declared overlay', () => {
  // Verifies each declared sentence against its own probe. A description claiming the value is
  // trimmed and lowercased is only true if it is, and this is where that stops being prose.
  it.each(
    Object.entries(declared).flatMap(([dtoName, props]) =>
      Object.entries(props).map(([property, entry]) => ({ dtoName, property, entry }))
    )
  )('$dtoName.$property behaves as its description claims', ({ dtoName, property, entry }) => {
    const dto = REQUEST_SCHEMA_DTOS.find((candidate) => candidate.name === dtoName)

    expect(dto).toBeDefined()
    expect(entry.description.length).toBeGreaterThan(0)
    expect(transformed(dto!, property, entry.probe.input)).toBe(entry.probe.expected)
  })

  // Verifies the overlay covers every property that actually transforms. This is the other
  // direction: a `@Transform` added with no entry here would otherwise ship undocumented, and
  // the per-entry probes above cannot see it because there is no entry to run.
  it('declares every property the canary shows transforming', () => {
    const transforming: string[] = []

    for (const dto of REQUEST_SCHEMA_DTOS) {
      for (const property of Object.keys(deriveRequestSchema(dto).properties)) {
        if (transformed(dto, property, CANARY) !== CANARY) {
          transforming.push(`${dto.name}.${property}`)
        }
      }
    }

    expect(transforming.sort()).toEqual([...declaredKeys].sort())
  })

  // Verifies the overlay declares nothing that does not exist, so a renamed or removed property
  // cannot leave a sentence describing a field no request can carry.
  it('declares no property the DTOs do not have', () => {
    for (const [dtoName, props] of Object.entries(declared)) {
      const dto = REQUEST_SCHEMA_DTOS.find((candidate) => candidate.name === dtoName)
      expect(dto).toBeDefined()

      const properties = Object.keys(deriveRequestSchema(dto!).properties)
      for (const property of Object.keys(props)) {
        expect(properties).toContain(property)
      }
    }
  })
})
