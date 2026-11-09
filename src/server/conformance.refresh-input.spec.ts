/**
 * @fileoverview Binds the shared contract's statements about request input to this library: the
 * refresh-token bound, and the rule that a validation error names the wire property.
 *
 * @layer Test
 */

import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import type { ArgumentMetadata } from '@nestjs/common'

import { AuthException } from './errors/auth-exception'
import { REQUEST_SCHEMAS } from './openapi/generated/request-schemas'
import { REQUEST_SCHEMA_DTOS } from './openapi/request-schema-dtos'
import { createAuthValidationPipe } from './pipes/auth-validation.pipe'
import { DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE } from './services/membership.service'
import { REFRESH_TOKEN_MAX_LENGTH } from './services/token-delivery.service'

const contract = JSON.parse(
  readFileSync(join(__dirname, '../../conformance/wire-contract.json'), 'utf8')
) as {
  requestFieldBounds: {
    opaqueToken: { min: number; max: number }
    pageLimit: { min: number; max: number; default: number }
  }
  refreshTokenInput: { body: string; cookie: string }
}

describe('the refresh token input the contract states', () => {
  // Scenario: the bound the service enforces and the bound the contract and the schema publish.
  // Expected: one number. Why: a bound that differs between the three is a request one side
  // accepts and another refuses.
  it('holds the service, the contract and the published schema to one bound', () => {
    const schema = REQUEST_SCHEMAS['RefreshTokenBodyDto']?.properties?.['refreshToken']

    expect(contract.requestFieldBounds.opaqueToken).toEqual({
      min: 1,
      max: REFRESH_TOKEN_MAX_LENGTH
    })
    expect(schema).toMatchObject({ minLength: 1, maxLength: REFRESH_TOKEN_MAX_LENGTH })
  })

  // Scenario: the two statements. Expected: each names the bound and the answer, and the cookie one
  // names the logout exception. Why: it is the rule rust-auth mirrors.
  it('states the body and the cookie rule', () => {
    expect(contract.refreshTokenInput.body).toMatch(/1 to 2048 characters.*400 auth\.validation/)
    expect(contract.refreshTokenInput.cookie).toMatch(
      /over 2048 characters.*400 auth\.validation.*except on logout.*no token/
    )
  })
})

describe('the field a validation error names', () => {
  /** The fields a wrong value for every property of a DTO is reported under. */
  async function reportedFields(
    dto: (typeof REQUEST_SCHEMA_DTOS)[number],
    properties: string[]
  ): Promise<string[]> {
    const body = Object.fromEntries(properties.map((name) => [name, { wrong: true }]))
    const metadata: ArgumentMetadata = { type: 'body', metatype: dto }
    try {
      await createAuthValidationPipe().transform(body, metadata)
    } catch (error) {
      const response = (error as AuthException).getResponse() as {
        error: { details: { field: string }[] }
      }
      return response.error.details.map((detail) => detail.field)
    }
    return []
  }

  // Scenario: every DTO the schema artifact covers, sent a wrong value under each wire property.
  // Expected: each reported field is one of the wire properties, never a renamed one. Why: a client
  // maps an error to its form field by this name, and both libraries must name the same key.
  it.each(REQUEST_SCHEMA_DTOS.map((dto) => [dto.name, dto] as const))(
    'names only wire properties for %s',
    async (name, dto) => {
      const properties = Object.keys(REQUEST_SCHEMAS[name]?.properties ?? {})

      const fields = await reportedFields(dto, properties)

      expect(fields.length).toBeGreaterThan(0)
      expect(fields.filter((field) => !properties.includes(field))).toEqual([])
    }
  )
})

describe('the page limit the contract states', () => {
  // Scenario: the contract's bound, the service's constants and the published pattern for the
  // `limit` query. Expected: one range, and the pattern accepts exactly it. Why: a list that
  // clamps where the contract refuses, or the reverse, is a request two clients read differently.
  it('holds the service, the contract and the published pattern to one range', () => {
    const pattern = new RegExp(
      (REQUEST_SCHEMAS['WorkspacePageQueryDto']?.properties?.['limit'] as { pattern: string })
        .pattern
    )
    const accepted = Array.from({ length: 200 }, (_, index) => String(index)).filter((value) =>
      pattern.test(value)
    )

    expect(contract.requestFieldBounds.pageLimit).toMatchObject({
      min: 1,
      max: MAX_PAGE_SIZE,
      default: DEFAULT_PAGE_SIZE
    })
    expect(accepted).toEqual(Array.from({ length: MAX_PAGE_SIZE }, (_, index) => String(index + 1)))
    expect(pattern.test('1.5')).toBe(false)
    expect(['05', '007', '0100'].some((value) => pattern.test(value))).toBe(false)
  })
})
