/**
 * @fileoverview Binds the shared contract's statements about request input to this library: the
 * refresh-token bound, and the rule that a validation error names the wire property.
 *
 * @layer Test
 */

import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import type { ArgumentMetadata } from '@nestjs/common'
import { Type } from 'class-transformer'
import { IsString, ValidateNested } from 'class-validator'

import { AUTH_ERROR_CODES } from './errors/auth-error-codes'
import { AuthException } from './errors/auth-exception'
import { REQUEST_SCHEMAS } from './openapi/generated/request-schemas'
import { REQUEST_SCHEMA_DTOS } from './openapi/request-schema-dtos'
import { createAuthValidationPipe } from './pipes/auth-validation.pipe'
import { DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE } from './services/membership.service'
import { REFRESH_TOKEN_MAX_LENGTH } from './services/token-delivery.service'
import {
  WORKSPACE_CURSOR_MAX_LENGTH,
  WORKSPACE_OWNER_ROLE_MAX_LENGTH,
  isWorkspaceOwnerRole
} from './utils/workspace-cursor'

const contract = JSON.parse(
  readFileSync(join(__dirname, '../../conformance/wire-contract.json'), 'utf8')
) as {
  requestFieldBounds: {
    opaqueToken: { min: number; max: number }
    pageLimit: { min: number; max: number; default: number; cursor: { min: number; max: number } }
  }
  workspaceOwnerRole: {
    maxLength: number
    accepts: string[]
    refuses: { case: string; value: string; unpairedSurrogateCodeUnits?: number[] }[]
  }
  refreshTokenInput: { body: string; cookie: string }
  passwordResetOrder: { steps: string[]; reason: string }
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
    expect(contract.refreshTokenInput.body).toMatch(
      /1 to 2048 characters; a missing field or a JSON null is no token.*400 auth\.validation/
    )
    expect(contract.refreshTokenInput.cookie).toMatch(
      /over 2048 characters.*400 auth\.validation.*except on logout.*no token.*both.*body is the token that applies/
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

describe('the workspace cursor bounds the contract states', () => {
  // Scenario: the cursor bound the contract and the published schema state, and the one the codec
  // and the page query enforce. Expected: one number. Why: a bound that differs is a cursor one
  // side issues and the other refuses, which ends paging on page one.
  it('holds the codec, the contract and the published schema to one cursor bound', () => {
    const schema = REQUEST_SCHEMAS['WorkspacePageQueryDto']?.properties?.['cursor'] as {
      maxLength: number
    }

    expect(contract.requestFieldBounds.pageLimit.cursor).toEqual({
      min: 1,
      max: WORKSPACE_CURSOR_MAX_LENGTH
    })
    expect(schema.maxLength).toBe(WORKSPACE_CURSOR_MAX_LENGTH)
  })

  // Scenario: the owner-role rule the contract states and the one startup enforces. Expected: the
  // same length bound, every accepted vector accepted and every refused vector refused. A refused
  // vector with unpaired surrogates is built from its code units, so the file holds none.
  it('holds the owner-role rule to the contract and its vectors', () => {
    const rule = contract.workspaceOwnerRole
    const refused = rule.refuses.map(
      (entry) => entry.value + String.fromCharCode(...(entry.unpairedSurrogateCodeUnits ?? []))
    )

    expect(rule.maxLength).toBe(WORKSPACE_OWNER_ROLE_MAX_LENGTH)
    expect(rule.accepts.every((role) => isWorkspaceOwnerRole(role))).toBe(true)
    expect(refused.some((role) => isWorkspaceOwnerRole(role))).toBe(false)
  })
})

class Line {
  @IsString()
  name!: string
}

class Order {
  @ValidateNested()
  @Type(() => Line)
  billing!: Line

  @ValidateNested({ each: true })
  @Type(() => Line)
  items!: Line[]
}

describe('the field path a nested validation error names', () => {
  // Scenario: a nested object and an array element each carry an invalid value. Expected: the path
  // is dotted property names with the array index as a segment, never bracketed. Why: the contract
  // pins the form so a client maps `items.0.name` to the same input in both libraries.
  it('writes a dotted path with the array index as a segment', async () => {
    const metadata: ArgumentMetadata = { type: 'body', metatype: Order }
    let fields: string[] = []
    try {
      await createAuthValidationPipe().transform(
        { billing: { name: 1 }, items: [{ name: 'ok' }, { name: 2 }] },
        metadata
      )
    } catch (error) {
      const response = (error as AuthException).getResponse() as {
        error: { details: { field: string }[] }
      }
      fields = response.error.details.map((detail) => detail.field)
    }

    expect(fields.sort()).toEqual(['billing.name', 'items.1.name'])
  })
})

describe('the password reset order the contract states', () => {
  // Scenario: the three steps. Expected: they run classify, judge, spend, and every code they name
  // is one this library answers. Why: the order is the contract; the declared-structures probes and
  // the e2e run it, and this ties the wording to the real codes.
  it('names the three steps in order with real codes', () => {
    const { steps } = contract.passwordResetOrder

    expect(steps.map((step) => step.slice(0, 2))).toEqual(['1.', '2.', '3.'])
    expect(steps[0]).toContain(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    expect(steps[1]).toContain(AUTH_ERROR_CODES.VALIDATION)
    expect(steps[1]).toContain(AUTH_ERROR_CODES.PASSWORD_COMPROMISED)
    expect(steps[2]).toContain(AUTH_ERROR_CODES.OTP_INVALID)
  })
})
