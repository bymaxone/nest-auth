/**
 * @fileoverview The table of request schemas per controller family, against the controllers.
 *
 * `REQUEST_SCHEMAS_BY_CONTROLLER` is data the fragment reads at boot instead of reflecting over
 * controllers. That is only safe while the data says what the controllers' own route metadata
 * says, so this derives the same table the way the document builder reads it and requires the two
 * to be equal in both directions: a DTO added to a handler without an entry, and an entry no
 * handler takes, are both failures.
 */
import { ROUTE_ARGS_METADATA } from '@nestjs/common/constants'
import { RouteParamtypes } from '@nestjs/common/enums/route-paramtypes.enum'
import type { Type } from '@nestjs/common'

import { AUTH_CONTROLLERS } from '../bymax-auth.module'
import type { RegisteredControllers } from './auth-openapi-fragment'
import { REQUEST_SCHEMAS } from './generated/request-schemas'
import { REQUEST_SCHEMAS_BY_CONTROLLER } from './request-schema-mounts'

/** The registration switch that mounts each controller class. */
const FLAG_OF: Readonly<Record<string, keyof RegisteredControllers>> = {
  AuthController: 'auth',
  PasswordResetController: 'passwordReset',
  MfaController: 'mfa',
  SessionController: 'sessions',
  PlatformAuthController: 'platform',
  PlatformMfaController: 'platformMfa',
  OAuthController: 'oauth',
  InvitationController: 'invitations',
  EmailChangeController: 'emailChange'
}

/** The DTO class names a controller's handlers take as a request body, in route-metadata order. */
function bodyDtosOf(controller: Type<object>): string[] {
  const names: string[] = []
  for (const method of Object.getOwnPropertyNames(controller.prototype)) {
    if (method === 'constructor') continue
    const args = Reflect.getMetadata(ROUTE_ARGS_METADATA, controller, method) as
      Record<string, { index: number }> | undefined
    const types = Reflect.getMetadata('design:paramtypes', controller.prototype, method) as
      Array<{ name: string }> | undefined
    if (args === undefined || types === undefined) continue
    for (const [key, { index }] of Object.entries(args)) {
      if (Number(key.split(':')[0]) !== RouteParamtypes.BODY) continue
      const type = types[index]
      if (type !== undefined && !names.includes(type.name)) names.push(type.name)
    }
  }
  return names
}

describe('request schemas per controller family', () => {
  // Scenario: every controller class the module can mount. Expected: each has a registration
  // switch in this spec's map and the map names no other class. Why: the loop below covers only
  // the controllers it is given, so a controller added to the module with no entry here would be
  // skipped silently.
  it('knows the registration switch of every controller', () => {
    expect(AUTH_CONTROLLERS.map((c) => c.name).sort()).toEqual(Object.keys(FLAG_OF).sort())
  })

  // Scenario: each controller's request bodies read from its route metadata. Expected: the table
  // lists exactly those DTOs under its switch. Why: the fragment contributes the table's names, so
  // a body DTO missing from it reaches a consumer's document as an empty schema.
  it.each(AUTH_CONTROLLERS.map((c) => [c.name, c] as const))(
    'lists exactly the body DTOs of %s',
    (name, controller) => {
      const flag = FLAG_OF[name] as keyof RegisteredControllers

      expect([...REQUEST_SCHEMAS_BY_CONTROLLER[flag]].sort()).toEqual(bodyDtosOf(controller).sort())
    }
  )

  // Scenario: the table's keys against the registration switches. Expected: one entry per switch.
  // Why: a switch with no entry would contribute nothing and read as a deliberate omission.
  it('has an entry for every registration switch and no other', () => {
    expect(Object.keys(REQUEST_SCHEMAS_BY_CONTROLLER).sort()).toEqual(Object.values(FLAG_OF).sort())
  })

  // Scenario: every name the table lists. Expected: a generated schema exists for it. Why: the
  // fragment throws on a name with no schema, and a boot-time failure in a consumer's document
  // build is worse than this one.
  it('names only DTOs the generated module has a schema for', () => {
    const named = Object.values(REQUEST_SCHEMAS_BY_CONTROLLER).flat()

    expect(named.length).toBeGreaterThan(0)
    for (const name of named) expect(REQUEST_SCHEMAS).toHaveProperty(name)
  })
})
