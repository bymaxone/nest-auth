/**
 * auth-openapi-fragment — request-schema unit tests: which DTO schemas the fragment contributes for
 * the families a deployment mounted.
 */
import { buildAuthOpenApiFragment } from './auth-openapi-fragment'
import type { RegisteredControllers } from './auth-openapi-fragment'
import { DEFAULTS, EVERYTHING, optionsFor } from './__tests__/fragment-fixtures'
import { REQUEST_SCHEMAS } from './generated/request-schemas'

describe('buildAuthOpenApiFragment request schemas', () => {
  // Scenario: the default registration (auth and passwordReset). Expected: exactly the nine DTOs
  // those two families take, each deep-equal to the generated schema. Why: a document that names a
  // schema nothing references is noise in the served spec and in the client generated from it, and
  // one that omits a referenced DTO leaves the empty placeholder in place.
  it('contributes exactly the schemas of the mounted families', () => {
    const { schemas } = buildAuthOpenApiFragment(optionsFor('cookie'), DEFAULTS).components

    expect(Object.keys(schemas).sort()).toEqual(
      [
        'ChangePasswordDto',
        'ForgotPasswordDto',
        'LoginDto',
        'RegisterDto',
        'ResendOtpDto',
        'ResendVerificationDto',
        'ResetPasswordDto',
        'VerifyEmailDto',
        'VerifyOtpDto'
      ].sort()
    )
    expect(schemas['LoginDto']).toBe(REQUEST_SCHEMAS['LoginDto'])
  })

  // Scenario: a family switched on. Expected: its DTOs appear and nothing else changes. Why: the
  // schemas follow the registration flags the same way the operations do.
  it("adds a family's schemas when its switch is on", () => {
    const without = buildAuthOpenApiFragment(optionsFor('cookie'), DEFAULTS).components.schemas
    const withMfa = buildAuthOpenApiFragment(optionsFor('cookie'), { ...DEFAULTS, mfa: true })
      .components.schemas

    expect(
      Object.keys(withMfa)
        .filter((name) => !(name in without))
        .sort()
    ).toEqual([
      'MfaChallengeDto',
      'MfaDisableDto',
      'MfaRegenerateRecoveryCodesDto',
      'MfaSetupDto',
      'MfaVerifyDto'
    ])
  })

  // Scenario: a DTO two families share, with both mounted. Expected: one entry. Why: a component
  // name is a key, and a duplicate would be one schema the second family silently overwrote.
  it('contributes a DTO shared by two families once', () => {
    const { schemas } = buildAuthOpenApiFragment(optionsFor('cookie'), {
      ...DEFAULTS,
      mfa: true,
      platform: true
    }).components

    expect(Object.keys(schemas).filter((name) => name === 'MfaChallengeDto')).toHaveLength(1)
    expect(schemas['PlatformLoginDto']).toBe(REQUEST_SCHEMAS['PlatformLoginDto'])
  })

  // Scenario: nothing mounted. Expected: no schemas. Why: a deployment that mounts no controller
  // has no operation for a schema to describe.
  it('contributes nothing when no family is mounted', () => {
    // Spelled out, so a registration switch added to `RegisteredControllers` is a compile error here
    // instead of a fixture that silently leaves it unset.
    const none: RegisteredControllers = {
      auth: false,
      passwordReset: false,
      mfa: false,
      sessions: false,
      platform: false,
      platformMfa: false,
      invitations: false,
      emailChange: false,
      oauth: false,
      workspaces: false,
      workspaceInvitations: false
    }

    expect(buildAuthOpenApiFragment(optionsFor('cookie'), none).components.schemas).toEqual({})
  })

  // Scenario: the table names a DTO the generated module has no schema for. Expected: building the
  // fragment throws and names the DTO. Why: a name with no schema would otherwise be dropped and
  // reach a consumer as the empty placeholder, which is the defect this fragment exists to remove;
  // a failure at the consumer's boot, naming the DTO, is the cheaper way to find it.
  it('refuses a table entry that has no generated schema', () => {
    jest.isolateModules(() => {
      jest.doMock('./generated/request-schemas', () => ({ REQUEST_SCHEMAS: {} }))
      const isolated =
        require('./auth-openapi-fragment') as typeof import('./auth-openapi-fragment')

      expect(() => isolated.buildAuthOpenApiFragment(optionsFor('cookie'), DEFAULTS)).toThrow(
        /no generated request schema for \w+Dto/
      )
    })
    jest.dontMock('./generated/request-schemas')
  })

  // Scenario: every family mounted. Expected: every body DTO and no query DTO. Why: the query
  // DTOs are not request bodies, and a schema contributed for a name the document never registers
  // is a component nothing references.
  it('contributes no schema for the OAuth query DTOs', () => {
    const { schemas } = buildAuthOpenApiFragment(optionsFor('cookie'), EVERYTHING).components

    expect(schemas).not.toHaveProperty('OAuthInitiateQueryDto')
    expect(schemas).not.toHaveProperty('OAuthCallbackQueryDto')
    expect(Object.keys(schemas)).toHaveLength(28)
  })
})
