/**
 * auth-openapi-fragment — unit tests.
 *
 * The posture map, per delivery mode and per registration. What a consumer asserts on their side
 * is the operation-to-security map of the whole document, so these are the same claims one level
 * up: which schemes exist, which operations reference them, and which operations declare that
 * they need nothing.
 */
import {
  AUTH_SECURITY_SCHEMES,
  buildAuthOpenApiFragment,
  OPENAPI_CONTRACT_VERSION
} from './auth-openapi-fragment'
import type { RegisteredControllers } from './auth-openapi-fragment'
import type { ResolvedOptions } from '../config/resolved-options'

/** The default registration: `auth` and `passwordReset`, which is what a bare module mounts. */
const DEFAULTS: RegisteredControllers = {
  auth: true,
  passwordReset: true,
  mfa: false,
  sessions: false,
  platform: false,
  platformMfa: false,
  invitations: false,
  emailChange: false,
  oauth: false
}

/** Everything mounted. */
const EVERYTHING: RegisteredControllers = {
  auth: true,
  passwordReset: true,
  mfa: true,
  sessions: true,
  platform: true,
  platformMfa: true,
  invitations: true,
  emailChange: true,
  oauth: true
}

function optionsFor(
  tokenDelivery: ResolvedOptions['tokenDelivery'],
  cookieNames = { accessTokenName: 'access_token', refreshTokenName: 'refresh_token' }
): ResolvedOptions {
  return { tokenDelivery, cookies: cookieNames } as unknown as ResolvedOptions
}

describe('buildAuthOpenApiFragment', () => {
  // Verifies the fragment self-describes its contract revision. A fragment crossing a package
  // boundary is data, and only the value travelling at runtime can say which shape it is.
  it('stamps the contract version', () => {
    const fragment = buildAuthOpenApiFragment(optionsFor('cookie'), DEFAULTS)

    expect(fragment.contractVersion).toBe(OPENAPI_CONTRACT_VERSION)
  })

  // Verifies the default registration describes exactly the thirteen operations it mounts —
  // and nothing else. Naming a handler the document does not contain fails a consumer's document
  // build, so over-declaring is not a harmless excess: it is a broken build in their repository.
  it('describes only the operations the deployment mounted', () => {
    const fragment = buildAuthOpenApiFragment(optionsFor('cookie'), DEFAULTS)
    const handlers = Object.keys(fragment.operations)

    expect(handlers).toHaveLength(13)
    expect(
      handlers.every(
        (key) => key.startsWith('AuthController.') || key.startsWith('PasswordResetController.')
      )
    ).toBe(true)
  })

  // The same claim from the other side: turning a controller on adds its handlers and only its
  // handlers. Without this pair, a builder that ignored `registered` entirely would pass the
  // case above by luck of the fixture.
  it('adds a controller’s handlers when the deployment mounts it', () => {
    const withoutMfa = buildAuthOpenApiFragment(optionsFor('cookie'), DEFAULTS)
    const withMfa = buildAuthOpenApiFragment(optionsFor('cookie'), { ...DEFAULTS, mfa: true })

    const added = Object.keys(withMfa.operations).filter(
      (key) => !Object.keys(withoutMfa.operations).includes(key)
    )

    expect(added).toEqual([
      'MfaController.setup',
      'MfaController.verifyEnable',
      'MfaController.challenge',
      'MfaController.disable',
      'MfaController.regenerateRecoveryCodes'
    ])
  })

  // Verifies a public operation says `security: []` rather than omitting the member. The
  // difference is the whole point: an omitted member inherits the document's default, which on a
  // consumer's document is "authenticated" — so a login that said nothing would be described as
  // requiring the credential it exists to issue.
  it('declares public operations as explicitly unauthenticated', () => {
    const fragment = buildAuthOpenApiFragment(optionsFor('cookie'), DEFAULTS)

    expect(fragment.operations['AuthController.login']).toEqual({ security: [] })
    expect(fragment.operations['PasswordResetController.forgotPassword']).toEqual({ security: [] })
  })

  describe('tokenDelivery: cookie', () => {
    const fragment = buildAuthOpenApiFragment(optionsFor('cookie'), EVERYTHING)

    // Verifies the access requirement is the cookie alone, and that the scheme carries the
    // configured NAME — the reason this cannot be a static document in the first place.
    it('requires the access cookie, under the configured cookie name', () => {
      expect(fragment.operations['AuthController.me']).toEqual({
        security: [{ [AUTH_SECURITY_SCHEMES.accessCookie]: [] }]
      })
      expect(fragment.components.securitySchemes[AUTH_SECURITY_SCHEMES.accessCookie]).toEqual(
        expect.objectContaining({ type: 'apiKey', in: 'cookie', name: 'access_token' })
      )
    })

    // Verifies the bearer scheme is ABSENT — not defined-and-unreferenced. A document that
    // defines a credential the server will not read tells a generated client to offer it.
    it('defines no bearer scheme', () => {
      expect(
        fragment.components.securitySchemes[AUTH_SECURITY_SCHEMES.accessBearer]
      ).toBeUndefined()
    })

    // Verifies refresh is the refresh cookie and carries NO request body: on this deployment the
    // token is never read from one.
    it('requires the refresh cookie and contributes no body', () => {
      expect(fragment.operations['AuthController.refresh']).toEqual({
        security: [{ [AUTH_SECURITY_SCHEMES.refreshCookie]: [] }]
      })
    })

    // The cookie name is the consumer's. Asserted against a renamed pair, because a scheme that
    // hardcoded `refresh_token` would pass every test above.
    it('follows a renamed cookie', () => {
      const renamed = buildAuthOpenApiFragment(
        optionsFor('cookie', { accessTokenName: 'sid', refreshTokenName: 'sid_r' }),
        EVERYTHING
      )

      expect(renamed.components.securitySchemes[AUTH_SECURITY_SCHEMES.accessCookie]).toEqual(
        expect.objectContaining({ name: 'sid' })
      )
      expect(renamed.components.securitySchemes[AUTH_SECURITY_SCHEMES.refreshCookie]).toEqual(
        expect.objectContaining({ name: 'sid_r' })
      )
    })
  })

  describe('tokenDelivery: bearer', () => {
    const fragment = buildAuthOpenApiFragment(optionsFor('bearer'), EVERYTHING)

    it('requires the bearer token and defines no cookie scheme', () => {
      expect(fragment.operations['AuthController.me']).toEqual({
        security: [{ [AUTH_SECURITY_SCHEMES.accessBearer]: [] }]
      })
      expect(
        fragment.components.securitySchemes[AUTH_SECURITY_SCHEMES.accessCookie]
      ).toBeUndefined()
      expect(
        fragment.components.securitySchemes[AUTH_SECURITY_SCHEMES.refreshCookie]
      ).toBeUndefined()
    })

    // The refresh operations have no scheme to reference at all — the token arrives in the body,
    // which OpenAPI models as a request body and not as a security scheme. So the operation is
    // `security: []` PLUS a contributed body, and this is the one place the two halves of the
    // decision meet: absent scheme, described body.
    it('describes the refresh token as a request body instead', () => {
      const refresh = fragment.operations['AuthController.refresh']

      expect(refresh?.['security']).toEqual([])
      expect(refresh?.['requestBody']).toEqual(
        expect.objectContaining({
          required: false,
          content: expect.objectContaining({
            'application/json': expect.objectContaining({
              schema: expect.objectContaining({
                properties: expect.objectContaining({ refreshToken: expect.anything() })
              })
            })
          })
        })
      )
    })
  })

  describe('tokenDelivery: both', () => {
    const fragment = buildAuthOpenApiFragment(optionsFor('both'), EVERYTHING)

    // Verifies the alternation is a two-entry LIST. One entry with two schemes would mean AND —
    // a server demanding the same credential twice — and it is the mistake the four-name
    // vocabulary exists to make impossible to write by accident.
    it('offers the two access transports as alternatives, not as a conjunction', () => {
      expect(fragment.operations['AuthController.me']).toEqual({
        security: [
          { [AUTH_SECURITY_SCHEMES.accessCookie]: [] },
          { [AUTH_SECURITY_SCHEMES.accessBearer]: [] }
        ]
      })
    })

    // Refresh accepts either, so both are described: the cookie as a requirement and the body as
    // an optional one.
    it('describes the refresh cookie and the body together', () => {
      const refresh = fragment.operations['AuthController.refresh']

      expect(refresh?.['security']).toEqual([{ [AUTH_SECURITY_SCHEMES.refreshCookie]: [] }])
      expect(refresh?.['requestBody']).toEqual(expect.objectContaining({ required: false }))
    })
  })

  describe('the platform surface', () => {
    // Verifies the platform credential is bearer in EVERY mode. `extractPlatformAccessToken`
    // reads the Authorization header whatever `tokenDelivery` says, so a cookie-only deployment
    // still authenticates its administrators by header — and a document that described them as
    // cookie-authenticated would be describing a server that refuses those requests.
    it.each(['cookie', 'bearer', 'both'] as const)(
      'requires the platform bearer scheme under tokenDelivery: %s',
      (tokenDelivery) => {
        const fragment = buildAuthOpenApiFragment(optionsFor(tokenDelivery), EVERYTHING)

        expect(fragment.operations['PlatformAuthController.me']).toEqual({
          security: [{ [AUTH_SECURITY_SCHEMES.platformBearer]: [] }]
        })
        expect(fragment.components.securitySchemes[AUTH_SECURITY_SCHEMES.platformBearer]).toEqual(
          expect.objectContaining({ type: 'http', scheme: 'bearer' })
        )
      }
    )

    // Platform refresh is the one operation with no access token: the body IS the credential, so
    // the body is required rather than optional.
    it('describes the platform refresh body as required', () => {
      const fragment = buildAuthOpenApiFragment(optionsFor('cookie'), EVERYTHING)
      const refresh = fragment.operations['PlatformAuthController.refresh']

      expect(refresh?.['security']).toEqual([])
      expect(refresh?.['requestBody']).toEqual(expect.objectContaining({ required: true }))
    })

    // Platform logout reads both, and tolerates a missing refresh token — it answers 204 either
    // way — so the body is described and NOT required. Declaring it required would describe a
    // server that refuses a request this one accepts.
    it('describes the platform logout body as optional, beside the bearer requirement', () => {
      const fragment = buildAuthOpenApiFragment(optionsFor('cookie'), EVERYTHING)
      const logout = fragment.operations['PlatformAuthController.logout']

      expect(logout?.['security']).toEqual([{ [AUTH_SECURITY_SCHEMES.platformBearer]: [] }])
      expect(logout?.['requestBody']).toEqual(expect.objectContaining({ required: false }))
    })

    // Verifies a deployment with no platform surface defines no platform scheme — the same
    // absent-not-unreferenced rule, applied to registration rather than to transport.
    it('defines no platform scheme when the surface is not mounted', () => {
      const fragment = buildAuthOpenApiFragment(optionsFor('both'), DEFAULTS)

      expect(
        fragment.components.securitySchemes[AUTH_SECURITY_SCHEMES.platformBearer]
      ).toBeUndefined()
    })

    // And the mirror: a platform-ONLY deployment defines no dashboard scheme. This is the case
    // that would otherwise slip through — the dashboard schemes are the default ones, so a
    // builder that always defined them would look right everywhere except here.
    it('defines no dashboard scheme on a platform-only deployment', () => {
      const platformOnly: RegisteredControllers = {
        ...DEFAULTS,
        auth: false,
        passwordReset: false,
        platform: true,
        platformMfa: true
      }

      const fragment = buildAuthOpenApiFragment(optionsFor('both'), platformOnly)

      expect(Object.keys(fragment.components.securitySchemes)).toEqual([
        AUTH_SECURITY_SCHEMES.platformBearer
      ])
    })
  })
})
