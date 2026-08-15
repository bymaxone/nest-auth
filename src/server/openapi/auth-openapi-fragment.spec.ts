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

  // The invariant nest-core enforces at the consumer's boot: a requirement naming a scheme the
  // document does not define fails the build. So it has to hold for every registration a
  // deployment can choose, not only for the fixtures the tests above happen to use — the
  // interesting combinations are the lopsided ones, where a surface is mounted without its
  // sibling and the definition is decided by a condition that has to read as OR.
  it.each([
    ['dashboard only', { ...DEFAULTS }],
    ['the auth controller alone', { ...DEFAULTS, passwordReset: false }],
    ['a dashboard surface without the auth controller', { ...DEFAULTS, auth: false }],
    [
      'the session surface without the auth controller',
      { ...DEFAULTS, auth: false, sessions: true }
    ],
    [
      'the session surface alone',
      { ...DEFAULTS, auth: false, passwordReset: false, sessions: true }
    ],
    ['platform without its MFA surface', { ...DEFAULTS, platform: true }],
    ['the platform MFA surface alone', { ...DEFAULTS, platform: false, platformMfa: true }],
    ['everything', EVERYTHING]
  ])('references no scheme it did not define — %s', (_why, registered) => {
    for (const tokenDelivery of ['cookie', 'bearer', 'both'] as const) {
      const fragment = buildAuthOpenApiFragment(optionsFor(tokenDelivery), registered)
      const defined = Object.keys(fragment.components.securitySchemes)

      const referenced = Object.values(fragment.operations)
        .flatMap((operation) => operation['security'] as Record<string, unknown>[])
        .flatMap((requirement) => Object.keys(requirement))

      // The mode travels into the assertion so a failure names the deployment that broke, rather
      // than reporting a bare list of scheme names three iterations into a loop.
      expect({
        tokenDelivery,
        dangling: referenced.filter((scheme) => !defined.includes(scheme))
      }).toEqual({ tokenDelivery, dangling: [] })
    }
  })

  // The table itself, pinned handler by handler on a deployment that mounts everything.
  //
  // Every test around this one covers one decision — a transport, a mode, a registration. None
  // of them would notice a single entry changing credential, and that is the failure worth
  // catching: a handler quietly promoted from `access` to `none` publishes a protected route as
  // public in the consumer's document, and a generated client then stops attaching the
  // credential the server requires. The table is a contract, so it is asserted as one.
  it('pins the credential of every operation it can mount', () => {
    const fragment = buildAuthOpenApiFragment(optionsFor('cookie'), EVERYTHING)
    const PUBLIC: unknown[] = []
    const ACCESS = [{ [AUTH_SECURITY_SCHEMES.accessCookie]: [] }]
    // Access required, refresh read: the pair is one AND-entry, and the access-alone entry beside
    // it is what says the operation still answers without the refresh token.
    const ACCESS_WITH_OPTIONAL_REFRESH = [
      {
        [AUTH_SECURITY_SCHEMES.accessCookie]: [],
        [AUTH_SECURITY_SCHEMES.refreshCookie]: []
      },
      { [AUTH_SECURITY_SCHEMES.accessCookie]: [] }
    ]
    const PLATFORM = [{ [AUTH_SECURITY_SCHEMES.platformBearer]: [] }]

    const security = Object.fromEntries(
      Object.entries(fragment.operations).map(([handler, operation]) => [
        handler,
        operation['security']
      ])
    )

    expect(security).toEqual({
      'AuthController.register': PUBLIC,
      'AuthController.login': PUBLIC,
      // Every form it reads, richest first, and the empty entry last: `logout` requires nothing
      // (a user whose access token expired must still be able to sign out) but blacklists the
      // access token's `jti` when it gets one, so a document that named only the refresh cookie
      // would have generated clients perform a weaker logout than the server supports.
      'AuthController.logout': [
        {
          [AUTH_SECURITY_SCHEMES.accessCookie]: [],
          [AUTH_SECURITY_SCHEMES.refreshCookie]: []
        },
        { [AUTH_SECURITY_SCHEMES.accessCookie]: [] },
        { [AUTH_SECURITY_SCHEMES.refreshCookie]: [] },
        {}
      ],
      'AuthController.refresh': [{ [AUTH_SECURITY_SCHEMES.refreshCookie]: [] }],
      'AuthController.me': ACCESS,
      'AuthController.wsTicket': ACCESS,
      'AuthController.verifyEmail': PUBLIC,
      'AuthController.resendVerification': PUBLIC,
      'PasswordResetController.forgotPassword': PUBLIC,
      'PasswordResetController.resetPassword': PUBLIC,
      'PasswordResetController.changePassword': ACCESS_WITH_OPTIONAL_REFRESH,
      'PasswordResetController.verifyOtp': PUBLIC,
      'PasswordResetController.resendOtp': PUBLIC,
      'MfaController.setup': ACCESS,
      'MfaController.verifyEnable': ACCESS,
      'MfaController.challenge': PUBLIC,
      'MfaController.disable': ACCESS,
      'MfaController.regenerateRecoveryCodes': ACCESS,
      'SessionController.listSessions': ACCESS_WITH_OPTIONAL_REFRESH,
      'SessionController.revokeAllSessions': [
        {
          [AUTH_SECURITY_SCHEMES.accessCookie]: [],
          [AUTH_SECURITY_SCHEMES.refreshCookie]: []
        }
      ],
      'SessionController.revokeSession': ACCESS,
      'PlatformAuthController.login': PUBLIC,
      'PlatformAuthController.mfaChallenge': PUBLIC,
      'PlatformAuthController.me': PLATFORM,
      'PlatformAuthController.logout': [{ [AUTH_SECURITY_SCHEMES.platformBearer]: [] }, {}],
      'PlatformAuthController.refresh': PUBLIC,
      'PlatformAuthController.revokeSessions': PLATFORM,
      'PlatformMfaController.setup': PLATFORM,
      'PlatformMfaController.verifyEnable': PLATFORM,
      'PlatformMfaController.disable': PLATFORM,
      'PlatformMfaController.regenerateRecoveryCodes': PLATFORM,
      'InvitationController.invite': ACCESS,
      'InvitationController.revoke': ACCESS,
      'InvitationController.accept': PUBLIC,
      'EmailChangeController.requestChange': ACCESS,
      'EmailChangeController.confirmChange': PUBLIC,
      'OAuthController.initiate': PUBLIC,
      'OAuthController.callback': PUBLIC
    })
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
      // Pinned whole: a Security Scheme Object is copied into the consumer's document verbatim,
      // so every field here is published. `description` included — it is what a developer reads
      // in the rendered document to know which credential this is.
      expect(fragment.components.securitySchemes[AUTH_SECURITY_SCHEMES.accessCookie]).toEqual({
        type: 'apiKey',
        in: 'cookie',
        name: 'access_token',
        description: 'Access token, delivered as an HttpOnly cookie.'
      })
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
      expect(renamed.components.securitySchemes[AUTH_SECURITY_SCHEMES.refreshCookie]).toEqual({
        type: 'apiKey',
        in: 'cookie',
        name: 'sid_r',
        description: 'Refresh token, delivered as an HttpOnly cookie scoped to the auth prefix.'
      })
    })
  })

  describe('tokenDelivery: bearer', () => {
    const fragment = buildAuthOpenApiFragment(optionsFor('bearer'), EVERYTHING)

    it('requires the bearer token and defines no cookie scheme', () => {
      expect(fragment.operations['AuthController.me']).toEqual({
        security: [{ [AUTH_SECURITY_SCHEMES.accessBearer]: [] }]
      })
      expect(fragment.components.securitySchemes[AUTH_SECURITY_SCHEMES.accessBearer]).toEqual({
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description: 'Access token, delivered in the Authorization header.'
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
    // `security: []` PLUS a contributed body, and the body is REQUIRED here: with no cookie
    // fallback, a caller omitting it hands the service an empty string and cannot succeed.
    // Pinned WHOLE rather than with `objectContaining`, and that is the point of the test: every
    // string in here is consumed literally by a code generator. A media type of `""`, a schema
    // with no `type`, a property with no description — each produces a client that compiles and
    // sends the wrong request, and each is invisible to an assertion that only checks the keys it
    // names. Both requirements are asserted because they say different things: the body must be
    // sent, AND it must carry the token — under `'bearer'` there is no cookie to carry it
    // instead, so a generated client that accepted `{}` would be describing a call that fails.
    it('describes the refresh token as a required request body instead', () => {
      const refresh = fragment.operations['AuthController.refresh']

      expect(refresh?.['security']).toEqual([])
      expect(refresh?.['requestBody']).toEqual({
        required: true,
        content: {
          'application/json': {
            schema: {
              type: 'object',
              required: ['refreshToken'],
              properties: {
                refreshToken: {
                  type: 'string',
                  description: 'The refresh token, when it is not delivered as a cookie.'
                }
              }
            }
          }
        }
      })
    })

    // The session sweep needs BOTH credentials, and under `'bearer'` they arrive by different
    // channels: the access token in the header, the refresh token in the body. So the operation
    // is one access requirement PLUS a required body — and the body is the one the property
    // requirement rides on, because a caller who sends `{}` here is refused
    // (`auth.session_not_found`), not served a lesser answer.
    it('asks for the access header and a required body when both credentials are needed', () => {
      const revokeAll = fragment.operations['SessionController.revokeAllSessions']

      expect(revokeAll?.['security']).toEqual([{ [AUTH_SECURITY_SCHEMES.accessBearer]: [] }])
      expect(revokeAll?.['requestBody']).toEqual({
        required: true,
        content: {
          'application/json': {
            schema: {
              type: 'object',
              required: ['refreshToken'],
              properties: {
                refreshToken: {
                  type: 'string',
                  description: 'The refresh token, when it is not delivered as a cookie.'
                }
              }
            }
          }
        }
      })
    })

    // The same two credentials where the refresh half is only read: same access requirement, and
    // a body that may be omitted. The pair is the point — one required body and one optional,
    // from one delivery mode, because the two handlers really do differ.
    it('asks for the same header and an optional body when the refresh half is only read', () => {
      const list = fragment.operations['SessionController.listSessions']

      expect(list?.['security']).toEqual([{ [AUTH_SECURITY_SCHEMES.accessBearer]: [] }])
      expect(list?.['requestBody']).toEqual({
        required: false,
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                refreshToken: {
                  type: 'string',
                  description: 'The refresh token, when it is not delivered as a cookie.'
                }
              }
            }
          }
        }
      })
    })

    // Logout reads the same channels and requires none of them: it answers 204 whatever arrives.
    // The pair is the point — one required body and one optional, from one delivery mode, because
    // the two operations really do differ.
    it('describes the logout body as optional', () => {
      // The access half is named here too, and that is the security half of this operation: the
      // handler blacklists the access token's `jti` for whatever life it has left, so a client
      // told to send no `Authorization` header would revoke the refresh session and leave a live
      // access token in circulation until it expires. Neither credential is required — the empty
      // alternative says so — but both are named, so a generator attaches what it holds.
      expect(fragment.operations['AuthController.logout']?.['security']).toEqual([
        { [AUTH_SECURITY_SCHEMES.accessBearer]: [] },
        {}
      ])
      expect(fragment.operations['AuthController.logout']?.['requestBody']).toEqual({
        required: false,
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                refreshToken: {
                  type: 'string',
                  description: 'The refresh token, when it is not delivered as a cookie.'
                }
              }
            }
          }
        }
      })
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

    // Refresh accepts either form, and the empty requirement is what says so: `[{cookie}, {}]`
    // reads as "the cookie, OR nothing declared here" — which is how OpenAPI expresses a
    // credential that may arrive somewhere `security` cannot model. Without it the document
    // would refuse to describe the body-only caller, who is valid on this deployment.
    it('offers the cookie or the body, and describes both', () => {
      const refresh = fragment.operations['AuthController.refresh']

      expect(refresh?.['security']).toEqual([{ [AUTH_SECURITY_SCHEMES.refreshCookie]: [] }, {}])
      // Pinned whole because the interesting failure is a swap, not an absence: this is the one
      // mode where the property must NOT be required — the cookie may be carrying the token, so
      // a body that omits it is a request this deployment really does accept. Contributing the
      // `'bearer'` variant here would have a generated client reject its own valid caller.
      expect(refresh?.['requestBody']).toEqual({
        required: false,
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                refreshToken: {
                  type: 'string',
                  description: 'The refresh token, when it is not delivered as a cookie.'
                }
              }
            }
          }
        }
      })
    })
  })

  describe('two credentials at once, under tokenDelivery: both', () => {
    const fragment = buildAuthOpenApiFragment(optionsFor('both'), EVERYTHING)

    // Every access form, once with the refresh cookie beside it and once without — the product,
    // because a caller may present the access token either way and the refresh token either as
    // the cookie or in the body. An entry without the refresh cookie is NOT "no refresh token":
    // it is the body-borne one, which `security` has no way to name.
    it('offers each access form with and without the refresh cookie', () => {
      expect(fragment.operations['SessionController.revokeAllSessions']?.['security']).toEqual([
        {
          [AUTH_SECURITY_SCHEMES.accessCookie]: [],
          [AUTH_SECURITY_SCHEMES.refreshCookie]: []
        },
        {
          [AUTH_SECURITY_SCHEMES.accessBearer]: [],
          [AUTH_SECURITY_SCHEMES.refreshCookie]: []
        },
        { [AUTH_SECURITY_SCHEMES.accessCookie]: [] },
        { [AUTH_SECURITY_SCHEMES.accessBearer]: [] }
      ])
    })

    // Required and optional collapse here, and the test records it rather than hiding it: once a
    // body-borne alternative exists, no requirement list can insist on a credential that might be
    // arriving in the body. What the document CAN still say is that the body itself is optional —
    // the cookie may be carrying the token — so both operations describe it that way.
    it('describes the required and the optional case identically, body included', () => {
      const revokeAll = fragment.operations['SessionController.revokeAllSessions']
      const list = fragment.operations['SessionController.listSessions']

      expect(list?.['security']).toEqual(revokeAll?.['security'])
      expect(list?.['requestBody']).toEqual(revokeAll?.['requestBody'])
      expect(revokeAll?.['requestBody']).toEqual(expect.objectContaining({ required: false }))
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
        expect(fragment.components.securitySchemes[AUTH_SECURITY_SCHEMES.platformBearer]).toEqual({
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
          description:
            'Platform administrator access token, always delivered in the Authorization header ' +
            'regardless of tokenDelivery.'
        })
      }
    )

    // Platform refresh is the one operation with no access token: the body IS the credential, so
    // the body is required rather than optional.
    it('describes the platform refresh body as required', () => {
      const fragment = buildAuthOpenApiFragment(optionsFor('cookie'), EVERYTHING)
      const refresh = fragment.operations['PlatformAuthController.refresh']

      expect(refresh?.['security']).toEqual([])
      expect(refresh?.['requestBody']).toEqual({
        required: true,
        content: {
          'application/json': {
            schema: {
              type: 'object',
              required: ['refreshToken'],
              properties: {
                refreshToken: { type: 'string', description: 'The platform refresh token.' }
              }
            }
          }
        }
      })
    })

    // Platform logout is `@Public()` on purpose: an operator whose access token expired must
    // still be able to end the session, so the refresh token alone is enough. Both are read and
    // NEITHER is required — the empty alternative beside the bearer scheme is what lets a
    // generated client model the refresh-only logout the server supports, and a mandatory
    // requirement there would have it refuse to.
    it('describes platform logout as optional in both channels', () => {
      const fragment = buildAuthOpenApiFragment(optionsFor('cookie'), EVERYTHING)
      const logout = fragment.operations['PlatformAuthController.logout']

      expect(logout?.['security']).toEqual([{ [AUTH_SECURITY_SCHEMES.platformBearer]: [] }, {}])
      // The platform body keeps its schema-level requirement even here, where the body itself is
      // optional: the two say different things, and they are not in conflict. Logout accepts a
      // request with no body at all; one that DOES arrive still has to carry the token, because
      // there is no cookie on this surface for an empty object to be standing in for.
      expect(logout?.['requestBody']).toEqual({
        required: false,
        content: {
          'application/json': {
            schema: {
              type: 'object',
              required: ['refreshToken'],
              properties: {
                refreshToken: { type: 'string', description: 'The platform refresh token.' }
              }
            }
          }
        }
      })
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
