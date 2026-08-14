/**
 * @fileoverview Derives this library's OpenAPI security posture from its resolved options.
 *
 * A pure function, separate from the contributor class that calls it, because everything
 * interesting here is a function of configuration and nothing of Nest: which schemes a
 * deployment can satisfy, which operations exist to describe, and what each of them requires.
 * The class is the adapter; this is the decision.
 *
 * **Why a library cannot state this statically.** The same build serves `/auth/login` in one
 * deployment and `/api/v2/identity/login` in another, with the credential in a cookie here and
 * in an `Authorization` header there, under cookie names the consumer chose. A static document
 * fragment would be wrong for every deployment but one. So the fragment is derived at the
 * consumer's boot, from the options that were actually resolved, and keyed by handler identity —
 * which survives every prefix, version and mount point.
 *
 * @layer OpenAPI
 */
import type { ResolvedOptions } from '../config/resolved-options'

/**
 * The contract revision this library writes fragments against.
 *
 * Inlined rather than imported, because this package depends on no other Bymax library — not
 * even in tests. A fragment carrying the wrong revision fails the consumer's document build
 * loudly and names this contributor, which is the failure mode the self-describing version
 * exists for; and the consumer's own suite is where the two constants can be compared at the
 * versions actually installed. See the conformance spec's gate.
 */
export const OPENAPI_CONTRACT_VERSION = 1

/**
 * The metadata key that marks a provider as a contributor.
 *
 * The documented string literal rather than nest-core's `BymaxOpenApiContributor()` decorator:
 * importing the decorator would make that package a dependency of this one. nest-core documents
 * the key as a literal precisely so a library can do this — it mints no random key per module
 * load. A typo here is silent (the provider is simply never discovered), which is why the
 * consumer's suite should assert it against `BYMAX_OPENAPI_CONTRIBUTOR_METADATA`.
 */
export const OPENAPI_CONTRIBUTOR_METADATA = 'bymax-one:openapi-contributor'

/**
 * The four security scheme names this library may define. A closed vocabulary.
 *
 * Each carries its transport, and that is load-bearing rather than decorative: a Security Scheme
 * Object has exactly one `type`, so `tokenDelivery: 'both'` cannot be one scheme — the
 * alternation lives in the requirement list, per OAS 3.0.3, which means the two transports need
 * two names. A bare `bymaxPlatformAccess` beside three suffixed names would then teach that the
 * suffix means "has a sibling", and a second platform transport would force either a breaking
 * rename or a permanent inconsistency.
 *
 * Renaming a scheme is a break a generated client feels, so these are stable identifiers. The
 * DEFINITIONS are derived from configuration; the names are not.
 */
export const AUTH_SECURITY_SCHEMES = {
  accessCookie: 'bymaxAuthAccessCookie',
  accessBearer: 'bymaxAuthAccessBearer',
  refreshCookie: 'bymaxAuthRefreshCookie',
  platformBearer: 'bymaxPlatformAccessBearer'
} as const

/** Which of this library's controllers a deployment actually mounted. */
export interface RegisteredControllers {
  auth: boolean
  passwordReset: boolean
  mfa: boolean
  sessions: boolean
  platform: boolean
  platformMfa: boolean
  invitations: boolean
  emailChange: boolean
  oauth: boolean
}

/** One OpenAPI object, copied into the document and never interpreted. */
type FragmentObject = Readonly<Record<string, unknown>>

/** The shape `contributeOpenApi()` returns — structurally identical to nest-core's. */
export interface AuthOpenApiFragment {
  readonly contractVersion: typeof OPENAPI_CONTRACT_VERSION
  readonly operations: Readonly<Record<string, FragmentObject>>
  readonly components: { readonly securitySchemes: Readonly<Record<string, FragmentObject>> }
}

/**
 * What a handler needs from the caller, before the deployment's transport is applied.
 *
 * `none` is not the absence of a requirement — it is the statement that the operation is
 * reachable unauthenticated, which OpenAPI writes as `security: []` and which a generated client
 * needs in order to NOT attach a credential. Leaving it out would let the document's own default
 * apply, and the consumer's default is "authenticated".
 */
type Credential =
  | 'none'
  | 'access'
  /** The refresh credential is REQUIRED: with none of its forms present the operation 401s. */
  | 'refreshRequired'
  /** The refresh credential is READ but optional: absent, the operation still answers 204. */
  | 'refreshOptional'
  | 'platform'
  | 'platformLogout'
  | 'platformRefresh'

/**
 * Every operation this library can mount, with the credential it requires.
 *
 * Keyed by handler identity — `'<ControllerClassName>.<methodName>'` — which is what nest-core
 * resolves against the operations the scan produced. A key naming a handler the document does
 * not contain **fails the consumer's document build**, so the list is filtered by what the
 * deployment registered before it is contributed. That is why this is a table rather than a
 * literal: the fragment is a function of the module's own registration decisions.
 */
const OPERATIONS: Readonly<
  Record<keyof RegisteredControllers, Readonly<Record<string, Credential>>>
> = {
  auth: {
    'AuthController.register': 'none',
    'AuthController.login': 'none',
    // Both read the refresh credential, and neither is behind a guard: they are `@Public()`
    // because an expired access token must not stop a caller from ending or renewing a
    // session. What authorises them is the refresh token itself.
    // Measured, and the two differ: `logout` answers 204 with no credential at all, while
    // `refresh` 401s. Describing them alike would tell a generated client that one demands
    // something it does not, or that the other tolerates something it will refuse.
    'AuthController.logout': 'refreshOptional',
    'AuthController.refresh': 'refreshRequired',
    'AuthController.me': 'access',
    'AuthController.wsTicket': 'access',
    'AuthController.verifyEmail': 'none',
    'AuthController.resendVerification': 'none'
  },
  passwordReset: {
    'PasswordResetController.forgotPassword': 'none',
    'PasswordResetController.resetPassword': 'none',
    'PasswordResetController.changePassword': 'access',
    'PasswordResetController.verifyOtp': 'none',
    'PasswordResetController.resendOtp': 'none'
  },
  mfa: {
    'MfaController.setup': 'access',
    'MfaController.verifyEnable': 'access',
    // The challenge is reached with a temp token, not a session — by definition the caller has
    // no access token yet, which is what the challenge exists to earn.
    'MfaController.challenge': 'none',
    'MfaController.disable': 'access',
    'MfaController.regenerateRecoveryCodes': 'access'
  },
  sessions: {
    'SessionController.listSessions': 'access',
    'SessionController.revokeAllSessions': 'access',
    'SessionController.revokeSession': 'access'
  },
  platform: {
    'PlatformAuthController.login': 'none',
    'PlatformAuthController.mfaChallenge': 'none',
    'PlatformAuthController.me': 'platform',
    // The access token authorises the logout; the refresh token in the body names the session
    // to end. Both are read, so both are described.
    'PlatformAuthController.logout': 'platformLogout',
    // Refresh is the one platform operation with no access token at all: the refresh token in
    // the body is the whole credential.
    'PlatformAuthController.refresh': 'platformRefresh',
    'PlatformAuthController.revokeSessions': 'platform'
  },
  platformMfa: {
    'PlatformMfaController.setup': 'platform',
    'PlatformMfaController.verifyEnable': 'platform',
    'PlatformMfaController.disable': 'platform',
    'PlatformMfaController.regenerateRecoveryCodes': 'platform'
  },
  invitations: {
    'InvitationController.invite': 'access',
    'InvitationController.revoke': 'access',
    // Accepting is how an invitee gets their first credential, so it cannot require one.
    'InvitationController.accept': 'none'
  },
  emailChange: {
    'EmailChangeController.requestChange': 'access',
    // Public because the holder is proving control of a mailbox, not of a session.
    'EmailChangeController.confirmChange': 'none'
  },
  oauth: {
    'OAuthController.initiate': 'none',
    'OAuthController.callback': 'none'
  }
}

/**
 * The request body the two dashboard token operations read when the refresh token is not a
 * cookie.
 *
 * Contributed rather than declared on a DTO because there is no DTO: both handlers read the raw
 * body through `TokenDeliveryService`, so `@nestjs/swagger` has nothing to scan and a generated
 * client is told to POST nothing. Optional, because under `'both'` the same operation accepts
 * the cookie instead.
 */
const REFRESH_BODY: FragmentObject = {
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
}

/** The same body, required — the platform surface never accepts a cookie. */
const PLATFORM_REFRESH_BODY: FragmentObject = {
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
}

/**
 * Builds this library's fragment for one resolved deployment.
 *
 * @param options - The options this deployment resolved.
 * @param registered - Which of this library's controllers it mounted.
 * @returns The fragment to hand to nest-core.
 */
export function buildAuthOpenApiFragment(
  options: ResolvedOptions,
  registered: RegisteredControllers
): AuthOpenApiFragment {
  const cookieDelivery = options.tokenDelivery === 'cookie' || options.tokenDelivery === 'both'
  const bearerDelivery = options.tokenDelivery === 'bearer' || options.tokenDelivery === 'both'

  const operations: Record<string, FragmentObject> = {}

  for (const [controller, handlers] of Object.entries(OPERATIONS)) {
    if (!registered[controller as keyof RegisteredControllers]) continue

    for (const [handler, credential] of Object.entries(handlers)) {
      operations[handler] = describe(credential, cookieDelivery, bearerDelivery)
    }
  }

  return {
    contractVersion: OPENAPI_CONTRACT_VERSION,
    operations,
    components: { securitySchemes: schemesFor(options, registered, cookieDelivery, bearerDelivery) }
  }
}

/**
 * The security requirement — and, where one is read, the request body — for one credential.
 *
 * The alternation under `'both'` is a two-entry requirement LIST, which OpenAPI reads as OR: a
 * caller satisfies the operation with either the cookie or the bearer token. Writing it as one
 * entry with two schemes would mean AND, and would describe a server that demands the credential
 * twice.
 */
function describe(
  credential: Credential,
  cookieDelivery: boolean,
  bearerDelivery: boolean
): FragmentObject {
  switch (credential) {
    case 'none':
      return { security: [] }
    case 'access':
      return {
        security: [
          ...(cookieDelivery ? [{ [AUTH_SECURITY_SCHEMES.accessCookie]: [] }] : []),
          ...(bearerDelivery ? [{ [AUTH_SECURITY_SCHEMES.accessBearer]: [] }] : [])
        ]
      }
    case 'refreshRequired':
      // Under `'bearer'` there is no refresh scheme to reference — the token arrives in the body,
      // which OpenAPI models as a request body and not as a security scheme. So a scheme the
      // resolved options cannot satisfy is ABSENT rather than defined-and-unreferenced, and the
      // body carries the requirement instead: REQUIRED here, because with neither form present
      // this operation refuses.
      //
      // Under `'both'` either form works, and the empty requirement is what says so: a two-entry
      // list `[{cookie}, {}]` reads as "the cookie, OR nothing declared here" — which is how
      // OpenAPI expresses a credential that may arrive somewhere it cannot model. Without the
      // empty entry the document would refuse to describe the body-only caller, who is valid.
      return {
        security: cookieDelivery
          ? bearerDelivery
            ? [{ [AUTH_SECURITY_SCHEMES.refreshCookie]: [] }, {}]
            : [{ [AUTH_SECURITY_SCHEMES.refreshCookie]: [] }]
          : [],
        ...(bearerDelivery
          ? { requestBody: cookieDelivery ? REFRESH_BODY : { ...REFRESH_BODY, required: true } }
          : {})
      }
    case 'refreshOptional':
      // Same channels, no requirement: this operation answers 204 whatever arrives, so every
      // form is optional and the empty alternative is present in every mode that has a scheme.
      return {
        security: cookieDelivery ? [{ [AUTH_SECURITY_SCHEMES.refreshCookie]: [] }, {}] : [],
        ...(bearerDelivery ? { requestBody: REFRESH_BODY } : {})
      }
    case 'platform':
      return { security: [{ [AUTH_SECURITY_SCHEMES.platformBearer]: [] }] }
    case 'platformLogout':
      // `@Public()`, deliberately: an operator whose access token expired must still be able to
      // end the session, so the refresh token alone is enough. Both are read and NEITHER is
      // required — the empty alternative beside the bearer scheme is what lets a generated
      // client model the refresh-only logout the server supports.
      return {
        security: [{ [AUTH_SECURITY_SCHEMES.platformBearer]: [] }, {}],
        requestBody: { ...PLATFORM_REFRESH_BODY, required: false }
      }
    case 'platformRefresh':
      return { security: [], requestBody: PLATFORM_REFRESH_BODY }
  }
}

/**
 * The scheme definitions a deployment can actually satisfy.
 *
 * A scheme the resolved options cannot satisfy is neither defined nor referenced — absent, not
 * unreferenced. Two reasons, and the second is the one that decides it: nest-core fails the boot
 * on a requirement naming a scheme the document does not define, so definition and reference
 * have to agree; and a document that defines `bymaxAuthAccessBearer` on a cookie-only deployment
 * tells a client generator to offer a credential the server will not read.
 *
 * The cookie NAMES are the consumer's to choose, which is the other half of why this cannot be
 * static: `apiKey`-in-cookie schemes carry the name, and a document naming `access_token` on a
 * deployment that renamed it describes a different server.
 */
function schemesFor(
  options: ResolvedOptions,
  registered: RegisteredControllers,
  cookieDelivery: boolean,
  bearerDelivery: boolean
): Record<string, FragmentObject> {
  const schemes: Record<string, FragmentObject> = {}

  // The dashboard schemes exist only where a dashboard operation does. A platform-only
  // deployment defines neither.
  const dashboardMounted =
    registered.auth ||
    registered.passwordReset ||
    registered.mfa ||
    registered.sessions ||
    registered.invitations ||
    registered.emailChange

  if (dashboardMounted && cookieDelivery) {
    schemes[AUTH_SECURITY_SCHEMES.accessCookie] = {
      type: 'apiKey',
      in: 'cookie',
      name: options.cookies.accessTokenName,
      description: 'Access token, delivered as an HttpOnly cookie.'
    }
  }

  if (dashboardMounted && bearerDelivery) {
    schemes[AUTH_SECURITY_SCHEMES.accessBearer] = {
      type: 'http',
      scheme: 'bearer',
      bearerFormat: 'JWT',
      description: 'Access token, delivered in the Authorization header.'
    }
  }

  // The refresh cookie is referenced only by `logout` and `refresh`, so it is defined only when
  // the controller carrying them is mounted AND the deployment delivers it as a cookie.
  if (registered.auth && cookieDelivery) {
    schemes[AUTH_SECURITY_SCHEMES.refreshCookie] = {
      type: 'apiKey',
      in: 'cookie',
      name: options.cookies.refreshTokenName,
      description: 'Refresh token, delivered as an HttpOnly cookie scoped to the auth prefix.'
    }
  }

  // The platform credential is bearer in every mode: `extractPlatformAccessToken` reads the
  // Authorization header whatever `tokenDelivery` says, so a cookie-only deployment still
  // authenticates its platform admins by header. The pair never has a refresh scheme, in any
  // mode — the platform refresh token is a body field.
  if (registered.platform || registered.platformMfa) {
    schemes[AUTH_SECURITY_SCHEMES.platformBearer] = {
      type: 'http',
      scheme: 'bearer',
      bearerFormat: 'JWT',
      description:
        'Platform administrator access token, always delivered in the Authorization header ' +
        'regardless of tokenDelivery.'
    }
  }

  return schemes
}
