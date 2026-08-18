/**
 * @fileoverview Derives the document-level security requirement a consumer's OWN routes need.
 *
 * Layer: server / OpenAPI contribution.
 *
 * An OpenAPI contributor carries operations and components — never the document root. So the
 * top-level `security` default, which is what covers the routes a consuming backend owns, stays
 * the consumer's to set. But the scheme it must name, and whether that scheme exists at all, are
 * both decided by THIS library's configuration: `tokenDelivery` picks the transport, and a
 * platform guard reads the Authorization header whatever that setting says.
 *
 * That split is a trap. The consumer has to write a name they do not control, so they write a
 * literal, and the literal is correct until someone changes a setting in a different file. It has
 * already cost a real deployment: a backend whose `tokenDelivery` is a validated environment enum
 * kept a hard-coded cookie scheme in its document default, and setting that variable to `bearer`
 * stopped the process from booting — the document named a scheme nothing declared, and the
 * document build refuses that rather than serving a dangling reference.
 *
 * This function is the derivation those consumers were writing by hand, answering the two
 * questions the README poses in prose: which guard protects your routes, and how does this
 * deployment deliver tokens.
 */
import { AUTH_SECURITY_SCHEMES, deliversBearer, deliversCookie } from './auth-openapi-fragment'
import { DEFAULT_OPTIONS } from '../config/default-options'
import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'

/**
 * Which of this library's guards protects the consumer's own routes.
 *
 * The two families take different credentials, and only one of them varies with delivery — which
 * is why a recipe phrased on `tokenDelivery` alone is wrong for half the deployments that use it.
 */
export type AuthGuardFamily = 'dashboard' | 'platform'

/**
 * One of the four names this library may define.
 *
 * Typed as the closed vocabulary rather than `string`, so the helper below cannot be handed a
 * name the library never declares — which is the whole failure this module exists to prevent.
 */
type AuthSecuritySchemeName = (typeof AUTH_SECURITY_SCHEMES)[keyof typeof AUTH_SECURITY_SCHEMES]

/** One OpenAPI Security Requirement Object: scheme name to the scopes it takes. */
export type OpenApiSecurityRequirement = Readonly<Record<string, readonly string[]>>

/** The two questions that decide a deployment's document-level default. */
export interface AuthDocumentSecurityParams {
  /**
   * The guard on the consumer's own routes: `JwtAuthGuard` is `'dashboard'`,
   * `JwtPlatformGuard` is `'platform'`.
   */
  readonly guard: AuthGuardFamily
  /**
   * The value passed to `BymaxAuthModule.forRoot({ tokenDelivery })` — **including `undefined`**.
   *
   * Optional there, so a deployment that never set it is relying on the library's default, and
   * this accepts the option exactly as it is written rather than making the caller narrow it. A
   * required parameter here would force `options.tokenDelivery ?? 'cookie'` at every call site,
   * which hardcodes a library decision into consumer code — the failure this whole function
   * exists to remove, reintroduced one line further out.
   */
  readonly tokenDelivery: BymaxAuthModuleOptions['tokenDelivery']
}

/**
 * The scopes every requirement this library emits carries.
 *
 * Empty, and necessarily so: scopes belong to OAuth2 and OpenID Connect schemes, and every scheme
 * this library defines is `apiKey` or `http`. A non-empty list against those is a document no
 * generator can satisfy.
 */
const NO_SCOPES: readonly string[] = Object.freeze([])

/**
 * Wraps one scheme name as a frozen single-scheme requirement.
 *
 * @param scheme - A name from {@link AUTH_SECURITY_SCHEMES}.
 * @returns The requirement object, frozen.
 */
function requirementFor(scheme: AuthSecuritySchemeName): OpenApiSecurityRequirement {
  return Object.freeze({ [scheme]: NO_SCOPES })
}

/**
 * Derives the document-level `security` default for a deployment's own routes.
 *
 * Drop the result straight into the `security` your OpenAPI document is built with. Deriving it
 * rather than writing a literal is what keeps the document honest when `tokenDelivery` changes:
 * the name follows the setting, so a mode switch cannot leave the default naming a scheme the
 * document no longer declares.
 *
 * Under `'both'` the result is a two-entry LIST, which OpenAPI reads as OR — a caller satisfies
 * the requirement with either transport. Merging the two names into a single entry would mean
 * AND, and would describe a server demanding the same credential twice.
 *
 * @param params - The guard family and the configured delivery mode. See
 *   {@link AuthDocumentSecurityParams}.
 * @returns The security requirement list, frozen, with every entry naming exactly one scheme.
 *
 * @remarks
 * The scheme is *declared* only where a surface that uses it is mounted — the dashboard names
 * require a dashboard controller, the platform name requires the platform surface. A deployment
 * that mounts neither has no library scheme to name and should not set a default from this
 * library at all.
 *
 * @example
 * ```ts
 * BymaxCoreModule.forRoot({
 *   openapi: { security: authDocumentSecurity({ guard: 'dashboard', tokenDelivery }) }
 * })
 * ```
 */
export function authDocumentSecurity({
  guard,
  tokenDelivery
}: AuthDocumentSecurityParams): readonly OpenApiSecurityRequirement[] {
  // The platform credential is bearer in every mode: `extractPlatformAccessToken` reads the
  // Authorization header whatever `tokenDelivery` says, so delivery does not enter this arm.
  if (guard === 'platform') {
    return Object.freeze([requirementFor(AUTH_SECURITY_SCHEMES.platformBearer)])
  }

  // The same two predicates the fragment builder uses to decide which schemes it DECLARES.
  // Shared rather than restated: a document default naming a scheme the fragment does not declare
  // is the boot failure this function exists to remove, and two copies of the condition is where
  // that divergence would come from.
  // Omission resolved through the SAME default the module resolves it with. Reading it from
  // `DEFAULT_OPTIONS` rather than writing `'cookie'` here keeps one source: a change to the
  // module default reaches this derivation without anyone remembering that a second copy exists.
  //
  // Left unresolved, both predicates answer `false` for `undefined` and a dashboard guard would
  // derive an EMPTY requirement list — a document declaring the consumer's guarded routes open.
  const delivery = tokenDelivery ?? DEFAULT_OPTIONS.tokenDelivery

  const schemes = [
    ...(deliversCookie(delivery) ? [AUTH_SECURITY_SCHEMES.accessCookie] : []),
    ...(deliversBearer(delivery) ? [AUTH_SECURITY_SCHEMES.accessBearer] : [])
  ]

  return Object.freeze(schemes.map(requirementFor))
}
