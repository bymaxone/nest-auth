/**
 * @fileoverview The provider `@bymax-one/nest-core` discovers when it builds a document.
 *
 * Deliberately **not exported** from `src/server/index.ts`. A consumer never names this class:
 * they enable OpenAPI on their side and the fragments appear, or they do not use nest-core and
 * this provider is one unread metadata entry.
 *
 * **There is no coupling at all** — not a dependency, not a peer, not a devDependency. The
 * contract version is inlined, the marker is the documented string literal, and the fragment type
 * is written out; a conformance gate fails on an import of any other `@bymax-one/*` package, in
 * any file including tests. What that gives up is a compile-time check that the fragment still
 * matches nest-core's contract, and that check belongs to the consumer: their suite runs both
 * packages at the versions they installed, which is the only place the question is real.
 *
 * @layer OpenAPI
 */
import { Inject, Injectable, SetMetadata } from '@nestjs/common'

import { buildAuthOpenApiFragment, OPENAPI_CONTRIBUTOR_METADATA } from './auth-openapi-fragment'
import type { AuthOpenApiFragment, RegisteredControllers } from './auth-openapi-fragment'
import { BYMAX_AUTH_OPTIONS, BYMAX_AUTH_REGISTERED_CONTROLLERS } from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'

/**
 * Describes this library's routes in the consumer's OpenAPI document.
 *
 * Structurally an `IOpenApiContributor` — nest-core discovers it by the metadata marker and
 * calls `contributeOpenApi()` once, while the document is being built. The interface is asserted
 * against nest-core's own declaration in `auth-openapi.conformance.spec.ts` rather than
 * `implements`-ed here: a type import in production code would be a compile-time coupling to a
 * package this library does not depend on, and the assertion is the same check moved to where
 * the dependency is allowed to exist.
 *
 * Registered unconditionally. It costs an application that never builds a document one metadata
 * entry, and there is no opt-out flag by decision rather than by omission: the blast radius is a
 * dev-only document, the failures are loud and name the contributor, and an escape hatch is a
 * second path to test and mutate forever for a case nobody could name.
 *
 * **On nest-core < 1.4.0 there is no contributor lane at all**, so the fragments are silently
 * ignored: the document renders exactly as before, with no error, no warning and no failed boot.
 * That is stated in the README symptom-first, because a boot warning would mean reaching into
 * nest-core to detect it — the coupling this whole arrangement exists to avoid.
 */
@Injectable()
@SetMetadata(OPENAPI_CONTRIBUTOR_METADATA, true)
export class AuthOpenApiContributor {
  constructor(
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions,
    @Inject(BYMAX_AUTH_REGISTERED_CONTROLLERS)
    private readonly registered: RegisteredControllers
  ) {}

  /**
   * Produces the fragments for this deployment.
   *
   * @returns Operations keyed by handler identity, and the security schemes they reference.
   */
  contributeOpenApi(): AuthOpenApiFragment {
    return buildAuthOpenApiFragment(this.options, this.registered)
  }
}
