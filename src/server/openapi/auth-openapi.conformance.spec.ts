/**
 * @fileoverview Binds the contributor's claims to this repository — and to nothing outside it.
 *
 * **This package imports no other Bymax library, anywhere, including in tests.** The OpenAPI
 * contract version is inlined, the contributor marker is the documented string literal, and the
 * fragment type is written out rather than imported, so nothing here names `@bymax-one/nest-core`
 * — and the gate below fails on an import of ANY `@bymax-one/*` package other than this one's own
 * subpaths.
 *
 * What that costs is a compile-time check that the fragment still matches nest-core's contract.
 * What it buys is the rule this repository already applies to the envelope filter: a library does
 * not take a dependency on its consumers' stack in order to assert a composition. **The consumer
 * owns that assertion**, and they can make it better than we can — their suite has both packages
 * installed at the versions they actually run.
 *
 * Everything below is checkable without anyone else's code: the handler table against the real
 * controllers in both directions, the scheme vocabulary, and the invariant that no requirement
 * names a scheme the fragment does not define.
 */
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

import {
  AUTH_SECURITY_SCHEMES,
  buildAuthOpenApiFragment,
  OPENAPI_CONTRACT_VERSION,
  OPENAPI_CONTRIBUTOR_METADATA
} from './auth-openapi-fragment'
import type { RegisteredControllers } from './auth-openapi-fragment'
import { AuthOpenApiContributor } from './auth-openapi.contributor'
import { AuthController } from '../controllers/auth.controller'
import { EmailChangeController } from '../controllers/email-change.controller'
import { InvitationController } from '../controllers/invitation.controller'
import { MfaController } from '../controllers/mfa.controller'
import { PasswordResetController } from '../controllers/password-reset.controller'
import { PlatformAuthController } from '../controllers/platform-auth.controller'
import { PlatformMfaController } from '../controllers/platform-mfa.controller'
import { SessionController } from '../controllers/session.controller'
import { OAuthController } from '../oauth/oauth.controller'
import type { ResolvedOptions } from '../config/resolved-options'

/** Every controller this library can mount, by the class name the handler keys use. */
const CONTROLLERS: Readonly<Record<string, new (...args: never[]) => object>> = {
  AuthController,
  PasswordResetController,
  MfaController,
  SessionController,
  PlatformAuthController,
  PlatformMfaController,
  InvitationController,
  EmailChangeController,
  OAuthController
}

/** Everything mounted, so the fragment carries every handler this library can declare. */
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

/** Enough resolved options for the fragment builder, which reads three fields. */
function optionsFor(tokenDelivery: ResolvedOptions['tokenDelivery']): ResolvedOptions {
  return {
    tokenDelivery,
    cookies: { accessTokenName: 'access_token', refreshTokenName: 'refresh_token' }
  } as unknown as ResolvedOptions
}

describe('OpenAPI contributor — conformance', () => {
  // Verifies the two values a consumer's document build depends on, and that they are STABLE.
  // Neither is compared against nest-core here — that would mean depending on it — so what this
  // pins is that they cannot drift silently on our side. The comparison against their constants
  // is the CONSUMER's to make, in the one place both packages exist at their installed versions.
  it('publishes a stable contract version and marker', () => {
    expect(OPENAPI_CONTRACT_VERSION).toBe(1)
    expect(OPENAPI_CONTRIBUTOR_METADATA).toBe('bymax-one:openapi-contributor')
  })

  // Verifies the contributor produces a fragment of the shape the contract describes: a version,
  // operations keyed by handler, and components carrying the security schemes. Structural rather
  // than a type assignment, because the type it would be assigned to lives in a package this
  // repository does not install.
  it('produces a fragment shaped the way the contract describes', () => {
    const fragment = new AuthOpenApiContributor(
      optionsFor('cookie'),
      EVERYTHING
    ).contributeOpenApi()

    expect(fragment.contractVersion).toBe(OPENAPI_CONTRACT_VERSION)
    expect(Object.keys(fragment.operations).length).toBeGreaterThan(0)
    expect(fragment.components.securitySchemes).toEqual(expect.any(Object))
  })

  // Verifies every declared handler key names a ROUTE handler on the controller it names — not
  // merely a method. This is the acceptance test the whole table depends on: nest-core fails a
  // consumer's document build for a key it cannot resolve, so a renamed handler here would not
  // be a stale comment — it would be a broken build in someone else's repository, on upgrade.
  //
  // `typeof === 'function'` was the earlier check and is too loose in two ways that meet. It
  // accepts a real method that carries no verb decorator, which produces no operation for the
  // key to match; and the lookup resolves through the PROTOTYPE CHAIN, so `toString`,
  // `valueOf` and `hasOwnProperty` all answer `'function'` on any class. A typo landing on an
  // inherited member would therefore pass here and fail in the consumer's build — the same
  // prototype-chain reach that once let a catalog lookup hand a FUNCTION to `HttpException` as
  // a status. Requiring the routing metadata closes both: a key must name something Nest
  // actually routes.
  it.each(Object.keys(buildAuthOpenApiFragment(optionsFor('both'), EVERYTHING).operations))(
    '%s names a real route handler',
    (key) => {
      const [controllerName, method] = key.split('.')
      const controller = CONTROLLERS[controllerName!]

      expect(controller).toBeDefined()
      const target = (controller!.prototype as Record<string, unknown>)[method!]

      expect(typeof target).toBe('function')
      expect(Reflect.hasMetadata('path', target as object)).toBe(true)
    }
  )

  // Verifies the reverse direction — every ROUTE handler on a mounted controller is described.
  // Without it the table can silently fall behind: a new endpoint ships undescribed, the
  // document renders, and the operation inherits the consumer's document-level security, which
  // is the wrong answer for a public route and an unenforced promise for a protected one.
  it.each(Object.entries(CONTROLLERS))(
    '%s has every route handler described',
    (name, controller) => {
      const declared = new Set(
        Object.keys(buildAuthOpenApiFragment(optionsFor('both'), EVERYTHING).operations)
      )

      const handlers = Object.getOwnPropertyNames(controller.prototype).filter(
        (member) =>
          member !== 'constructor' &&
          typeof (controller.prototype as Record<string, unknown>)[member] === 'function' &&
          // Private helpers are not routes. They are the only non-route methods on these classes,
          // and each is named for what it does rather than for a path.
          Reflect.hasMetadata(
            'path',
            (controller.prototype as Record<string, unknown>)[member] as object
          )
      )

      expect(handlers.length).toBeGreaterThan(0)
      for (const handler of handlers) {
        expect(declared).toContain(`${name}.${handler}`)
      }
    }
  )

  // Verifies the coupling: **no file in this repository imports another Bymax library**, test
  // files included. This is the invariant every other decision here rests on — the contract
  // version is inlined and the marker is a string literal precisely so nothing, published or not,
  // names another package in the family.
  //
  // An earlier draft imported nest-core's constants to compare against, reasoning that test files
  // do not ship. True, and not the point: a library does not take a dependency on its consumers'
  // stack in order to assert a composition. That is the rule this repository already applies to
  // the envelope filter, and the consumer is better placed to make the assertion anyway — their
  // suite runs both packages at the versions they installed.
  //
  // This package's OWN subpaths are excluded: `@bymax-one/nest-auth/shared` inside `src/client`
  // is a self-reference the build maps back into this tree, not a dependency on anyone.
  //
  // Prose is fine, and the exclusion is deliberate: the envelope-filter JSDoc names nest-core on
  // purpose, and a reader is not an importer.
  it('imports no other Bymax library, in any file', () => {
    const offenders: string[] = []
    // Every import form, not just the one that reads naturally: `from '…'`, a dynamic
    // `import('…')`, a bare side-effect `import '…'`, and `require('…')`. A side-effect import
    // introduces the dependency while carrying no binding to grep for, which is exactly the shape
    // that would have slipped past the first version of this gate.
    const foreign = /(?:from|import|require)\s*\(?\s*['"]@bymax-one\/(?!nest-auth)/

    const walk = (dir: string): void => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const path = join(dir, entry.name)
        if (entry.isDirectory()) {
          if (entry.name !== 'coverage') walk(path)
          continue
        }
        if (!entry.name.endsWith('.ts') && !entry.name.endsWith('.tsx')) continue
        if (foreign.test(readFileSync(path, 'utf8'))) offenders.push(path)
      }
    }

    walk(join(__dirname, '../..'))

    expect(offenders).toEqual([])
  })

  // Verifies the scheme vocabulary is exactly the four names that were settled. Renaming one is a
  // break a generated client feels — the requirement list stops matching the definitions — so the
  // set is pinned rather than left to whatever the builder happens to emit.
  it('declares exactly the four settled scheme names', () => {
    expect(Object.values(AUTH_SECURITY_SCHEMES).sort()).toEqual([
      'bymaxAuthAccessBearer',
      'bymaxAuthAccessCookie',
      'bymaxAuthRefreshCookie',
      'bymaxPlatformAccessBearer'
    ])
  })

  // Verifies every scheme a requirement names is also defined, in every delivery mode. This is
  // the invariant nest-core enforces at the consumer's boot (`assertSchemesDeclared`), so a
  // deployment that could produce a dangling reference fails HERE — in this repository, on the
  // change that introduced it — rather than in an application that merely installed it.
  it.each(['cookie', 'bearer', 'both'] as const)(
    'references no undefined scheme under tokenDelivery: %s',
    (tokenDelivery) => {
      const fragment = buildAuthOpenApiFragment(optionsFor(tokenDelivery), EVERYTHING)
      const defined = new Set(Object.keys(fragment.components.securitySchemes))

      const referenced = Object.values(fragment.operations)
        .flatMap((operation) => (operation['security'] ?? []) as Record<string, unknown>[])
        .flatMap((requirement) => Object.keys(requirement))

      expect(referenced.length).toBeGreaterThan(0)
      for (const name of referenced) {
        expect(defined).toContain(name)
      }
    }
  )

  // The other half of the same rule: a scheme that is DEFINED but never referenced. nest-core
  // does not fail on it, which is what makes it worth asserting here — an unreferenced scheme is
  // a credential the document offers and the server never reads, and it survives every check
  // that only looks for dangling references.
  it.each(['cookie', 'bearer', 'both'] as const)(
    'defines no unreferenced scheme under tokenDelivery: %s',
    (tokenDelivery) => {
      const fragment = buildAuthOpenApiFragment(optionsFor(tokenDelivery), EVERYTHING)

      const referenced = new Set(
        Object.values(fragment.operations)
          .flatMap((operation) => (operation['security'] ?? []) as Record<string, unknown>[])
          .flatMap((requirement) => Object.keys(requirement))
      )

      for (const name of Object.keys(fragment.components.securitySchemes)) {
        expect(referenced).toContain(name)
      }
    }
  )
})
