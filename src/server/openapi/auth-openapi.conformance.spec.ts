/**
 * @fileoverview Binds this library's inlined OpenAPI contract values to `@bymax-one/nest-core`'s
 * real ones, and the declared handler keys to the real controllers.
 *
 * The coupling decision is that nest-core is a **devDependency** and nothing in the published
 * bundle names it: the contract version is inlined, the contributor marker is the documented
 * string literal, and the fragment type is written out rather than imported. That buys a
 * zero-runtime bundle and costs the compile-time check — a fragment written against a contract
 * that has moved would compile here and fail at the consumer's boot.
 *
 * This file is where the check comes back. It imports nest-core's constants **as values** and
 * its types **as types**, in a file that never ships (`files` excludes specs), so the assertion
 * is real and the bundle is unchanged. A revision of the contract that this library has not
 * followed turns this suite red in the change that installed it, instead of turning a consumer's
 * document build red after publish.
 */
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

import {
  BYMAX_OPENAPI_CONTRACT_VERSION,
  BYMAX_OPENAPI_CONTRIBUTOR_METADATA
} from '@bymax-one/nest-core/openapi'
import type { IOpenApiContributor, OpenApiFragment } from '@bymax-one/nest-core/openapi'

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

describe('OpenAPI contributor — conformance with @bymax-one/nest-core', () => {
  // Verifies the inlined contract version is the one nest-core speaks. A fragment self-describes
  // because compile-time types protect nothing across a package boundary: the library compiled
  // against one revision runs inside an application that installed another. Inlining the value
  // is what keeps nest-core out of the runtime graph; this is what keeps the inlined value true.
  it('inlines the contract version nest-core publishes', () => {
    expect(OPENAPI_CONTRACT_VERSION).toBe(BYMAX_OPENAPI_CONTRACT_VERSION)
  })

  // Verifies the marker string is theirs. nest-core documents it as a literal precisely so a
  // library can write it without importing the decorator — and a typo here is invisible: the
  // provider simply is never discovered, the document renders without the fragments, and nothing
  // fails.
  it('marks the contributor with the metadata key nest-core scans for', () => {
    expect(OPENAPI_CONTRIBUTOR_METADATA).toBe(BYMAX_OPENAPI_CONTRIBUTOR_METADATA)
  })

  // Verifies the contributor satisfies nest-core's interface, and the fragment its fragment type.
  // Both are assignments rather than assertions: they fail at COMPILE time, which is the only
  // moment a shape mismatch can be caught before a consumer's boot. The runtime expectation
  // below is there so the case is not an empty test body.
  it('produces a value assignable to nest-core’s own types', () => {
    const contributor: IOpenApiContributor = new AuthOpenApiContributor(
      optionsFor('cookie'),
      EVERYTHING
    )
    const fragment: OpenApiFragment = contributor.contributeOpenApi()

    expect(fragment.contractVersion).toBe(BYMAX_OPENAPI_CONTRACT_VERSION)
  })

  // Verifies every declared handler key names a method that really exists on the controller it
  // names. This is the acceptance test the whole table depends on: nest-core fails a consumer's
  // document build for a key it cannot resolve, so a renamed handler here would not be a stale
  // comment — it would be a broken build in someone else's repository, on upgrade.
  it.each(Object.keys(buildAuthOpenApiFragment(optionsFor('both'), EVERYTHING).operations))(
    '%s names a real controller method',
    (key) => {
      const [controllerName, method] = key.split('.')
      const controller = CONTROLLERS[controllerName!]

      expect(controller).toBeDefined()
      expect(typeof (controller!.prototype as Record<string, unknown>)[method!]).toBe('function')
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

  // Verifies the coupling itself: no file that SHIPS imports `@bymax-one/nest-core`. This is the
  // invariant every other decision here rests on — the contract version is inlined and the
  // marker is a string literal precisely so the published bundle never names that package, and
  // an `import type` added in a hurry would undo it silently. TypeScript erases type-only
  // imports, so the bundle would still look clean while the emitted `.d.ts` referenced a package
  // no consumer installed, and their build would fail on a name they never wrote.
  //
  // Asserted over the source rather than over `dist`, so it fails before a build has to happen —
  // and over the whole tree rather than this directory, because the next import would not
  // necessarily be here. Prose in a comment is fine and is what the exclusion below allows: the
  // envelope-filter JSDoc names nest-core deliberately, and a reader is not an importer.
  it('imports @bymax-one/nest-core from test files only', () => {
    const offenders: string[] = []

    const walk = (dir: string): void => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const path = join(dir, entry.name)
        if (entry.isDirectory()) {
          if (entry.name !== 'coverage') walk(path)
          continue
        }
        if (!entry.name.endsWith('.ts') || entry.name.endsWith('.spec.ts')) continue
        if (/(?:from|import\()\s*['"]@bymax-one\/nest-core/.test(readFileSync(path, 'utf8'))) {
          offenders.push(path)
        }
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
