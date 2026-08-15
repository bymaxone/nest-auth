/**
 * @fileoverview The OpenAPI contributor, read out of a booted application.
 *
 * The unit specs prove what the fragment says for a given configuration. What they cannot prove
 * is that a consumer ever RECEIVES it: the provider has to be registered by the module, carry the
 * metadata marker nest-core scans for, and be constructible with the registration flags the
 * module computed — none of which is visible from a function that takes its inputs as arguments.
 *
 * So this boots the real module, resolves the provider from the container the way nest-core's
 * `DiscoveryService` would, and reads the fragment it produces for the controllers that
 * deployment actually mounted.
 */

import { RequestMethod } from '@nestjs/common'
import { METHOD_METADATA } from '@nestjs/common/constants'
import { Reflector } from '@nestjs/core'

import { AuthController } from '../../src/server/controllers/auth.controller'
import { EmailChangeController } from '../../src/server/controllers/email-change.controller'
import { InvitationController } from '../../src/server/controllers/invitation.controller'
import { MfaController } from '../../src/server/controllers/mfa.controller'
import { PasswordResetController } from '../../src/server/controllers/password-reset.controller'
import { PlatformAuthController } from '../../src/server/controllers/platform-auth.controller'
import { PlatformMfaController } from '../../src/server/controllers/platform-mfa.controller'
import { SessionController } from '../../src/server/controllers/session.controller'
import { OAuthController } from '../../src/server/oauth/oauth.controller'

import { AuthOpenApiContributor } from '../../src/server/openapi/auth-openapi.contributor'
import { OPENAPI_CONTRIBUTOR_METADATA } from '../../src/server/openapi/auth-openapi-fragment'
import { bootstrapTestApp } from './setup'
import type { BootstrappedTestApp } from './setup'

/** Methods RFC 7231 leaves without payload semantics, which OpenAPI 3.0.3 defers to. */
const BODYLESS_METHODS = new Set([RequestMethod.GET, RequestMethod.DELETE, RequestMethod.HEAD])

/**
 * Every controller this library can mount, by the class name the fragment keys itself with.
 *
 * The map exists so the check below can reach a handler's decorator metadata from a
 * `'Controller.method'` string. A contributed controller missing from it fails the test rather
 * than being skipped — the silent skip is the failure mode a coverage gate like this dies of.
 */
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

/**
 * The HTTP method Nest will route a contributed handler with.
 *
 * Read from `METHOD_METADATA` on the handler itself — the same metadata the framework's own
 * route explorer reads — so the answer comes from the decorator rather than from a list this
 * suite would have to keep in step with the controllers.
 *
 * @param handler - A `'Controller.method'` key from the fragment.
 * @returns The `RequestMethod` the handler is decorated with.
 */
function methodOf(handler: string): RequestMethod {
  const [controllerName, methodName] = handler.split('.')
  const controller = CONTROLLERS[controllerName as keyof typeof CONTROLLERS]

  if (controller === undefined || methodName === undefined) {
    // Not a soft skip: a contributed controller this map does not know is exactly the case that
    // would let a future handler carry an ignored body past the gate.
    throw new Error(`no controller class registered for the contributed handler '${handler}'`)
  }

  const target = (controller.prototype as Record<string, unknown>)[methodName]
  const method: unknown = Reflect.getMetadata(METHOD_METADATA, target as object)

  if (typeof method !== 'number') {
    throw new Error(`'${handler}' carries no HTTP method metadata`)
  }
  return method
}

describe('OpenAPI contributor (E2E)', () => {
  let boot: BootstrappedTestApp

  afterEach(async () => {
    await boot.app.close()
  })

  // Verifies the provider is registered and discoverable. nest-core finds contributors by
  // scanning providers for the marker, so a class that is correct but unregistered — or
  // registered but unmarked — contributes nothing, and the consumer's document renders exactly
  // as before with no error and no warning. That silence is why this is asserted rather than
  // assumed.
  it('registers a marked, resolvable contributor', async () => {
    boot = await bootstrapTestApp()

    const contributor = boot.app.get(AuthOpenApiContributor)
    const marked = new Reflector().get<boolean>(
      OPENAPI_CONTRIBUTOR_METADATA,
      AuthOpenApiContributor
    )

    expect(contributor).toBeInstanceOf(AuthOpenApiContributor)
    expect(marked).toBe(true)
  })

  // The rule OpenAPI 3.0.3 inherits from RFC 7231: a payload is only defined for methods that
  // define one, and on the others `requestBody` **SHALL be ignored by consumers**. A fragment
  // that contributed one there would describe a request no generated client sends — which is not
  // a cosmetic error, because the operation that hit this needed the body to succeed and
  // answered `auth.session_not_found` without it, on every call, forever.
  //
  // Asserted against the REAL router rather than against a list kept beside the table: the
  // method belongs to the framework, and a handler that changes verb has no reason to remember
  // a constant in another file. This reads the routes Nest actually registered and crosses them
  // with the operations the fragment contributed.
  it('contributes no request body to a method that has no body semantics', async () => {
    boot = await bootstrapTestApp(
      { platform: { enabled: true } },
      {
        controllers: { auth: true, passwordReset: true, sessions: true, mfa: true, platform: true }
      }
    )

    const fragment = boot.app.get(AuthOpenApiContributor).contributeOpenApi()
    const withBody = Object.entries(fragment.operations)
      .filter(([, operation]) => 'requestBody' in operation)
      .map(([handler]) => handler)

    const offenders = withBody.filter((handler) => BODYLESS_METHODS.has(methodOf(handler)))

    expect(offenders).toEqual([])
    // The filter must have had something to look at: a fragment contributing no bodies at all
    // would pass the assertion above while proving nothing.
    expect(withBody.length).toBeGreaterThan(0)
  })

  // Verifies the fragment describes the controllers this deployment mounted — and no others.
  // A key naming a handler the document does not contain fails a consumer's document build, so
  // "describes only what was mounted" is not tidiness: it is the difference between a document
  // that builds and one that does not.
  it('describes the mounted controllers and nothing else', async () => {
    boot = await bootstrapTestApp()

    const fragment = boot.app.get(AuthOpenApiContributor).contributeOpenApi()
    const controllers = new Set(Object.keys(fragment.operations).map((key) => key.split('.')[0]))

    // The bootstrap mounts auth, mfa, passwordReset and sessions.
    expect([...controllers].sort()).toEqual([
      'AuthController',
      'MfaController',
      'PasswordResetController',
      'SessionController'
    ])
  })

  // The registration flags reach the contributor from the module rather than from the resolved
  // options — they cannot live in the options, because Nest reads `controllers` synchronously
  // before any factory runs. This is the case that proves the wiring: turn the platform surface
  // on, and the platform operations and their scheme appear.
  it('follows the registration switch, not the resolved options', async () => {
    boot = await bootstrapTestApp(
      { platform: { enabled: true } },
      { controllers: { auth: true, platform: true, mfa: false, passwordReset: false } }
    )

    const fragment = boot.app.get(AuthOpenApiContributor).contributeOpenApi()

    expect(Object.keys(fragment.operations)).toEqual(
      expect.arrayContaining(['PlatformAuthController.me', 'PlatformMfaController.setup'])
    )
    expect(Object.keys(fragment.components.securitySchemes)).toContain('bymaxPlatformAccessBearer')
    expect(Object.keys(fragment.operations)).not.toEqual(
      expect.arrayContaining(['MfaController.setup'])
    )
  })

  // Verifies the transport reaches the fragment from the SAME options the server enforces. The
  // bootstrap runs `tokenDelivery: 'bearer'`, so the document must describe a bearer credential
  // and define no cookie scheme — the document and the server agreeing because they read one
  // source, not because two files were edited together.
  it('describes the transport this deployment actually serves', async () => {
    boot = await bootstrapTestApp()

    const fragment = boot.app.get(AuthOpenApiContributor).contributeOpenApi()

    expect(boot.options.tokenDelivery).toBe('bearer')
    expect(Object.keys(fragment.components.securitySchemes)).toEqual(['bymaxAuthAccessBearer'])
    expect(fragment.operations['AuthController.me']).toEqual({
      security: [{ bymaxAuthAccessBearer: [] }]
    })
  })
})
