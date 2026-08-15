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

import { Reflector } from '@nestjs/core'

import { AuthOpenApiContributor } from '../../src/server/openapi/auth-openapi.contributor'
import { OPENAPI_CONTRIBUTOR_METADATA } from '../../src/server/openapi/auth-openapi-fragment'
import { bootstrapTestApp } from './setup'
import type { BootstrappedTestApp } from './setup'

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
