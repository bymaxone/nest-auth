/**
 * @fileoverview The request schemas the contributor offers a document builder, against the
 * document the builder produces for the same deployment.
 *
 * The package is built without the `@nestjs/swagger` CLI plugin, so every DTO it ships reaches a
 * consumer's document as `{"type":"object","properties":{}}` unless a contributor fills it in.
 * That empty schema is valid OpenAPI, it resolves, and a dangling-`$ref` sweep passes over it —
 * which is how a generated client came to type `login(body: {})`.
 *
 * The merge that fills it belongs to the document builder (`@bymax-one/nest-core`), which this
 * repository does not import, so what is checkable here is the half this package owns: the
 * builder is run over the real, fully mounted controllers (through `@nestjs/swagger`, the library
 * it is built on), and the fragment must offer, under the SAME name, a schema for every empty
 * placeholder the builder registers — and none for a name it does not. The name is the join key
 * of the merge, so a fragment keyed by anything else is dropped without a signal.
 *
 * The merge itself belongs to the document builder and is not exercised here.
 */

import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger'

import { BYMAX_AUTH_EMAIL_PROVIDER } from '../../src/server/bymax-auth.constants'
import { AuthOpenApiContributor } from '../../src/server/openapi/auth-openapi.contributor'
import { bootstrapTestApp, createMockEmailProvider } from './setup'
import type { BootstrappedTestApp } from './setup'

/** The options every optional controller needs before the module will mount it. */
const EVERY_FEATURE = {
  platform: { enabled: true },
  invitations: { enabled: true, tokenTtlSeconds: 3_600 },
  oauth: {
    google: {
      clientId: 'test-client-id',
      clientSecret: 'test-client-secret',
      callbackUrl: 'https://app.example.com/auth/oauth/google/callback'
    }
  }
}

/** Every registration switch on, with an e-mail provider that can deliver an address change. */
const EVERY_CONTROLLER = {
  extraModuleProviders: [
    {
      provide: BYMAX_AUTH_EMAIL_PROVIDER,
      useValue: {
        ...createMockEmailProvider(),
        sendEmailChangeVerification: async (): Promise<void> => undefined
      }
    }
  ],
  controllers: {
    auth: true,
    passwordReset: true,
    sessions: true,
    mfa: true,
    platform: true,
    invitations: true,
    emailChange: true,
    oauth: true
  }
}

interface SchemaLike {
  properties?: Record<string, unknown>
  required?: string[]
}

describe('request schemas offered to a document builder (E2E)', () => {
  let boot: BootstrappedTestApp
  let registered: Record<string, SchemaLike>
  let offered: Record<string, SchemaLike>

  beforeAll(async () => {
    boot = await bootstrapTestApp(EVERY_FEATURE, EVERY_CONTROLLER)

    const document = SwaggerModule.createDocument(boot.app, new DocumentBuilder().build())
    registered = (document.components?.schemas ?? {}) as Record<string, SchemaLike>
    offered = boot.app.get(AuthOpenApiContributor).contributeOpenApi().components.schemas
  })

  afterAll(async () => {
    await boot.app.close()
  })

  /** The names the builder registered with no property at all: the placeholders to be filled. */
  const placeholders = (): string[] =>
    Object.entries(registered)
      .filter(([, schema]) => Object.keys(schema.properties ?? {}).length === 0)
      .map(([name]) => name)

  // Scenario: the builder over a deployment with every controller mounted. Expected: it registers
  // placeholders for the library's request DTOs, and plenty of them. Why: the control for
  // everything below — without it the defect is not reproduced here and a green result could mean
  // the builder produced nothing to fill.
  it('reproduces the empty placeholders the builder registers for the DTOs', () => {
    expect(placeholders()).toContain('LoginDto')
    expect(placeholders().length).toBeGreaterThan(10)
  })

  // Scenario: every placeholder the builder registered. Expected: the fragment offers a schema
  // under that exact name, and it describes at least one property. Why: the merge fills a
  // placeholder only from a contribution of the same name, and a placeholder left alone is
  // what a generated client types as `{}`.
  it('offers a described schema for every placeholder, under the same name', () => {
    const missing = placeholders().filter(
      (name) => Object.keys(offered[name]?.properties ?? {}).length === 0
    )

    expect(missing).toEqual([])
  })

  // Scenario: every schema the fragment offers. Expected: the builder registered a placeholder
  // for it. Why: a component nothing references is noise in the served document and in the
  // client generated from it, and it is the sign that a name drifted from the DTO class.
  it('offers no schema the builder does not reference', () => {
    const unreferenced = Object.keys(offered).filter((name) => !(name in registered))

    expect(unreferenced).toEqual([])
  })

  // Scenario: every schema the fragment offers. Expected: none declares an empty `required`.
  // Why: OpenAPI 3.0 adopts Wright Draft 00, whose `required` MUST hold at least one element, so
  // an empty list makes the merged document invalid to a strict validator.
  it('offers no schema with an empty required list', () => {
    const empty = Object.entries(offered)
      .filter(([, schema]) => schema.required !== undefined && schema.required.length === 0)
      .map(([name]) => name)

    expect(empty).toEqual([])
  })

  // Scenario: the schema of the most-used request. Expected: its fields, and the two a caller
  // must send. Why: the generated client's `login(body)` is typed from exactly this.
  it('describes LoginDto with its fields and required members', () => {
    expect(Object.keys(offered['LoginDto']?.properties ?? {}).sort()).toEqual([
      'email',
      'password',
      'tenantId'
    ])
    expect(offered['LoginDto']?.required).toEqual(['email', 'password'])
  })

  // Scenario: the OAuth endpoints, whose DTOs are taken as query parameters. Expected: the
  // builder registers no component for them and the fragment offers none. Why: the schema half
  // covers request BODIES; the query parameters of those two operations are an operation-level
  // description, not a component, and a schema offered for a name nothing references would be
  // dropped.
  it('has no component for the OAuth query DTOs on either side', () => {
    expect(registered).not.toHaveProperty('OAuthInitiateQueryDto')
    expect(registered).not.toHaveProperty('OAuthCallbackQueryDto')
    expect(offered).not.toHaveProperty('OAuthInitiateQueryDto')
    expect(offered).not.toHaveProperty('OAuthCallbackQueryDto')
  })
})
