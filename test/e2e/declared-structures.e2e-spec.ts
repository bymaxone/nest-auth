/**
 * @fileoverview Runs the behavioural half of `conformance/openapi-declared-structures.json`.
 *
 * The unit suite beside the overlay proves each declared structure says what its probes say, and
 * enforces the ones the validation pipe refuses. It cannot reach the rest: the exactly-one-of
 * proof set is enforced by `PasswordResetService`, the password floor by `PasswordService`, and
 * anti-enumeration is not a property of any single response but of two responses being
 * indistinguishable. All three need a real application answering real requests, which is here.
 *
 * Every case is driven from the artifact rather than restated beside it. A claim added to the
 * overlay with no probe, or a probe no suite runs, fails the coverage assertions at the bottom —
 * a declared contract nobody exercises is exactly the shape this project keeps finding green over
 * a broken surface.
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import type { INestApplication } from '@nestjs/common'
import request from 'supertest'

import type { AuthErrorCode } from '../../src/server/errors/auth-error-codes'
import type { BymaxAuthModuleOptions } from '../../src/server/interfaces/auth-module-options.interface'
import { bootstrapTestApp, expectAuthError } from './setup'

// ---------------------------------------------------------------------------
// The artifact
// ---------------------------------------------------------------------------

/** A partial options overlay a probe needs the deployment to carry. */
type Deployment = Partial<BymaxAuthModuleOptions>

interface HttpProbe {
  note: string
  body: Record<string, unknown>
  expect: { code: AuthErrorCode; field?: string }
}

interface StructureEntry {
  structure: unknown
  enforcement: {
    kind: 'pipe' | 'http'
    path: string
    rejection: AuthErrorCode
    deployment: Deployment
  }
  probes: readonly (HttpProbe & { satisfies: boolean })[]
  narrowing?: { pairs: readonly NarrowingPair[] }
}

/** One body run under every declared deployment, with what the pair is for. */
interface NarrowingPair {
  role: 'demonstrates' | 'documents'
  note: string
  body: Record<string, unknown>
  outcomes: readonly { deployment: Deployment; expect: { code: AuthErrorCode } }[]
}

interface PolicyFloorEntry {
  kind: 'policyFloor'
  path: string
  probes: readonly (HttpProbe & { deployment: Deployment })[]
}

interface IndistinguishableEntry {
  kind: 'indistinguishable'
  path: string
  registeredBody: Record<string, unknown>
  unknownBody: Record<string, unknown>
  expect: { status: number; code?: AuthErrorCode }
  deployment: Deployment
}

type SemanticEntry = PolicyFloorEntry | IndistinguishableEntry

const declared = JSON.parse(
  readFileSync(join(__dirname, '../../conformance/openapi-declared-structures.json'), 'utf8')
) as {
  requestStructures: Record<string, StructureEntry>
  operationSemantics: Record<string, SemanticEntry>
}

const httpStructures = Object.entries(declared.requestStructures).filter(
  ([, entry]) => entry.enforcement.kind === 'http'
)

const semantics = Object.entries(declared.operationSemantics)

const policyFloors = semantics.filter(
  (pair): pair is [string, PolicyFloorEntry] => pair[1].kind === 'policyFloor'
)

const indistinguishables = semantics.filter(
  (pair): pair is [string, IndistinguishableEntry] => pair[1].kind === 'indistinguishable'
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** The password every seeded account uses — past the default 15-character policy floor. */
const SEED_PASSWORD = 'Str0ng-Probe-Passphrase'

/** Posts a probe body and returns the response. */
async function post(
  app: INestApplication,
  path: string,
  body: Record<string, unknown>
): Promise<{ status: number; body: unknown }> {
  return request(app.getHttpServer()).post(path).send(body)
}

/**
 * Groups probes by the deployment they need, so one application serves every probe that shares
 * a configuration instead of one per probe.
 *
 * Keyed by the serialized overlay: two probes asking for the same deployment must share an app,
 * and two asking for different ones must not — which is the whole point of the narrowing probes,
 * where the body is identical and only the deployment differs.
 */
function byDeployment<T extends { deployment: Deployment }>(
  probes: readonly T[]
): { key: string; deployment: Deployment; probes: T[] }[] {
  const groups = new Map<string, { key: string; deployment: Deployment; probes: T[] }>()

  for (const probe of probes) {
    const key = JSON.stringify(probe.deployment)
    const group = groups.get(key) ?? { key, deployment: probe.deployment, probes: [] }

    group.probes.push(probe)
    groups.set(key, group)
  }

  return [...groups.values()]
}

// ---------------------------------------------------------------------------
// Request structures enforced by the service
// ---------------------------------------------------------------------------

describe.each(httpStructures)('declared structure — %s over HTTP', (_name, entry) => {
  let app: INestApplication

  beforeAll(async () => {
    ;({ app } = await bootstrapTestApp(entry.enforcement.deployment))
  })

  afterAll(async () => {
    await app.close()
  })

  // Verifies each probe body is answered exactly as the overlay says. The bodies that violate the
  // structure must all answer the declared refusal, and at least one satisfying body must answer
  // something else — the unit suite asserts that second property over the artifact, so a set of
  // probes that a refuse-everything server would satisfy cannot be committed.
  it.each(entry.probes)('$note', async (probe) => {
    const res = await post(app, entry.enforcement.path, probe.body)

    expectAuthError(res, probe.expect.code)
  })
})

describe.each(httpStructures.filter(([, entry]) => entry.narrowing !== undefined))(
  'declared narrowing — %s',
  (_name, entry) => {
    // Verifies the deployment, not the body, is what decides eligibility — and, for a `documents`
    // pair, that the two deployments are indistinguishable from the caller's seat.
    //
    // Each pair sends ONE body to two applications differing in a single option. `demonstrates`
    // must come back with different codes; `documents` must come back **equal** — the same status
    // and the same body, asserted the way the anti-enumeration pairs are, rather than merely both
    // being refusals. That stronger form is the point: an ineligible proof answering its own code
    // (a plausible "better diagnostics" refactor) would let any caller learn the deployment's
    // configured method by probing, and two separate `expectAuthError` calls would not notice.
    it.each(entry.narrowing!.pairs)('$role — $note', async (pair) => {
      const responses: { status: number; body: unknown }[] = []

      for (const outcome of pair.outcomes) {
        const { app } = await bootstrapTestApp(outcome.deployment)

        try {
          const res = await post(app, entry.enforcement.path, pair.body)

          expectAuthError(res, outcome.expect.code)
          responses.push({ status: res.status, body: res.body })
        } finally {
          await app.close()
        }
      }

      const [first, ...rest] = responses

      for (const other of rest) {
        if (pair.role === 'documents') {
          expect(other).toEqual(first)
        } else {
          expect(other).not.toEqual(first)
        }
      }
    })
  }
)

// ---------------------------------------------------------------------------
// The password policy floor
// ---------------------------------------------------------------------------

describe.each(policyFloors)('declared policy floor — %s', (_name, entry) => {
  describe.each(byDeployment(entry.probes))('deployment $key', (group) => {
    let app: INestApplication

    beforeAll(async () => {
      ;({ app } = await bootstrapTestApp(group.deployment))
    })

    afterAll(async () => {
      await app.close()
    })

    // Verifies the gap between the two floors is real and visible. The unit suite proves the pipe
    // accepts the ten-character password; this proves the server does not, and names the field it
    // refuses — which is what a client generated from the schema alone would need to have been
    // told.
    it.each(group.probes)('$note', async (probe) => {
      const res = await post(app, entry.path, probe.body)

      expectAuthError(res, probe.expect.code)

      if (probe.expect.field !== undefined) {
        const body = res.body as { error: { details: unknown } }
        expect(body.error.details).toContainEqual(
          expect.objectContaining({ field: probe.expect.field })
        )
      }
    })
  })
})

// ---------------------------------------------------------------------------
// Anti-enumeration
// ---------------------------------------------------------------------------

describe.each(indistinguishables)('declared anti-enumeration — %s', (_name, entry) => {
  let app: INestApplication

  beforeAll(async () => {
    ;({ app } = await bootstrapTestApp(entry.deployment))

    await post(app, '/register', {
      email: entry.registeredBody['email'],
      password: SEED_PASSWORD,
      name: 'Probe',
      tenantId: entry.registeredBody['tenantId']
    })
  })

  afterAll(async () => {
    await app.close()
  })

  // Verifies the two responses are identical, not merely both successful. Asserting each one
  // against its expected status separately would stay green if the bodies differed — and a body
  // that differs is the disclosure, whatever the status line says.
  it('answers a registered address and an unknown one identically', async () => {
    const registered = await post(app, entry.path, entry.registeredBody)
    const unknown = await post(app, entry.path, entry.unknownBody)

    expect(registered.status).toBe(entry.expect.status)
    expect(unknown.status).toBe(registered.status)
    expect(unknown.body).toEqual(registered.body)

    if (entry.expect.code !== undefined) {
      expectAuthError(registered, entry.expect.code)
    }
  })

  // Verifies the seeded account is really there. Without it the pair above is satisfied by a
  // deployment where NEITHER address exists — two identical answers proving nothing, which is
  // the vacuous-absence shape rather than an anti-enumeration check.
  it('is comparing a real account against an absent one', async () => {
    const duplicate = await post(app, '/register', {
      email: entry.registeredBody['email'],
      password: SEED_PASSWORD,
      name: 'Probe',
      tenantId: entry.registeredBody['tenantId']
    })

    expect(duplicate.status).toBe(409)
  })
})

// ---------------------------------------------------------------------------
// Coverage of the artifact
// ---------------------------------------------------------------------------

describe('declared structures — artifact coverage', () => {
  // Verifies this suite owns every entry whose enforcement the unit suite cannot reach. An entry
  // of an unrecognised kind would otherwise be declared, published and exercised by nothing.
  it('runs every entry of the kinds it owns', () => {
    expect(httpStructures.length).toBeGreaterThan(0)
    expect(policyFloors.length).toBeGreaterThan(0)
    expect(indistinguishables.length).toBeGreaterThan(0)

    const kinds = semantics.map(([, entry]) => entry.kind)
    expect(kinds.every((kind) => kind === 'policyFloor' || kind === 'indistinguishable')).toBe(true)
    expect(policyFloors.length + indistinguishables.length).toBe(semantics.length)
  })
})
