/**
 * @fileoverview Binds `conformance/openapi-declared-structures.json` to the DTOs and the pipe.
 *
 * The declared structures carry what a decorator cannot express, so nothing can generate them
 * and nothing can check them by comparison. What makes them safe is the same thing that made the
 * normalisation descriptions safe: every claim ships with probes, and the probes run.
 *
 * This suite covers the half that is reachable without an HTTP server — the keyword census, the
 * evaluation of every probe against its own structure, the binding to real DTO properties, and
 * the enforcement of the structures the validation pipe is what refuses. The half that only a
 * bootstrapped application can answer — the service-enforced exactly-one-of, the policy floor,
 * the anti-enumeration pairs — lives in `test/e2e/declared-structures.e2e-spec.ts`, which reads
 * this same file. Neither suite may skip an entry silently: each asserts it handled every entry
 * of the kinds it owns.
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import type { AuthErrorCode } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { createAuthValidationPipe } from '../pipes/auth-validation.pipe'
import { assertKnownStructureKeywords, satisfiesStructure } from './declared-structure'
import type { DeclaredStructure } from './declared-structure'
import { deriveRequestSchema } from './derive-request-schemas'
import { REQUEST_SCHEMA_DTOS } from './request-schema-dtos'

/** One probe under a declared request structure. */
interface StructureProbe {
  note: string
  body: Record<string, unknown>
  satisfies: boolean
  expect: { code?: AuthErrorCode; accepted?: boolean; field?: string }
}

/** How a declared structure is enforced, and therefore which suite proves it. */
interface Enforcement {
  kind: 'pipe' | 'http'
  rejection: AuthErrorCode
}

/**
 * One body run under every declared deployment, with what the pair is FOR.
 *
 * `demonstrates` — the deployments must answer differently, which is what shows the option and
 * not the body decides. `documents` — they must answer identically, which is itself a claim: an
 * ineligible proof must not be distinguishable from an eligible-but-wrong one, or a caller learns
 * the deployment's configured method by probing.
 */
interface NarrowingPair {
  role: 'demonstrates' | 'documents'
  note: string
  body: Record<string, unknown>
  outcomes: readonly { deployment: Record<string, unknown>; expect: { code: AuthErrorCode } }[]
}

/** One declared request structure. */
interface DeclaredRequestStructure {
  description: string
  structure: DeclaredStructure
  enforcement: Enforcement
  probes: readonly StructureProbe[]
  narrowing?: { description: string; pairs: readonly NarrowingPair[] }
}

const ARTIFACT = join(__dirname, '../../../conformance/openapi-declared-structures.json')

/**
 * One probe of the policy-floor claim, whose two halves are checked in two suites.
 *
 * `acceptedByPipe` is this suite's half — whether the structural `@MinLength(8)` lets the body
 * through. What the deployment then does with it is the e2e suite's. Splitting the claim is the
 * only way to state it: the whole point is that the two answers differ, and neither suite can
 * see both.
 */
interface PolicyFloorProbe {
  note: string
  body: Record<string, unknown>
  dto: string
  acceptedByPipe: boolean
  expect: { code: AuthErrorCode; field?: string }
}

const declared = JSON.parse(readFileSync(ARTIFACT, 'utf8')) as {
  $comment: readonly string[]
  openapi: string
  requestStructures: Record<string, DeclaredRequestStructure>
  operationSemantics: Record<string, { kind: string; probes?: readonly PolicyFloorProbe[] }>
}

/** Every probe of every declared policy floor, flattened for the per-probe cases below. */
const policyFloorProbes = Object.values(declared.operationSemantics)
  .filter((entry) => entry.kind === 'policyFloor')
  .flatMap((entry) => entry.probes ?? [])

const requestStructures = Object.entries(declared.requestStructures)

/** The probe bodies, paired with the entry they belong to, for the per-probe cases below. */
const probes = requestStructures.flatMap(([dtoName, entry]) =>
  entry.probes.map((probe) => ({ dtoName, entry, probe }))
)

/** Runs one body through the library's own validation pipe, as a controller would. */
async function throughPipe(dto: string, body: Record<string, unknown>): Promise<AuthException> {
  const metatype = REQUEST_SCHEMA_DTOS.find((candidate) => candidate.name === dto)
  const pipe = createAuthValidationPipe()

  return pipe
    .transform(body, { type: 'body', metatype })
    .then(() => new AuthException(AUTH_ERROR_CODES.INTERNAL))
    .catch((error: unknown) => error as AuthException)
}

describe('OpenAPI declared structures — overlay', () => {
  // Verifies the dialect is pinned in the data, for the reason the generated half pins it: a 3.1
  // fragment merged into DocumentBuilder's 3.0 document validates as neither, and a migration
  // should be one coordinated change rather than a mixture.
  it('pins the OpenAPI dialect and carries its own provenance', () => {
    expect(declared.openapi).toBe('3.0')
    expect(declared.$comment.length).toBeGreaterThan(0)
  })

  // Verifies no structure uses a keyword the evaluator ignores. Without this the overlay could
  // publish an `allOf` or a `not` that no probe and no suite ever reads — a contract narrower on
  // paper than in the check, which is the failure the census on the generated half also exists
  // to prevent.
  it.each(requestStructures)('%s declares only evaluated keywords', (dtoName, entry) => {
    expect(() => assertKnownStructureKeywords(entry.structure, dtoName)).not.toThrow()
  })

  // Verifies every probe body agrees with the structure it sits under. This is what makes the
  // structure data rather than punctuation: the JSON says which bodies it accepts, and the
  // evaluator says whether it does.
  it.each(probes)('$dtoName — $probe.note', ({ entry, probe }) => {
    expect(satisfiesStructure(probe.body, entry.structure)).toBe(probe.satisfies)
  })

  // Verifies each structure names properties the DTO actually has, so a renamed or removed field
  // cannot leave a `required` describing something no request can carry.
  it.each(requestStructures)('%s names only properties the DTO declares', (dtoName, entry) => {
    const dto = REQUEST_SCHEMA_DTOS.find((candidate) => candidate.name === dtoName)
    expect(dto).toBeDefined()

    const properties = Object.keys(deriveRequestSchema(dto!).properties)
    for (const property of namedProperties(entry.structure)) {
      expect(properties).toContain(property)
    }
  })

  // Verifies each entry can tell the working server from a broken one. A set of probes that all
  // expect the structural refusal is satisfied by a server that refuses everything — the shape of
  // check this project has found green over a broken surface more than once. At least one
  // satisfying body must therefore be answered differently from a violating one.
  it.each(requestStructures)('%s discriminates acceptance from refusal', (_dtoName, entry) => {
    const accepted = entry.probes.filter((probe) => probe.satisfies)
    const refused = entry.probes.filter((probe) => !probe.satisfies)

    expect(accepted.length).toBeGreaterThan(0)
    expect(refused.length).toBeGreaterThan(0)
    expect(
      accepted.some(
        (probe) =>
          probe.expect.accepted === true || probe.expect.code !== entry.enforcement.rejection
      )
    ).toBe(true)
  })

  // Verifies every violating probe expects exactly the refusal the entry declares. A probe free
  // to expect any error would pass against a server refusing for an unrelated reason — a body
  // rejected for a malformed e-mail would "prove" an exactly-one-of nobody enforces.
  it.each(probes.filter(({ probe }) => !probe.satisfies))(
    '$dtoName violation expects the declared refusal — $probe.note',
    ({ entry, probe }) => {
      const expected = entry.enforcement.kind === 'pipe' ? false : entry.enforcement.rejection
      expect(probe.expect.code ?? probe.expect.accepted).toBe(expected)
    }
  )

  // Verifies the pipe-enforced structures against the pipe itself — the same instance the auth
  // controllers mount, so what is asserted is the enforcement rather than a re-implementation of
  // it. `@ValidateIf` is the only reason the OAuth callback's requirement is conditional, and
  // this is where that stops being a comment.
  it.each(probes.filter(({ entry }) => entry.enforcement.kind === 'pipe'))(
    '$dtoName is enforced by the pipe — $probe.note',
    async ({ dtoName, entry, probe }) => {
      const outcome = await throughPipe(dtoName, probe.body)
      const body = outcome.getResponse() as { error: { code: string; details: unknown } }

      if (probe.expect.accepted === true) {
        // `AUTH_ERROR_CODES.INTERNAL` is what `throughPipe` returns when the pipe did NOT throw.
        expect(body.error.code).toBe(AUTH_ERROR_CODES.INTERNAL)
        return
      }

      expect(body.error.code).toBe(entry.enforcement.rejection)
      expect(body.error.details).toContainEqual(
        expect.objectContaining({ field: probe.expect.field })
      )
    }
  )

  // Verifies the structural half of the policy floor: whether the DTO's own `@MinLength(8)` lets
  // the body through. The claim the overlay makes is that the pipe and the deployment disagree,
  // and this is the only place the pipe's answer can be read — the e2e suite sees the request
  // after both floors have had their turn and cannot tell which one refused it.
  it.each(policyFloorProbes)(
    'the pipe answers as declared — $note',
    async ({ dto, body, acceptedByPipe }) => {
      const outcome = await throughPipe(dto, body)
      const answered = outcome.getResponse() as { error: { code: string } }

      // `AUTH_ERROR_CODES.INTERNAL` is what `throughPipe` returns when the pipe did NOT throw.
      expect(answered.error.code).toBe(
        acceptedByPipe ? AUTH_ERROR_CODES.INTERNAL : AUTH_ERROR_CODES.VALIDATION
      )
    }
  )

  // Verifies the floors are actually two different checks. A probe set where the pipe answered
  // the same way every time would be consistent with there being one floor described twice —
  // which is the reading this whole entry exists to correct.
  it('declares a body each floor answers differently', () => {
    expect(policyFloorProbes.some((probe) => probe.acceptedByPipe)).toBe(true)
    expect(policyFloorProbes.some((probe) => !probe.acceptedByPipe)).toBe(true)
  })

  // Verifies this suite handled every pipe-enforced entry, and that the rest are accounted for by
  // the e2e suite rather than by nothing. An entry whose kind neither suite owns would otherwise
  // ship declared and unchecked.
  it('covers every entry with a suite that owns its enforcement kind', () => {
    const kinds = requestStructures.map(([, entry]) => entry.enforcement.kind)

    expect(kinds.length).toBeGreaterThan(0)
    expect(kinds.every((kind) => kind === 'pipe' || kind === 'http')).toBe(true)
    expect(kinds).toContain('pipe')
    expect(kinds).toContain('http')
  })

  // Verifies the overlay still declares what it is supposed to declare — the guard against
  // SUBTRACTION rather than against mutation.
  //
  // Every other check here reads the entries that exist. Delete one and they simply iterate over
  // less: no keyword is wrong, no probe expects anything, the census has nothing to census, and
  // the artifact goes quiet about a contract while staying green. That asymmetry — mutation
  // covered, absence not — is the shape that produced the empty DTO schemas in the first place.
  //
  // Pinned as an exact set rather than a minimum, for the reason the validator census is: a
  // collection nothing pins lets the checks over it pass while covering less than they claim.
  it('declares a structure for exactly the DTOs it is supposed to', () => {
    expect(Object.keys(declared.requestStructures).sort()).toEqual([
      'OAuthCallbackQueryDto',
      'ResetPasswordDto'
    ])

    expect(Object.keys(declared.operationSemantics).sort()).toEqual([
      'AuthController.resendVerification',
      'AuthController.verifyEmail',
      'PasswordResetController.forgotPassword',
      'PasswordResetController.resendOtp',
      'PasswordResetController.resetPassword#passwordFloor'
    ])
  })

  // Verifies no structure has been emptied. `{}` is satisfied by anything — JSON Schema's own
  // reading, and the reason the census exists — so an entry reduced to it would leave every
  // `satisfies: true` probe passing while the constraint it documents had vanished. Only the
  // `satisfies: false` probes would notice, which makes their survival load-bearing by accident.
  // This says it directly instead.
  it.each(requestStructures)('%s declares at least one keyword', (_dtoName, entry) => {
    expect(Object.keys(entry.structure).length).toBeGreaterThan(0)
  })
})

// ---------------------------------------------------------------------------
// The narrowing experiment
// ---------------------------------------------------------------------------

/**
 * Flattens a nested plain object to `path=value` leaves.
 *
 * Used to compare two deployment overlays for the one thing that must be true of them — that they
 * differ in exactly one option. Comparing the objects whole would only say "different".
 */
function leafPaths(value: unknown, prefix = ''): string[] {
  if (typeof value !== 'object' || value === null) {
    return [`${prefix}=${JSON.stringify(value)}`]
  }

  return Object.entries(value).flatMap(([key, child]) =>
    leafPaths(child, prefix === '' ? key : `${prefix}.${key}`)
  )
}

describe('OpenAPI declared structures — the narrowing is a single-variable experiment', () => {
  const pairs = (declared.requestStructures['ResetPasswordDto']?.narrowing?.pairs ??
    []) as readonly NarrowingPair[]

  const outcomes = pairs.flatMap((pair) => pair.outcomes)
  const deploymentKeys = [...new Set(outcomes.map((one) => JSON.stringify(one.deployment)))]

  // Verifies the two configurations differ in EXACTLY one option.
  //
  // The narrowing's claim is that the *deployment* decides which proof is eligible. Pairing
  // identical bodies rules out the body deciding, but it only isolates the option if the two
  // fixtures are otherwise identical. Two hand-written option objects can drift apart in a later
  // edit and the confound arrives silently: the probes stay green and the claim quietly weakens
  // to "something about the deployment decides". Asserting the single variable makes it a
  // property of the experiment rather than of how carefully the fixture was written.
  it('varies exactly one option between the two deployments', () => {
    expect(deploymentKeys).toHaveLength(2)

    const [first, second] = deploymentKeys.map((key) => new Set(leafPaths(JSON.parse(key))))
    const differing = [
      ...[...first!].filter((leaf) => !second!.has(leaf)),
      ...[...second!].filter((leaf) => !first!.has(leaf))
    ]

    // One leaf from each side, and both name the same option — so the two overlays differ in that
    // option's VALUE and in nothing else.
    expect(differing).toHaveLength(2)
    expect(new Set(differing.map((leaf) => leaf.split('=')[0])).size).toBe(1)
  })

  // Verifies every pair is run under BOTH deployments. A pair with one outcome contributes an
  // observation with nothing to compare it against, which is the single-probe reading the pairing
  // exists to rule out.
  it.each(pairs)('runs $role pair under both deployments — $note', (pair) => {
    expect(pair.outcomes.map((one) => JSON.stringify(one.deployment)).sort()).toEqual(
      [...deploymentKeys].sort()
    )
  })

  // Verifies each pair does what its own `role` says.
  //
  // The role is data because the belief about it is where this went wrong once already: the pairs
  // were described as all discriminating, only one did, and nothing in the artifact could
  // contradict the description — it lived in prose. A global "at least one pair differs" would
  // still be satisfied by a single discriminating pair with any number of mislabelled ones around
  // it, and the next person to add a pair believing it demonstrates something would get no
  // correction. Per-pair, the belief is checked at the moment it is written down.
  it.each(pairs)('$role pair behaves as its role claims — $note', (pair) => {
    const codes = new Set(pair.outcomes.map((one) => one.expect.code))

    expect(codes.size).toBe(pair.role === 'demonstrates' ? pair.outcomes.length : 1)
  })

  // Verifies the roles themselves are the two this suite understands, and that a `demonstrates`
  // pair exists at all. Without the second, every pair could be `documents` — internally
  // consistent, and consistent with the option changing nothing.
  it('declares only known roles, and at least one that demonstrates', () => {
    expect(pairs.every((pair) => pair.role === 'demonstrates' || pair.role === 'documents')).toBe(
      true
    )
    expect(pairs.some((pair) => pair.role === 'demonstrates')).toBe(true)
  })
})

/** Every property name a structure mentions, at any depth. */
function namedProperties(structure: DeclaredStructure): string[] {
  return [
    ...(structure.required ?? []),
    ...(structure.oneOf ?? []).flatMap(namedProperties),
    ...(structure.anyOf ?? []).flatMap(namedProperties)
  ]
}
