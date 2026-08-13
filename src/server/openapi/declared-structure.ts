/**
 * @fileoverview Evaluates the declared structural overlay against a request body.
 *
 * Not exported from the package: nothing reachable from `src/server/index.ts` imports it, so it
 * never enters the published bundle. It exists so the structures in
 * `conformance/openapi-declared-structures.json` are checkable data rather than prose — the same
 * move that made the normalisation descriptions safe. A declared `oneOf` nobody evaluates is a
 * sentence in JSON punctuation.
 *
 * Deliberately not a JSON Schema library. This package has zero direct dependencies, and the
 * subset the overlay uses is three keywords over a flat body; a validator for it is smaller than
 * the argument for taking one on. The census below is what keeps that honest: a keyword this
 * cannot evaluate is refused at load rather than skipped, so the overlay can never claim more
 * than the evaluator checks.
 *
 * @layer OpenAPI
 */

/**
 * The keyword subset the declared overlay may use, and this module evaluates.
 *
 * OpenAPI 3.0's Schema Object is "an extended subset of JSON Schema Specification Wright Draft
 * 00", which includes `oneOf`, `anyOf`, `allOf` and `not`. Only three are here, because only
 * three have a contract to express: exactly-one-of a proof set, at-least-one-of a callback
 * pair, and unconditional presence. `allOf` and `not` are absent rather than unimplemented —
 * adding one means adding its evaluation and its probes in the same change, which is what
 * {@link assertKnownStructureKeywords} forces.
 */
export const STRUCTURE_KEYWORDS = ['anyOf', 'oneOf', 'required'] as const

/** One declared structure: the keywords above, conjunctively. */
export interface DeclaredStructure {
  /** Properties that must be present. */
  required?: readonly string[]
  /** Exactly one branch must be satisfied. */
  oneOf?: readonly DeclaredStructure[]
  /** At least one branch must be satisfied. */
  anyOf?: readonly DeclaredStructure[]
}

/**
 * Whether a property counts as present on a request body.
 *
 * `null` counts as **absent**, which is not JSON Schema's rule and is deliberate: it is this
 * server's rule. `@IsOptional()` registers a conditional whose predicate is
 * `value !== null && value !== undefined` (measured in class-validator's own
 * `decorator/common/IsOptional.js`), so a body sending `null` and a body omitting the key are
 * the same request here — the validators are skipped either way and the service reads
 * `undefined`. Declaring presence as bare `hasOwnProperty` would make the overlay claim a
 * distinction the server does not draw, and the probe carrying `token: null` beside a real
 * `otp` is what proves it.
 *
 * The type constraint is not this module's job. A present-but-wrong-typed value is rejected by
 * the generated half of the artifact, whose properties are all `type: 'string'`; composing the
 * two is what describes the request completely.
 *
 * Read through a property descriptor rather than an index expression: own properties only, so a
 * body carrying `constructor` or `toString` cannot resolve an inherited member, and no computed
 * member access for `security/detect-object-injection` to flag.
 *
 * @param body - The request body, as JSON parsed it.
 * @param property - The property name to look for.
 * @returns `true` when the body carries that property with a non-`null` value.
 */
function isPresent(body: Readonly<Record<string, unknown>>, property: string): boolean {
  const descriptor = Object.getOwnPropertyDescriptor(body, property)

  return descriptor !== undefined && descriptor.value !== null
}

/**
 * Whether a request body satisfies a declared structure.
 *
 * Every keyword the structure carries must hold; a structure carrying none is satisfied by
 * anything, which is JSON Schema's own reading of `{}` and the reason the census exists — an
 * empty structure is indistinguishable from one whose only keyword was misspelled.
 *
 * @param body - The request body to test.
 * @param structure - The declared structure, already through
 *   {@link assertKnownStructureKeywords}.
 * @returns Whether the body satisfies it.
 */
export function satisfiesStructure(
  body: Readonly<Record<string, unknown>>,
  structure: DeclaredStructure
): boolean {
  const requiredHolds = (structure.required ?? []).every((property) => isPresent(body, property))

  const oneOfHolds =
    structure.oneOf === undefined ||
    structure.oneOf.filter((branch) => satisfiesStructure(body, branch)).length === 1

  const anyOfHolds =
    structure.anyOf === undefined ||
    structure.anyOf.some((branch) => satisfiesStructure(body, branch))

  return requiredHolds && oneOfHolds && anyOfHolds
}

/**
 * Refuses a structure carrying a keyword this module does not evaluate.
 *
 * The failure mode this exists for is silent: `satisfiesStructure` reads the keywords it knows
 * and ignores the rest, so a `not` or an `allOf` written into the overlay would be published as
 * part of the contract and checked by nothing. The probes would still pass — they would simply
 * be testing a weaker structure than the one a client generates against. Refusing at load turns
 * that into a red suite in the change that introduced it.
 *
 * The same shape as the validator census over the generated half: there, an unmapped decorator
 * thins the schema silently; here, an unevaluated keyword thins the check.
 *
 * @param structure - The value to inspect, untrusted — it comes from a JSON file.
 * @param path - Where in the overlay this structure sits, for the message. Defaults to the root.
 * @throws `Error` naming the keyword and its path.
 */
export function assertKnownStructureKeywords(structure: unknown, path = '$'): void {
  if (typeof structure !== 'object' || structure === null) {
    throw new Error(`[openapi] ${path} is not a structure object.`)
  }

  for (const [keyword, value] of Object.entries(structure)) {
    if (!STRUCTURE_KEYWORDS.includes(keyword as (typeof STRUCTURE_KEYWORDS)[number])) {
      throw new Error(
        `[openapi] ${path}.${keyword} is not a keyword the declared overlay evaluates. ` +
          `Evaluated keywords: ${STRUCTURE_KEYWORDS.join(', ')}. Add its evaluation and its ` +
          'probes together, or express the contract with one of these.'
      )
    }

    if (keyword !== 'required') {
      const branches = value as readonly unknown[]
      branches.forEach((branch, index) =>
        assertKnownStructureKeywords(branch, `${path}.${keyword}[${String(index)}]`)
      )
    }
  }
}
