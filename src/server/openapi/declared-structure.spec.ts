/**
 * @fileoverview Unit tests for the declared-structure evaluator.
 *
 * The evaluator is what turns the declared overlay from prose into a check, so it is tested
 * against the shapes the overlay actually uses and against the ones it must refuse. The census
 * gets as much attention as the evaluation: a keyword accepted but not evaluated is a contract
 * that looks stricter than the suite behind it.
 */
import {
  STRUCTURE_KEYWORDS,
  assertKnownStructureKeywords,
  satisfiesStructure
} from './declared-structure'
import type { DeclaredStructure } from './declared-structure'

/**
 * The three proof branches the reset-password overlay declares.
 *
 * Named separately so the cases below can put the SAME branches under a different keyword — which
 * is the only way to show that the exactly-one rule rests on `oneOf` rather than on the branches.
 */
const PROOF_BRANCHES: readonly DeclaredStructure[] = [
  { required: ['token'] },
  { required: ['otp'] },
  { required: ['verifiedToken'] }
]

/** The exactly-one-of itself, reused across the cases below. */
const EXACTLY_ONE: DeclaredStructure = { oneOf: PROOF_BRANCHES }

describe('satisfiesStructure', () => {
  // Verifies the vacuous case reads as JSON Schema reads it. It matters because it is also the
  // shape a structure collapses to when its only keyword is misspelled — which is precisely what
  // the census exists to catch, and why this being `true` is not a bug.
  it('is satisfied by anything when it declares no keyword', () => {
    expect(satisfiesStructure({}, {})).toBe(true)
    expect(satisfiesStructure({ anything: 1 }, {})).toBe(true)
  })

  // Verifies `required` over the three states a property can be in.
  it.each([
    { body: { state: 'nonce' }, expected: true, why: 'present' },
    { body: {}, expected: false, why: 'absent' },
    { body: { state: null }, expected: false, why: 'null, which this server reads as absent' },
    {
      body: { state: undefined },
      expected: false,
      why: 'an own property explicitly set to undefined, which `@IsOptional()` also reads as absent'
    }
  ])('required: $why → $expected', ({ body, expected }) => {
    expect(satisfiesStructure(body, { required: ['state'] })).toBe(expected)
  })

  // Verifies presence is an OWN property. A body carrying no `toString` of its own must not
  // satisfy a requirement for one via the prototype — the same hardening the error catalog needed
  // when a code of `constructor` resolved an inherited member.
  it('does not accept an inherited property as present', () => {
    expect(satisfiesStructure({}, { required: ['toString'] })).toBe(false)
  })

  // Verifies every property named must be present, not merely some of them.
  it('requires all named properties, not one of them', () => {
    expect(satisfiesStructure({ state: 'nonce' }, { required: ['state', 'code'] })).toBe(false)
    expect(satisfiesStructure({ state: 'nonce', code: 'c' }, { required: ['state', 'code'] })).toBe(
      true
    )
  })

  // Verifies `oneOf` is exactly-one across every count that matters. Zero and two are what
  // separate it from `anyOf`, and three is what separates "exactly one" from "at most two".
  it.each([
    { body: {}, expected: false, why: 'no branch matches' },
    { body: { otp: '123456' }, expected: true, why: 'exactly one branch matches' },
    { body: { otp: '123456', token: 't' }, expected: false, why: 'two branches match' },
    {
      body: { otp: '123456', token: 't', verifiedToken: 'v' },
      expected: false,
      why: 'three branches match'
    }
  ])('oneOf: $why → $expected', ({ body, expected }) => {
    expect(satisfiesStructure(body, EXACTLY_ONE)).toBe(expected)
  })

  // Verifies where the exactly-one rule actually rests. Three rewrites look like tightenings and
  // each ends somewhere different, so the guard is a PAIR of assertions rather than a comment
  // saying "do not touch this".
  //
  //   1. Symmetric exclusivity — every branch `not`s the others. Redundant, NOT inverting: a
  //      two-proof body satisfies ZERO branches instead of two, and `oneOf` refuses it either
  //      way. Measured across all eight subsets of the three proofs; the verdict is identical to
  //      the minimal form on every one.
  //   2. Dropping those `not` clauses afterwards, once exclusivity has made `oneOf` and `anyOf`
  //      agree on every input and the keyword looks like it carries no weight. That leaves
  //      `anyOf` over the plain branches, which ACCEPTS two proofs. The end state, two steps out.
  //   3. ASYMMETRIC exclusivity — only the later branches exclude the earlier ones, which is what
  //      a half-finished edit looks like. This inverts in ONE step: every multi-proof body then
  //      satisfies exactly one branch and passes, on four of the eight subsets, while the server
  //      refuses all four.
  //
  // The case below asserts the destination shared by (2), so no route reaches it silently. The
  // census case after it refuses `not` at load, which is what stops (1) and (3) — and (3) is the
  // reason that matters, since it is the likely accident and the only one that inverts directly.
  it('rests on oneOf: the same branches under anyOf would accept two proofs', () => {
    const twoProofs = { token: 't', otp: '123456' }

    expect(satisfiesStructure(twoProofs, EXACTLY_ONE)).toBe(false)
    expect(satisfiesStructure(twoProofs, { anyOf: PROOF_BRANCHES })).toBe(true)
  })

  // Verifies both exclusivity rewrites are refused at load rather than evaluated — `not` is a real
  // OpenAPI 3.0 keyword this evaluator does not read, so an artifact carrying one would be checked
  // by less than it claims. The asymmetric shape is here explicitly because it is the one that
  // inverts, and a guard that only recognised the symmetric shape would miss it.
  it.each([
    {
      why: 'symmetric — every branch excludes the others',
      structure: {
        oneOf: [
          { required: ['token'], not: { anyOf: [{ required: ['otp'] }] } },
          { required: ['otp'], not: { anyOf: [{ required: ['token'] }] } }
        ]
      }
    },
    {
      why: 'asymmetric — only the later branch excludes the earlier one',
      structure: {
        oneOf: [
          { required: ['token'] },
          { required: ['otp'], not: { anyOf: [{ required: ['token'] }] } }
        ]
      }
    }
  ])('refuses the exclusivity rewrite at load: $why', ({ structure }) => {
    expect(() => assertKnownStructureKeywords(structure)).toThrow(/\.not is not a keyword/)
  })

  // Verifies `anyOf` is at-least-one, which is the difference that makes the OAuth callback
  // accept a provider sending both `code` and `error`.
  it.each([
    { body: {}, expected: false, why: 'no branch matches' },
    { body: { code: 'c' }, expected: true, why: 'one branch matches' },
    { body: { code: 'c', error: 'access_denied' }, expected: true, why: 'both branches match' }
  ])('anyOf: $why → $expected', ({ body, expected }) => {
    const structure: DeclaredStructure = {
      anyOf: [{ required: ['code'] }, { required: ['error'] }]
    }

    expect(satisfiesStructure(body, structure)).toBe(expected)
  })

  // Verifies the keywords conjoin. Each case satisfies one keyword and fails the other, so a
  // reading that returned either one alone would answer `true` here.
  it.each([
    { body: { code: 'c' }, why: '`anyOf` holds, `required` does not' },
    { body: { state: 'nonce' }, why: '`required` holds, `anyOf` does not' }
  ])('conjoins its keywords — $why', ({ body }) => {
    const structure: DeclaredStructure = {
      required: ['state'],
      anyOf: [{ required: ['code'] }, { required: ['error'] }]
    }

    expect(satisfiesStructure(body, structure)).toBe(false)
    expect(satisfiesStructure({ state: 'nonce', code: 'c' }, structure)).toBe(true)
  })

  // Verifies branches are evaluated recursively rather than only one level deep.
  it('evaluates nested branches', () => {
    const structure: DeclaredStructure = {
      anyOf: [{ oneOf: [{ required: ['a'] }, { required: ['b'] }] }, { required: ['c'] }]
    }

    expect(satisfiesStructure({ a: 1 }, structure)).toBe(true)
    expect(satisfiesStructure({ a: 1, b: 2 }, structure)).toBe(false)
    expect(satisfiesStructure({ a: 1, b: 2, c: 3 }, structure)).toBe(true)
  })
})

describe('assertKnownStructureKeywords', () => {
  // Verifies the set the overlay may use is exactly what the evaluator reads. Pinned as a value
  // rather than left implicit, for the same reason the validator census is: a set nothing pins
  // lets the check over it cover less than it claims.
  it('evaluates exactly the keywords it advertises', () => {
    expect([...STRUCTURE_KEYWORDS]).toEqual(['anyOf', 'oneOf', 'required'])
  })

  // Verifies the shapes the overlay actually ships are accepted, including `required`'s array of
  // plain strings — which must NOT be recursed into as though its entries were structures.
  it('accepts the structures the overlay declares', () => {
    expect(() => assertKnownStructureKeywords(EXACTLY_ONE)).not.toThrow()
    expect(() =>
      assertKnownStructureKeywords({
        required: ['state'],
        anyOf: [{ required: ['code'] }, { required: ['error'] }]
      })
    ).not.toThrow()
  })

  // Verifies an unevaluated keyword is refused rather than skipped, and asserts the WHOLE message.
  // `allOf` and `not` are real OpenAPI 3.0 keywords, which is what makes this the plausible
  // mistake rather than a contrived one — and the half of the message that says what to do about
  // it is the half that reaches whoever hits this. Matching only the first clause let the guidance
  // be emptied without a test noticing; the keyword list is asserted too, so the sentence cannot
  // drift from `STRUCTURE_KEYWORDS`.
  it('refuses a keyword it does not evaluate, naming it, its path, and the way out', () => {
    expect(() => assertKnownStructureKeywords({ not: { required: ['token'] } })).toThrow(
      '[openapi] $.not is not a keyword the declared overlay evaluates. ' +
        `Evaluated keywords: ${STRUCTURE_KEYWORDS.join(', ')}. ` +
        'Add its evaluation and its probes together, or express the contract with one of these.'
    )
  })

  // Verifies the refusal reaches into branches, at the index it reports. A census that only read
  // the root would accept `oneOf: [{ allOf: [...] }]` — a claim nested one level out of sight.
  it('refuses an unevaluated keyword nested in a branch', () => {
    expect(() =>
      assertKnownStructureKeywords({
        oneOf: [{ required: ['token'] }, { allOf: [{ required: ['otp'] }] }]
      })
    ).toThrow(/\$\.oneOf\[1\]\.allOf is not a keyword/)
  })

  // Verifies the path prefix a caller supplies is used, so a failure in the overlay names the DTO
  // it belongs to rather than an anonymous `$`.
  it('reports the caller-supplied path', () => {
    expect(() => assertKnownStructureKeywords({ not: {} }, 'ResetPasswordDto')).toThrow(
      /ResetPasswordDto\.not is not a keyword/
    )
  })

  // Verifies a value that is not a structure at all is refused rather than silently iterated.
  // `null` is the case worth naming: `typeof null` is `'object'`, so a check that only tested the
  // type would walk into it.
  it.each([
    { value: null, why: 'null' },
    { value: 'required', why: 'a string' },
    { value: 42, why: 'a number' }
  ])('refuses $why in place of a structure', ({ value }) => {
    expect(() => assertKnownStructureKeywords(value)).toThrow(/is not a structure object/)
  })
})
