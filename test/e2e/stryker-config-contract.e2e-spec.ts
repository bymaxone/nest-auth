/**
 * @fileoverview Pins the annotated Stryker config in the plan to the one that actually runs.
 *
 * `docs/mutation_testing_plan.md` carries a fully commented copy of `stryker.config.json` and
 * tells the reader to strip the comments and save it. That makes it a **canonical setup snippet**:
 * whatever it says is what the next contributor's config becomes. When it drifts, it does not go
 * stale quietly — it actively teaches the wrong setup, and every gate in this repository stays
 * green while it does, because nothing runs the snippet.
 *
 * It had drifted on four points at once, each one a rule documented elsewhere in the repo:
 * `cleanTempDir: true` (the setting that left a 45 MB sandbox on disk after every failed run),
 * `configFile: "jest.config.ts"` (the sandbox needs `jest.stryker.config.ts`, for the explicit-
 * extension reason CLAUDE.md states), thresholds of 95/85/80 (the gate is 100/100/100), and two
 * keys missing outright. Three of the four were found only by parsing both files and diffing
 * them — a grep for the setting named in the review comment found the first and none of the rest.
 *
 * So the rule is a test rather than a habit. Equality is asserted on the whole parsed object, not
 * on the keys that happened to drift: a check that named them would go stale exactly the way the
 * snippet did.
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

/** Repository root, from this suite's location under `test/e2e/`. */
const REPO_ROOT = join(__dirname, '../..')

/** The config Stryker actually loads — the side of the contract that is not negotiable. */
const CONFIG_PATH = join(REPO_ROOT, 'stryker.config.json')

/**
 * Strips whole-line `//` comments so a JSONC block can be parsed as JSON.
 *
 * Anchored to the start of the line (allowing indentation) rather than matching `//` anywhere,
 * because a `//` inside a string value — a URL, most plausibly — is content and not a comment.
 * This is the same transformation the plan instructs a reader to perform by hand.
 *
 * @param jsonc - The annotated block.
 * @returns The block with its comment lines removed.
 */
function stripLineComments(jsonc: string): string {
  return jsonc.replace(/^\s*\/\/.*$/gm, '')
}

/**
 * Extracts the annotated config block from the plan.
 *
 * Selected by CONTENT rather than by position: the document holds more than one fenced block, and
 * an index would silently pick the wrong one the next time a block is added above it.
 *
 * @param markdown - The plan's full text.
 * @returns The single fenced block that carries the Stryker config.
 * @throws {Error} When no block, or more than one, carries it.
 */
function extractConfigBlock(markdown: string): string {
  const blocks = [...markdown.matchAll(/```jsonc?\n([\s\S]*?)```/g)]
    .map((match) => match[1] ?? '')
    .filter((block) => block.includes('"cleanTempDir"'))

  const [block, ...rest] = blocks

  // Destructured rather than indexed-and-asserted: under `noUncheckedIndexedAccess` a `[0]` read
  // needs a cast to type-check, and a cast here would be the one place this file stopped proving
  // things and started claiming them.
  if (block === undefined || rest.length > 0) {
    throw new Error(`expected exactly one Stryker config block in the plan, found ${blocks.length}`)
  }

  return block
}

describe('Stryker config contract (E2E)', () => {
  // The whole object, not a chosen subset. A contributor following the plan verbatim must end up
  // with the file this repository runs — including the keys nobody thought to assert, which is
  // where three of the four drifts were hiding.
  it('keeps the plan snippet identical to the config that runs', () => {
    const plan = readFileSync(join(REPO_ROOT, 'docs/mutation_testing_plan.md'), 'utf8')
    const documented: unknown = JSON.parse(stripLineComments(extractConfigBlock(plan)))
    const actual: unknown = JSON.parse(readFileSync(CONFIG_PATH, 'utf8'))

    expect(documented).toEqual(actual)
  })

  // The gate CLAUDE.md names, asserted against the config rather than restated. `break` is what
  // makes a survivor fail the run; `high`/`low` only colour the report, so all three are pinned
  // to keep the report from calling 96% "good" while the run correctly fails it.
  it('keeps every mutation threshold at 100', () => {
    const actual: unknown = JSON.parse(readFileSync(CONFIG_PATH, 'utf8'))

    expect(actual).toMatchObject({ thresholds: { high: 100, low: 100, break: 100 } })
  })

  // `"always"`, never `true`. `true` cleans only after a run that PASSED, and a run that fails the
  // 100 threshold is the normal state while iterating — which is how a second copy of `src/` came
  // to be left in the tree, the exact hazard `jest.coverage.config.ts` names in its ignore list.
  it('cleans the sandbox after a failing run too', () => {
    const actual: unknown = JSON.parse(readFileSync(CONFIG_PATH, 'utf8'))

    expect(actual).toMatchObject({ cleanTempDir: 'always' })
  })
})
