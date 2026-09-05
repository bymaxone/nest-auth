/**
 * @fileoverview Structural checks on the agent-instruction files.
 *
 * `AGENTS.md` is read by Codex on every review turn, and it is read by walking the file tree from
 * the repository root down to the working directory — at most one file per directory, links never
 * followed. Those mechanics make two things silently breakable that no other gate watches:
 *
 * 1. **Relative links depend on the file's directory.** A path written from the repository root
 *    resolves to nothing from `src/server/`, so moving a section between these files silently
 *    invalidates every relative link it carries. Nothing renders them in CI, and a link is
 *    unreachable rather than wrong-looking, so only an assertion makes that visible.
 * 2. **The combined chain must stay under the budget.** Truncation is byte-level and silent — no
 *    error, no failed check — and the shared block sits at the top, so what stops reaching the
 *    reviewer is this repository's own rules, from the end of the file backwards.
 */

import { readFileSync, existsSync } from 'node:fs'
import { dirname, join, normalize, resolve } from 'node:path'

/** Repository root, from this file's location. */
const ROOT = resolve(__dirname, '..', '..')

/**
 * The instruction files, and the deepest working directory each one is loaded for.
 *
 * Codex loads one `AGENTS.md` per directory along the root-to-cwd walk, so the cost that matters is
 * the worst CHAIN — root plus whichever nested files sit on one path — never the sum of every file.
 */
const AGENT_FILES = ['AGENTS.md', 'src/server/AGENTS.md'] as const

/** Documentation referenced by the instruction files but never loaded by Codex. */
const LINKED_DOCS = ['docs/repository-guide.md'] as const

/**
 * `project_doc_max_bytes`, Codex's default budget for the concatenated instruction chain.
 *
 * Not configurable in a way this test may assume: `.codex/config.toml` raises it only for someone
 * who has TRUSTED the project, and a fresh clone gets this number. The test holds the default so a
 * new contributor's experience is the one being measured.
 */
const CODEX_DOC_BUDGET_BYTES = 32_768

/**
 * Headroom the chain must keep, in bytes.
 *
 * The margin exists because the chain grows from a side this repository does not control: the
 * shared block is centrally managed and arrives already grown, with no warning and no say. A
 * margin sized to survive exactly one such revision fails on the next, so this holds several —
 * enough that crossing it is a signal to restructure rather than an emergency.
 */
const REQUIRED_HEADROOM_BYTES = 3_000

/**
 * Every relative markdown link target in a file, as written.
 *
 * Relative means "resolved against this file's directory", which is every target that is not an
 * absolute URL and not a bare anchor — `docs/foo.md` as much as `./docs/foo.md`. Matching only the
 * dot-prefixed forms would leave the plainest spelling of a broken link unguarded, and a checker
 * that skips a case it claims to cover is worse than one that claims less.
 *
 * @param source - The markdown file's contents.
 * @returns Each relative target, in source order, with anchors and query strings stripped.
 */
function relativeLinksIn(source: string): readonly string[] {
  return [...source.matchAll(/\]\(([^)\s]+)/g)]
    .map((match) => (match[1] as string).split('#')[0] as string)
    .filter((target) => target !== '' && !/^(?:[a-z][a-z0-9+.-]*:|\/\/|\/)/i.test(target))
}

describe('agent instruction files', () => {
  describe.each(AGENT_FILES)('%s', (file) => {
    const source = readFileSync(join(ROOT, file), 'utf8')

    // Resolution is from the file's own directory, not the repository root — the distinction a
    // moved section silently crosses, and one no renderer in this pipeline would surface.
    it('has no relative link that fails to resolve from its own directory', () => {
      const unresolved = relativeLinksIn(source).filter(
        (link) => !existsSync(normalize(join(ROOT, dirname(file), link)))
      )

      expect(unresolved).toEqual([])
    })
  })

  // The same check for documentation the instruction files point at: those links are not loaded by
  // Codex, but a person following one still deserves it to work.
  describe.each(LINKED_DOCS)('%s', (file) => {
    const source = readFileSync(join(ROOT, file), 'utf8')

    it('has no relative link that fails to resolve from its own directory', () => {
      const unresolved = relativeLinksIn(source).filter(
        (link) => !existsSync(normalize(join(ROOT, dirname(file), link)))
      )

      expect(unresolved).toEqual([])
    })
  })

  // Truncation is silent, so this assertion is the only thing in the repository that can report
  // the budget being crossed. Over the cap, CI stays green and part of the file is simply not
  // read — the failure has no other symptom.
  it('keeps the worst instruction chain under the Codex budget with room to grow', () => {
    const chainBytes = AGENT_FILES.reduce(
      (total, file) => total + Buffer.byteLength(readFileSync(join(ROOT, file), 'utf8')),
      0
    )

    expect(chainBytes).toBeLessThanOrEqual(CODEX_DOC_BUDGET_BYTES - REQUIRED_HEADROOM_BYTES)
  })
})
