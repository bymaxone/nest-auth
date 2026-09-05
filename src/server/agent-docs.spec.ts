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
 * Sized against observed growth rather than an aesthetic: the shared canonical block grew five
 * times in one week, most recently by 930 bytes. A margin that survives one revision is a margin
 * that fails on the next, so this holds roughly three.
 */
const REQUIRED_HEADROOM_BYTES = 3_000

/** Every relative markdown link in a file, as written. */
function relativeLinksIn(source: string): readonly string[] {
  return [...source.matchAll(/\]\((\.{1,2}\/[^)#\s]+)/g)].map((match) => match[1] as string)
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
