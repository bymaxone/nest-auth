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

import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, normalize, posix, relative, resolve, sep } from 'node:path'

/** Repository root, from this file's location. */
const ROOT = resolve(__dirname, '..', '..')

/** Directories that never hold an instruction file this repository ships. */
const SKIPPED_DIRECTORIES = new Set([
  '.git',
  '.stryker-tmp',
  'coverage',
  'dist',
  'node_modules',
  'reports'
])

/**
 * Every `AGENTS.md` under a root, as root-relative paths.
 *
 * Discovered rather than listed: Codex loads whatever file sits on the walk from the root to the
 * working directory, so a file added in a new directory is read by the reviewer whether or not
 * anyone remembered to register it here. A fixed list leaves exactly that file unchecked.
 *
 * @param root - Directory to scan.
 * @returns Root-relative paths with '/' separators on every platform, sorted so the order is stable.
 */
function findAgentFiles(root: string): readonly string[] {
  const found: string[] = []
  const walk = (directory: string): void => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (!SKIPPED_DIRECTORIES.has(entry.name)) walk(join(directory, entry.name))
      } else if (entry.name === 'AGENTS.md') {
        found.push(relative(root, join(directory, entry.name)).split(sep).join('/'))
      }
    }
  }
  walk(root)
  return found.sort()
}

/**
 * Size in bytes of the heaviest instruction chain under a root.
 *
 * Codex loads at most one `AGENTS.md` per directory along the root-to-cwd walk, so what one session
 * reads is a CHAIN: a file plus the files in its ancestor directories. Siblings are never loaded
 * together, so summing every file would overstate the cost and, worse, hide which path is heaviest.
 *
 * @param root - Directory to scan.
 * @returns The largest root-to-leaf total, or 0 when there is no instruction file.
 */
function worstChainBytes(root: string): number {
  const files = findAgentFiles(root)
  const bytes = (file: string): number => Buffer.byteLength(readFileSync(join(root, file), 'utf8'))
  const ancestors = (file: string): readonly string[] =>
    files.filter((other) => {
      // Paths are root-relative with '/' separators on every platform, so ancestry is a posix test.
      const scope = posix.dirname(other)
      const own = posix.dirname(file)
      return scope === '.' || own === scope || own.startsWith(scope + '/')
    })
  return Math.max(0, ...files.map((file) => ancestors(file).reduce((sum, f) => sum + bytes(f), 0)))
}

/** The instruction files this repository ships. */
const AGENT_FILES = findAgentFiles(ROOT)

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

  it('discovers the instruction files instead of trusting a list', () => {
    expect(AGENT_FILES).toContain('AGENTS.md')
    expect(AGENT_FILES).toContain('src/server/AGENTS.md')
  })

  // Truncation is silent, so this assertion is the only thing in the repository that can report
  // the budget being crossed. Over the cap, CI stays green and part of the file is simply not
  // read — the failure has no other symptom.
  it('keeps the worst instruction chain under the Codex budget with room to grow', () => {
    expect(worstChainBytes(ROOT)).toBeLessThanOrEqual(
      CODEX_DOC_BUDGET_BYTES - REQUIRED_HEADROOM_BYTES
    )
  })
})

describe('instruction chain discovery', () => {
  let root: string

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'agent-docs-'))
  })

  afterEach(() => {
    rmSync(root, { recursive: true, force: true })
  })

  /** Writes a file of the given size, creating its directory. */
  function put(path: string, size: number): void {
    mkdirSync(dirname(join(root, path)), { recursive: true })
    writeFileSync(join(root, path), 'x'.repeat(size))
  }

  // A new nested file must be found without anyone registering it, or its links and bytes go
  // unchecked while the reviewer still reads it.
  it('finds a nested instruction file nobody registered', () => {
    put('AGENTS.md', 10)
    put('packages/api/AGENTS.md', 10)

    expect(findAgentFiles(root)).toEqual(['AGENTS.md', 'packages/api/AGENTS.md'])
  })

  // Dependencies and build output carry their own AGENTS.md; counting them would fail the gate on
  // files the repository does not ship.
  it('ignores dependency and build directories', () => {
    put('AGENTS.md', 10)
    put('node_modules/pkg/AGENTS.md', 10)
    put('dist/AGENTS.md', 10)

    expect(findAgentFiles(root)).toEqual(['AGENTS.md'])
  })

  // Siblings are never loaded together, so the cost is the heavier path, not the sum of both.
  it('measures the heaviest root-to-leaf chain, not the sum of siblings', () => {
    put('AGENTS.md', 100)
    put('a/AGENTS.md', 30)
    put('b/AGENTS.md', 50)

    expect(worstChainBytes(root)).toBe(150)
  })

  // A nested file extends every deeper path under it and nothing beside it.
  it('adds each ancestor on the path and no file outside it', () => {
    put('AGENTS.md', 100)
    put('a/AGENTS.md', 20)
    put('a/b/AGENTS.md', 5)
    put('c/AGENTS.md', 10)

    expect(worstChainBytes(root)).toBe(125)
  })

  // A directory whose name merely starts like another is not its descendant.
  it('does not treat a prefix-named sibling directory as an ancestor', () => {
    put('AGENTS.md', 1)
    put('pkg/AGENTS.md', 40)
    put('pkg-extra/AGENTS.md', 10)

    expect(worstChainBytes(root)).toBe(41)
  })

  it('reports zero when there is no instruction file', () => {
    expect(worstChainBytes(root)).toBe(0)
  })
})
