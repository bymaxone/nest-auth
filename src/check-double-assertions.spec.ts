/**
 * Pins `scripts/check-double-assertions.mjs`, the gate for `as unknown as`. It is plain Node, so
 * each case runs it the way CI does, as a child process against a throwaway git repository, and
 * asserts the exit code and the printed problems.
 *
 * Layer: repository tooling, tests.
 */
import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'

const SCRIPT = resolve(__dirname, '..', 'scripts', 'check-double-assertions.mjs')

interface Result {
  readonly status: number | null
  readonly output: string
}

const roots: string[] = []

/** One double assertion, written the way the rule forbids. */
const SITE = 'const a = value as unknown as string\n'

/** Lays out a git repository holding `files` (path to text), all added to the index. */
function repo(files: Record<string, string>, baseline: unknown = { files: {} }): string {
  const root = mkdtempSync(join(tmpdir(), 'double-assertion-spec-'))
  roots.push(root)
  spawnSync('git', ['init', '-q'], { cwd: root })
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(join(root, dirname(path)), { recursive: true })
    writeFileSync(join(root, path), text)
  }
  mkdirSync(join(root, 'scripts'), { recursive: true })
  writeFileSync(join(root, 'scripts', 'double-assertion-baseline.json'), JSON.stringify(baseline))
  spawnSync('git', ['add', '-A'], { cwd: root })
  return root
}

/** Runs the script in `root` and returns its exit status and combined output. */
function run(root: string, ...args: string[]): Result {
  const result = spawnSync(process.execPath, [SCRIPT, '--root', root, ...args], {
    encoding: 'utf8'
  })
  return { status: result.status, output: `${result.stdout}${result.stderr}` }
}

/** Commits the index as the base revision of `root`, so `--base HEAD` can read the baseline from it. */
function commitBase(root: string): void {
  spawnSync(
    'git',
    ['-c', 'user.name=t', '-c', 'user.email=t@example.com', 'commit', '-q', '-m', 'base'],
    { cwd: root }
  )
}

/** Rewrites the working-tree baseline of `root` without committing it. */
function setBaseline(root: string, baseline: unknown): void {
  writeFileSync(join(root, 'scripts', 'double-assertion-baseline.json'), JSON.stringify(baseline))
}

afterAll(() => {
  for (const root of roots) rmSync(root, { recursive: true, force: true })
})

describe('check-double-assertions', () => {
  it('passes when no file holds a double assertion', () => {
    const result = run(repo({ 'src/a.ts': 'export const a = 1\n', 'test/b.ts': 'export {}\n' }))

    expect(result.status).toBe(0)
    expect(result.output).toContain('No tracked source or test file')
  })

  it.each(['src/a.ts', 'test/a.ts', 'src/view.tsx'])('fails a new site in %s', (path) => {
    const result = run(repo({ [path]: SITE }))

    expect(result.status).toBe(1)
    expect(result.output).toContain(`${path} has 1 \`as unknown as\` site(s)`)
  })

  it('counts a site that is parenthesized, split over lines, or nested in a call', () => {
    const text = [
      'const a = (value as unknown) as string',
      'const b = value as unknown as',
      '  string',
      'const c = f(value as unknown as number, other as unknown as string)'
    ].join('\n')

    const result = run(repo({ 'src/a.ts': text }))

    expect(result.output).toContain('src/a.ts has 4 `as unknown as` site(s)')
  })

  it('does not count a mention in a string or a comment, a single assertion, or a file out of scope', () => {
    const files = {
      'src/a.ts':
        "// value as unknown as string\nconst a = 'x as unknown as y'\nconst b = v as unknown\nconst c = v as string\n",
      'scripts/tool.ts': SITE
    }

    expect(run(repo(files)).status).toBe(0)
  })

  it('passes a baselined file at its recorded count', () => {
    const result = run(repo({ 'src/a.ts': SITE }, { files: { 'src/a.ts': 1 } }))

    expect(result.status).toBe(0)
  })

  it('fails a baselined file that gained a site', () => {
    const result = run(repo({ 'src/a.ts': SITE + SITE }, { files: { 'src/a.ts': 1 } }))

    expect(result.status).toBe(1)
    expect(result.output).toContain(
      'src/a.ts grew from 1 to 2 sites. A baselined file may only shrink.'
    )
  })

  it('fails until the entry of a file that lost a site is lowered', () => {
    const result = run(repo({ 'src/a.ts': SITE }, { files: { 'src/a.ts': 2 } }))

    expect(result.status).toBe(1)
    expect(result.output).toContain('Lower its baseline entry from 2 to 1')
  })

  it('fails until the entry of a file with no site left is removed', () => {
    const result = run(repo({ 'src/a.ts': 'export {}\n' }, { files: { 'src/a.ts': 1 } }))

    expect(result.status).toBe(1)
    expect(result.output).toContain('Remove its entry')
  })

  it('refuses a baseline entry that is not a positive count', () => {
    const result = run(repo({ 'src/a.ts': SITE }, { files: { 'src/a.ts': 0 } }))

    expect(result.status).not.toBe(0)
    expect(result.output).toContain('must record an integer count of 1 or more')
  })

  describe('against a base revision', () => {
    it('refuses a baseline entry the base did not have', () => {
      const root = repo({ 'src/a.ts': SITE }, { files: {} })
      commitBase(root)
      setBaseline(root, { files: { 'src/a.ts': 1 } })

      const result = run(root, '--base', 'HEAD')

      expect(result.status).toBe(1)
      expect(result.output).toContain('the base revision does not have it')
    })

    it('refuses a baseline entry raised above the base', () => {
      const root = repo({ 'src/a.ts': SITE + SITE }, { files: { 'src/a.ts': 1 } })
      commitBase(root)
      setBaseline(root, { files: { 'src/a.ts': 2 } })

      const result = run(root, '--base', 'HEAD')

      expect(result.output).toContain(
        'src/a.ts is recorded at 2 sites, above 1 on the base revision'
      )
    })

    it('imposes nothing when the base has no baseline file, and fails on an unknown revision', () => {
      const root = repo({ 'src/a.ts': SITE }, { files: { 'src/a.ts': 1 } })
      commitBase(root)

      expect(run(root, '--base', 'HEAD').status).toBe(0)
      expect(run(root, '--base', 'no-such-ref').status).not.toBe(0)
    })
  })

  it('writes the baseline from the sites it finds', () => {
    const root = repo({ 'src/a.ts': SITE + SITE, 'test/b.ts': SITE })

    const written = run(root, '--write-baseline')
    const checked = run(root)

    expect(written.status).toBe(0)
    expect(checked.status).toBe(0)
  })
})
