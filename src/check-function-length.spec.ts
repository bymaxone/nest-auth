/**
 * Pins `scripts/check-function-length.mjs`, the gate for the 50-line limit on a function or a test
 * body. It is plain Node, so each case runs it the way CI does, as a child process against a
 * throwaway git repository, and asserts the exit code and the printed problems.
 *
 * Layer: repository tooling, tests.
 */
import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'

const SCRIPT = resolve(__dirname, '..', 'scripts', 'check-function-length.mjs')

interface Result {
  readonly status: number | null
  readonly output: string
}

const roots: string[] = []

/** `lines` lines of statements, for the inside of a body. */
function statements(lines: number): string {
  return '  work()\n'.repeat(lines)
}

/** A function declaration named `name` spanning exactly `lines` lines, signature and brace included. */
function declaration(name: string, lines: number): string {
  return `function ${name}() {\n${statements(lines - 2)}}\n`
}

/** A call `head(...)` whose callback spans exactly `lines` lines. */
function callback(head: string, lines: number): string {
  return `${head}(() => {\n${statements(lines - 2)}})\n`
}

/** Lays out a git repository holding `files` (path to text), all added to the index. */
function repo(files: Record<string, string>, functions: Record<string, number> = {}): string {
  const root = mkdtempSync(join(tmpdir(), 'function-length-spec-'))
  roots.push(root)
  spawnSync('git', ['init', '-q'], { cwd: root })
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(join(root, dirname(path)), { recursive: true })
    writeFileSync(join(root, path), text)
  }
  mkdirSync(join(root, 'scripts'), { recursive: true })
  writeBaseline(root, functions)
  spawnSync('git', ['add', '-A'], { cwd: root })
  return root
}

/** Writes the working-tree baseline of `root` without committing it. */
function writeBaseline(root: string, functions: unknown): void {
  writeFileSync(
    join(root, 'scripts', 'function-length-baseline.json'),
    JSON.stringify({ functions })
  )
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

afterAll(() => {
  for (const root of roots) rmSync(root, { recursive: true, force: true })
})

describe('check-function-length', () => {
  describe('what it measures', () => {
    it('passes a function of exactly 50 lines and fails one of 51, naming the line count', () => {
      expect(run(repo({ 'src/a.ts': declaration('fits', 50) })).status).toBe(0)

      const result = run(repo({ 'src/a.ts': declaration('tooLong', 51) }))

      expect(result.status).toBe(1)
      expect(result.output).toContain('src/a.ts::tooLong spans 51 lines, over the 50-line limit')
    })

    it('measures from the signature to the closing brace, not from the comment above it', () => {
      const comment = `/**\n${' * about it\n'.repeat(40)} */\n`

      expect(run(repo({ 'src/a.ts': `${comment}\n\n${declaration('f', 50)}` })).status).toBe(0)
    })

    it.each([
      ['a function declaration', declaration('named', 51), 'src/a.ts::named'],
      ['a method', `class Box {\n  open() {\n${statements(49)}  }\n}\n`, 'src/a.ts::Box.open'],
      [
        'a constructor',
        `class Box {\n  constructor() {\n${statements(49)}  }\n}\n`,
        'src/a.ts::Box.constructor'
      ],
      [
        'a getter',
        `class Box {\n  get size() {\n${statements(48)}    return 1\n  }\n}\n`,
        'src/a.ts::Box.size'
      ],
      [
        'a setter',
        `class Box {\n  set size(v: number) {\n${statements(49)}  }\n}\n`,
        'src/a.ts::Box.size'
      ],
      [
        'an arrow assigned to a constant',
        `const make = () => {\n${statements(49)}}\n`,
        'src/a.ts::make'
      ],
      [
        'a function expression assigned to a property',
        `const table = {\n  run: function () {\n${statements(49)}  }\n}\n`,
        'src/a.ts::run'
      ],
      [
        'an anonymous callback',
        `export default [1].map(() => {\n${statements(49)}})\n`,
        'src/a.ts::<anonymous>'
      ]
    ])('measures %s', (_name, text, key) => {
      const result = run(repo({ 'src/a.ts': text }))

      expect(result.status).toBe(1)
      expect(result.output).toContain(`${key} spans 51 lines`)
    })

    it('reads a tsx file and a file under test', () => {
      const tsx = `export const View = () => {\n${statements(49)}  return <div />\n}\n`

      expect(run(repo({ 'src/View.tsx': tsx })).output).toContain(
        'src/View.tsx::View spans 52 lines'
      )
      expect(run(repo({ 'test/b.ts': declaration('helper', 51) })).output).toContain(
        'test/b.ts::helper'
      )
    })

    it('leaves out what is not hand-written source in scope', () => {
      const files = {
        'scripts/tool.ts': declaration('inScripts', 80),
        'src/server/openapi/generated/schemas.ts': declaration('generated', 80),
        'src/a.js': declaration('plainJs', 80),
        'src/a.d.mts': declaration('other', 80)
      }

      expect(run(repo(files)).status).toBe(0)
    })
  })

  describe('test bodies and containers', () => {
    it.each([
      ['it', `it('does it', () => {\n${statements(49)}})\n`, 'it does it'],
      ['test', `test('does it', () => {\n${statements(49)}})\n`, 'test does it'],
      ['it.only', `it.only('does it', () => {\n${statements(49)}})\n`, 'it does it'],
      ['it.skip', `it.skip('does it', () => {\n${statements(49)}})\n`, 'it does it'],
      ['it.each', `it.each([1, 2])('does %s', () => {\n${statements(49)}})\n`, 'it does %s'],
      ['it.concurrent', `it.concurrent('does it', () => {\n${statements(49)}})\n`, 'it does it'],
      ['xit', `xit('does it', () => {\n${statements(49)}})\n`, 'xit does it'],
      ['fit', `fit('does it', () => {\n${statements(49)}})\n`, 'fit does it'],
      ['xtest', `xtest('does it', () => {\n${statements(49)}})\n`, 'xtest does it'],
      [
        'an it.each template table',
        `it.each\`\n  a | b\n  ${'${1}'} | ${'${2}'}\n\`('does it', () => {\n${statements(49)}})\n`,
        'it does it'
      ],
      ['a test with a dynamic title', `it(title, () => {\n${statements(49)}})\n`, 'it <dynamic>']
    ])('measures the body of %s', (_name, text, name) => {
      const spec = `describe('Suite', () => {\n${text}})\n`
      const result = run(repo({ 'src/a.spec.ts': spec }))

      expect(result.status).toBe(1)
      expect(result.output).toContain(`src/a.spec.ts::describe Suite > ${name}`)
    })

    it('keeps a describe callback, a hook and a describe.each callback out of the count', () => {
      const small = Array.from(
        { length: 30 },
        (_, i) => `it('t${i}', () => {\n  work()\n})\n`
      ).join('')
      const spec = [
        `describe('Suite', () => {\n${small}})\n`,
        callback('beforeEach', 60),
        callback('afterEach', 60),
        callback('beforeAll', 60),
        callback('afterAll', 60),
        `describe.each([1])('each %s', () => {\n${statements(60)}})\n`,
        `context('ctx', () => {\n${statements(60)}})\n`,
        `suite('suite', () => {\n${statements(60)}})\n`,
        `describe.each\`\n  a | b\n  ${'${1}'} | ${'${2}'}\n\`('table', () => {\n${statements(60)}})\n`,
        `xdescribe('skipped', () => {\n${statements(60)}})\n`,
        `fdescribe('focused', () => {\n${statements(60)}})\n`,
        `describe.only('only', () => {\n${statements(60)}})\n`,
        `describe.skip('skip', () => {\n${statements(60)}})\n`
      ].join('')

      expect(run(repo({ 'src/a.spec.ts': spec })).status).toBe(0)
    })

    it('numbers only the tests over the limit, so a short test with the same title changes nothing', () => {
      const long = (): string => `  it('same', () => {\n${statements(49)}  })\n`
      const short = "  it('same', () => {\n    work()\n  })\n"
      const spec = (body: string): string => `describe('Suite', () => {\n${body}})\n`
      const root = repo({ 'src/a.spec.ts': spec(long() + short + long()) })

      run(root, '--write-baseline')
      const baseline = JSON.parse(
        readFileSync(join(root, 'scripts', 'function-length-baseline.json'), 'utf8')
      ) as { functions: Record<string, number> }
      writeFileSync(join(root, 'src/a.spec.ts'), spec(short + long() + short + long() + short))

      expect(Object.keys(baseline.functions)).toEqual([
        'src/a.spec.ts::describe Suite > it same',
        'src/a.spec.ts::describe Suite > it same #2'
      ])
      expect(run(root).status).toBe(0)
    })

    it('does not rename a baselined function when a small function is added before it', () => {
      const big = `  return [2].map((v) => {\n${statements(55)}  })\n`
      const before = `function f() {\n  [1].map((v) => v)\n${big}}\n`
      const root = repo({ 'src/a.ts': before })
      run(root, '--write-baseline')

      writeFileSync(
        join(root, 'src/a.ts'),
        `function f() {\n  [0].map((v) => v)\n  [1].map((v) => v)\n${big}}\n`
      )

      expect(run(root).output).toContain('src/a.ts::f grew from')
      expect(run(root).output).not.toContain('<anonymous> #')
    })

    it('keys a class property arrow with its class, so two classes with one member name differ', () => {
      const member = (cls: string): string =>
        `class ${cls} {\n  run = () => {\n${statements(49)}  }\n}\n`

      const result = run(repo({ 'src/a.ts': member('A') + member('B') }))

      expect(result.output).toContain('src/a.ts::A.run spans 51 lines')
      expect(result.output).toContain('src/a.ts::B.run spans 51 lines')
    })

    it('numbers two tests with one title', () => {
      const long = (): string => `  it('same', () => {\n${statements(49)}  })\n`
      const spec = `describe('Suite', () => {\n${long()}${long()}})\n`

      const result = run(repo({ 'src/a.spec.ts': spec }))

      expect(result.output).toContain('it same spans 51 lines')
      expect(result.output).toContain('it same #2 spans 51 lines')
    })
  })

  describe('against the baseline', () => {
    const KEY = 'src/a.ts::big'

    it('passes a function at its recorded length', () => {
      expect(run(repo({ 'src/a.ts': declaration('big', 60) }, { [KEY]: 60 })).status).toBe(0)
    })

    it('fails a baselined function that grew', () => {
      const result = run(repo({ 'src/a.ts': declaration('big', 61) }, { [KEY]: 60 }))

      expect(result.status).toBe(1)
      expect(result.output).toContain(
        `${KEY} grew from 60 to 61 lines. A baselined function may only shrink.`
      )
    })

    it('fails until the entry of a function that shrank is lowered', () => {
      const result = run(repo({ 'src/a.ts': declaration('big', 55) }, { [KEY]: 60 }))

      expect(result.status).toBe(1)
      expect(result.output).toContain('Lower its baseline entry from 60 to 55')
    })

    it('fails until the entry of a function now within the limit is removed', () => {
      const result = run(repo({ 'src/a.ts': declaration('big', 50) }, { [KEY]: 60 }))

      expect(result.status).toBe(1)
      expect(result.output).toContain(
        `${KEY} now spans 50 lines, within the limit. Remove its entry.`
      )
    })

    it('fails until the entry of a function that no longer exists is removed', () => {
      const result = run(repo({ 'src/a.ts': 'export {}\n' }, { [KEY]: 60 }))

      expect(result.status).toBe(1)
      expect(result.output).toContain(
        `${KEY} is on the baseline but no longer exists. Remove its entry.`
      )
    })

    it('removes the entry of a numbered offender that is gone while its namesake stays', () => {
      const baseline = { [KEY]: 60, [`${KEY} #2`]: 60 }

      const result = run(repo({ 'src/a.ts': declaration('big', 60) }, baseline))

      expect(result.output).toContain(
        `${KEY} #2 is on the baseline but no longer exists. Remove its entry.`
      )
      expect(result.output).not.toContain(`${KEY} spans`)
    })

    it('names both sides of a rename', () => {
      const result = run(repo({ 'src/a.ts': declaration('renamed', 60) }, { [KEY]: 60 }))

      expect(result.output).toContain(
        'If it was renamed, its old entry `src/a.ts::big` is the stale one below.'
      )
      expect(result.output).toContain('If it was renamed, the new offender is `src/a.ts::renamed`.')
      expect(result.output).toContain('2 function-length problem(s).')
    })

    it('does not link a stale entry in one file to a new offender in another', () => {
      const result = run(
        repo({ 'src/a.ts': 'export {}\n', 'src/b.ts': declaration('other', 60) }, { [KEY]: 60 })
      )

      expect(result.output).not.toContain('If it was renamed')
    })

    it.each([
      ['a count of fifty or less', { [KEY]: 50 }],
      ['a count that is not an integer', { [KEY]: 60.5 }],
      ['a count that is not a number', { [KEY]: 'long' }]
    ])('refuses a baseline entry with %s', (_name, functions) => {
      const result = run(
        repo({ 'src/a.ts': declaration('big', 60) }, functions as Record<string, number>)
      )

      expect(result.status).not.toBe(0)
      expect(result.output).toContain('must record an integer above 50 lines')
    })

    it('refuses a baseline that is not the expected shape', () => {
      const root = repo({ 'src/a.ts': 'export {}\n' })
      writeFileSync(
        join(root, 'scripts', 'function-length-baseline.json'),
        JSON.stringify({ functions: [] })
      )

      const result = run(root)

      expect(result.status).not.toBe(0)
      expect(result.output).toContain('expected { "functions"')
    })
  })

  describe('a function nested in another', () => {
    const nested = (inner: number): string =>
      `export function outer() {\n  const run = () => {\n${statements(inner - 2)}  }\n${statements(5)}}\n`

    it('is measured on its own and inside its container, and says the two entries move together', () => {
      const result = run(repo({ 'src/a.ts': nested(52) }))

      expect(result.output).toContain('src/a.ts::outer > run spans 52 lines')
      expect(result.output).toContain('src/a.ts::outer spans 59 lines')
      expect(result.output).toContain(
        'It is also counted inside `src/a.ts::outer`, so that entry moves with it: this is one change, not two offenders.'
      )
    })

    it('reports growth of the inner function against both baseline entries', () => {
      const baseline = { 'src/a.ts::outer': 59, 'src/a.ts::outer > run': 52 }

      const result = run(repo({ 'src/a.ts': nested(53) }, baseline))

      expect(result.output).toContain('src/a.ts::outer > run grew from 52 to 53 lines')
      expect(result.output).toContain('src/a.ts::outer grew from 59 to 60 lines')
      expect(result.output).toContain('2 function-length problem(s).')
    })
  })

  describe('against a base revision', () => {
    it('refuses a baseline entry the base did not have', () => {
      const root = repo({ 'src/a.ts': declaration('big', 60) })
      commitBase(root)
      writeBaseline(root, { 'src/a.ts::big': 60 })

      const result = run(root, '--base', 'HEAD')

      expect(result.status).toBe(1)
      expect(result.output).toContain('the base revision does not have it')
    })

    it('refuses a baseline entry raised above the base', () => {
      const root = repo({ 'src/a.ts': declaration('big', 70) }, { 'src/a.ts::big': 60 })
      commitBase(root)
      writeBaseline(root, { 'src/a.ts::big': 70 })

      const result = run(root, '--base', 'HEAD')

      expect(result.output).toContain(
        'src/a.ts::big is recorded at 70 lines, above 60 on the base revision'
      )
    })

    it('accepts an entry kept or lowered, imposes nothing when the base has no baseline, and fails on an unknown revision', () => {
      const root = repo({ 'src/a.ts': declaration('big', 60) }, { 'src/a.ts::big': 60 })
      commitBase(root)

      expect(run(root, '--base', 'HEAD').status).toBe(0)
      expect(run(root, '--base', 'no-such-ref').status).not.toBe(0)

      const bare = mkdtempSync(join(tmpdir(), 'function-length-spec-'))
      roots.push(bare)
      spawnSync('git', ['init', '-q'], { cwd: bare })
      mkdirSync(join(bare, 'src'), { recursive: true })
      writeFileSync(join(bare, 'src', 'a.ts'), 'export {}\n')
      spawnSync('git', ['add', '-A'], { cwd: bare })
      commitBase(bare)
      mkdirSync(join(bare, 'scripts'), { recursive: true })
      writeBaseline(bare, {})

      expect(run(bare, '--base', 'HEAD').status).toBe(0)
    })
  })

  describe('--write-baseline', () => {
    it('writes every offender and nothing else, sorted, and the result passes the check', () => {
      const root = repo({
        'src/b.ts': declaration('second', 70),
        'src/a.ts':
          declaration('first', 60) +
          declaration('fine', 40) +
          declaration('atTheLimit', 50) +
          declaration('justOver', 51)
      })

      const written = run(root, '--write-baseline')
      const text = readFileSync(join(root, 'scripts', 'function-length-baseline.json'), 'utf8')

      expect(written.status).toBe(0)
      expect(written.output).toContain('Wrote 3 baseline entries')
      expect(JSON.parse(text)).toEqual({
        functions: { 'src/a.ts::first': 60, 'src/a.ts::justOver': 51, 'src/b.ts::second': 70 }
      })
      expect(Object.keys(JSON.parse(text).functions)).toEqual([
        'src/a.ts::first',
        'src/a.ts::justOver',
        'src/b.ts::second'
      ])
      expect(text.endsWith('}\n')).toBe(true)
      expect(run(root).status).toBe(0)
    })

    it('round-trips: writing again over a passing baseline leaves the file byte for byte the same', () => {
      const root = repo({ 'src/a.ts': declaration('first', 60) })
      run(root, '--write-baseline')
      const first = readFileSync(join(root, 'scripts', 'function-length-baseline.json'), 'utf8')

      run(root, '--write-baseline')
      const second = readFileSync(join(root, 'scripts', 'function-length-baseline.json'), 'utf8')

      expect(second).toBe(first)
    })

    it('writes an empty table for a repository with no offender', () => {
      const root = repo({ 'src/a.ts': declaration('fine', 10) })

      run(root, '--write-baseline')

      expect(
        JSON.parse(readFileSync(join(root, 'scripts', 'function-length-baseline.json'), 'utf8'))
      ).toEqual({
        functions: {}
      })
    })
  })

  describe('the committed baseline', () => {
    it('is the one the script would generate for this repository, so it is never edited by hand', () => {
      const repoRoot = resolve(__dirname, '..')
      const committed = readFileSync(
        join(repoRoot, 'scripts', 'function-length-baseline.json'),
        'utf8'
      )
      const scratch = join(tmpdir(), `function-length-regenerated-${process.pid}.json`)
      roots.push(scratch)

      const result = spawnSync(
        process.execPath,
        [SCRIPT, '--root', repoRoot, '--baseline', scratch, '--write-baseline'],
        { encoding: 'utf8' }
      )

      expect(result.status).toBe(0)
      expect(readFileSync(scratch, 'utf8')).toBe(committed)
    })
  })
})
