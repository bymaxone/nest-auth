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

/** A segment of a key, as the format specifies them: a kind first, then its strings. */
type Segment = string[]

/**
 * The key the baseline holds for a function, written out from the format's definition and not by
 * the script: `[path, ...segments]`, with a trailing ordinal from 2.
 */
function keyOf(path: string, segments: Segment[], ordinal = 1): string {
  return JSON.stringify(ordinal === 1 ? [path, ...segments] : [path, ...segments, ordinal])
}

/** A top-level function `name` in `src/a.ts`. */
function fnKey(name: string, ordinal = 1): string {
  return keyOf('src/a.ts', [['fn', name]], ordinal)
}

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

    it('keeps a tracked path that spells the delimiter apart from a title that does', () => {
      const test = `it('foo.ts::g', () => {\n${statements(49)}})\n`
      const root = repo({
        'src/a.spec.ts': test,
        'src/a.spec.ts::it foo.ts': declaration('g', 51)
      })

      run(root, '--write-baseline')
      const baseline = JSON.parse(
        readFileSync(join(root, 'scripts', 'function-length-baseline.json'), 'utf8')
      ) as { functions: Record<string, number> }

      expect(Object.keys(baseline.functions)).toHaveLength(2)
      expect(run(root).status).toBe(0)
    })

    it('does not let a suite title spell the path of nested suites', () => {
      const test = (lines: number): string => `it('case', () => {\n${statements(lines)}})\n`
      const nested = (lines: number): string =>
        `describe('outer', () => {\ndescribe('inner', () => {\n${test(lines)}})\n})\n`
      const spelled = `describe('outer > describe inner', () => {\n${test(49)}})\n`
      const root = repo({ 'src/a.spec.ts': nested(49) })
      run(root, '--write-baseline')
      commitBase(root)

      writeFileSync(join(root, 'src/a.spec.ts'), nested(5) + spelled)
      const result = run(root, '--base', 'HEAD')

      expect(result.status).toBe(1)
      expect(result.output).toContain('over the 50-line limit')
    })

    it('does not let a title spell the placeholder of a dynamic title', () => {
      const dynamic = `it(title, () => {\n${statements(49)}})\n`
      const literal = `it('<dynamic>', () => {\n${statements(49)}})\n`
      const root = repo({ 'src/a.spec.ts': dynamic })
      run(root, '--write-baseline')
      commitBase(root)

      writeFileSync(join(root, 'src/a.spec.ts'), `it(title, () => {})\n${literal}`)
      const result = run(root, '--base', 'HEAD')

      expect(result.status).toBe(1)
      expect(result.output).toContain('over the 50-line limit')
    })

    it('keeps a test titled like an ordinal apart from the second test of that title', () => {
      const long = (title: string, lines: number): string =>
        `  it('${title}', () => {\n${statements(lines)}  })\n`
      const spec = (second: number): string =>
        `describe('Suite', () => {\n${long('same', 49)}${long('same', second)}${long('same #2', 49)}})\n`
      const root = repo({ 'src/a.spec.ts': spec(49) })
      run(root, '--write-baseline')
      commitBase(root)

      writeFileSync(join(root, 'src/a.spec.ts'), spec(90))
      const result = run(root, '--base', 'HEAD')

      expect(result.status).toBe(1)
      expect(result.output).toContain('describe Suite > it same #2 grew from')
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

      const suite = ['container', 'describe', 'Suite']
      expect(Object.keys(baseline.functions)).toEqual([
        keyOf('src/a.spec.ts', [suite, ['test', 'it', 'same']]),
        keyOf('src/a.spec.ts', [suite, ['test', 'it', 'same']], 2)
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
    const KEY = fnKey('big')
    const NAME = 'src/a.ts::big'

    it('passes a function at its recorded length', () => {
      expect(run(repo({ 'src/a.ts': declaration('big', 60) }, { [KEY]: 60 })).status).toBe(0)
    })

    it('fails a baselined function that grew', () => {
      const result = run(repo({ 'src/a.ts': declaration('big', 61) }, { [KEY]: 60 }))

      expect(result.status).toBe(1)
      expect(result.output).toContain(
        `${NAME} grew from 60 to 61 lines. A baselined function may only shrink.`
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
        `${NAME} now spans 50 lines, within the limit. Remove its entry.`
      )
    })

    it('fails until the entry of a function that no longer exists is removed', () => {
      const result = run(repo({ 'src/a.ts': 'export {}\n' }, { [KEY]: 60 }))

      expect(result.status).toBe(1)
      expect(result.output).toContain(
        `${NAME} is on the baseline but no longer exists. Remove its entry.`
      )
    })

    it('removes the entry of a numbered offender that is gone while its namesake stays', () => {
      const baseline = { [KEY]: 60, [fnKey('big', 2)]: 60 }

      const result = run(repo({ 'src/a.ts': declaration('big', 60) }, baseline))

      expect(result.output).toContain(
        `${NAME} #2 is on the baseline but no longer exists. Remove its entry.`
      )
      expect(result.output).not.toContain(`${NAME} spans`)
    })

    it('says a numbered entry is within the limit when its name no longer has two offenders', () => {
      const baseline = { [fnKey('big')]: 60, [fnKey('big', 2)]: 60 }

      const result = run(repo({ 'src/a.ts': declaration('big', 40) }, baseline))

      expect(result.output).toContain(`src/a.ts::big #2 now spans 40 lines, within the limit.`)
    })

    it('calls a numbered entry gone, not within the limit, while its namesake spans 51 lines', () => {
      const baseline = { [KEY]: 60, [fnKey('big', 2)]: 60 }

      const result = run(repo({ 'src/a.ts': declaration('big', 51) }, baseline))

      expect(result.output).toContain(
        `${NAME} #2 is on the baseline but no longer exists. Remove its entry.`
      )
      expect(result.output).not.toContain('within the limit')
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
      const baseline = {
        [fnKey('outer')]: 59,
        [keyOf('src/a.ts', [
          ['fn', 'outer'],
          ['fn', 'run']
        ])]: 52
      }

      const result = run(repo({ 'src/a.ts': nested(53) }, baseline))

      expect(result.output).toContain('src/a.ts::outer > run grew from 52 to 53 lines')
      expect(result.output).toContain('src/a.ts::outer grew from 59 to 60 lines')
      expect(result.output).toContain('2 function-length problem(s).')
    })
  })

  describe('against a base revision', () => {
    it('refuses a baseline key that is not a structured key, naming it', () => {
      const result = run(repo({ 'src/a.ts': declaration('big', 60) }, { 'src/a.ts::big': 60 }))

      expect(result.status).not.toBe(0)
      expect(result.output).toContain('src/a.ts::big is not a function key')
    })

    describe('whose baseline predates structured keys', () => {
      /** A repository whose base commit holds `files` and a baseline in the earlier string format. */
      function legacyBase(files: Record<string, string>, legacy: Record<string, number>): string {
        const root = repo(files, legacy)
        commitBase(root)
        return root
      }

      it('reads the base from its sources, so an unchanged entry passes', () => {
        const root = legacyBase({ 'src/a.ts': declaration('big', 60) }, { 'src/a.ts::big': 60 })
        writeBaseline(root, { [fnKey('big')]: 60 })

        expect(run(root, '--base', 'HEAD').status).toBe(0)
      })

      it('still refuses an entry raised above the base and one the base did not have', () => {
        const root = legacyBase({ 'src/a.ts': declaration('big', 60) }, { 'src/a.ts::big': 60 })
        writeFileSync(join(root, 'src/a.ts'), declaration('big', 70) + declaration('other', 60))
        writeBaseline(root, { [fnKey('big')]: 70, [fnKey('other')]: 60 })

        const result = run(root, '--base', 'HEAD')

        expect(result.output).toContain(
          'src/a.ts::big is recorded at 70 lines, above 60 on the base revision'
        )
        expect(result.output).toContain(
          'src/a.ts::other is on the baseline but the base revision does not have it'
        )
      })

      it('does not take a file added since the base for part of the base', () => {
        const root = legacyBase({ 'src/a.ts': declaration('big', 60) }, { 'src/a.ts::big': 60 })
        writeFileSync(join(root, 'src/b.ts'), declaration('added', 60))
        spawnSync('git', ['add', '-A'], { cwd: root })
        writeBaseline(root, {
          [fnKey('big')]: 60,
          [keyOf('src/b.ts', [['fn', 'added']])]: 60
        })

        const result = run(root, '--base', 'HEAD')

        expect(result.output).toContain(
          'src/b.ts::added is on the baseline but the base revision does not have it'
        )
      })

      it('does not admit a new test whose title spells the ordinal of an old one', () => {
        const test = (title: string): string => `it('${title}', () => {\n${statements(60)}})\n`
        const root = legacyBase(
          { 'src/a.spec.ts': test('x') + test('x') },
          { 'src/a.spec.ts::it x': 62, 'src/a.spec.ts::it x #2': 62 }
        )
        writeFileSync(join(root, 'src/a.spec.ts'), test('x') + test('x') + test('x #2'))
        run(root, '--write-baseline')

        const result = run(root, '--base', 'HEAD')

        expect(result.status).toBe(1)
        expect(result.output).toContain('the base revision does not have it')
      })

      it('keeps passing a title the earlier format escaped', () => {
        const root = legacyBase(
          { 'src/a.spec.ts': `it('foo#bar', () => {\n${statements(60)}})\n` },
          { 'src/a.spec.ts::it foo\\#bar': 62 }
        )
        run(root, '--write-baseline')

        expect(run(root, '--base', 'HEAD').status).toBe(0)
      })
    })

    it('refuses a baseline entry the base did not have', () => {
      const root = repo({ 'src/a.ts': declaration('big', 60) })
      commitBase(root)
      writeBaseline(root, { [fnKey('big')]: 60 })

      const result = run(root, '--base', 'HEAD')

      expect(result.status).toBe(1)
      expect(result.output).toContain('the base revision does not have it')
    })

    it('refuses a baseline entry raised above the base', () => {
      const root = repo({ 'src/a.ts': declaration('big', 70) }, { [fnKey('big')]: 60 })
      commitBase(root)
      writeBaseline(root, { [fnKey('big')]: 70 })

      const result = run(root, '--base', 'HEAD')

      expect(result.output).toContain(
        'src/a.ts::big is recorded at 70 lines, above 60 on the base revision'
      )
    })

    it('accepts an entry kept or lowered, imposes nothing when the base has no baseline, and fails on an unknown revision', () => {
      const root = repo({ 'src/a.ts': declaration('big', 60) }, { [fnKey('big')]: 60 })
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
        functions: {
          [fnKey('first')]: 60,
          [fnKey('justOver')]: 51,
          [keyOf('src/b.ts', [['fn', 'second']])]: 70
        }
      })
      expect(Object.keys(JSON.parse(text).functions)).toEqual([
        fnKey('first'),
        fnKey('justOver'),
        keyOf('src/b.ts', [['fn', 'second']])
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

/** Runs `source` as an ES module that can import the key module, and parses what it prints. */
function runKeyModule(source: string): unknown {
  const keyModule = resolve(__dirname, '..', 'scripts', 'function-length-key.mjs')
  const result = spawnSync(
    process.execPath,
    ['--input-type=module', '-e', `import * as k from ${JSON.stringify(keyModule)}\n${source}`],
    { encoding: 'utf8' }
  )
  if (result.status !== 0) throw new Error(result.stderr)
  return JSON.parse(result.stdout)
}

describe('the function key', () => {
  // The property that makes the gate's identity safe: every key reads back as exactly the
  // value it was built from, so two different values can never share a key. Free text is drawn from
  // the pieces that have broken string-joined keys: both separators, an ordinal, a placeholder, the
  // escape character, quotes and brackets.
  it('reads back as what was encoded, for random values spelled with every delimiter', () => {
    const outcome = runKeyModule(`
      let seed = 20260711
      const next = () => {
        seed = (seed + 0x6d2b79f5) | 0
        let t = Math.imul(seed ^ (seed >>> 15), 1 | seed)
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296
      }
      const pick = (list) => list[Math.floor(next() * list.length)]
      const pieces = ['a', 'b', '::', ' > ', ' #2', '#', '<dynamic>', '<anonymous>', String.fromCharCode(92), '"', '[', ']', ',', 'é', ' ', '']
      const text = () => Array.from({ length: Math.floor(next() * 3) }, () => pick(pieces)).join('')
      const arity = { fn: 1, member: 2, ctor: 1, anon: 0, test: 2, 'dynamic-test': 1, container: 2, 'dynamic-container': 1 }
      const segment = () => {
        const kind = pick(Object.keys(arity))
        return [kind, ...Array.from({ length: arity[kind] }, text)]
      }
      const seen = new Map()
      const failures = []
      for (let i = 0; i < 20000; i++) {
        const value = {
          path: text(),
          segments: Array.from({ length: 1 + Math.floor(next() * 3) }, segment),
          ordinal: next() < 0.3 ? 2 + Math.floor(next() * 3) : 1
        }
        const key = k.encodeKey(value.path, value.segments, value.ordinal)
        const canonical = JSON.stringify(value)
        if (JSON.stringify(k.decodeKey(key)) !== canonical) failures.push(['round trip', canonical])
        if (seen.has(key) && seen.get(key) !== canonical) failures.push(['collision', canonical])
        seen.set(key, canonical)
      }
      console.log(JSON.stringify({ failures, distinct: seen.size }))
    `) as { failures: unknown[]; distinct: number }

    expect(outcome.failures).toEqual([])
    expect(outcome.distinct).toBeGreaterThan(5000)
  })

  it.each([
    ['text that is not JSON', 'src/a.ts::big'],
    ['a JSON string', '"fn"'],
    ['a segment that is a string', '["src/a.ts","fn"]'],
    ['JSON that is not an array', '{"a":1}'],
    ['a path that is not a string', '[1,["fn","big"]]'],
    ['no segment at all', '["src/a.ts"]'],
    ['an empty segment', '["src/a.ts",[]]'],
    ['a segment of an unknown kind', '["src/a.ts",["nope","big"]]'],
    ['a segment with the wrong number of strings', '["src/a.ts",["fn"]]'],
    ['a segment holding a number', '["src/a.ts",["fn",1]]'],
    ['an explicit ordinal of 1', '["src/a.ts",["fn","big"],1]'],
    ['a fractional ordinal', '["src/a.ts",["fn","big"],2.5]'],
    ['spacing the serialization would not write', '["src/a.ts", ["fn","big"]]']
  ])('refuses %s', (_name, key) => {
    const message = runKeyModule(
      `try { k.decodeKey(${JSON.stringify(key)}); console.log('null') } catch (e) { console.log(JSON.stringify(e.message)) }`
    )

    expect(message).toBe(`${key} is not a function key`)
  })

  it('shows a key as file::outer > inner #2', () => {
    const shown = runKeyModule(`
      console.log(JSON.stringify([
        k.displayKey(k.encodeKey('src/a.ts', [['fn', 'outer'], ['member', 'Box', 'run']], 2)),
        k.displayKey(k.encodeKey('src/a.ts', [['ctor', '<class>'], ['anon']])),
        k.displayKey(k.encodeKey('t.ts', [['container', 'describe', 'S'], ['dynamic-test', 'it']]))
      ]))
    `)

    expect(shown).toEqual([
      'src/a.ts::outer > Box.run #2',
      'src/a.ts::<class>.constructor > <anonymous>',
      't.ts::describe S > it <dynamic>'
    ])
  })
})
