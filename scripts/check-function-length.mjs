/**
 * @fileoverview Function-length gate: fails when a function or a test body in a tracked source or
 * test file spans more than 50 lines and is not on a frozen baseline that can only shrink.
 * @layer scripts
 *
 * `AGENTS.md` caps a function or a test body at 50 lines, and the pull-request review reports a
 * newly introduced one as a blocking finding. Nothing enforced it before the review did, so the
 * same rule was broken twice in one pull request. The repository already holds offenders, so this
 * gate is red for what a change introduces and not for what is inherited.
 *
 * The unit is a function-like node (a declaration, a method, a constructor, an accessor, a function
 * or an arrow expression) measured from its first line to its last, signature and braces included.
 * That is how the review reports it, so the gate and the reviewer never argue about the measure. A
 * test body is the callback of `it` or `test`, `.each` forms included. The callback of `describe`,
 * `context`, `suite` and the setup and teardown hooks is a container, not a unit: a spec file's
 * `describe` holds all its tests and would otherwise fail every spec.
 *
 * A function nested in another is measured on its own and inside the span of the one that
 * contains it. Growing it therefore moves two baseline entries, and the failure says so, so the
 * two are not read as two offenders.
 *
 * The baseline maps `file::qualified name` to a line count, and is kept honest from both sides:
 *
 * - a function over the limit that is not on the baseline fails (a new offender);
 * - a baselined function that grew fails (the baseline cannot widen);
 * - a baselined function that shrank fails until its entry is lowered, or removed once it is
 *   within the limit, so a fixed function cannot quietly regress later.
 *
 * A renamed function reads as a stale entry and a new offender; each failure names the other.
 * With `--base <ref>` the baseline is also compared with the one at that revision, because the
 * baseline in a change is the change's own file and could otherwise admit the function it adds.
 *
 * The baseline is written by `--write-baseline` and never by hand.
 *
 * Usage: node scripts/check-function-length.mjs [--root <dir>] [--baseline <file>] [--base <ref>]
 *                                               [--write-baseline]
 */

import { execFileSync } from 'node:child_process'
import { readFileSync, writeFileSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'

import ts from 'typescript'

/** The longest a function or a test body may be, in lines. */
const MAX_LINES = 50

/** Directories whose TypeScript is checked: the library and its tests. */
const SCOPE = /^(?:src|test)\//

/** Generated files are not written by hand and are not held to the rule. */
const GENERATED = /\/generated\//

/** Tracked files with these extensions are parsed. */
const SOURCE_EXTENSION = /\.(?:ts|tsx)$/

/** Callbacks that group tests or run around them: containers, never units. */
const CONTAINERS = new Set([
  'describe',
  'xdescribe',
  'fdescribe',
  'context',
  'suite',
  'beforeAll',
  'beforeEach',
  'afterAll',
  'afterEach'
])

/** Callbacks that are a test body. */
const TESTS = new Set(['it', 'xit', 'fit', 'test', 'xtest'])

/** Reads `--name value` from the arguments, or returns the fallback. */
function option(name, fallback) {
  const index = process.argv.indexOf(name)
  return index === -1 ? fallback : (process.argv[index + 1] ?? fallback)
}

/**
 * The identifier at the root of a call's callee: `it` for `it.each(table)(name, fn)`, for
 * `it.each\`table\`(name, fn)` and for `it.only(name, fn)`.
 */
function calleeRoot(call) {
  let callee = call.expression
  for (;;) {
    if (ts.isCallExpression(callee) || ts.isPropertyAccessExpression(callee)) {
      callee = callee.expression
    } else if (ts.isTaggedTemplateExpression(callee)) {
      callee = callee.tag
    } else {
      break
    }
  }
  return ts.isIdentifier(callee) ? callee.text : null
}

/** The first argument of a call as text when it is a plain string, else a placeholder. */
function titleOf(call) {
  const first = call.arguments[0]
  const plain =
    first !== undefined && (ts.isStringLiteral(first) || ts.isNoSubstitutionTemplateLiteral(first))
  return plain ? first.text : '<dynamic>'
}

/** The name a property or variable declaration gives its value. */
function nameOf(node) {
  return node.name === undefined ? '<anonymous>' : node.name.getText()
}

/** Whether a node is a function-like unit this gate looks at. */
function isFunctionLike(node) {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isMethodDeclaration(node) ||
    ts.isConstructorDeclaration(node) ||
    ts.isGetAccessor(node) ||
    ts.isSetAccessor(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node)
  )
}

/** The class a member belongs to, as a name. */
function classNameOf(member) {
  const owner = member.parent
  return owner.name === undefined ? '<class>' : owner.name.text
}

/**
 * What a function-like node is called in a key, and whether it is a measured unit.
 * A container callback is named so that tests under it get distinct keys, but is not measured.
 */
function describeNode(node) {
  const call = ts.isCallExpression(node.parent) ? node.parent : null
  const root = call === null ? null : calleeRoot(call)
  if (call !== null && root !== null && CONTAINERS.has(root)) {
    return { name: `${root} ${titleOf(call)}`, measured: false }
  }
  if (call !== null && root !== null && TESTS.has(root)) {
    return { name: `${root} ${titleOf(call)}`, measured: true }
  }
  if (ts.isFunctionDeclaration(node)) return { name: nameOf(node), measured: true }
  if (ts.isMethodDeclaration(node) || ts.isGetAccessor(node) || ts.isSetAccessor(node)) {
    return { name: `${classNameOf(node)}.${nameOf(node)}`, measured: true }
  }
  if (ts.isConstructorDeclaration(node))
    return { name: `${classNameOf(node)}.constructor`, measured: true }
  const holder = node.parent
  if (ts.isPropertyDeclaration(holder)) {
    return { name: `${classNameOf(holder)}.${nameOf(holder)}`, measured: true }
  }
  const named = ts.isVariableDeclaration(holder) || ts.isPropertyAssignment(holder)
  return { name: named ? nameOf(holder) : '<anonymous>', measured: true }
}

/**
 * Every measured function in a source text, in document order: its qualified name, its length, and
 * the position of the measured function that contains it, or -1.
 */
function collect(path, text) {
  const kind = path.endsWith('x') ? ts.ScriptKind.TSX : ts.ScriptKind.TS
  const file = ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true, kind)
  const found = []
  const visit = (node, names, container) => {
    let nextNames = names
    let nextContainer = container
    if (isFunctionLike(node)) {
      const { name, measured } = describeNode(node)
      nextNames = [...names, name]
      if (measured) {
        const start = file.getLineAndCharacterOfPosition(node.getStart()).line
        const end = file.getLineAndCharacterOfPosition(node.getEnd()).line
        found.push({ base: `${path}::${nextNames.join(' > ')}`, lines: end - start + 1, container })
        nextContainer = found.length - 1
      }
    }
    ts.forEachChild(node, (child) => visit(child, nextNames, nextContainer))
  }
  visit(file, [], -1)
  return found
}

/**
 * The offenders of a source text, keyed, and the longest span of every qualified name.
 *
 * Only offenders are numbered when they share a name, in document order, so a small function added
 * or removed beside them never renames one: a key changes only when another function over the limit
 * with the same name appears or goes before it.
 */
function measure(path, text) {
  const found = collect(path, text)
  const seen = new Map()
  const keys = found.map((entry) => {
    if (entry.lines <= MAX_LINES) return null
    const count = (seen.get(entry.base) ?? 0) + 1
    seen.set(entry.base, count)
    return count === 1 ? entry.base : `${entry.base} #${count}`
  })
  const offenders = []
  for (const [index, entry] of found.entries()) {
    if (keys[index] === null) continue
    const owners = []
    for (let up = entry.container; up !== -1; up = found[up].container) owners.push(keys[up])
    offenders.push({ key: keys[index], lines: entry.lines, owners })
  }
  return { offenders, longest: found }
}

/** Paths of the tracked files in scope, relative to the root. */
function trackedSources(root) {
  const listing = execFileSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'utf8' })
  return listing
    .split('\0')
    .filter((p) => SCOPE.test(p) && SOURCE_EXTENSION.test(p) && !GENERATED.test(p))
}

/** The qualified name of a key: the key without the number that tells same-named offenders apart. */
function baseOf(key) {
  return key.replace(/ #\d+$/, '')
}

/** Every offender in the tracked sources by key, and the longest span of each qualified name. */
function functionsIn(root) {
  const offenders = new Map()
  const longest = new Map()
  for (const path of trackedSources(root)) {
    const result = measure(path, readFileSync(join(root, path), 'utf8'))
    for (const entry of result.offenders) offenders.set(entry.key, entry)
    for (const { base, lines } of result.longest) {
      longest.set(base, Math.max(lines, longest.get(base) ?? 0))
    }
  }
  return { offenders, longest }
}

/** Reads the baseline's `functions` table from JSON text as a map, failing loudly on one that is not. */
function parseBaseline(text, path) {
  const functions = JSON.parse(text)?.functions
  if (functions === null || typeof functions !== 'object' || Array.isArray(functions)) {
    throw new Error(`${path}: expected { "functions": { "<file>::<name>": <lines> } }`)
  }
  const table = new Map(Object.entries(functions))
  for (const [key, lines] of table) {
    if (!Number.isInteger(lines) || lines <= MAX_LINES) {
      throw new Error(
        `${path}: ${key} must record an integer above ${MAX_LINES} lines, got ${String(lines)}`
      )
    }
  }
  return table
}

/** The baseline table at a git revision, or `null` when that revision has no baseline file. */
function baselineAt(root, ref, path) {
  try {
    execFileSync('git', ['rev-parse', '--verify', '--quiet', `${ref}^{commit}`], {
      cwd: root,
      stdio: 'ignore'
    })
  } catch {
    throw new Error(`${ref}: not a revision in this repository`)
  }
  const spec = `${ref}:${relative(root, path).split('\\').join('/')}`
  try {
    execFileSync('git', ['cat-file', '-e', spec], { cwd: root, stdio: 'ignore' })
  } catch {
    return null
  }
  return parseBaseline(execFileSync('git', ['show', spec], { cwd: root, encoding: 'utf8' }), spec)
}

/** Problems with how the baseline differs from the base revision's: it may only lose or lower entries. */
function widening(baseline, base) {
  const problems = []
  for (const [key, lines] of baseline) {
    const inBase = base.get(key)
    if (inBase === undefined) {
      problems.push(
        `${key} is on the baseline but the base revision does not have it. A new offender is split, not listed.`
      )
    } else if (lines > inBase) {
      problems.push(`${key} is recorded at ${lines} lines, above ${inBase} on the base revision.`)
    }
  }
  return problems
}

/** The file part of a key. */
function fileOf(key) {
  return key.slice(0, key.indexOf('::'))
}

/** A note naming the containing functions that are offenders too, whose entries move with this one. */
function containerNote(owners, offenders) {
  const containing = owners.filter((owner) => offenders.has(owner))
  if (containing.length === 0) return ''
  return ` It is also counted inside ${containing.map((owner) => `\`${owner}\``).join(' and ')}, so that entry moves with it: this is one change, not two offenders.`
}

/** Compares the functions found with the baseline and returns one message per problem. */
function problemsOf({ offenders, longest }, baseline) {
  const stale = [...baseline.keys()].filter((key) => !offenders.has(key))
  const fresh = [...offenders.keys()].filter((key) => !baseline.has(key))
  const problems = []
  for (const [key, entry] of offenders) {
    const recorded = baseline.get(key)
    const note = containerNote(entry.owners, offenders)
    if (recorded === undefined) {
      const renamed = stale.filter((old) => fileOf(old) === fileOf(key))
      const hint =
        renamed.length === 0
          ? ''
          : ` If it was renamed, its old entry ${renamed.map((old) => `\`${old}\``).join(', ')} is the stale one below.`
      problems.push(
        `${key} spans ${entry.lines} lines, over the ${MAX_LINES}-line limit. Split it.${hint}${note}`
      )
    } else if (entry.lines > recorded) {
      problems.push(
        `${key} grew from ${recorded} to ${entry.lines} lines. A baselined function may only shrink.${note}`
      )
    } else if (entry.lines < recorded) {
      problems.push(
        `${key} now spans ${entry.lines} lines. Lower its baseline entry from ${recorded} to ${entry.lines}.${note}`
      )
    }
  }
  for (const key of stale) {
    const now = longest.get(baseOf(key))
    const renamedTo = fresh.filter((name) => fileOf(name) === fileOf(key))
    const hint =
      renamedTo.length === 0
        ? ''
        : ` If it was renamed, the new offender is ${renamedTo.map((name) => `\`${name}\``).join(', ')}.`
    problems.push(
      now === undefined || now > MAX_LINES
        ? `${key} is on the baseline but no longer exists. Remove its entry.${hint}`
        : `${key} now spans ${now} lines, within the limit. Remove its entry.`
    )
  }
  return problems
}

const root = resolve(option('--root', process.cwd()))
const baselinePath = resolve(
  option('--baseline', join(root, 'scripts', 'function-length-baseline.json'))
)

if (process.argv.includes('--write-baseline')) {
  const entries = [...functionsIn(root).offenders]
    .map(([key, entry]) => [key, entry.lines])
    .sort(([a], [b]) => a.localeCompare(b))
  writeFileSync(
    baselinePath,
    `${JSON.stringify({ functions: Object.fromEntries(entries) }, null, 2)}\n`
  )
  console.log(`Wrote ${entries.length} baseline entries to ${baselinePath}.`)
  process.exit(0)
}

const baseline = parseBaseline(readFileSync(baselinePath, 'utf8'), baselinePath)
const baseRef = option('--base', undefined)
const base = baseRef === undefined ? null : baselineAt(root, baseRef, baselinePath)

const problems = [
  ...problemsOf(functionsIn(root), baseline),
  ...(base === null ? [] : widening(baseline, base))
]

if (problems.length > 0) {
  for (const problem of problems) console.error(`✖ ${problem}`)
  console.error(`\n${problems.length} function-length problem(s).`)
  process.exit(1)
}

console.log(
  `No tracked function or test body exceeds ${MAX_LINES} lines unless it is on the baseline.`
)
