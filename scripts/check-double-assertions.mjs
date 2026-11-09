/**
 * @fileoverview Double-assertion gate: fails when a tracked source or test file holds an
 * `x as unknown as T` that is not on a frozen baseline that can only shrink.
 * @layer scripts
 *
 * `AGENTS.md` lists `as unknown as` laundering a real type error among the blocking findings. A
 * type assertion through `unknown` tells the compiler to stop checking, so a fixture or a cast
 * that does not match its type compiles anyway and the test exercises a value the type forbids.
 * The repository already holds such sites, so this gate is red for what a change introduces and
 * not for what is inherited. The baseline records how many each file holds, and is kept honest
 * from both sides:
 *
 * - a file with a site that is not on the baseline fails (a new offender);
 * - a baselined file that gained a site fails (the baseline cannot widen);
 * - a baselined file that lost sites fails until its entry is lowered to the new count, and an
 *   entry at zero is removed, so a fixed file cannot quietly regress later.
 *
 * With `--base <ref>` the baseline is also compared with the one at that revision, because the
 * baseline in a change is the change's own file and could otherwise admit the site it adds.
 *
 * The check reads the syntax tree, so a string or a comment that mentions the pattern is not a
 * site, and a double assertion split over lines or wrapped in parentheses is.
 *
 * Usage: node scripts/check-double-assertions.mjs [--root <dir>] [--baseline <file>] [--base <ref>]
 *                                                 [--write-baseline]
 */

import { execFileSync } from 'node:child_process'
import { readFileSync, writeFileSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'

import ts from 'typescript'

/** Directories whose TypeScript is checked: the library and its tests. */
const SCOPE = /^(?:src|test)\//

/** Tracked files with these extensions are parsed. */
const SOURCE_EXTENSION = /\.(?:ts|tsx)$/

/** Reads `--name value` from the arguments, or returns the fallback. */
function option(name, fallback) {
  const index = process.argv.indexOf(name)
  return index === -1 ? fallback : (process.argv[index + 1] ?? fallback)
}

/** The expression without the parentheses around it. */
function unwrap(node) {
  return ts.isParenthesizedExpression(node) ? unwrap(node.expression) : node
}

/** Number of `x as unknown as T` expressions in a source text. */
function siteCount(path, text) {
  const kind = path.endsWith('x') ? ts.ScriptKind.TSX : ts.ScriptKind.TS
  const file = ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true, kind)
  let count = 0
  const visit = (node) => {
    if (ts.isAsExpression(node)) {
      const inner = unwrap(node.expression)
      if (ts.isAsExpression(inner) && inner.type.kind === ts.SyntaxKind.UnknownKeyword) count += 1
    }
    ts.forEachChild(node, visit)
  }
  visit(file)
  return count
}

/** Paths of the tracked files in scope, relative to the root. */
function trackedSources(root) {
  const listing = execFileSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'utf8' })
  return listing.split('\0').filter((p) => SCOPE.test(p) && SOURCE_EXTENSION.test(p))
}

/** Sites per file, for the files that hold at least one. */
function sitesByFile(root) {
  const sites = new Map()
  for (const path of trackedSources(root)) {
    const count = siteCount(path, readFileSync(join(root, path), 'utf8'))
    if (count > 0) sites.set(path, count)
  }
  return sites
}

/** Reads the baseline's `files` table from JSON text as a map, failing loudly on a file that is not one. */
function parseBaseline(text, path) {
  const files = JSON.parse(text)?.files
  if (files === null || typeof files !== 'object' || Array.isArray(files)) {
    throw new Error(`${path}: expected { "files": { "<path>": <count> } }`)
  }
  const table = new Map(Object.entries(files))
  for (const [file, count] of table) {
    if (!Number.isInteger(count) || count < 1) {
      throw new Error(
        `${path}: ${file} must record an integer count of 1 or more, got ${String(count)}`
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
  for (const [file, count] of baseline) {
    const inBase = base.get(file)
    if (inBase === undefined) {
      problems.push(
        `${file} is on the baseline but the base revision does not have it. A new site is fixed, not listed.`
      )
    } else if (count > inBase) {
      problems.push(`${file} is recorded at ${count} sites, above ${inBase} on the base revision.`)
    }
  }
  return problems
}

/** Compares the sites found with the baseline and returns one message per problem. */
function problemsOf(found, baseline) {
  const problems = []
  for (const [file, count] of found) {
    const recorded = baseline.get(file)
    if (recorded === undefined) {
      problems.push(
        `${file} has ${count} \`as unknown as\` site(s). Type the value instead of asserting through unknown.`
      )
    } else if (count > recorded) {
      problems.push(
        `${file} grew from ${recorded} to ${count} sites. A baselined file may only shrink.`
      )
    } else if (count < recorded) {
      problems.push(
        `${file} now has ${count} site(s). Lower its baseline entry from ${recorded} to ${count}.`
      )
    }
  }
  for (const file of baseline.keys()) {
    if (!found.has(file)) {
      problems.push(
        `${file} is on the baseline but has no site left or is no longer tracked. Remove its entry.`
      )
    }
  }
  return problems
}

const root = resolve(option('--root', process.cwd()))
const baselinePath = resolve(
  option('--baseline', join(root, 'scripts', 'double-assertion-baseline.json'))
)

if (process.argv.includes('--write-baseline')) {
  const files = Object.fromEntries([...sitesByFile(root)].sort(([a], [b]) => a.localeCompare(b)))
  writeFileSync(baselinePath, `${JSON.stringify({ files }, null, 2)}\n`)
  console.log(`Wrote ${Object.keys(files).length} baseline entries to ${baselinePath}.`)
  process.exit(0)
}

const baseline = parseBaseline(readFileSync(baselinePath, 'utf8'), baselinePath)
const baseRef = option('--base', undefined)
const base = baseRef === undefined ? null : baselineAt(root, baseRef, baselinePath)

const problems = [
  ...problemsOf(sitesByFile(root), baseline),
  ...(base === null ? [] : widening(baseline, base))
]

if (problems.length > 0) {
  for (const problem of problems) console.error(`✖ ${problem}`)
  console.error(`\n${problems.length} double-assertion problem(s).`)
  process.exit(1)
}

console.log('No tracked source or test file holds an `as unknown as` that is not on the baseline.')
