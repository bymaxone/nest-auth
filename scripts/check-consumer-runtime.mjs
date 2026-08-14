#!/usr/bin/env node
/**
 * Consumer load gate (zero external dependencies).
 *
 * Every other gate reads the source or the type declarations. This one packs the
 * tarball, lays it out the way npm would, and loads every subpath from it — in
 * ESM and in CommonJS — asserting the values each one is supposed to export are
 * really there.
 *
 * `attw` proves the declarations *resolve*; it never runs the JavaScript. A
 * broken `exports` map, a bundler misconfiguration, or an entry that ships an
 * empty module all pass a type check and fail here.
 *
 * Usage: `node scripts/check-consumer-runtime.mjs` (run after `pnpm build`).
 */
import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const rootDir = join(dirname(fileURLToPath(import.meta.url)), '..')
const packageName = '@bymax-one/nest-auth'
const consumerDir = join(rootDir, '.consumer-runtime-check')

/**
 * Subpath → the values a consumer must find on it.
 *
 * `./nextjs` is deliberately absent. It exists to be imported from Next.js
 * middleware and route handlers, and it reaches `next/server`, which Next ships
 * without an `exports` map — so a bare ESM specifier cannot resolve it outside a
 * bundler. Loading it under CommonJS gets further and then trips Next's own
 * guard: "This module cannot be imported from a Client Component module." Both
 * are Next's design, not this package's, and neither says anything about whether
 * the subpath is built correctly. `attw` still checks that its declarations
 * resolve, which is the part a gate here could meaningfully assert.
 */
const SUBPATHS = {
  '.': ['AuthException', 'AuthExceptionFilter', 'WsAuthExceptionFilter', 'AUTH_ERROR_CODES'],
  './shared': ['AUTH_ERROR_CODES', 'AUTH_ACCESS_COOKIE_NAME', 'AUTH_DASHBOARD_ROUTES'],
  './client': ['createAuthClient', 'createAuthFetch', 'AuthClientError'],
  './react': ['AuthProvider', 'useAuth', 'useSession', 'useAuthStatus']
}

const probeBody = `
const failures = []
for (const [subpath, names] of Object.entries(SUBPATHS)) {
  const namespace = loaded[subpath]
  if (namespace === undefined) {
    failures.push(subpath + ' did not load')
    continue
  }
  const missing = names.filter((name) => namespace[name] === undefined)
  if (missing.length) failures.push(subpath + ' does not export: ' + missing.join(', '))
}
if (failures.length) {
  for (const failure of failures) console.error('  ✗ ' + failure)
  process.exit(1)
}
const total = Object.values(SUBPATHS).reduce((sum, names) => sum + names.length, 0)
console.log('  ✓ ' + FORMAT + ': ' + Object.keys(SUBPATHS).length + ' subpath(s), ' + total + ' export(s) present')
`

const specifier = (subpath) => (subpath === '.' ? packageName : packageName + subpath.slice(1))

const esmProbe = `${Object.keys(SUBPATHS)
  .map((s, i) => `import * as m${i} from '${specifier(s)}'`)
  .join('\n')}
const SUBPATHS = ${JSON.stringify(SUBPATHS)}
const loaded = { ${Object.keys(SUBPATHS)
  .map((s, i) => `'${s}': m${i}`)
  .join(', ')} }
const FORMAT = 'ESM'
${probeBody}`

const cjsProbe = `${Object.keys(SUBPATHS)
  .map((s, i) => `const m${i} = require('${specifier(s)}')`)
  .join('\n')}
const SUBPATHS = ${JSON.stringify(SUBPATHS)}
const loaded = { ${Object.keys(SUBPATHS)
  .map((s, i) => `'${s}': m${i}`)
  .join(', ')} }
const FORMAT = 'CJS'
${probeBody}`

function run(command, args, options = {}) {
  return execFileSync(command, args, { encoding: 'utf8', stdio: 'pipe', ...options })
}

function cleanup() {
  rmSync(consumerDir, { recursive: true, force: true })
}

console.log('Consumer load gate')

if (!existsSync(join(rootDir, 'dist'))) {
  console.error('✗ dist/ is missing — run `pnpm build` first')
  process.exit(1)
}

cleanup()
const packDir = mkdtempSync(join(tmpdir(), 'pack-'))
let failed = false

try {
  // `--ignore-scripts` keeps `prepublishOnly` from rebuilding underneath the
  // artifact this gate is meant to inspect.
  //
  // `npm publish --dry-run` exports `npm_config_dry_run`, which this nested pack
  // would inherit — and a dry pack writes no file, so the gate would fail on the
  // one path it most needs to hold: the publish that runs it. The variable is
  // dropped for the child only.
  const packEnv = { ...process.env }
  delete packEnv['npm_config_dry_run']
  run('npm', ['pack', '--ignore-scripts', '--silent', '--pack-destination', packDir], {
    cwd: rootDir,
    env: packEnv
  })
  // Read the directory rather than parse stdout: npm writes notices there too, and
  // the last line is not reliably the filename.
  const packed = readdirSync(packDir).filter((name) => name.endsWith('.tgz'))
  if (packed.length !== 1) {
    throw new Error(`expected one tarball in ${packDir}, found ${packed.length}`)
  }
  const tarball = join(packDir, packed[0])

  const packageDir = join(consumerDir, 'node_modules', packageName)
  mkdirSync(packageDir, { recursive: true })
  run('tar', ['-xzf', tarball, '-C', packageDir, '--strip-components=1'])

  writeFileSync(
    join(consumerDir, 'package.json'),
    `${JSON.stringify({ name: 'consumer-runtime-check', private: true, version: '0.0.0', type: 'module' }, null, 2)}\n`
  )
  writeFileSync(join(consumerDir, 'probe.mjs'), esmProbe)
  writeFileSync(join(consumerDir, 'probe.cjs'), cjsProbe)

  for (const probe of ['probe.mjs', 'probe.cjs']) {
    try {
      process.stdout.write(run('node', [probe], { cwd: consumerDir, stdio: 'pipe' }))
    } catch (error) {
      process.stdout.write(error.stdout ?? '')
      process.stderr.write(error.stderr ?? '')
      failed = true
    }
  }
} catch (error) {
  console.error(`✗ gate setup failed: ${error.message}`)
  if (error.stderr) process.stderr.write(error.stderr)
  failed = true
} finally {
  cleanup()
  rmSync(packDir, { recursive: true, force: true })
}

if (failed) {
  console.error('\n✗ The published artifact does not load for a consumer.')
  process.exit(1)
}

console.log('✓ Every subpath loads in ESM and CommonJS.')
