#!/usr/bin/env node
/**
 * Dogfood smoke test — validates the published package shape before tagging.
 *
 * What this script validates:
 *   1. Build artifacts exist for all 5 subpaths (ESM, CJS, .d.ts, .d.cts)
 *   2. ESM imports resolve all expected named exports per subpath
 *   3. CJS require resolves all expected named exports per subpath
 *   4. Tarball contents contain only dist/ + meta files
 *   5. Minimal consumer file: link — pnpm install + import from consumer side
 *
 * Exit codes:
 *   0 — all assertions pass
 *   1 — one or more assertions failed (details printed to stderr)
 *   2 — build artifacts missing (run `pnpm build` first)
 *
 * Usage:
 *   pnpm build && node scripts/dogfood-smoke-test.mjs
 */

import { existsSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { resolve, dirname, join } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { execSync, spawnSync } from 'node:child_process'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
// Created lazily inside section 5 (not at module load) so the earlier
// build-artifact check can `process.exit(2)` without leaking a temp dir.
let consumerDir

// ── Expected dist files per subpath ─────────────────────────────────────────

const SUBPATHS = ['server', 'shared', 'client', 'react', 'nextjs']

const EXPECTED_DIST_FILES = SUBPATHS.flatMap((s) =>
  ['mjs', 'cjs', 'd.ts', 'd.cts'].map((ext) => `dist/${s}/index.${ext}`)
)

// Representative concrete (non-type) exports to verify per subpath.
// Not exhaustive — just enough to confirm each subpath loads and exports its
// most critical symbols. Types are omitted (they don't appear at runtime).
const EXPECTED_EXPORTS = {
  server: [
    'BymaxAuthModule',
    'AUTH_ERROR_CODES',
    'AUTH_ERROR_MESSAGES',
    'AuthException',
    'JwtAuthGuard',
    'RolesGuard',
    'CurrentUser',
    'Roles',
    'LoginDto',
    'RegisterDto',
    'AuthService',
    'SessionService',
    'NoOpEmailProvider',
    'NoOpAuthHooks'
  ],
  shared: ['AUTH_ERROR_CODES', 'AuthClientError'],
  client: ['createAuthClient', 'createAuthFetch', 'AuthClientError'],
  react: ['AuthProvider', 'useSession', 'useAuth', 'useAuthStatus'],
  nextjs: [
    'createAuthProxy',
    'createClientRefreshHandler',
    'createLogoutHandler',
    'isBackgroundRequest',
    'buildSilentRefreshUrl',
    'CLIENT_REFRESH_ROUTE',
    'LOGOUT_ROUTE'
  ]
}

const ALLOWED_TARBALL_PATHS = ['package.json', 'README.md', 'CHANGELOG.md', 'LICENSE', 'dist/']

let failures = 0

function fail(msg) {
  console.error(`  FAIL: ${msg}`)
  failures++
}

function pass(msg) {
  console.log(`  PASS: ${msg}`)
}

function section(title) {
  console.log(`\n── ${title}`)
}

// ── 1. Build artifact presence ───────────────────────────────────────────────

section('1. Build artifacts (5 subpaths × 4 files = 20)')
for (const f of EXPECTED_DIST_FILES) {
  const abs = resolve(ROOT, f)
  if (!existsSync(abs)) {
    console.error(`Missing build artifact: ${f} — run \`pnpm build\` first.`)
    process.exit(2)
  }
  pass(f)
}

// ── 2 & 3. ESM + CJS exports per subpath ────────────────────────────────────

const { createRequire } = await import('node:module')
const req = createRequire(import.meta.url)

// Subpaths that bundle optional peer deps (next, react) which may not be
// installed in every dev environment. We attempt the import and skip gracefully
// when the peer is absent — section 1 already proved the dist file exists.
const PEER_OPTIONAL_SUBPATHS = new Set(['react', 'nextjs'])

for (const subpath of SUBPATHS) {
  section(`2. ESM exports — ${subpath}`)
  let mod
  try {
    mod = await import(resolve(ROOT, `dist/${subpath}/index.mjs`))
  } catch (err) {
    if (PEER_OPTIONAL_SUBPATHS.has(subpath)) {
      console.log(
        `  SKIP: ${subpath} — optional peer dep not installed (${err.code ?? err.message})`
      )
      continue
    }
    fail(`ESM import failed [${subpath}]: ${String(err.message)}`)
    continue
  }
  for (const name of EXPECTED_EXPORTS[subpath]) {
    if (name in mod) {
      pass(`export ${name}`)
    } else {
      fail(`Missing ESM export [${subpath}]: ${name}`)
    }
  }

  section(`3. CJS exports — ${subpath}`)
  let cjsMod
  try {
    cjsMod = req(resolve(ROOT, `dist/${subpath}/index.cjs`))
  } catch (err) {
    if (PEER_OPTIONAL_SUBPATHS.has(subpath)) {
      console.log(
        `  SKIP: ${subpath} — optional peer dep not installed (${err.code ?? err.message})`
      )
      continue
    }
    fail(`CJS require failed [${subpath}]: ${String(err.message)}`)
    continue
  }
  for (const name of EXPECTED_EXPORTS[subpath]) {
    if (name in cjsMod) {
      pass(`cjs export ${name}`)
    } else {
      fail(`Missing CJS export [${subpath}]: ${name}`)
    }
  }
}

// ── 4. Tarball contents ──────────────────────────────────────────────────────

section('4. Tarball contents (npm pack --dry-run)')
try {
  const packOut = execSync('npm pack --dry-run 2>&1', { cwd: ROOT, encoding: 'utf8' })
  // Match B, kB, KB, MB etc. in lines that list tarball file entries
  const SIZE_RE = /\s+[\d.]+\s*(?:[Mm][Bb]|[Kk][Bb]?|[Bb])\s+\S+/
  const SIZE_STRIP_RE = /.*npm notice\s+[\d.]+\s*(?:[Mm][Bb]|[Kk][Bb]?|[Bb])\s+/
  const contentLines = packOut
    .split('\n')
    .filter((l) => l.includes('npm notice') && SIZE_RE.test(l))
    .map((l) => l.replace(SIZE_STRIP_RE, '').trim())
    .filter((l) => Boolean(l) && !l.startsWith('npm notice') && !/^sha\d+:/i.test(l))

  const unexpected = contentLines.filter(
    (f) => !ALLOWED_TARBALL_PATHS.some((prefix) => f === prefix || f.startsWith(prefix))
  )
  if (unexpected.length === 0) {
    pass(`Tarball contains only dist/ + meta files (${contentLines.length} entries)`)
  } else {
    for (const f of unexpected) {
      fail(`Unexpected file in tarball: ${f}`)
    }
  }
  // No cleanup needed: `npm pack --dry-run` never writes a .tgz to disk.
} catch (err) {
  fail(`npm pack --dry-run failed: ${String(err.message)}`)
}

// ── 5. Consumer file: link smoke ─────────────────────────────────────────────

section('5. Consumer file: link smoke (minimal resolution check)')
try {
  // Unique, unpredictable temp dir (mkdtemp appends random chars) — avoids the
  // symlink/race hazards of a fixed /tmp path. Created here, not at module
  // load, so early exits leak nothing.
  consumerDir = mkdtempSync(join(tmpdir(), 'dogfood-nest-auth-consumer-'))

  writeFileSync(
    resolve(consumerDir, 'package.json'),
    JSON.stringify(
      {
        name: 'dogfood-nest-auth-consumer',
        version: '0.0.1',
        type: 'module',
        dependencies: { '@bymax-one/nest-auth': `file:${ROOT}` }
      },
      null,
      2
    )
  )

  const installResult = spawnSync('pnpm', ['install', '--no-frozen-lockfile'], {
    cwd: consumerDir,
    encoding: 'utf8',
    timeout: 60_000
  })
  if (installResult.status !== 0) {
    fail(`pnpm install in consumer failed: ${installResult.stderr}`)
  } else {
    pass('pnpm install with file: link succeeded')

    for (const subpath of SUBPATHS) {
      const esmPath = resolve(
        consumerDir,
        `node_modules/@bymax-one/nest-auth/dist/${subpath}/index.mjs`
      )
      if (existsSync(esmPath)) {
        pass(`${subpath} subpath resolves from consumer node_modules`)
      } else {
        fail(`${subpath} subpath missing from consumer node_modules`)
      }
    }

    // Import by PACKAGE SPECIFIER from the consumer's cwd (not an absolute
    // path) so this exercises the published `exports` map exactly as a real
    // consumer's `import '@bymax-one/nest-auth/shared'` would resolve it. We use
    // the zero-dep `shared` subpath because the minimal consumer installs no
    // peer deps (@nestjs/common etc.); its successful import proves the file:
    // link, exports map, and ESM resolution all work.
    const specifierProbe = [
      "import('@bymax-one/nest-auth/shared')",
      ".then((s) => { if (!('AUTH_ERROR_CODES' in s)) process.exit(3) })",
      '.catch((e) => { console.error(e); process.exit(4) })'
    ].join('')
    const importResult = spawnSync('node', ['--input-type=module', '-e', specifierProbe], {
      cwd: consumerDir,
      encoding: 'utf8',
      timeout: 30_000
    })
    if (importResult.status === 0) {
      pass('shared specifier resolves via exports map from consumer cwd')
    } else {
      fail(
        `Consumer-side specifier import failed (code ${importResult.status}): ${importResult.stderr}`
      )
    }
  }
} catch (err) {
  fail(`Consumer scaffolding failed: ${String(err.message)}`)
} finally {
  // Cleanup (only if the temp dir was actually created)
  if (consumerDir) {
    try {
      rmSync(consumerDir, { recursive: true, force: true })
    } catch {
      // ignore
    }
  }
}

// ── Result ───────────────────────────────────────────────────────────────────

console.log('')
if (failures === 0) {
  console.log('✓ All dogfood smoke assertions passed.')
  process.exit(0)
} else {
  console.error(`✗ ${failures} assertion(s) failed.`)
  process.exit(1)
}
