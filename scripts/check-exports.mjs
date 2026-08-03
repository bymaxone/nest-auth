/**
 * @fileoverview Runs `attw` against the tarball this package would publish.
 * @layer tooling
 *
 * `attw --pack .` packs the tarball itself, and that is why this wrapper exists:
 * `npm publish --dry-run` exports `npm_config_dry_run`, the nested pack inherits
 * it, a dry pack writes no file, and attw fails with
 * `ENOENT: no such file or directory, open '<name>-<version>.tgz'`. attw offers
 * no way to clear the variable, so the gate could not run from inside
 * `prepublishOnly` — which is the one place it most needs to run, since that is
 * what stands between a manual `npm publish` and the registry.
 *
 * Packing here instead: the variable is dropped for the pack child, and attw is
 * handed a real tarball path. The check then holds identically from a shell, from
 * CI, from a dry run and from a real publish.
 */

import { execFileSync } from 'node:child_process'
import { mkdtempSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const rootDir = join(dirname(fileURLToPath(import.meta.url)), '..')
const packDir = mkdtempSync(join(tmpdir(), 'attw-pack-'))

try {
  const packEnv = { ...process.env }
  delete packEnv['npm_config_dry_run']

  // `--ignore-scripts`: the artifact under inspection is the one already built,
  // not one this gate rebuilds underneath itself.
  execFileSync('npm', ['pack', '--ignore-scripts', '--silent', '--pack-destination', packDir], {
    cwd: rootDir,
    env: packEnv,
    stdio: 'pipe'
  })

  // Read the directory rather than parse stdout: npm writes notices there too, and
  // the last line is not reliably the filename.
  const packed = readdirSync(packDir).filter((name) => name.endsWith('.tgz'))
  if (packed.length !== 1) {
    throw new Error(`expected one tarball in ${packDir}, found ${packed.length}`)
  }

  execFileSync('attw', ['--profile', 'strict', join(packDir, packed[0])], {
    cwd: rootDir,
    stdio: 'inherit'
  })
} finally {
  rmSync(packDir, { recursive: true, force: true })
}
