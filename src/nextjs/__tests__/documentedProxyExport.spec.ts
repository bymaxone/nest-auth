/**
 * Guards the ONE line a consumer copies to install the proxy.
 *
 * `export const { proxy } = createAuthProxy({ ... })` was the documented form in the README,
 * in this module's own JSDoc, and — because JSDoc ships in `dist/nextjs/index.d.ts` — in the
 * published package. It does not build. Next 16 statically scans `proxy.ts` for a function
 * exported under that name and does not recognise a destructuring pattern, so a consumer
 * following the instructions gets:
 *
 *     Error: The file "./proxy.ts" must export a function, either as a default export
 *     or as a named "proxy" export.
 *
 * It fails loudly rather than silently, so nothing was insecure — but it is the install
 * instruction for the library's route-protection control, and it means the `./nextjs`
 * integration had never been compiled by a real Next build. `check-consumer-runtime.mjs` and
 * `dogfood-smoke-test.mjs` assert only that the named exports exist, which this form satisfies.
 *
 * This test is a text guard, not a build. It cannot prove the snippet compiles; it can prove
 * the shape that is known not to compile has not come back, which is the regression that
 * actually happened.
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

/** Every file that carries the install snippet a consumer copies. */
const DOCUMENTED_SOURCES = [
  ['README.md', join(__dirname, '../../../README.md')],
  ['createAuthProxy.ts', join(__dirname, '../createAuthProxy.ts')]
] as const

describe('the documented proxy export form', () => {
  it.each(DOCUMENTED_SOURCES)('does not destructure `proxy` in %s', (_label, path) => {
    const source = readFileSync(path, 'utf8')

    // Anchored to the start of a line, allowing a JSDoc `*` prefix, so this matches the
    // SNIPPET and not the prose around it — both files explain the trap by naming the broken
    // form, and a guard that cannot tell an example from its warning is a guard that forces
    // the warning to be deleted.
    expect(source).not.toMatch(/^[ \t]*(?:\*[ \t]*)?export\s+const\s*\{\s*proxy\b/m)
  })

  it.each(DOCUMENTED_SOURCES)('shows the binding form instead in %s', (_label, path) => {
    const source = readFileSync(path, 'utf8')

    // A plain `export const proxy = ...`, which is what Next's scan recognises.
    expect(source).toMatch(/^[ \t]*(?:\*[ \t]*)?export\s+const\s+proxy\s*=/m)
  })
})
