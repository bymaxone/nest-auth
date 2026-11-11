/**
 * A scan of the browser-facing sources for a caller-supplied value put into a route by hand.
 *
 * The routes carry `:placeholders`, and a value interpolated into a path outside `fillRoute` can
 * leave its segment: a `..` is collapsed by a URL parser even when percent-encoded. This scan fails
 * when `client`, `react`, `nextjs` or `shared` sources fill a placeholder with `replace`, or append a
 * value to a route constant by concatenation or interpolation, anywhere but the helper itself. It is a
 * text scan, so it catches those spellings and not every possible one; the helper's own spec holds the
 * behaviour, and this holds that nothing goes around it.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

const SRC = join(__dirname, '../..')
const SCANNED = ['client', 'react', 'nextjs', 'shared']
const HELPER = 'shared/utils/fill-route.ts'

/** The spellings that put a value into a route outside the helper. */
const PATTERNS: ReadonlyArray<{ readonly name: string; readonly pattern: RegExp }> = [
  { name: 'fills a placeholder with replace', pattern: /\.replace\(\s*(?:'|"|`|\/)\\?:/ },
  { name: 'concatenates onto a route constant', pattern: /ROUTES(?:\.\w+)+\s*\+/ },
  {
    name: 'appends an interpolation to a route constant',
    pattern: /\$\{[^}]*ROUTES[^}]*\}\/[^`]*\$\{/
  },
  {
    name: 'prepends an interpolation to a route constant',
    pattern: /\$\{[^}]+\}\/\$\{(?![^}]*fillRoute)[^}]*ROUTES/
  }
]

/** The non-test source files under the scanned directories. */
function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((entry) => {
    const path = join(dir, entry)
    if (statSync(path).isDirectory()) return entry === '__tests__' ? [] : sources(path)
    return /\.(?:ts|tsx)$/.test(entry) && !/\.(?:spec|test|d)\.tsx?$/.test(entry) ? [path] : []
  })
}

/** The code of a source, with its comments removed: an example in a comment builds no route. */
function withoutComments(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|\s)\/\/.*$/gm, '$1')
}

/** What `text` does that the patterns name. */
function offences(text: string): string[] {
  const code = withoutComments(text)
  return PATTERNS.filter(({ pattern }) => pattern.test(code)).map(({ name }) => name)
}

describe('route interpolation', () => {
  it('finds no source that fills a route by hand', () => {
    const found = SCANNED.flatMap((dir) => sources(join(SRC, dir)))
      .map((file) => ({ file: relative(SRC, file), text: readFileSync(file, 'utf8') }))
      .filter(({ file }) => file !== HELPER)
      .flatMap(({ file, text }) => offences(text).map((name) => `${file}: ${name}`))

    expect(found).toEqual([])
  })

  it('scans the directories the browser entries are built from', () => {
    const files = SCANNED.flatMap((dir) => sources(join(SRC, dir))).map((f) => relative(SRC, f))

    expect(files).toEqual(
      expect.arrayContaining([
        'client/createWorkspaceClient.ts',
        'nextjs/helpers/workspaceAccess.ts',
        'react/WorkspaceProvider.tsx',
        'shared/utils/fill-route.ts'
      ])
    )
  })

  // The scan must be able to fail: each spelling it names is found in a sample that does it.
  it.each([
    ['fills a placeholder with replace', "url.replace(':workspaceId', id)"],
    ['fills a placeholder with replace', 'route.replace(/:workspaceId/, id)'],
    ['concatenates onto a route constant', "AUTH_ROUTES.workspaces.list + '/' + id"],
    [
      'appends an interpolation to a route constant',
      '`${AUTH_ROUTES.dashboard.sessions.list}/${id}`'
    ],
    ['prepends an interpolation to a route constant', '`${base}/${AUTH_ROUTES.workspaces.list}`']
  ])('flags a source that %s', (name, text) => {
    expect(offences(text)).toContain(name)
  })

  it('does not flag the helper being called, or a route constant used whole', () => {
    expect(offences('fillRoute(AUTH_ROUTES.workspaces.access, { workspaceId })')).toEqual([])
    expect(offences('`/auth/${AUTH_DASHBOARD_ROUTES.logout}`')).toEqual([])
  })

  it('ignores an example in a comment', () => {
    expect(offences('/** `${baseUrl}/${AUTH_ROUTES.dashboard.login}` */')).toEqual([])
    expect(offences("// route.replace(':id', value)")).toEqual([])
  })
})
