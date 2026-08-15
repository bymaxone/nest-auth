/**
 * The shared route constants against the routes the controllers actually declare.
 *
 * `AUTH_ROUTES` exists so a client composing a URL and a server serving it cannot drift, which
 * only holds while the constants are complete. They were not: `password/change`, `ws-ticket`,
 * `mfa/recovery-codes` and both OAuth routes were served by this library and named nowhere in
 * the map, so a consumer reaching them had to hardcode the path the constants were meant to
 * spare them — and would keep it hardcoded through a rename.
 *
 * Nothing here reads a list of expected paths: it reads `PATH_METADATA` off the controllers,
 * which is the same metadata Nest routes with. A handler that changes path, or a controller
 * that gains one, fails this test without anyone remembering to update it.
 *
 * The controllers come from `AUTH_CONTROLLERS` — the same list `BymaxAuthModule` assembles its
 * conditional `controllers` array from — rather than from a copy kept here. A copy would have
 * reintroduced exactly the failure this gate exists to remove: a new controller family absent
 * from the local list contributes no paths, so both assertions below pass while its routes are
 * named nowhere. `test/e2e/openapi-contributor.e2e-spec.ts` closes the remaining gap by
 * asserting, against a deployment with every flag on, that the classes Nest registered are
 * exactly the ones in that list.
 */
import { PATH_METADATA } from '@nestjs/common/constants'

import { AUTH_CONTROLLERS } from '../bymax-auth.module'
import { AUTH_ROUTES } from '../../shared/constants/routes'

/**
 * Every route path the controllers declare, relative to the auth prefix.
 *
 * @returns The controller-relative paths, deduplicated and sorted.
 */
function declaredPaths(): string[] {
  const paths = new Set<string>()

  for (const controller of AUTH_CONTROLLERS) {
    const prefix: unknown = Reflect.getMetadata(PATH_METADATA, controller)
    const proto = controller.prototype as Record<string, unknown>

    for (const name of Object.getOwnPropertyNames(proto)) {
      if (name === 'constructor') continue
      const handler = proto[name]
      const path: unknown = Reflect.getMetadata(PATH_METADATA, handler as object)
      if (typeof path !== 'string') continue

      const segments = [typeof prefix === 'string' ? prefix : '', path].filter(
        (segment) => segment !== '' && segment !== '/'
      )
      paths.add(segments.join('/'))
    }
  }

  return [...paths].sort()
}

/** Every path named in the shared route map, sorted. */
function constantPaths(): string[] {
  return Object.values(AUTH_ROUTES)
    .flatMap((family) => Object.values(family))
    .sort()
}

describe('AUTH_ROUTES against the declared routes', () => {
  // The direction that catches an endpoint a consumer cannot address by constant. Every one of
  // the five that were missing when this test was written is this failure: served, documented in
  // the README, and absent from the map a client composes URLs with.
  it('names every route the controllers declare', () => {
    expect(declaredPaths().filter((path) => !constantPaths().includes(path))).toEqual([])
  })

  // The other direction, which catches the rename that only got half-applied: a constant whose
  // path no controller serves sends a client to a 404 that looks like a deployment problem.
  it('names no route the controllers do not declare', () => {
    expect(constantPaths().filter((path) => !declaredPaths().includes(path))).toEqual([])
  })

  // Both lists have to be non-trivial for the two assertions above to mean anything — an empty
  // pair of sets satisfies them perfectly.
  it('compares two populated sets', () => {
    expect(declaredPaths().length).toBeGreaterThan(20)
    expect(constantPaths().length).toBe(declaredPaths().length)
  })
})
