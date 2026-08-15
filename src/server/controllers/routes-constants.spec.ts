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
 */
import { PATH_METADATA } from '@nestjs/common/constants'

import { AuthController } from './auth.controller'
import { EmailChangeController } from './email-change.controller'
import { InvitationController } from './invitation.controller'
import { MfaController } from './mfa.controller'
import { PasswordResetController } from './password-reset.controller'
import { PlatformAuthController } from './platform-auth.controller'
import { PlatformMfaController } from './platform-mfa.controller'
import { SessionController } from './session.controller'
import { OAuthController } from '../oauth/oauth.controller'
import { AUTH_ROUTES } from '../../shared/constants/routes'

/**
 * Every controller this library can mount.
 *
 * Typed as constructors rather than left to inference: the loop below reaches a handler by name
 * off the prototype, which needs an index, and a union of nine instance types has none. Naming
 * the array's element type as the class shape it really is keeps that a single assertion on
 * `object` instead of one laundered through `unknown`.
 */
const CONTROLLERS: readonly (new (...args: never[]) => object)[] = [
  AuthController,
  PasswordResetController,
  MfaController,
  SessionController,
  PlatformAuthController,
  PlatformMfaController,
  InvitationController,
  EmailChangeController,
  OAuthController
]

/**
 * Every route path the controllers declare, relative to the auth prefix.
 *
 * @returns The controller-relative paths, deduplicated and sorted.
 */
function declaredPaths(): string[] {
  const paths = new Set<string>()

  for (const controller of CONTROLLERS) {
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
