/**
 * The contributed operations table against the handlers the controllers actually declare.
 *
 * Every assertion around this one is driven by `OPERATIONS` itself — the count, the credential,
 * the per-mode shape — so a handler added to a controller and forgotten in the table is
 * described by nothing and noticed by no test. The fragment simply carries one entry fewer, and
 * every existing assertion still passes.
 *
 * That used to be a quiet imprecision: an operation nobody describes inherits the consumer's
 * document-level default, which is "authenticated" and therefore safe-but-vague. It stopped
 * being quiet once `@bymax-one/nest-core` began reporting operations that end up requiring
 * nothing — an undescribed route of ours now surfaces in the CONSUMER's warning, attributed to
 * them, on a path they do not own and cannot fix. The gap has to close on this side.
 *
 * Both directions are asserted. A described key naming a handler that does not exist fails the
 * consumer's document build by contract, which is a loud failure in the wrong repository; it
 * belongs here, on the change that introduces it.
 */
import { METHOD_METADATA } from '@nestjs/common/constants'

import { buildAuthOpenApiFragment } from './auth-openapi-fragment'
import type { RegisteredControllers } from './auth-openapi-fragment'
import { AUTH_CONTROLLERS } from '../bymax-auth.module'
import type { ResolvedOptions } from '../config/resolved-options'

/** Everything mounted, so the table is compared at its full extent. */
const EVERYTHING: RegisteredControllers = {
  auth: true,
  passwordReset: true,
  mfa: true,
  sessions: true,
  platform: true,
  platformMfa: true,
  invitations: true,
  emailChange: true,
  oauth: true
}

const OPTIONS = {
  tokenDelivery: 'cookie',
  cookies: { accessTokenName: 'access_token', refreshTokenName: 'refresh_token' }
} as unknown as ResolvedOptions

/**
 * Every `'Controller.method'` a mounted controller declares a route for.
 *
 * Read from `METHOD_METADATA`, the metadata Nest routes with, so a handler that gains or loses a
 * verb decorator changes this list without anyone maintaining it.
 *
 * @returns The handler keys, sorted.
 */
function declaredHandlers(): string[] {
  const keys: string[] = []

  for (const controller of AUTH_CONTROLLERS) {
    const proto = controller.prototype as Record<string, unknown>

    for (const name of Object.getOwnPropertyNames(proto)) {
      if (name === 'constructor') continue
      const method: unknown = Reflect.getMetadata(METHOD_METADATA, proto[name] as object)
      if (typeof method === 'number') keys.push(`${controller.name}.${name}`)
    }
  }

  return keys.sort()
}

/** Every handler key the contributed fragment describes, with everything mounted. */
function describedHandlers(): string[] {
  return Object.keys(buildAuthOpenApiFragment(OPTIONS, EVERYTHING).operations).sort()
}

describe('the operations table against the controllers', () => {
  // The direction that matters now that a consumer's document build reports operations requiring
  // nothing: a route of ours that no fragment describes is reported to THEM, on a path they do
  // not own. Before that report existed this only produced a vague description; it is now a
  // support question landing in the wrong repository.
  it('describes every handler a mounted controller declares', () => {
    const described = describedHandlers()

    expect(declaredHandlers().filter((key) => !described.includes(key))).toEqual([])
  })

  // The other direction fails the CONSUMER's document build by contract — nest-core refuses a
  // fragment key naming a handler the scan did not produce. A typo in the table would therefore
  // break an application that merely installed this library, which is the wrong place to find
  // out about it.
  it('describes no handler the controllers do not declare', () => {
    const declared = declaredHandlers()

    expect(describedHandlers().filter((key) => !declared.includes(key))).toEqual([])
  })

  // Both lists have to be non-trivial for the two assertions above to mean anything.
  it('compares two populated sets', () => {
    expect(declaredHandlers().length).toBeGreaterThan(30)
    expect(describedHandlers()).toHaveLength(declaredHandlers().length)
  })
})
