/**
 * @fileoverview The resolved `oauth` options, and each provider in them, hold no prototype: a key planted on
 * `Object.prototype` after the module started is not an `errorRedirectUrl` or a provider setting the host never wrote.
 *
 * @layer Test
 */

import { resolveOptions } from './resolved-options'
import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'

const GOOGLE = { clientId: 'id', clientSecret: 'secret', callbackUrl: 'https://app.example/cb' }

/** Valid options with a Google provider and no `errorRedirectUrl`. */
function withGoogle(): BymaxAuthModuleOptions {
  const given: Partial<Record<keyof BymaxAuthModuleOptions, unknown>> = {
    jwt: { secret: 'xY9!kL2@mN5#pQ8$rS1%tU4^vW7&zA0B' },
    roles: { hierarchy: { MEMBER: [] } },
    rateLimit: { clientIpSource: 'peer' },
    oauth: { google: { ...GOOGLE } }
  }
  return given as BymaxAuthModuleOptions
}

describe('the resolved oauth options', () => {
  // Scenario: the options resolved with a Google provider, then a key planted on Object.prototype under the name of an option
  // the host did not write. Expected: neither the `oauth` group nor the provider answers it. Why: `errorRedirectUrl` is where a
  // failed callback sends the browser, so a planted one would redirect to an address the host never chose.
  it.each(['errorRedirectUrl', 'successRedirectUrl', 'mfaRedirectUrl', 'scope'] as const)(
    'does not answer a planted %s',
    (name) => {
      const resolved = resolveOptions(withGoogle())
      Object.defineProperty(Object.prototype, name, {
        value: 'https://attacker.example/',
        configurable: true,
        enumerable: true,
        writable: true
      })
      try {
        expect(Reflect.get(resolved.oauth as object, name)).toBeUndefined()
        expect(Reflect.get(resolved.oauth?.google as object, name)).toBeUndefined()
      } finally {
        Reflect.deleteProperty(Object.prototype, name)
      }
    }
  )

  // Scenario: the resolved group and its provider. Expected: each has no prototype, and the secret of the provider stays out
  // of a serialization. Why: the copy that withholds the secret is the object the services read.
  it('holds no prototype and still withholds the secret of the provider', () => {
    const resolved = resolveOptions(withGoogle())

    expect(Object.getPrototypeOf(resolved.oauth)).toBeNull()
    expect(Object.getPrototypeOf(resolved.oauth?.google)).toBeNull()
    expect(JSON.stringify(resolved.oauth)).not.toContain('secret')
    expect(resolved.oauth?.google?.clientSecret).toBe('secret')
  })
})
