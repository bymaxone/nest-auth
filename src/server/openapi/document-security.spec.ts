/**
 * document-security — unit tests.
 *
 * The consumer-facing derivation: which security requirement a deployment's OWN routes should
 * carry at the document root. The library cannot set that root — a fragment carries operations
 * and components, never the document — so the consumer names a scheme, and both the name and its
 * existence are decided by this library's configuration.
 *
 * These tests pin the two axes the README states as questions (which guard, which delivery) and,
 * above all, the alternation: `'both'` is a two-entry list, which OpenAPI reads as OR. Written as
 * one entry with two schemes it would mean AND, describing a server that demands the credential
 * twice. That is the mistake this function exists to make unavailable.
 */
import { authDocumentSecurity } from './document-security'
import { AUTH_SECURITY_SCHEMES } from './auth-openapi-fragment'

describe('authDocumentSecurity', () => {
  // Verifies the dashboard family under cookie delivery names the cookie scheme and nothing else.
  // A document default naming a scheme the deployment does not declare fails the consumer's
  // document build outright, which is the failure a hand-copied literal produced in the field.
  it('names the access cookie under cookie delivery', () => {
    expect(authDocumentSecurity({ guard: 'dashboard', tokenDelivery: 'cookie' })).toEqual([
      { [AUTH_SECURITY_SCHEMES.accessCookie]: [] }
    ])
  })

  // Verifies the mirror: bearer delivery declares no cookie scheme, so a default naming one would
  // be a dangling reference. This is the exact configuration that took a consumer's backend down
  // at boot while their literal went on naming the cookie.
  it('names the access bearer under bearer delivery', () => {
    expect(authDocumentSecurity({ guard: 'dashboard', tokenDelivery: 'bearer' })).toEqual([
      { [AUTH_SECURITY_SCHEMES.accessBearer]: [] }
    ])
  })

  // Verifies `'both'` produces TWO entries rather than one entry with two schemes. The distinction
  // is invisible in prose and total in meaning: a list is OR, an entry is AND. A consumer who
  // merges the two names by hand describes a server that requires cookie AND header together,
  // and every generated client then sends both or fails.
  it('offers the two transports as alternatives under both, never as a pair', () => {
    const security = authDocumentSecurity({ guard: 'dashboard', tokenDelivery: 'both' })

    expect(security).toEqual([
      { [AUTH_SECURITY_SCHEMES.accessCookie]: [] },
      { [AUTH_SECURITY_SCHEMES.accessBearer]: [] }
    ])
    // Stated separately from the equality above, because the equality would still pass if the
    // shape were ever collapsed into a single two-key entry by a future edit that also updated
    // the expectation. The arity is the contract.
    expect(security).toHaveLength(2)
    for (const requirement of security) {
      expect(Object.keys(requirement)).toHaveLength(1)
    }
  })

  // Verifies the platform family ignores `tokenDelivery` entirely. `extractPlatformAccessToken`
  // reads the Authorization header in every mode, so a cookie-only deployment still authenticates
  // its platform admins by header — and a default derived from delivery alone would name a cookie
  // scheme that is never declared for them.
  it.each(['cookie', 'bearer', 'both'] as const)(
    'names the platform bearer in every mode — %s',
    (tokenDelivery) => {
      expect(authDocumentSecurity({ guard: 'platform', tokenDelivery })).toEqual([
        { [AUTH_SECURITY_SCHEMES.platformBearer]: [] }
      ])
    }
  )

  // Verifies every name this function can emit belongs to the library's closed vocabulary. A
  // typo here is not caught by the tests above, which compare against the same constant; this
  // compares against the map as a whole, so a name invented outside it fails.
  it.each([
    ['dashboard', 'cookie'],
    ['dashboard', 'bearer'],
    ['dashboard', 'both'],
    ['platform', 'cookie'],
    ['platform', 'bearer'],
    ['platform', 'both']
  ] as const)('emits only names from the closed vocabulary — %s/%s', (guard, tokenDelivery) => {
    const known = new Set<string>(Object.values(AUTH_SECURITY_SCHEMES))

    const emitted = authDocumentSecurity({ guard, tokenDelivery }).flatMap((requirement) =>
      Object.keys(requirement)
    )

    expect(emitted.length).toBeGreaterThan(0)
    for (const name of emitted) {
      expect(known).toContain(name)
    }
  })

  // Verifies every requirement carries an empty scope array. OAuth2 and OpenID Connect schemes
  // take scopes there; `apiKey` and `http` schemes — the only kinds this library defines — take
  // none, and a non-empty list against them is a document a generator cannot satisfy.
  it.each([
    ['dashboard', 'both'],
    ['platform', 'cookie']
  ] as const)('scopes every requirement empty — %s/%s', (guard, tokenDelivery) => {
    for (const requirement of authDocumentSecurity({ guard, tokenDelivery })) {
      for (const scopes of Object.values(requirement)) {
        expect(scopes).toEqual([])
      }
    }
  })

  // Verifies the result cannot be mutated into a different document posture by its caller. The
  // value goes straight into a consumer's options object and is read at boot; a shared mutable
  // array handed to two modules is a defect that only appears in the second one.
  it('returns a frozen structure', () => {
    const security = authDocumentSecurity({ guard: 'dashboard', tokenDelivery: 'both' })

    expect(Object.isFrozen(security)).toBe(true)
    for (const requirement of security) {
      expect(Object.isFrozen(requirement)).toBe(true)
    }
  })
})
