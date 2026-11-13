/**
 * Tests for the claims `verifyJwtToken` holds a token to beyond its signature: the issuer, the
 * audience and the retired secrets the backend still verifies with, and their route through the
 * proxy's token state.
 *
 * The backend requires a configured issuer or audience on every token and keeps verifying with the
 * secrets in `jwt.previousSecrets` while a rotation drains. A proxy that checked neither would
 * treat as authenticated a token the backend refuses, or refuse one it still accepts.
 */

import { verifyJwtToken } from '..'
import { resolveConfig } from '../internal/configValidation'
import { readTokenState } from '../internal/tokenState'
import { DEFAULT_PROXY_CONFIG, makeMockRequest, signHs256Token } from './_testHelpers'

const SECRET = 'current-secret-material-at-least-32-bytes'
const RETIRED = 'retired-secret-material-at-least-32-bytes'
const OTHER = 'another-secret-material-at-least-32-bytes'
const FUTURE = Math.floor(Date.now() / 1000) + 3600

/** A dashboard access-token payload with the claims a test overrides. */
function claims(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { sub: 'u1', tenantId: 't1', role: 'member', type: 'dashboard', exp: FUTURE, ...extra }
}

/** A value an untyped caller could hand over as the retired list, which the type would refuse. */
function untypedList(value: unknown): readonly string[] {
  return value as readonly string[]
}

describe('verifyJwtToken — retired secrets', () => {
  // Scenario: a token signed with a secret that is being rotated out, while the backend still lists
  // it. Expected: verified, as the backend verifies it.
  it('verifies a token signed with a retired secret', async () => {
    const token = await signHs256Token(claims(), RETIRED)

    const decoded = await verifyJwtToken(token, SECRET, { previousSecrets: [OTHER, RETIRED] })

    expect(decoded.isValid).toBe(true)
    expect(decoded.signatureVerified).toBe(true)
  })

  // Scenario: the current secret still verifies when retired ones are configured.
  it('still verifies a token signed with the current secret', async () => {
    const token = await signHs256Token(claims(), SECRET)

    const decoded = await verifyJwtToken(token, SECRET, { previousSecrets: [RETIRED] })

    expect(decoded.signatureVerified).toBe(true)
  })

  // Scenario: a secret that is in neither list. Expected: refused, so the list does not widen what
  // verifies beyond the configured secrets.
  it('refuses a token signed with a secret in neither list', async () => {
    const token = await signHs256Token(claims(), OTHER)

    const decoded = await verifyJwtToken(token, SECRET, { previousSecrets: [RETIRED] })

    expect(decoded.isValid).toBe(false)
    expect(decoded.signatureVerified).toBe(false)
  })

  // Scenario: a retired secret supplied with no current one. Expected: refused. A missing current
  // secret authenticates nobody, and a retired list must not turn that into somebody.
  it.each([[undefined], [null], ['']])(
    'refuses everything when the current secret is %p, whatever is retired',
    async (secret) => {
      const token = await signHs256Token(claims(), RETIRED)

      const decoded = await verifyJwtToken(token, secret, { previousSecrets: [RETIRED] })

      expect(decoded.signatureVerified).toBe(false)
    }
  )

  // Scenario: an empty entry ahead of a real one, as an unset environment variable arrives.
  // Expected: the empty one verifies nothing and the real one is still tried.
  it('skips past an empty retired entry to the next one', async () => {
    const token = await signHs256Token(claims(), RETIRED)

    const decoded = await verifyJwtToken(token, SECRET, { previousSecrets: ['', RETIRED] })

    expect(decoded.signatureVerified).toBe(true)
  })

  // Scenario: only an empty entry listed, and a token under an unrelated secret. Expected: refused.
  it('never lets an empty retired entry verify a token', async () => {
    const token = await signHs256Token(claims(), OTHER)

    const decoded = await verifyJwtToken(token, SECRET, { previousSecrets: [''] })

    expect(decoded.signatureVerified).toBe(false)
  })
})

describe('verifyJwtToken — issuer and audience', () => {
  // Scenario: a configured issuer. Expected: the token must carry exactly that issuer, and one with
  // none, another, or a non-string value is refused: omitting the claim must not opt out.
  it.each([
    ['the issuer', { iss: 'issuer-a' }, true],
    ['another issuer', { iss: 'issuer-b' }, false],
    ['no issuer', {}, false],
    ['a numeric issuer', { iss: 1 }, false],
    ['an array issuer', { iss: ['issuer-a'] }, false]
  ])('with an issuer configured, a token carrying %s is judged %p', async (_why, extra, ok) => {
    const token = await signHs256Token(claims(extra), SECRET)

    const decoded = await verifyJwtToken(token, SECRET, { issuer: 'issuer-a' })

    expect(decoded.isValid).toBe(ok)
    expect(decoded.signatureVerified).toBe(ok)
  })

  // Scenario: a configured audience. Expected: a string audience must equal it and an array must
  // contain it; none, another, an array without it, or a non-string is refused.
  it.each([
    ['the audience as a string', { aud: 'aud-a' }, true],
    ['an array containing it', { aud: ['other', 'aud-a'] }, true],
    ['another audience', { aud: 'aud-b' }, false],
    ['an array without it', { aud: ['aud-b', 'aud-c'] }, false],
    ['no audience', {}, false],
    ['a numeric audience', { aud: 1 }, false],
    ['an empty array', { aud: [] }, false]
  ])('with an audience configured, a token carrying %s is judged %p', async (_why, extra, ok) => {
    const token = await signHs256Token(claims(extra), SECRET)

    const decoded = await verifyJwtToken(token, SECRET, { audience: 'aud-a' })

    expect(decoded.isValid).toBe(ok)
  })

  // Scenario: an empty configured value, as an unset environment variable arrives. Expected: treated
  // as unconfigured, the reading the backend gives it, so a token with no claim is accepted.
  it.each([[{ issuer: '' }], [{ audience: '' }], [{}], [undefined]])(
    'does not require a claim for the unconfigured options %j',
    async (options) => {
      const token = await signHs256Token(claims(), SECRET)

      const decoded = await verifyJwtToken(token, SECRET, options)

      expect(decoded.isValid).toBe(true)
    }
  )

  // Scenario: both configured. Expected: both must hold.
  it('requires both when both are configured', async () => {
    const both = await signHs256Token(claims({ iss: 'issuer-a', aud: 'aud-a' }), SECRET)
    const onlyIssuer = await signHs256Token(claims({ iss: 'issuer-a' }), SECRET)
    const options = { issuer: 'issuer-a', audience: 'aud-a' }

    expect((await verifyJwtToken(both, SECRET, options)).isValid).toBe(true)
    expect((await verifyJwtToken(onlyIssuer, SECRET, options)).isValid).toBe(false)
  })

  // Scenario: a retired secret and an issuer together. Expected: a token under the retired secret
  // with the wrong issuer is still refused, so the rotation list cannot bypass the claim.
  it('applies the issuer to a token signed with a retired secret', async () => {
    const wrong = await signHs256Token(claims({ iss: 'issuer-b' }), RETIRED)
    const right = await signHs256Token(claims({ iss: 'issuer-a' }), RETIRED)
    const options = { issuer: 'issuer-a', previousSecrets: [RETIRED] }

    expect((await verifyJwtToken(wrong, SECRET, options)).isValid).toBe(false)
    expect((await verifyJwtToken(right, SECRET, options)).isValid).toBe(true)
  })
})

describe('the proxy token state with the backend’s claims configured', () => {
  /** The state of a request carrying `token` in the access cookie, under the config. */
  async function stateOf(token: string, config: Record<string, unknown>) {
    const resolved = resolveConfig({ ...DEFAULT_PROXY_CONFIG, jwtSecret: SECRET, ...config })
    const request = makeMockRequest({
      cookies: { [resolved.cookieNames?.access ?? 'access_token']: token }
    })
    return readTokenState(request as never, resolved)
  }

  // Scenario: the proxy configured with the backend's issuer, audience and retired secrets.
  // Expected: authenticated for a token the backend accepts, not for one it refuses.
  it('authenticates what the backend accepts and refuses what it refuses', async () => {
    const config = { jwtIssuer: 'issuer-a', jwtAudience: 'aud-a', jwtPreviousSecrets: [RETIRED] }
    const accepted = await signHs256Token(claims({ iss: 'issuer-a', aud: 'aud-a' }), RETIRED)
    const wrongAudience = await signHs256Token(claims({ iss: 'issuer-a', aud: 'aud-b' }), SECRET)
    const noClaims = await signHs256Token(claims(), SECRET)

    expect((await stateOf(accepted, config)).authenticated).toBe(true)
    expect((await stateOf(wrongAudience, config)).authenticated).toBe(false)
    expect((await stateOf(noClaims, config)).authenticated).toBe(false)
  })

  // Scenario: nothing configured. Expected: unchanged behaviour, a token with no claims passes.
  it('keeps the unconfigured behaviour', async () => {
    const token = await signHs256Token(claims(), SECRET)

    expect((await stateOf(token, {})).authenticated).toBe(true)
  })
})

describe('verifyJwtToken — a misconfigured retired-secret list', () => {
  // Scenario: a host passes the list as a string, as an environment variable arrives from untyped
  // code. Expected: read as no retired secrets, never spread into one-character keys, so a token
  // signed with a single letter that appears in the string does not verify.
  it.each([['abc'], [RETIRED], [42], [null], [{ 0: RETIRED, length: 1 }]])(
    'reads a non-array list %p as none',
    async (previousSecrets) => {
      const token = await signHs256Token(claims(), 'a')

      const decoded = await verifyJwtToken(token, SECRET, {
        previousSecrets: untypedList(previousSecrets)
      })

      expect(decoded.signatureVerified).toBe(false)
    }
  )

  // Scenario: an array with entries that are not strings. Expected: they are dropped and the string
  // entries are still tried, so one bad entry does not disable the rotation window.
  it('drops a non-string entry and still tries the strings', async () => {
    const token = await signHs256Token(claims(), RETIRED)

    const decoded = await verifyJwtToken(token, SECRET, {
      previousSecrets: untypedList([null, 7, RETIRED])
    })

    expect(decoded.signatureVerified).toBe(true)
  })
})
