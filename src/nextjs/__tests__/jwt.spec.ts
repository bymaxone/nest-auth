/**
 * Security tests for the JWT helpers in `src/nextjs/helpers/jwt.ts`.
 *
 * The file under test is the authoritative token-verification path
 * for the Edge Runtime proxy. These tests exercise:
 *
 *   - `decodeJwtToken`: expiry-only validity, tolerance of malformed
 *     inputs, access to individual claims via the typed helpers.
 *   - `verifyJwtToken`: HS256 signature verification via Web Crypto,
 *     decode-only fallback when `secret` is missing, and — critically
 *     — rejection of the two classic algorithm-confusion attacks:
 *     `alg: none` and RS256 tokens presented to an HS256 verifier.
 *   - `isTokenExpired`, `getUserRole`, `getUserId`, `getTenantId`.
 *
 * Test data is generated on the fly so we exercise REAL base64url
 * encoding. HS256 signatures are produced via `signHs256Token` in
 * `_testHelpers.ts` — hand-crafting them would only exercise the
 * decode-only path.
 */

import {
  decodeJwtToken,
  getTenantId,
  getUserId,
  getUserRole,
  isTokenExpired,
  verifyJwtToken
} from '..'
import { base64UrlEncode, signHs256Token } from './_testHelpers'

const SECRET = 'test-secret-material-at-least-32-bytes'
const ONE_HOUR = 3600

describe('decodeJwtToken', () => {
  // Happy path: a valid future-dated HS256 token decodes to isValid
  // with all claims accessible.
  it('decodes a well-formed token and computes isValid from exp', async () => {
    const token = await signHs256Token(
      {
        sub: 'user-1',
        role: 'admin',
        tenantId: 'tenant-a',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + ONE_HOUR
      },
      SECRET
    )
    const decoded = decodeJwtToken(token)
    expect(decoded.isValid).toBe(true)
    expect(decoded.sub).toBe('user-1')
    expect(decoded.role).toBe('admin')
    expect(decoded.tenantId).toBe('tenant-a')
  })

  // Expired token: claims are still accessible but isValid flips to
  // false. The verifier uses this to distinguish "merely expired"
  // (retry via silent-refresh) from "malformed" (log the user out).
  it('returns isValid false for an expired token', async () => {
    const token = await signHs256Token(
      { sub: 'u', role: 'member', exp: Math.floor(Date.now() / 1000) - 60 },
      SECRET
    )
    const decoded = decodeJwtToken(token)
    expect(decoded.isValid).toBe(false)
    expect(decoded.sub).toBe('u')
  })

  // Structurally invalid input: < 3 parts → immediately rejected.
  it('returns isValid false for a token with fewer than 3 segments', () => {
    const decoded = decodeJwtToken('not.a-jwt')
    expect(decoded.isValid).toBe(false)
    expect(decoded.sub).toBeUndefined()
  })

  // Base64 garbage in the payload must not poison the decoder —
  // `safeJsonParse` catches the throw and the helper returns
  // `emptyDecoded()`.
  it('returns isValid false when the payload is not valid base64url', () => {
    const decoded = decodeJwtToken('ZXlK.@@@.signature')
    expect(decoded.isValid).toBe(false)
  })

  // Non-object JSON payload (e.g., an array or string) must be
  // rejected — RFC 7519 §4 requires a JSON object.
  it('rejects a token whose payload is a JSON array', () => {
    const header = base64UrlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
    const payload = base64UrlEncode(JSON.stringify(['not', 'an', 'object']))
    const token = `${header}.${payload}.fakesig`
    const decoded = decodeJwtToken(token)
    expect(decoded.isValid).toBe(false)
  })
})

describe('verifyJwtToken — happy paths and fallbacks', () => {
  // Verify with the correct secret succeeds.
  it('verifies a correctly-signed HS256 token', async () => {
    const token = await signHs256Token(
      { sub: 'u', role: 'admin', exp: Math.floor(Date.now() / 1000) + ONE_HOUR },
      SECRET
    )
    const decoded = await verifyJwtToken(token, SECRET)
    expect(decoded.isValid).toBe(true)
    expect(decoded.sub).toBe('u')
  })

  // Wrong secret rejects — signature verification fails.
  it('rejects an HS256 token signed with a different secret', async () => {
    const token = await signHs256Token(
      { sub: 'u', role: 'admin', exp: Math.floor(Date.now() / 1000) + ONE_HOUR },
      SECRET
    )
    const decoded = await verifyJwtToken(token, 'wrong-secret')
    expect(decoded.isValid).toBe(false)
  })

  // Decode-only fallback: `undefined` / `null` secret bypasses
  // signature verification — documented escape hatch for proxies
  // that delegate verification to the upstream API.
  it('falls back to decode-only when secret is undefined', async () => {
    const token = await signHs256Token(
      { sub: 'u', role: 'admin', exp: Math.floor(Date.now() / 1000) + ONE_HOUR },
      SECRET
    )
    const decoded = await verifyJwtToken(token, undefined)
    expect(decoded.isValid).toBe(true)
  })

  // Empty secret: FAIL CLOSED. Empty HMAC keys are technically valid
  // from the Web Crypto API's perspective — they'd verify a token
  // signed with the same empty key. We refuse this misconfiguration
  // rather than silently degrade.
  it('fails closed when secret is an empty string', async () => {
    const token = await signHs256Token(
      { sub: 'u', role: 'admin', exp: Math.floor(Date.now() / 1000) + ONE_HOUR },
      SECRET
    )
    const decoded = await verifyJwtToken(token, '')
    expect(decoded.isValid).toBe(false)
  })
})

describe('verifyJwtToken — algorithm confusion defences', () => {
  // `alg: none` attack: attacker removes the signature. Without
  // algorithm pinning a naive verifier accepts the token as valid.
  // Our verifier MUST reject this even before any key import.
  it('rejects a token with alg: none', async () => {
    const header = base64UrlEncode(JSON.stringify({ alg: 'none', typ: 'JWT' }))
    const payload = base64UrlEncode(
      JSON.stringify({ sub: 'admin', role: 'admin', exp: Math.floor(Date.now() / 1000) + 600 })
    )
    // `none` tokens traditionally have an empty signature segment.
    const token = `${header}.${payload}.`
    const decoded = await verifyJwtToken(token, SECRET)
    expect(decoded.isValid).toBe(false)
  })

  // `alg: None` (uppercase variant) must also be rejected. Strict
  // equality on `'HS256'` covers this.
  it('rejects a token with alg: None (case variant)', async () => {
    const header = base64UrlEncode(JSON.stringify({ alg: 'None', typ: 'JWT' }))
    const payload = base64UrlEncode(JSON.stringify({ sub: 'admin' }))
    const token = `${header}.${payload}.x`
    const decoded = await verifyJwtToken(token, SECRET)
    expect(decoded.isValid).toBe(false)
  })

  // RS256→HS256 confusion: attacker signs an HS256 token using the
  // server's RSA public key as the HMAC secret. Without algorithm
  // pinning a naive verifier would import the public key as an HMAC
  // secret and accept the forgery. Our verifier rejects any
  // `alg !== 'HS256'` before key import.
  it('rejects a token with alg: RS256 (RS256→HS256 confusion)', async () => {
    const header = base64UrlEncode(JSON.stringify({ alg: 'RS256', typ: 'JWT' }))
    const payload = base64UrlEncode(
      JSON.stringify({ sub: 'admin', role: 'admin', exp: Math.floor(Date.now() / 1000) + 600 })
    )
    // Fake signature — doesn't matter, the algorithm check fires first.
    const token = `${header}.${payload}.AAAAAA`
    const decoded = await verifyJwtToken(token, SECRET)
    expect(decoded.isValid).toBe(false)
  })

  // HS384 / HS512 must also be rejected — only HS256 is accepted.
  it('rejects a token with alg: HS384', async () => {
    const header = base64UrlEncode(JSON.stringify({ alg: 'HS384', typ: 'JWT' }))
    const payload = base64UrlEncode(JSON.stringify({ sub: 'u' }))
    const token = `${header}.${payload}.x`
    const decoded = await verifyJwtToken(token, SECRET)
    expect(decoded.isValid).toBe(false)
  })

  // Whitespace / NUL suffix must not bypass strict equality.
  it('rejects a token with alg: "HS256 " (trailing space)', async () => {
    const header = base64UrlEncode(JSON.stringify({ alg: 'HS256 ', typ: 'JWT' }))
    const payload = base64UrlEncode(JSON.stringify({ sub: 'u' }))
    const token = `${header}.${payload}.x`
    const decoded = await verifyJwtToken(token, SECRET)
    expect(decoded.isValid).toBe(false)
  })
})

describe('isTokenExpired', () => {
  // Absent exp → treated as expired. Matches the conservative
  // "fail closed on unknown state" stance documented in the helper.
  it('returns true when exp is absent', () => {
    const decoded = decodeJwtToken('a.b.c')
    expect(isTokenExpired(decoded)).toBe(true)
  })

  // Past exp → expired.
  it('returns true for a past exp', async () => {
    const token = await signHs256Token(
      { sub: 'u', exp: Math.floor(Date.now() / 1000) - 60 },
      SECRET
    )
    expect(isTokenExpired(decodeJwtToken(token))).toBe(true)
  })

  // Future exp → not expired.
  it('returns false for a future exp', async () => {
    const token = await signHs256Token(
      { sub: 'u', exp: Math.floor(Date.now() / 1000) + ONE_HOUR },
      SECRET
    )
    expect(isTokenExpired(decodeJwtToken(token))).toBe(false)
  })
})

describe('claim accessors', () => {
  // getUserRole returns '' when the claim is missing so RBAC
  // `.includes(role)` checks fail closed.
  it('returns empty string for getUserRole when role is absent', async () => {
    const token = await signHs256Token(
      { sub: 'u', exp: Math.floor(Date.now() / 1000) + 600 },
      SECRET
    )
    expect(getUserRole(decodeJwtToken(token))).toBe('')
  })

  // getUserId returns '' when sub is missing.
  it('returns empty string for getUserId when sub is absent', () => {
    expect(getUserId(decodeJwtToken('a.b.c'))).toBe('')
  })

  // getTenantId returns undefined (not '') when tenantId is absent —
  // intentional asymmetry documented in the JWT helper JSDoc so the
  // platform-vs-tenant distinction is preserved.
  it('returns undefined for getTenantId when tenantId is absent (platform token)', async () => {
    const token = await signHs256Token(
      { sub: 'u', role: 'super_admin', exp: Math.floor(Date.now() / 1000) + 600 },
      SECRET
    )
    expect(getTenantId(decodeJwtToken(token))).toBeUndefined()
  })

  // getTenantId returns the string when tenantId is present.
  it('returns the tenantId string when present', async () => {
    const token = await signHs256Token(
      {
        sub: 'u',
        role: 'member',
        tenantId: 'tenant-42',
        exp: Math.floor(Date.now() / 1000) + 600
      },
      SECRET
    )
    expect(getTenantId(decodeJwtToken(token))).toBe('tenant-42')
  })
})
