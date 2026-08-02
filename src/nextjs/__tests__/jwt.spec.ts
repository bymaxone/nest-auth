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

/**
 * Sign a token whose HEADER advertises an arbitrary `alg` but whose
 * signature is a genuine HMAC-SHA-256 over `<header>.<payload>` using
 * `secret`. This produces a cryptographically-valid HS256 signature
 * carried under a non-`HS256` header — the precise shape needed to
 * prove that {@link verifyJwtToken}'s algorithm pin rejects the token
 * BEFORE (not because of) the signature check.
 */
async function signWithHeaderAlg(
  alg: string,
  payload: Readonly<Record<string, unknown>>,
  secret: string
): Promise<string> {
  const headerSegment = base64UrlEncode(JSON.stringify({ alg, typ: 'JWT' }))
  const payloadSegment = base64UrlEncode(JSON.stringify(payload))
  const signingInput = `${headerSegment}.${payloadSegment}`
  const key = await globalThis.crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )
  const signature = await globalThis.crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(signingInput)
  )
  return `${signingInput}.${base64UrlEncode(signature)}`
}

describe('decodeJwtToken', () => {
  // Happy path: a valid future-dated HS256 token decodes to isValid
  // with all claims accessible.
  it('decodes a well-formed token and computes isValid from exp', async () => {
    const token = await signHs256Token(
      {
        type: 'dashboard',
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

  // Boundary: a token whose `exp` equals the current second is NOT
  // valid. `isValid` is computed as `exp > now` (strictly future), so a
  // token expiring exactly now must be `isValid: false`. `Date.now` is
  // frozen for an exact comparison. Pins the `>` boundary; `>=` would
  // mark the just-expired token valid.
  it('computes isValid false when exp equals the current second', () => {
    const nowSeconds = 1_700_000_000
    const realNow = Date.now
    Date.now = () => nowSeconds * 1000
    try {
      const header = base64UrlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
      const payload = base64UrlEncode(
        JSON.stringify({ type: 'dashboard', sub: 'u', exp: nowSeconds })
      )
      expect(decodeJwtToken(`${header}.${payload}.sig`).isValid).toBe(false)
    } finally {
      Date.now = realNow
    }
  })

  // Expired token: claims are still accessible but isValid flips to
  // false. The verifier uses this to distinguish "merely expired"
  // (retry via silent-refresh) from "malformed" (log the user out).
  it('returns isValid false for an expired token', async () => {
    const token = await signHs256Token(
      { type: 'dashboard', sub: 'u', role: 'member', exp: Math.floor(Date.now() / 1000) - 60 },
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

  // A token with EXACTLY TWO segments must be rejected: the structural
  // check is `parts.length !== 3`. Even though both the header and the
  // payload here are well-formed and the payload has a future `exp`,
  // decoding must NOT proceed. Pins the `!== 3` segment-count guard;
  // dropping it (→ `if (false)`) would let a 2-segment token decode to
  // `isValid: true`.
  it('rejects a structurally valid 2-segment token (no signature segment)', () => {
    const header = base64UrlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
    const payload = base64UrlEncode(
      JSON.stringify({ type: 'dashboard', sub: 'u', exp: 9999999999 })
    )
    const decoded = decodeJwtToken(`${header}.${payload}`)
    expect(decoded.isValid).toBe(false)
    expect(decoded.sub).toBeUndefined()
  })

  // An EMPTY header segment with an otherwise-valid payload must be
  // rejected. The header-empty operand of
  // `headerSegment.length === 0 || payloadSegment.length === 0` is what
  // catches it — `decodeJwtToken` (unlike the verify path) has no
  // downstream `header === undefined` guard, so removing this operand
  // would let the valid payload decode to `isValid: true` with the
  // claims populated.
  it('rejects a token with an empty header segment but a valid payload', () => {
    const payload = base64UrlEncode(
      JSON.stringify({ type: 'dashboard', sub: 'u', exp: 9999999999 })
    )
    const decoded = decodeJwtToken(`.${payload}.sig`)
    expect(decoded.isValid).toBe(false)
    expect(decoded.sub).toBeUndefined()
  })

  // A JSON `null` header (valid payload) must leave `decoded.header`
  // undefined — `safeJsonParse` rejects `null` via its `parsed === null`
  // operand. A mutated guard would surface `null` as the header.
  it('leaves header undefined when the header JSON is null', () => {
    const header = base64UrlEncode(JSON.stringify(null))
    const payload = base64UrlEncode(
      JSON.stringify({ type: 'dashboard', sub: 'u', exp: 9999999999 })
    )
    expect(decodeJwtToken(`${header}.${payload}.sig`).header).toBeUndefined()
  })

  // A JSON number header (valid payload) must leave `decoded.header`
  // undefined — `safeJsonParse` rejects it via the
  // `typeof parsed !== 'object'` operand. A mutated guard would surface
  // the number as the header.
  it('leaves header undefined when the header JSON is a number', () => {
    const header = base64UrlEncode(JSON.stringify(42))
    const payload = base64UrlEncode(
      JSON.stringify({ type: 'dashboard', sub: 'u', exp: 9999999999 })
    )
    expect(decodeJwtToken(`${header}.${payload}.sig`).header).toBeUndefined()
  })

  // A JSON array header (valid payload) must leave `decoded.header`
  // undefined — `safeJsonParse` rejects it via the `Array.isArray`
  // operand (because `typeof [] === 'object'`). A mutated guard would
  // surface the array as the header. Also pins the `return undefined`
  // block inside the guard.
  it('leaves header undefined when the header JSON is an array', () => {
    const header = base64UrlEncode(JSON.stringify(['HS256']))
    const payload = base64UrlEncode(
      JSON.stringify({ type: 'dashboard', sub: 'u', exp: 9999999999 })
    )
    expect(decodeJwtToken(`${header}.${payload}.sig`).header).toBeUndefined()
  })

  // The `iat` claim is read under the exact key `'iat'`. A token
  // carrying `iat` must expose it on the decoded token. Pins the
  // `pickClaim(payload, 'iat')` claim-name literal — blanking it (→ '')
  // would always yield `iat: undefined`.
  it('exposes the iat claim from the payload', () => {
    const header = base64UrlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
    const payload = base64UrlEncode(
      JSON.stringify({ type: 'dashboard', sub: 'u', iat: 1700000000, exp: 9999999999 })
    )
    expect(decodeJwtToken(`${header}.${payload}.sig`).iat).toBe(1700000000)
  })

  // The payload is decoded with a FATAL UTF-8 decoder: bytes that are
  // invalid UTF-8 must abort the decode and produce an empty payload,
  // even when a LENIENT decoder would substitute U+FFFD and yield a
  // parseable JSON object. The fixture is `{"a":"<0x80>"}` — valid JSON
  // shape with one stray continuation byte. Pins `{ fatal: true }`
  // (both the boolean and the options-object): a lenient decode would
  // populate `payload` with `{ a: '�' }`.
  it('produces an empty payload when invalid UTF-8 would otherwise parse as JSON', () => {
    const header = base64UrlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
    // Bytes spelling `{"a":"` + 0x80 (a lone UTF-8 continuation byte) + `"}`.
    // A lenient decoder yields `{"a":"�"}` (parseable); a fatal one throws.
    const prefix = [...new TextEncoder().encode('{"a":"')]
    const suffix = [...new TextEncoder().encode('"}')]
    const bytes = Uint8Array.from([...prefix, 0x80, ...suffix])
    const payload = base64UrlEncode(bytes.buffer)
    const decoded = decodeJwtToken(`${header}.${payload}.sig`)
    expect(Object.keys(decoded.payload)).toHaveLength(0)
  })

  // A base64url segment containing a `/` (a standard-base64 character
  // OUTSIDE the base64url alphabet) must be rejected by the alphabet
  // regex before `atob`, which would otherwise decode it to a valid
  // JSON object. The fixture's payload segment decodes — only if the
  // guard is bypassed — to `{"exp":9999999999,...}` (a future, "valid"
  // token). Pins the `^[A-Za-z0-9_-]*$` guard and both anchors: any of
  // them being dropped lets the `/` through and flips `isValid` to true.
  it('rejects a payload segment containing a non-base64url "/" character', () => {
    const header = base64UrlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
    // Standard-base64 of {"exp":9999999999,"sub":"`?}Q0+"} — contains a '/'.
    const payloadWithSlash = 'eyJleHAiOjk5OTk5OTk5OTksInN1YiI6ImA/fVEwKyJ9'
    expect(payloadWithSlash).toContain('/')
    const decoded = decodeJwtToken(`${header}.${payloadWithSlash}.sig`)
    expect(decoded.isValid).toBe(false)
    expect(Object.keys(decoded.payload)).toHaveLength(0)
  })
})

describe('verifyJwtToken — happy paths and fallbacks', () => {
  // Verify with the correct secret succeeds.
  it('verifies a correctly-signed HS256 token', async () => {
    const token = await signHs256Token(
      { type: 'dashboard', sub: 'u', role: 'admin', exp: Math.floor(Date.now() / 1000) + ONE_HOUR },
      SECRET
    )
    const decoded = await verifyJwtToken(token, SECRET)
    expect(decoded.isValid).toBe(true)
    expect(decoded.sub).toBe('u')
  })

  // Wrong secret rejects — signature verification fails.
  it('rejects an HS256 token signed with a different secret', async () => {
    const token = await signHs256Token(
      { type: 'dashboard', sub: 'u', role: 'admin', exp: Math.floor(Date.now() / 1000) + ONE_HOUR },
      SECRET
    )
    const decoded = await verifyJwtToken(token, 'wrong-secret')
    expect(decoded.isValid).toBe(false)
  })

  // A missing secret FAILS CLOSED. This used to fall back to a decode-only read that
  // reported `isValid: true` for any well-formed token, forged ones included — an escape
  // hatch for proxies delegating verification upstream. The two branches were
  // indistinguishable at runtime, so a caller writing
  // `if (verifyJwtToken(t).isValid && t.role === 'ADMIN')` — the natural reading of the
  // name — admitted an attacker-minted token the moment the secret went missing, and an
  // unset environment variable was enough. `decodeJwtToken` is the explicit,
  // correctly-named entry point for that read; this one refuses.
  it.each([
    ['undefined', undefined],
    ['null', null]
  ])('fails closed when the secret is %s', async (_label, secret) => {
    const token = await signHs256Token(
      { type: 'dashboard', sub: 'u', role: 'admin', exp: Math.floor(Date.now() / 1000) + ONE_HOUR },
      SECRET
    )
    const decoded = await verifyJwtToken(token, secret)
    expect(decoded.isValid).toBe(false)
    expect(decoded.signatureVerified).toBe(false)
    // No claims escape a refused result — a caller cannot read a role off it.
    expect(decoded.role).toBeUndefined()
  })

  // Empty secret: FAIL CLOSED. Empty HMAC keys are technically valid
  // from the Web Crypto API's perspective — they'd verify a token
  // signed with the same empty key. We refuse this misconfiguration
  // rather than silently degrade.
  it('fails closed when secret is an empty string', async () => {
    const token = await signHs256Token(
      { type: 'dashboard', sub: 'u', role: 'admin', exp: Math.floor(Date.now() / 1000) + ONE_HOUR },
      SECRET
    )
    const decoded = await verifyJwtToken(token, '')
    expect(decoded.isValid).toBe(false)
  })

  // A 4-segment token must be rejected by the `parts.length !== 3`
  // structural guard in verify mode — even when its first three
  // segments form a perfectly valid, correctly-signed HS256 token with
  // a trailing `.extra`. Dropping the guard would let the verifier
  // ignore the extra segment and accept the token.
  it('rejects a correctly-signed token with a trailing 4th segment', async () => {
    const valid = await signHs256Token(
      { type: 'dashboard', sub: 'u', role: 'admin', exp: Math.floor(Date.now() / 1000) + ONE_HOUR },
      SECRET
    )
    const decoded = await verifyJwtToken(`${valid}.extra`, SECRET)
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
      JSON.stringify({
        type: 'dashboard',
        sub: 'admin',
        role: 'admin',
        exp: Math.floor(Date.now() / 1000) + 600
      })
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
    const payload = base64UrlEncode(JSON.stringify({ type: 'dashboard', sub: 'admin' }))
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
      JSON.stringify({
        type: 'dashboard',
        sub: 'admin',
        role: 'admin',
        exp: Math.floor(Date.now() / 1000) + 600
      })
    )
    // Fake signature — doesn't matter, the algorithm check fires first.
    const token = `${header}.${payload}.AAAAAA`
    const decoded = await verifyJwtToken(token, SECRET)
    expect(decoded.isValid).toBe(false)
  })

  // HS384 / HS512 must also be rejected — only HS256 is accepted.
  it('rejects a token with alg: HS384', async () => {
    const header = base64UrlEncode(JSON.stringify({ alg: 'HS384', typ: 'JWT' }))
    const payload = base64UrlEncode(JSON.stringify({ type: 'dashboard', sub: 'u' }))
    const token = `${header}.${payload}.x`
    const decoded = await verifyJwtToken(token, SECRET)
    expect(decoded.isValid).toBe(false)
  })

  // Whitespace / NUL suffix must not bypass strict equality.
  it('rejects a token with alg: "HS256 " (trailing space)', async () => {
    const header = base64UrlEncode(JSON.stringify({ alg: 'HS256 ', typ: 'JWT' }))
    const payload = base64UrlEncode(JSON.stringify({ type: 'dashboard', sub: 'u' }))
    const token = `${header}.${payload}.x`
    const decoded = await verifyJwtToken(token, SECRET)
    expect(decoded.isValid).toBe(false)
  })

  // The algorithm pin must reject a non-`HS256` header EVEN WHEN the
  // signature is a genuine, verifiable HMAC-SHA-256 over the segments.
  // Here the header says `alg: HS384` but the token is HMAC-SHA-256
  // signed with `SECRET`, so the signature itself WOULD verify. Only
  // the `header.alg !== 'HS256'` pin stops it. Sibling tests use fake
  // signatures, which the signature check would also reject — so they
  // cannot distinguish the pin from the signature step. Pins both the
  // `header === undefined ||` and the `header.alg !== 'HS256'` operands.
  it('rejects a non-HS256 alg even with a valid HMAC-SHA-256 signature', async () => {
    const token = await signWithHeaderAlg(
      'HS384',
      {
        type: 'dashboard',
        sub: 'admin',
        role: 'admin',
        exp: Math.floor(Date.now() / 1000) + ONE_HOUR
      },
      SECRET
    )
    // Sanity: the same payload/secret under an HS256 header verifies,
    // proving the signature material itself is valid.
    const honest = await signHs256Token(
      {
        type: 'dashboard',
        sub: 'admin',
        role: 'admin',
        exp: Math.floor(Date.now() / 1000) + ONE_HOUR
      },
      SECRET
    )
    expect((await verifyJwtToken(honest, SECRET)).isValid).toBe(true)
    expect((await verifyJwtToken(token, SECRET)).isValid).toBe(false)
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
      { type: 'dashboard', sub: 'u', exp: Math.floor(Date.now() / 1000) - 60 },
      SECRET
    )
    expect(isTokenExpired(decodeJwtToken(token))).toBe(true)
  })

  // Future exp → not expired.
  it('returns false for a future exp', async () => {
    const token = await signHs256Token(
      { type: 'dashboard', sub: 'u', exp: Math.floor(Date.now() / 1000) + ONE_HOUR },
      SECRET
    )
    expect(isTokenExpired(decodeJwtToken(token))).toBe(false)
  })

  // Boundary: `exp` EXACTLY equal to the current second. The contract
  // is `exp <= now` → expired (a token expiring this very second is no
  // longer usable). `Date.now` is frozen so the comparison is exact.
  // Pins the `<=` boundary; `<` would treat the just-expired token as
  // still valid.
  it('returns true when exp equals the current second (inclusive boundary)', () => {
    const nowSeconds = 1_700_000_000
    const realNow = Date.now
    Date.now = () => nowSeconds * 1000
    try {
      // Build the decoded token under the same frozen clock so its
      // fields are stable, then assert the expiry boundary.
      const header = base64UrlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
      const payload = base64UrlEncode(
        JSON.stringify({ type: 'dashboard', sub: 'u', exp: nowSeconds })
      )
      const decoded = decodeJwtToken(`${header}.${payload}.sig`)
      expect(isTokenExpired(decoded)).toBe(true)
    } finally {
      Date.now = realNow
    }
  })
})

describe('claim accessors', () => {
  // getUserRole returns '' when the claim is missing so RBAC
  // `.includes(role)` checks fail closed.
  it('returns empty string for getUserRole when role is absent', async () => {
    const token = await signHs256Token(
      { type: 'dashboard', sub: 'u', exp: Math.floor(Date.now() / 1000) + 600 },
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
      {
        type: 'dashboard',
        sub: 'u',
        role: 'super_admin',
        exp: Math.floor(Date.now() / 1000) + 600
      },
      SECRET
    )
    expect(getTenantId(decodeJwtToken(token))).toBeUndefined()
  })

  // getTenantId returns the string when tenantId is present.
  it('returns the tenantId string when present', async () => {
    const token = await signHs256Token(
      {
        type: 'dashboard',
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

describe('signatureVerified — proof that a signature was actually checked', () => {
  // The two flags are independent, and the combination that surprises is REACHABLE on the
  // ordinary path: the signature is checked before the expiry is read, so a genuinely signed
  // token that simply ran out comes back `signatureVerified: true, isValid: false`. Anyone
  // gating on `signatureVerified` alone — which the field's own JSDoc used to invite — accepts
  // expired sessions forever. Pinning it here keeps that documented behaviour honest.
  it('is true for a genuinely signed token that has expired, while isValid is false', async () => {
    const expired = await signHs256Token(
      { type: 'dashboard', sub: 'u_1', role: 'admin', exp: Math.floor(Date.now() / 1000) - 60 },
      SECRET
    )

    const decoded = await verifyJwtToken(expired, SECRET)

    expect(decoded.signatureVerified).toBe(true)
    expect(decoded.isValid).toBe(false)
    // Which is why the documented check is the conjunction, not either flag alone.
    expect(decoded.isValid && decoded.signatureVerified).toBe(false)
  })

  // A token carrying no `exp` at all lands in the same place, and is the more dangerous of the
  // two: nothing about it ever becomes false with time.
  it('is true with isValid false for a signed token carrying no exp', async () => {
    const noExpiry = await signHs256Token({ type: 'dashboard', sub: 'u_1', role: 'admin' }, SECRET)

    const decoded = await verifyJwtToken(noExpiry, SECRET)

    expect(decoded.signatureVerified).toBe(true)
    expect(decoded.isValid).toBe(false)
  })

  // `isValid` alone never proves authenticity: `decodeJwtToken` sets it from expiry only.
  // `signatureVerified` is the other half, and only a real HS256 verification against a
  // non-empty secret sets it.
  it('is true only when a signature was actually checked', async () => {
    const genuine = await signHs256Token(
      { type: 'dashboard', sub: 'u_1', role: 'admin', exp: Math.floor(Date.now() / 1000) + 600 },
      SECRET
    )

    const verified = await verifyJwtToken(genuine, SECRET)
    expect(verified.isValid).toBe(true)
    expect(verified.signatureVerified).toBe(true)

    // Without a secret the call refuses outright rather than answering a weaker question.
    for (const secret of [undefined, null, '']) {
      const refused = await verifyJwtToken(genuine, secret)
      expect(refused.isValid).toBe(false)
      expect(refused.signatureVerified).toBe(false)
    }
  })

  // A token signed with a secret the verifier does not hold still decodes and still carries
  // whatever `role` the attacker chose — which is exactly why `decodeJwtToken`'s result must
  // never claim a verified signature, and why the verifier rejects it outright.
  it('is false for a forged token on both entry points', async () => {
    const forged = await signHs256Token(
      {
        type: 'dashboard',
        sub: 'attacker',
        role: 'admin',
        exp: Math.floor(Date.now() / 1000) + 600
      },
      'a-secret-the-verifier-does-not-hold'
    )

    const rejected = await verifyJwtToken(forged, SECRET)
    expect(rejected.isValid).toBe(false)
    expect(rejected.signatureVerified).toBe(false)

    // `decodeJwtToken` happily reads it — that is its contract — but flags it as unverified.
    const decoded = decodeJwtToken(forged)
    expect(decoded.isValid).toBe(true)
    expect(decoded.role).toBe('admin')
    expect(decoded.signatureVerified).toBe(false)
  })

  // decodeJwtToken never checks a signature, so it can never claim one.
  it('is never true on a decodeJwtToken result', async () => {
    const genuine = await signHs256Token(
      { type: 'dashboard', sub: 'u_1', role: 'admin', exp: Math.floor(Date.now() / 1000) + 600 },
      SECRET
    )
    expect(decodeJwtToken(genuine).signatureVerified).toBe(false)
    expect(decodeJwtToken('not-a-token').signatureVerified).toBe(false)
  })
})
