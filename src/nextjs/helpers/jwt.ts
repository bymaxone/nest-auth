/**
 * JWT helpers for the Next.js auth proxy (Edge Runtime).
 *
 * The proxy runs under Next.js Edge middleware, where Node's `crypto`
 * module is unavailable. These helpers therefore use the Web Crypto
 * API (`globalThis.crypto.subtle`) for signature verification and
 * never import from `node:crypto` or `@nestjs/jwt`.
 *
 * Two modes are supported:
 *
 *   - **Verify mode**: when a `JWT_SECRET` is provided we call
 *     {@link verifyJwtToken} which performs HS256 signature
 *     verification and expiry validation. This is the production path.
 *
 *   - **Decode-only mode**: when no secret is available (e.g., during
 *     local development or in a proxy that delegates signature
 *     verification to the upstream API) we fall back to
 *     {@link decodeJwtToken} which parses the payload without
 *     verifying the signature. Decode-only mode is explicit — the
 *     caller must pass `undefined`/`null` as the secret.
 *
 * SECURITY — algorithm pinning:
 *
 * {@link verifyJwtToken} hard-pins `alg: 'HS256'`. Any token whose
 * header advertises a different algorithm (including `none`, `HS384`,
 * `HS512`, `RS256`, `ES256`, etc.) is rejected without key import.
 * This defends against two classic attacks:
 *
 *   - `alg: none` — the attacker removes the signature. Without
 *     algorithm pinning a naive verifier treats the token as valid.
 *   - `RS256 → HS256 confusion` — the attacker signs an HS256 token
 *     using the server's RS256 PUBLIC key as the HMAC secret. Without
 *     algorithm pinning the verifier imports the public key bytes as
 *     an HMAC secret and accepts the forgery.
 *
 * Pinning the algorithm at verification time eliminates both vectors.
 */

/**
 * Header of a JWT as carried in the first base64url segment.
 *
 * Only the fields we branch on are typed; anything else is permitted
 * but ignored. Exported so consumers of `DecodedToken` can name the
 * type of `DecodedToken.header`.
 */
export interface JwtHeader {
  alg?: string
  typ?: string
  kid?: string
}

/**
 * Decoded representation of a JWT.
 *
 * `isValid` reflects **expiry only** — the signature is NOT checked by
 * {@link decodeJwtToken}. Use {@link verifyJwtToken} when the caller
 * needs cryptographic assurance that the token was issued by the
 * backend.
 *
 * All optional claim accessors (`sub`, `role`, `tenantId`, …) return
 * `undefined` when the claim is absent from the payload. They are
 * exposed as plain properties so helpers like {@link getUserRole} can
 * extract them without re-parsing.
 */
export interface DecodedToken {
  /**
   * `true` when the payload parses AND `exp` is in the future.
   *
   * WARNING: this flag does NOT on its own imply signature
   * verification. {@link decodeJwtToken} sets it from expiry only,
   * while {@link verifyJwtToken} sets it after BOTH signature
   * verification and expiry validation. Callers must therefore track
   * which function they called and treat `isValid` as authoritative
   * only when `verifyJwtToken` was invoked with a non-null secret.
   */
  readonly isValid: boolean
  /** Raw header object, or `undefined` if the header failed to parse. */
  readonly header: JwtHeader | undefined
  /**
   * Raw payload record. Empty object when the payload failed to parse
   * — callers should check `isValid` before reading individual claims.
   */
  readonly payload: Readonly<Record<string, unknown>>
  /** Standard `sub` claim if present and a string. */
  readonly sub: string | undefined
  /** Role claim (`role`) if present and a string. */
  readonly role: string | undefined
  /** Tenant claim (`tenantId`) if present and a string. */
  readonly tenantId: string | undefined
  /** Expiry as a Unix timestamp (seconds), or `undefined`. */
  readonly exp: number | undefined
  /** Issued-at as a Unix timestamp (seconds), or `undefined`. */
  readonly iat: number | undefined
}

/**
 * Decode a JWT without verifying the signature.
 *
 * Returns a {@link DecodedToken} with `isValid` computed from the
 * `exp` claim — `true` only when the token parses AND `exp` is in the
 * future. Malformed tokens (not three base64url segments, invalid
 * JSON, non-object payload) return `{ isValid: false }` with empty
 * fields.
 *
 * Do NOT use this function for authorisation decisions. Signature
 * verification must happen either via {@link verifyJwtToken} in the
 * proxy or by delegating to the upstream API. This function is safe
 * for inspecting non-authoritative claims like `role` for UI hints
 * that are re-checked on the server.
 *
 * @param token - JWS compact serialisation (`header.payload.signature`).
 */
export function decodeJwtToken(token: string): DecodedToken {
  const parts = token.split('.')
  if (parts.length !== 3) return emptyDecoded()

  // `parts.length === 3` guarantees indices 0-2 are defined; the
  // `?? ''` only exists to satisfy `noUncheckedIndexedAccess`.
  /* istanbul ignore next -- defensive `noUncheckedIndexedAccess` fallback, unreachable after length check */
  const headerSegment = parts[0] ?? ''
  /* istanbul ignore next -- defensive `noUncheckedIndexedAccess` fallback, unreachable after length check */
  const payloadSegment = parts[1] ?? ''
  if (headerSegment.length === 0 || payloadSegment.length === 0) return emptyDecoded()

  const header = safeJsonParse<JwtHeader>(base64UrlDecodeToString(headerSegment))
  const payload = safeJsonParse<Record<string, unknown>>(base64UrlDecodeToString(payloadSegment))
  if (payload === undefined) return emptyDecoded()

  return buildDecodedToken(header, payload)
}

/**
 * Verify a JWT using HS256 via Web Crypto API.
 *
 * Steps:
 *   1. Structural validation: three base64url segments.
 *   2. Decode + parse the header.
 *   3. **Pin `alg === 'HS256'`** — reject every other algorithm,
 *      including `none`, `HS384`, `HS512`, `RS256`, and `ES256`.
 *   4. Decode + parse the payload.
 *   5. Import the secret as an HMAC-SHA-256 key.
 *   6. Verify the signature over `<header>.<payload>` (ASCII bytes).
 *   7. Validate `exp` is in the future.
 *
 * When `secret` is `undefined` or `null` this falls back to
 * {@link decodeJwtToken} (decode-only mode) — the caller has
 * explicitly opted out of signature verification. This is useful in
 * proxy deployments that delegate verification to the upstream API;
 * it is NOT safe when the proxy is the authorisation boundary.
 *
 * When `secret` is the EMPTY STRING this function fails closed and
 * returns `emptyDecoded()`. An empty HMAC key is technically valid
 * from the Web Crypto API's perspective and would verify a token
 * signed with the same empty key — a common misconfiguration (e.g.,
 * `JWT_SECRET=""` in an environment file) that we refuse rather
 * than silently downgrade to a no-op.
 *
 * @param token  - JWS compact serialisation.
 * @param secret - HS256 shared secret, or `undefined`/`null` for
 *                 decode-only mode.
 * @returns A {@link DecodedToken} where `isValid` reflects BOTH the
 *          signature verification AND the expiry check.
 */
export async function verifyJwtToken(token: string, secret?: string | null): Promise<DecodedToken> {
  if (secret === undefined || secret === null) {
    return decodeJwtToken(token)
  }
  // Fail closed on an empty secret — see the JSDoc above for rationale.
  if (secret.length === 0) {
    return emptyDecoded()
  }

  const parts = token.split('.')
  if (parts.length !== 3) return emptyDecoded()

  // `parts.length === 3` guarantees indices 0-2 are defined; the
  // `?? ''` only exists to satisfy `noUncheckedIndexedAccess`.
  /* istanbul ignore next -- defensive `noUncheckedIndexedAccess` fallback, unreachable after length check */
  const headerSegment = parts[0] ?? ''
  /* istanbul ignore next -- defensive `noUncheckedIndexedAccess` fallback, unreachable after length check */
  const payloadSegment = parts[1] ?? ''
  /* istanbul ignore next -- defensive `noUncheckedIndexedAccess` fallback, unreachable after length check */
  const signatureSegment = parts[2] ?? ''
  if (headerSegment.length === 0 || payloadSegment.length === 0 || signatureSegment.length === 0) {
    return emptyDecoded()
  }

  const header = safeJsonParse<JwtHeader>(base64UrlDecodeToString(headerSegment))

  // Algorithm pinning — rejects `alg: none`, and `alg: RS256` that
  // would otherwise be accepted as HS256 with the public key as the
  // HMAC secret.
  if (header === undefined || header.alg !== 'HS256') return emptyDecoded()

  const payload = safeJsonParse<Record<string, unknown>>(base64UrlDecodeToString(payloadSegment))
  if (payload === undefined) return emptyDecoded()

  const signatureBytes = base64UrlDecodeToBytes(signatureSegment)
  if (signatureBytes === undefined) return emptyDecoded()

  const signatureValid = await verifyHs256Signature(
    headerSegment,
    payloadSegment,
    signatureBytes,
    secret
  )
  if (!signatureValid) return emptyDecoded()

  return buildDecodedToken(header, payload)
}

/**
 * Execute the HS256 verification step against the Web Crypto API.
 *
 * Extracted from {@link verifyJwtToken} so the top-level function
 * stays focused on structural validation and algorithm pinning.
 * Any runtime error from `subtle.importKey` / `subtle.verify`
 * collapses to `false` so the caller returns `emptyDecoded()` with
 * no secret leakage.
 */
async function verifyHs256Signature(
  headerSegment: string,
  payloadSegment: string,
  signatureBytes: Uint8Array,
  secret: string
): Promise<boolean> {
  const signingInput = asciiBytes(`${headerSegment}.${payloadSegment}`)
  const secretBytes = utf8Bytes(secret)

  try {
    const keyMaterial = await globalThis.crypto.subtle.importKey(
      'raw',
      toArrayBuffer(secretBytes),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    )
    return await globalThis.crypto.subtle.verify(
      'HMAC',
      keyMaterial,
      toArrayBuffer(signatureBytes),
      toArrayBuffer(signingInput)
    )
  } catch {
    return false
  }
}

/**
 * Returns `true` when the decoded token has no `exp` claim OR the
 * `exp` claim has already passed relative to the system clock.
 *
 * Separate from `DecodedToken.isValid` because `isValid` folds expiry
 * and signature-verification together; callers sometimes want to know
 * whether a signature-valid token has merely expired (so they can
 * trigger a silent refresh) as opposed to being forged.
 *
 * @param token - A {@link DecodedToken} produced by
 *                {@link decodeJwtToken} or {@link verifyJwtToken}.
 * @returns `true` when `exp` is absent or has already elapsed.
 */
export function isTokenExpired(token: DecodedToken): boolean {
  if (token.exp === undefined) return true
  const nowSeconds = Math.floor(Date.now() / 1000)
  return token.exp <= nowSeconds
}

/**
 * Extract the user's role from a decoded token. Returns an empty
 * string when the claim is absent — the empty string is guaranteed
 * NOT to match any configured role, so RBAC checks fail safely.
 *
 * Uses `''` rather than `undefined` on purpose: callers typically
 * feed the result into a string equality or `.includes(...)` check
 * where a sentinel is more ergonomic. Compare with
 * {@link getTenantId} which deliberately keeps `undefined` as its
 * sentinel to preserve the platform-vs-tenant distinction.
 *
 * @param token - The decoded token.
 */
export function getUserRole(token: DecodedToken): string {
  return token.role ?? ''
}

/**
 * Extract the user's subject identifier (`sub`) from a decoded token.
 * Returns an empty string when the claim is absent. See
 * {@link getUserRole} for the rationale on empty-string vs.
 * `undefined` sentinels.
 *
 * @param token - The decoded token.
 */
export function getUserId(token: DecodedToken): string {
  return token.sub ?? ''
}

/**
 * Extract the tenant identifier from a decoded token. Returns
 * `undefined` — not an empty string — so callers can distinguish
 * "platform token without tenant" (legitimate) from "tenant token
 * with an empty tenantId" (a server bug worth surfacing). This is
 * intentionally ASYMMETRIC with {@link getUserRole} and
 * {@link getUserId}, which use `''` as their sentinel.
 *
 * @param token - The decoded token.
 */
export function getTenantId(token: DecodedToken): string | undefined {
  return token.tenantId
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function buildDecodedToken(
  header: JwtHeader | undefined,
  payload: Record<string, unknown>
): DecodedToken {
  // Bracket access is safe here: the keys are compile-time constants,
  // not user-controlled, so the `security/detect-object-injection`
  // warning is a false positive — payload is an arbitrary JSON object
  // and we extract typed scalars only.
  const exp = asNumber(pickClaim(payload, 'exp'))
  const iat = asNumber(pickClaim(payload, 'iat'))
  const sub = asString(pickClaim(payload, 'sub'))
  const role = asString(pickClaim(payload, 'role'))
  const tenantId = asString(pickClaim(payload, 'tenantId'))

  const nowSeconds = Math.floor(Date.now() / 1000)
  const isValid = exp !== undefined && exp > nowSeconds

  return {
    isValid,
    header,
    payload,
    sub,
    role,
    tenantId,
    exp,
    iat
  }
}

function pickClaim(payload: Record<string, unknown>, key: string): unknown {
  // Only constant keys ('exp', 'iat', 'sub', 'role', 'tenantId') are
  // ever passed in — not user input — so indexing is safe here.
  return Object.prototype.hasOwnProperty.call(payload, key)
    ? // eslint-disable-next-line security/detect-object-injection -- key is a compile-time constant from the call sites above.
      payload[key]
    : undefined
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  // Copy into a fresh ArrayBuffer so Web Crypto (which demands a
  // non-shared ArrayBuffer-backed BufferSource) accepts the input
  // regardless of whether `TextEncoder` produces a `SharedArrayBuffer`
  // or a plain `ArrayBuffer` under the current TypeScript lib.
  const copy = new Uint8Array(bytes.byteLength)
  copy.set(bytes)
  return copy.buffer
}

function emptyDecoded(): DecodedToken {
  return {
    isValid: false,
    header: undefined,
    payload: {},
    sub: undefined,
    role: undefined,
    tenantId: undefined,
    exp: undefined,
    iat: undefined
  }
}

function safeJsonParse<T>(raw: string | undefined): T | undefined {
  if (raw === undefined) return undefined
  try {
    const parsed = JSON.parse(raw) as unknown
    // Reject null, primitives, and arrays — JWT headers and payloads
    // must be JSON objects per RFC 7519 §4. `typeof [] === 'object'`
    // so an explicit Array.isArray guard is required.
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return undefined
    }
    return parsed as T
  } catch {
    return undefined
  }
}

function asNumber(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined
}

function base64UrlDecodeToString(segment: string): string | undefined {
  const bytes = base64UrlDecodeToBytes(segment)
  if (bytes === undefined) return undefined
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    return undefined
  }
}

function base64UrlDecodeToBytes(segment: string): Uint8Array | undefined {
  // base64url → base64: `-` → `+`, `_` → `/`, then pad to a multiple
  // of 4. Reject anything outside the base64url alphabet so we do not
  // silently accept garbage. Hyphen is placed last in the character
  // class (standard convention) so a future edit cannot accidentally
  // turn it into a range operator.
  if (!/^[A-Za-z0-9_-]*$/.test(segment)) return undefined
  const padded = segment.replace(/-/g, '+').replace(/_/g, '/')
  const padding = (4 - (padded.length % 4)) % 4
  const base64 = padded + '='.repeat(padding)
  try {
    // `atob` is available in the Edge Runtime and Node 18+.
    const binary = atob(base64)
    const out = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i += 1) {
      // eslint-disable-next-line security/detect-object-injection -- i is a bounded numeric loop index over a typed array we just allocated.
      out[i] = binary.charCodeAt(i)
    }
    return out
  } catch {
    return undefined
  }
}

/**
 * Encode an ASCII-only string as raw bytes.
 *
 * Used exclusively to build the HMAC signing input
 * `<headerSegment>.<payloadSegment>`, where both segments have already
 * passed the base64url alphabet regex — so every code point is
 * guaranteed to be ≤ 0x7f. The precondition assert surfaces a mistake
 * loudly instead of silently corrupting the HMAC input via the
 * `& 0xff` mask.
 */
function asciiBytes(input: string): Uint8Array {
  const out = new Uint8Array(input.length)
  for (let i = 0; i < input.length; i += 1) {
    const code = input.charCodeAt(i)
    /* istanbul ignore if -- only called with base64url strings whose chars are all <= 0x7f; the guard is a defensive assert against future misuse */
    if (code > 0x7f) {
      throw new TypeError(`asciiBytes: non-ASCII character at index ${i}`)
    }
    // eslint-disable-next-line security/detect-object-injection -- i is a bounded numeric loop index over a typed array we just allocated.
    out[i] = code
  }
  return out
}

function utf8Bytes(input: string): Uint8Array {
  return new TextEncoder().encode(input)
}
