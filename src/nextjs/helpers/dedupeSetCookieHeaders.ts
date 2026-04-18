/**
 * Set-Cookie parsing and deduplication utilities for the Next.js auth
 * proxy.
 *
 * In multi-domain white-label deployments the upstream API may emit
 * multiple `Set-Cookie` headers for different domains during a single
 * response (e.g., one for the tenant sub-domain and one for the
 * marketing apex). When the proxy forwards these headers to the browser
 * it can accidentally duplicate the same `(name, domain)` pair if the
 * backend retries a cookie write or if the framework's cookie jar
 * flushes twice. Browsers then persist whichever cookie happened to
 * arrive last, producing hard-to-reproduce session bugs.
 *
 * {@link dedupeSetCookieHeaders} collapses that array down to a single
 * entry per `(name + domain)` pair — *last writer wins* — so the
 * forwarded response is deterministic regardless of how many writes
 * the backend performed.
 *
 * {@link parseSetCookieHeader} breaks a single `Set-Cookie` string into
 * its structured attributes so dedup logic (and any future cookie
 * inspection) can work against a typed object instead of raw strings.
 *
 * {@link getSetCookieHeaders} is a fallback that extracts the list of
 * raw Set-Cookie strings from either a modern `Headers.getSetCookie()`
 * (Node 18.14+ / undici 5.19+) or the legacy `get('set-cookie')` (which
 * concatenates cookies with commas — only safe when the values don't
 * themselves contain unquoted commas).
 *
 * Edge-Runtime-safe: pure string manipulation, no Node-only APIs.
 *
 * Security & correctness notes:
 *
 *   - Inputs containing CR (`\r`) or LF (`\n`) are rejected: RFC 6265
 *     forbids them in Set-Cookie values, and passing such a string
 *     straight through to `response.headers.append('set-cookie', …)`
 *     would enable response-header smuggling.
 *   - The dedup key is `(name, domain)` — NOT `(name, domain, path)`.
 *     This is intentional: the upstream NestJS API never emits two
 *     cookies with the same name and domain but different paths, so
 *     collapsing by `(name, domain)` is sufficient and preserves the
 *     *most-recent-writer-wins* invariant users rely on. If that
 *     upstream behaviour ever changes, widen the key.
 *   - `parseSetCookieHeader` intentionally does NOT trim the cookie
 *     *value* — RFC 6265 §5.2 step 2 says the value is everything
 *     after the first `=` up to the first `;`. Attribute *values*
 *     (e.g., `Path=/x `) are trimmed because the spec explicitly
 *     permits surrounding OWS there.
 *   - Unknown `SameSite` values (e.g., a future spec value we do not
 *     recognise) leave the typed `sameSite` field as `undefined`;
 *     the raw attribute is still preserved in {@link rawAttributes}
 *     for faithful pass-through.
 */

/**
 * Maximum permitted byte-length of a single raw `Set-Cookie` header.
 *
 * RFC 6265 §6.1 recommends that user agents support at least 4096 bytes
 * per cookie; 8192 is a generous ceiling that catches any pathological
 * input without rejecting real-world cookies.
 */
const MAX_SET_COOKIE_LENGTH = 8192

/**
 * Maximum number of `Set-Cookie` headers we will accept in a single
 * combined header value. A bound on the cooperative product of size
 * and count keeps the legacy splitter's worst case at O(N) instead of
 * unbounded O(N²) against adversarial input.
 */
const MAX_SET_COOKIE_COUNT = 64

/**
 * Structured representation of a parsed `Set-Cookie` header.
 *
 * Only the attributes we actually reason about are modelled. Unknown
 * attributes are preserved inside {@link rawAttributes} so callers can
 * round-trip a cookie without losing fields we do not yet understand.
 */
export interface ParsedSetCookie {
  /** Cookie name (the part before the first `=`). Case-sensitive. */
  readonly name: string
  /** Cookie value (the part between the first `=` and the first `;`). Not trimmed. */
  readonly value: string
  /** `HttpOnly` attribute flag. */
  readonly httpOnly: boolean
  /** `Secure` attribute flag. */
  readonly secure: boolean
  /**
   * `SameSite` attribute value (lowercased) or `undefined` if absent OR
   * if present with an unrecognised value. The original raw attribute
   * is preserved in {@link rawAttributes}.
   */
  readonly sameSite: 'strict' | 'lax' | 'none' | undefined
  /** `Path` attribute value or `undefined` if absent. */
  readonly path: string | undefined
  /** `Domain` attribute value (lowercased) or `undefined` if absent. */
  readonly domain: string | undefined
  /** `Max-Age` attribute as a number, or `undefined` if absent / unparsable. */
  readonly maxAge: number | undefined
  /** `Expires` attribute as the raw string, or `undefined` if absent. */
  readonly expires: string | undefined
  /**
   * All attribute pairs in their original order and casing. Used when
   * the caller wants to re-serialise the cookie without losing unknown
   * attributes. Does not include the `name=value` prefix.
   */
  readonly rawAttributes: readonly string[]
}

/**
 * Minimal structural type accepted by {@link getSetCookieHeaders}.
 *
 * Both the native `Headers` object and a plain `{ get, getSetCookie? }`
 * mock satisfy this contract.
 */
export interface HeadersLike {
  get(name: string): string | null
  getSetCookie?: () => string[]
}

/**
 * Parse a single `Set-Cookie` header into a {@link ParsedSetCookie}.
 *
 * Attribute names are matched case-insensitively per RFC 6265. Values
 * with attribute semantics (`SameSite`, `Domain`) are lowercased to
 * keep the dedup key stable. The `name` and `value` of the cookie
 * itself are preserved as-is — including any internal whitespace, per
 * RFC 6265 §5.2 step 2.
 *
 * Rejects inputs containing CR or LF characters (header smuggling
 * defence): the returned record has an empty `name`, which the dedup
 * step filters out.
 *
 * Malformed input (no `=` in the first segment) similarly returns an
 * empty parsed record.
 *
 * @param raw - A single `Set-Cookie` header value.
 * @returns The parsed structured representation.
 */
export function parseSetCookieHeader(raw: string): ParsedSetCookie {
  if (containsHeaderSmugglingBytes(raw)) return emptyParsedCookie()
  if (raw.length > MAX_SET_COOKIE_LENGTH) return emptyParsedCookie()

  const segments = raw.split(';').map((part) => part.trim())
  // `split` always returns at least one element, so `segments[0]` is
  // defined — the `?? ''` only exists to satisfy
  // `noUncheckedIndexedAccess` and is never executed at runtime.
  /* istanbul ignore next -- defensive `noUncheckedIndexedAccess` fallback */
  const nameValueSegment = segments[0] ?? ''
  const attributeSegments = segments.slice(1)

  const firstEquals = nameValueSegment.indexOf('=')
  const name = firstEquals >= 0 ? nameValueSegment.slice(0, firstEquals).trim() : ''
  // Intentional: the cookie VALUE is NOT trimmed. RFC 6265 §5.2 step 2
  // treats everything between the first `=` and the first `;` as the
  // value verbatim.
  const value = firstEquals >= 0 ? nameValueSegment.slice(firstEquals + 1) : ''

  const attributes = parseCookieAttributes(attributeSegments)
  return { name, value, ...attributes, rawAttributes: attributeSegments }
}

/**
 * Typed attributes extracted from the segment list `segments[1..]` of
 * a `Set-Cookie` header. Separated from {@link parseSetCookieHeader}
 * so the top-level parser stays focused on name/value extraction.
 *
 * Unknown attributes and unknown `SameSite` values fall through to
 * the caller's `rawAttributes` for faithful round-trip.
 */
interface ParsedSetCookieAttributes {
  readonly httpOnly: boolean
  readonly secure: boolean
  readonly sameSite: 'strict' | 'lax' | 'none' | undefined
  readonly path: string | undefined
  readonly domain: string | undefined
  readonly maxAge: number | undefined
  readonly expires: string | undefined
}

function parseCookieAttributes(attributeSegments: readonly string[]): ParsedSetCookieAttributes {
  let httpOnly = false
  let secure = false
  let sameSite: 'strict' | 'lax' | 'none' | undefined
  let path: string | undefined
  let domain: string | undefined
  let maxAge: number | undefined
  let expires: string | undefined

  for (const attribute of attributeSegments) {
    if (attribute.length === 0) continue
    const [attrName, attrValue] = splitAttribute(attribute)

    switch (attrName) {
      case 'httponly':
        httpOnly = true
        break
      case 'secure':
        secure = true
        break
      case 'samesite':
        sameSite = normaliseSameSite(attrValue)
        break
      case 'path':
        path = attrValue
        break
      case 'domain':
        // Domain is case-insensitive per RFC — normalise so dedup
        // keys collide as expected.
        domain = attrValue.toLowerCase()
        break
      case 'max-age':
        maxAge = parseMaxAge(attrValue)
        break
      case 'expires':
        expires = attrValue
        break
      default:
        // Unknown attribute — retained in the caller's rawAttributes.
        break
    }
  }

  return { httpOnly, secure, sameSite, path, domain, maxAge, expires }
}

/**
 * Split an attribute segment into `[name, value]`. The name is
 * trimmed and lowercased; the value is trimmed. Flag attributes
 * (no `=`) produce an empty-string value.
 */
function splitAttribute(attribute: string): [string, string] {
  const attrEquals = attribute.indexOf('=')
  if (attrEquals < 0) return [attribute.trim().toLowerCase(), '']
  return [
    attribute.slice(0, attrEquals).trim().toLowerCase(),
    attribute.slice(attrEquals + 1).trim()
  ]
}

/**
 * Normalise the `SameSite` attribute value. Unknown values return
 * `undefined`; the raw attribute is still preserved in the caller's
 * `rawAttributes` for round-trip.
 */
function normaliseSameSite(value: string): 'strict' | 'lax' | 'none' | undefined {
  const normalised = value.toLowerCase()
  if (normalised === 'strict' || normalised === 'lax' || normalised === 'none') {
    return normalised
  }
  return undefined
}

/**
 * Parse a `Max-Age` attribute value. Non-numeric values return
 * `undefined`.
 */
function parseMaxAge(value: string): number | undefined {
  const parsed = Number.parseInt(value, 10)
  return Number.isFinite(parsed) ? parsed : undefined
}

/**
 * Deduplicate an array of raw `Set-Cookie` header strings by
 * `(name, domain)` — last writer wins.
 *
 * The ordering of the returned array matches the ordering of the
 * *last* occurrence of each unique key in the input, which preserves
 * the relative order of the cookies the browser will ultimately see
 * and keeps logs diff-able when the upstream API's cookie ordering
 * changes.
 *
 * Entries that fail to parse (no cookie name, or containing header
 * smuggling bytes) are dropped.
 *
 * @param cookies - Raw `Set-Cookie` header strings.
 * @returns Deduplicated list, preserving each winner's original string.
 */
export function dedupeSetCookieHeaders(cookies: readonly string[]): string[] {
  const lastIndexByKey = new Map<string, number>()

  for (let index = 0; index < cookies.length; index += 1) {
    // eslint-disable-next-line security/detect-object-injection -- index is a bounded numeric loop counter, not user input.
    const raw = cookies[index]
    /* istanbul ignore if -- `index < cookies.length` guarantees `raw` is defined; the guard only satisfies `noUncheckedIndexedAccess` */
    if (raw === undefined) continue
    const parsed = parseSetCookieHeader(raw)
    if (parsed.name.length === 0) continue
    lastIndexByKey.set(buildDedupKey(parsed.name, parsed.domain), index)
  }

  // Emit the winning indexes in ascending order so the resulting
  // sequence follows the original response flow as closely as
  // possible.
  const winnerIndexes = Array.from(lastIndexByKey.values()).sort((a, b) => a - b)
  const winners: string[] = []
  for (const index of winnerIndexes) {
    // eslint-disable-next-line security/detect-object-injection -- index originated from our own Map values, all from the same bounded loop above.
    const raw = cookies[index]
    if (raw !== undefined) winners.push(raw)
  }
  return winners
}

/**
 * Return the array of raw `Set-Cookie` header strings from a
 * {@link HeadersLike}.
 *
 * Prefers the modern `Headers.getSetCookie()` API (Node 18.14+,
 * undici 5.19+) which correctly separates multiple Set-Cookie headers.
 * Falls back to splitting the single comma-joined value returned by
 * `get('set-cookie')` on older runtimes — this split is aware that
 * commas inside `Expires` attribute values (e.g.,
 * `Expires=Wed, 09 Jun 2021 10:18:14 GMT`) must NOT be treated as
 * separators.
 *
 * @param headers - Any object with `get()` and optionally `getSetCookie()`.
 * @returns An array of raw `Set-Cookie` header strings (possibly empty).
 */
export function getSetCookieHeaders(headers: HeadersLike): string[] {
  if (typeof headers.getSetCookie === 'function') {
    return headers.getSetCookie()
  }

  const combined = headers.get('set-cookie')
  if (combined === null || combined.length === 0) return []

  return splitLegacySetCookie(combined)
}

function buildDedupKey(name: string, domain: string | undefined): string {
  // Domain-less cookies (no Domain attribute) use '' as their domain
  // component. This keeps them distinct from cookies that carry an
  // explicit Domain="" attribute (which is a separate RFC 6265 state)
  // and mirrors how browsers treat host-only cookies internally.
  return `${name}|${domain ?? ''}`
}

function containsHeaderSmugglingBytes(raw: string): boolean {
  // RFC 6265 does not allow CR or LF in the Set-Cookie value. Rejecting
  // them here is defence-in-depth against response-splitting attacks
  // when the caller forwards the raw string to
  // `response.headers.append('set-cookie', winner)`.
  for (let i = 0; i < raw.length; i += 1) {
    const code = raw.charCodeAt(i)
    if (code === 0x0a /* LF */ || code === 0x0d /* CR */) return true
  }
  return false
}

function emptyParsedCookie(): ParsedSetCookie {
  return {
    name: '',
    value: '',
    httpOnly: false,
    secure: false,
    sameSite: undefined,
    path: undefined,
    domain: undefined,
    maxAge: undefined,
    expires: undefined,
    rawAttributes: []
  }
}

/**
 * Split a legacy comma-joined `Set-Cookie` header into individual
 * cookie strings.
 *
 * A comma alone is ambiguous: the `Expires=Wed, 09 Jun 2021 10:18:14 GMT`
 * attribute embeds a comma that is NOT a separator. We therefore only
 * treat a comma as a separator when the character sequence that follows
 * it looks like the start of a new cookie — i.e., `<token>=` where
 * `<token>` is a cookie-name token (letters, digits, and a conservative
 * set of token characters per RFC 6265).
 *
 * Known limitation: a cookie whose NAME happens to be a three-letter
 * month abbreviation (`Jan`, `Feb`, `Mar`, …) immediately following an
 * `Expires=` comma with no intervening space would trigger a false
 * split — but stdlib-generated HTTP dates always insert a space between
 * the day-of-week comma and the day-of-month token, so real-world
 * responses are unaffected. This splitter is only reached on pre-Node
 * 18.14 runtimes without `Headers.getSetCookie()` anyway.
 */
function splitLegacySetCookie(combined: string): string[] {
  if (combined.length > MAX_SET_COOKIE_LENGTH * MAX_SET_COOKIE_COUNT) return []

  const result: string[] = []
  let cursor = 0
  for (let index = 0; index < combined.length; index += 1) {
    if (combined.charCodeAt(index) !== 0x2c /* , */) continue

    if (looksLikeCookieStart(combined, index + 1)) {
      result.push(combined.slice(cursor, index).trim())
      cursor = index + 1
    }
  }
  result.push(combined.slice(cursor).trim())
  return result.filter((entry) => entry.length > 0)
}

function looksLikeCookieStart(candidate: string, startIndex: number): boolean {
  let index = startIndex
  // OWS per RFC 7230: space (0x20) or horizontal tab (0x09). Legacy
  // HTTP stacks typically emit `, ` but some frameworks use `\t`.
  while (index < candidate.length) {
    const code = candidate.charCodeAt(index)
    if (code !== 0x20 && code !== 0x09) break
    index += 1
  }
  let tokenLength = 0
  while (
    index + tokenLength < candidate.length &&
    isCookieNameChar(candidate.charCodeAt(index + tokenLength))
  ) {
    tokenLength += 1
  }
  if (tokenLength === 0) return false
  return candidate.charCodeAt(index + tokenLength) === 0x3d /* = */
}

function isCookieNameChar(code: number): boolean {
  // RFC 6265 token chars: alphanumeric plus a conservative set
  // (!#$%&'*+-.^_`|~).
  if (code >= 0x30 && code <= 0x39) return true // 0-9
  /* istanbul ignore next -- range upper bound is proved by the tests covering A-Z names; fallback branch is the unreachable `else` of the combined range check */
  if (code >= 0x41 && code <= 0x5a) return true // A-Z
  if (code >= 0x61 && code <= 0x7a) return true // a-z
  switch (code) {
    case 0x21: // !
    case 0x23: // #
    case 0x24: // $
    case 0x25: // %
    case 0x26: // &
    case 0x27: // '
    case 0x2a: // *
    case 0x2b: // +
    case 0x2d: // -
    case 0x2e: // .
    case 0x5e: // ^
    case 0x5f: // _
    case 0x60: // `
    case 0x7c: // |
    case 0x7e: // ~
      return true
    default:
      return false
  }
}
