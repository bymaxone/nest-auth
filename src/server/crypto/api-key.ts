/**
 * @fileoverview Service API key format, digest and comparison.
 *
 * A key is `{prefix}_{keyId}_{secret}`. The `keyId` is a public lookup handle, the `secret` is
 * 32 random bytes in base64url, and only the HMAC-SHA-256 of the secret under a server-held
 * pepper is ever stored. The grammar and the digest are pinned by the `apiKeys` section of
 * `conformance/wire-contract.json`, because rust-auth mints and verifies the same keys.
 *
 * @layer Crypto
 */

import { randomBytes, timingSafeEqual } from 'node:crypto'

import { hmacSha256 } from './secure-token'

/** Separator between the three parts of a key. Base64url's alphabet contains it, hence the parse rule. */
const SEPARATOR = '_'

/**
 * Canonical lowercase UUID: the only `keyId` shape a key may carry.
 *
 * The anchors are belt and braces: `parseApiKey` slices exactly 36 characters before testing, and
 * the pattern is exactly 36 characters long, so an unanchored match is the whole string.
 */
// Stryker disable next-line Regex: the input is always sliced to 36 characters, so the anchors cannot change a verdict
const KEY_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

/** 32 bytes in unpadded base64url is exactly 43 characters. */
const SECRET_PATTERN = /^[A-Za-z0-9_-]{43}$/

/** Bytes of entropy in a secret: the HMAC-SHA-256 output length, the floor RFC 2104 §3 gives a key. */
const SECRET_BYTES = 32

/** A digest is a SHA-256 output, which is 32 bytes and 64 lowercase hex characters. */
const DIGEST_HEX = /^[0-9a-f]{64}$/

/**
 * The `keyId` verification substitutes for a key that did not parse, so the store lookup runs
 * on every request. A canonical UUID no issued key carries, because issued ids are random v4.
 */
export const API_KEY_DUMMY_KEY_ID = '00000000-0000-4000-8000-000000000000'

/** The secret substituted for a key that did not parse, so the digest step runs on every request. */
export const API_KEY_DUMMY_SECRET = 'A'.repeat(43)

/**
 * The digest compared against when no row was found. All zero, so it can equal the HMAC of
 * nothing the library computes: the verdict never rests on this comparison alone.
 */
export const API_KEY_DUMMY_DIGEST = '0'.repeat(64)

/** A key split into the two parts verification needs. */
export interface ParsedApiKey {
  /** Public lookup handle: the id of the stored row. */
  keyId: string
  /** The secret half, never stored and never logged. */
  secret: string
}

/**
 * Draws a fresh secret from the CSPRNG.
 *
 * @returns 43 base64url characters carrying 256 bits.
 */
export function generateApiKeySecret(): string {
  return randomBytes(SECRET_BYTES).toString('base64url')
}

/**
 * Joins the three parts into the string a caller presents.
 *
 * @param prefix - The deployment's key prefix.
 * @param keyId - The row id.
 * @param secret - The secret from {@link generateApiKeySecret}.
 * @returns The plaintext key, returned to its holder once and never stored.
 */
export function formatApiKey(prefix: string, keyId: string, secret: string): string {
  return `${prefix}${SEPARATOR}${keyId}${SEPARATOR}${secret}`
}

/**
 * Splits a presented key, or answers `null` for anything that is not exactly the grammar.
 *
 * Splits on the first two separators only: the prefix and a UUID contain none, and a secret may.
 * Never throws, so a malformed key is not distinguishable from a wrong one by an exception.
 *
 * @param raw - The header value as received. Anything but a string is malformed.
 * @param prefix - The deployment's key prefix.
 * @returns The two parts, or `null` when the value is not a well-formed key.
 */
export function parseApiKey(raw: unknown, prefix: string): ParsedApiKey | null {
  if (typeof raw !== 'string') return null
  const head = `${prefix}${SEPARATOR}`
  if (!raw.startsWith(head)) return null
  const rest = raw.slice(head.length)
  const keyId = rest.slice(0, 36)
  if (rest[36] !== SEPARATOR) return null
  const secret = rest.slice(37)
  if (!KEY_ID_PATTERN.test(keyId) || !SECRET_PATTERN.test(secret)) return null
  return { keyId, secret }
}

/**
 * Digest stored for a secret: lowercase hex HMAC-SHA-256 keyed with the pepper.
 *
 * Labels and scopes are deliberately not part of the input: they are mutable metadata, and a
 * digest that covered them would change when an operator edited either.
 *
 * @param secret - The secret half of a key.
 * @param pepper - The server-held pepper.
 * @returns 64 lowercase hex characters.
 */
export function apiKeyDigest(secret: string, pepper: string): string {
  return hmacSha256(secret, pepper)
}

/**
 * Compares two digests in constant time.
 *
 * `timingSafeEqual` throws on unequal lengths, so a stored value that is not a 32-byte digest —
 * a corrupted row — is mapped to a zero buffer and forced to a mismatch, which keeps the
 * comparison running and never lets a malformed row match anything, itself included.
 *
 * @param computed - The digest just computed from the presented secret.
 * @param stored - The digest on the row, or {@link API_KEY_DUMMY_DIGEST} when there was none.
 * @returns `true` only when both are well-formed and equal.
 */
export function digestsMatch(computed: string, stored: string): boolean {
  const wellFormed = DIGEST_HEX.test(computed) && DIGEST_HEX.test(stored)
  const left = Buffer.from(wellFormed ? computed : API_KEY_DUMMY_DIGEST, 'hex')
  const right = Buffer.from(wellFormed ? stored : API_KEY_DUMMY_DIGEST, 'hex')
  return timingSafeEqual(left, right) && wellFormed
}
