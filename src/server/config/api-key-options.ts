/**
 * @fileoverview Resolution and startup validation of the `apiKeys` option group.
 *
 * @layer Config
 */

import { DEFAULT_OPTIONS } from './default-options'
import { validateSecretStrength } from './secret-strength'
import { LIBRARY_READ_HEADERS } from '../constants/request-headers'
import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'

/** Letters, digits and `: . _ -`; bounded so a scope is a name and never a payload. */
const API_KEY_SCOPE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9:._-]{0,63}$/

/** Lowercase letters and digits, no underscore: the underscore separates the key's parts. */
const API_KEY_PREFIX_PATTERN = /^[a-z][a-z0-9]{1,15}$/

/** A lowercase header field name. */
const API_KEY_HEADER_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/

/**
 * Headers a key may not be read from: every one the library reads or derives a field from, so a
 * key never travels through a path built for something else.
 */
const API_KEY_FORBIDDEN_HEADERS: ReadonlySet<string> = new Set(LIBRARY_READ_HEADERS)

/**
 * Builds the resolved service-key group: the user's values over the defaults, field by field.
 *
 * A key the host set to `undefined` (a config object built from optional environment values)
 * must fall back to the default rather than erase it, which a plain spread would do.
 *
 * @param user - The `apiKeys` group as supplied, if any.
 * @returns The group with every field present.
 */
export function resolveApiKeys(
  user: BymaxAuthModuleOptions['apiKeys']
): Required<NonNullable<BymaxAuthModuleOptions['apiKeys']>> {
  const defaults = DEFAULT_OPTIONS.apiKeys
  return {
    enabled: user?.enabled ?? defaults.enabled,
    pepper: user?.pepper ?? defaults.pepper,
    scopes: user?.scopes ?? defaults.scopes,
    // Node lowercases incoming header names, so a mixed-case option would never match.
    header: typeof user?.header === 'string' ? user.header.toLowerCase() : defaults.header,
    prefix: user?.prefix ?? defaults.prefix,
    lastUsedFlushSeconds: user?.lastUsedFlushSeconds ?? defaults.lastUsedFlushSeconds,
    auditMode: user?.auditMode ?? defaults.auditMode
  }
}

/**
 * Validates the service-key group when the feature is enabled.
 *
 * Nothing is checked while the feature is off, so a host that never opts in is not asked for a
 * pepper. When it is on, every value that would otherwise fail late or fail silently is refused
 * here: a weak or shared pepper, an empty or malformed vocabulary, a header or prefix the
 * grammar cannot carry, and a flush interval or audit mode outside their documented range.
 *
 * @param userOptions - The options as supplied.
 * @throws {Error} Naming the first offending field.
 */
export function validateApiKeys(userOptions: BymaxAuthModuleOptions): void {
  const group = userOptions.apiKeys
  if (group?.enabled !== true) return

  validateApiKeyPepper(group.pepper, userOptions)
  validateApiKeyScopes(group.scopes)
  validateApiKeyTransport(group)
  validateApiKeyTuning(group)
}

/**
 * Requires the service-key pepper to be strong and distinct from every other key the module holds.
 *
 * @param pepper - The configured pepper.
 * @param userOptions - The options as supplied, for the keys it must not equal.
 * @throws {Error} When the pepper is weak or equals another key.
 */
function validateApiKeyPepper(pepper: string, userOptions: BymaxAuthModuleOptions): void {
  validateSecretStrength(pepper, 'apiKeys.pepper')
  // An absent `identifierKey` is `undefined`, which a validated string pepper never equals.
  // Stryker disable next-line ArrayDeclaration: a stand-in element in place of the empty fallback is a string no validated pepper (32+ characters of real entropy) can equal
  const retired = userOptions.jwt.previousSecrets ?? []
  // Stryker disable next-line ArrayDeclaration: a stand-in element in place of the empty fallback is a string no validated pepper can equal
  const mfaRetired = userOptions.mfa?.previousEncryptionKeys ?? []
  const mfaKeys = [userOptions.mfa?.encryptionKey, ...mfaRetired]
  const reused = new Set<unknown>([
    userOptions.jwt.secret,
    userOptions.identifierKey,
    ...retired,
    ...mfaKeys
  ])
  if (reused.has(pepper)) {
    throw new Error(
      `[BymaxAuthModule] apiKeys.pepper must not equal jwt.secret, a retired jwt secret, ` +
        `identifierKey or an MFA encryption key. A key shared across purposes is one leak away ` +
        `from all of them.`
    )
  }
}

/**
 * Requires the scope vocabulary to be a non-empty list of distinct, well-formed names.
 *
 * @param value - The configured `apiKeys.scopes`.
 * @throws {Error} Naming the offending entry.
 */
function validateApiKeyScopes(value: unknown): void {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(
      `[BymaxAuthModule] apiKeys.scopes must be a non-empty array: it is the closed vocabulary ` +
        `every route declaration and every issued key is checked against.`
    )
  }
  const seen = new Set<unknown>()
  for (const [index, scope] of value.entries()) {
    if (typeof scope !== 'string' || !API_KEY_SCOPE_PATTERN.test(scope)) {
      throw new Error(
        `[BymaxAuthModule] apiKeys.scopes[${index}] must be 1 to 64 characters of letters, ` +
          `digits and ':', '.', '_', '-', starting with a letter or digit.`
      )
    }
    if (seen.has(scope)) {
      throw new Error(`[BymaxAuthModule] apiKeys.scopes[${index}] repeats an earlier scope.`)
    }
    seen.add(scope)
  }
}

/**
 * Requires the header and prefix the key travels under to be ones the key grammar can carry.
 *
 * @param group - The `apiKeys` group as supplied.
 * @throws {Error} Naming the offending field.
 */
function validateApiKeyTransport(group: NonNullable<BymaxAuthModuleOptions['apiKeys']>): void {
  const { header, prefix } = group
  // Header names are case-insensitive, so the comparison is made on the lowercase form.
  const name = typeof header === 'string' ? header.toLowerCase() : header
  if (
    name !== undefined &&
    (typeof name !== 'string' ||
      !API_KEY_HEADER_PATTERN.test(name) ||
      API_KEY_FORBIDDEN_HEADERS.has(name))
  ) {
    throw new Error(
      `[BymaxAuthModule] apiKeys.header must be a header name other than a header the library ` +
        `reads or derives a field from (authorization, cookie, user-agent, origin, the ` +
        `forwarded-address headers and the like): a key read from one would travel through a ` +
        `path built for something else.`
    )
  }
  if (
    prefix !== undefined &&
    (typeof prefix !== 'string' || !API_KEY_PREFIX_PATTERN.test(prefix))
  ) {
    throw new Error(
      `[BymaxAuthModule] apiKeys.prefix must be 2 to 16 lowercase letters and digits, starting ` +
        `with a letter. An underscore is not allowed: it separates the parts of a key.`
    )
  }
}

/**
 * Requires the flush interval and the audit mode to be inside their documented range.
 *
 * @param group - The `apiKeys` group as supplied.
 * @throws {Error} Naming the offending field.
 */
function validateApiKeyTuning(group: NonNullable<BymaxAuthModuleOptions['apiKeys']>): void {
  const { lastUsedFlushSeconds, auditMode } = group
  if (
    lastUsedFlushSeconds !== undefined &&
    (!Number.isInteger(lastUsedFlushSeconds) ||
      lastUsedFlushSeconds < 1 ||
      lastUsedFlushSeconds > 3600)
  ) {
    throw new Error(
      `[BymaxAuthModule] apiKeys.lastUsedFlushSeconds must be an integer from 1 to 3600.`
    )
  }
  if (auditMode !== undefined && auditMode !== 'best-effort' && auditMode !== 'required') {
    throw new Error(`[BymaxAuthModule] apiKeys.auditMode must be 'best-effort' or 'required'.`)
  }
}
