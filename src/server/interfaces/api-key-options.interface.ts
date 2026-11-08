/**
 * @fileoverview The `apiKeys` group of the module options: scoped service keys for machine
 * callers.
 *
 * @layer Interface
 */

/** Options for scoped service API keys. See {@link BymaxAuthModuleOptions.apiKeys}. */
export interface ApiKeyOptions {
  /** Enables the feature. Default: `false`. */
  enabled?: boolean

  /**
   * The HMAC key every digest is computed under. Held to the same strength bar as
   * `jwt.secret`, and refused when it equals `jwt.secret`, `identifierKey` or a retired JWT
   * secret: a key shared across purposes is one leak away from all of them.
   *
   * Keep it in a secrets manager, apart from the database that stores the digests.
   */
  pepper: string

  /**
   * The closed vocabulary of scopes. `issue()` refuses any scope outside it, and the
   * bootstrap scan refuses a route that declares one. Letters, digits and `: . _ -`.
   */
  scopes: readonly string[]

  /** Header the key is read from, lowercase. Never the query string. Default: `x-api-key`. */
  header?: string

  /**
   * Prefix of every issued key: lowercase letters and digits, no underscore (the underscore
   * separates the parts). A literal prefix lets secret scanners find leaked keys.
   * Default: `bak`.
   */
  prefix?: string

  /**
   * How often, in seconds, the last-used timestamps coalesced in memory are flushed to the
   * store in one batch. With N instances a key is written up to N times per window, and a crash
   * loses at most one window of `lastUsedAt`. Default: `60`. Range: 1 to 3600.
   */
  lastUsedFlushSeconds?: number

  /**
   * What a failing audit hook does to the request it audits.
   *
   * - `'best-effort'`: the hook is fired without being awaited and its failure is logged. An
   *   audit outage never changes an answer.
   * - `'required'`: the hook is awaited, and if it throws the request is DENIED. For hosts whose
   *   audit row is a record they must have.
   *
   * Default: `'best-effort'`.
   */
  auditMode?: 'best-effort' | 'required'
}
