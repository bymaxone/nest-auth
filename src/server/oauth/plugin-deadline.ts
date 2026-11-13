/**
 * @fileoverview The time a provider plugin's network calls may take during an OAuth callback.
 *
 * @layer Service
 */

/** The deadline for a plugin's code exchange and profile fetch together, in milliseconds. */
export const OAUTH_PLUGIN_DEFAULT_TIMEOUT_MS = 10_000

/** The longest deadline a plugin may ask for, in milliseconds. */
export const OAUTH_PLUGIN_MAX_TIMEOUT_MS = 120_000

/**
 * The deadline for a plugin's calls: its own `timeoutMs` when that is a whole number of
 * milliseconds from 1 to {@link OAUTH_PLUGIN_MAX_TIMEOUT_MS}, otherwise the default.
 *
 * Anything else falls back instead of failing the callback, because a value that is zero, negative,
 * not finite or not a number would otherwise mean no deadline or an immediate one, and neither is
 * what a plugin that set it intended.
 *
 * @param plugin - The plugin, read for `timeoutMs`.
 * @returns The deadline in milliseconds.
 */
export function pluginDeadlineMs(plugin: { readonly timeoutMs?: unknown }): number {
  const { timeoutMs } = plugin
  return typeof timeoutMs === 'number' &&
    Number.isInteger(timeoutMs) &&
    timeoutMs >= 1 &&
    timeoutMs <= OAUTH_PLUGIN_MAX_TIMEOUT_MS
    ? timeoutMs
    : OAUTH_PLUGIN_DEFAULT_TIMEOUT_MS
}

/**
 * Runs the work and rejects when it has not settled within the deadline.
 *
 * The work is not cancelled, because a plugin's calls take no abort signal: the library stops
 * waiting for them. A plugin should bound its own requests too.
 *
 * @param work - The calls to bound.
 * @param ms - The deadline in milliseconds.
 * @returns What the work resolved to.
 * @throws {Error} When the deadline passes first.
 */
export async function withDeadline<T>(work: () => Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined
  const expiry = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      reject(new Error(`the plugin did not answer within ${ms} ms`))
    }, ms)
  })
  try {
    return await Promise.race([work(), expiry])
  } finally {
    clearTimeout(timer)
  }
}
