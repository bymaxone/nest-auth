/**
 * Maximum duration that `sleep` will wait, regardless of the `ms` argument.
 *
 * Prevents accidental event-loop starvation if a computed value is unexpectedly large.
 */
const MAX_SLEEP_MS = 10_000

/**
 * Returns a Promise that resolves after the specified number of milliseconds.
 *
 * Used for timing normalization in public-facing endpoints to prevent
 * side-channel attacks based on response-time differences. Anti-enumeration
 * endpoints (e.g. forgot-password, verify-email) should always wait a
 * constant minimum duration regardless of whether the operation succeeds or
 * fails, ensuring that an attacker cannot distinguish between "email exists"
 * and "email does not exist" by measuring latency.
 *
 * @remarks
 * The `ms` argument is clamped to `[0, 10_000]`. Negative values resolve
 * immediately (equivalent to 0 ms); values above 10 000 ms are capped.
 *
 * @example
 * ```typescript
 * const MIN_RESPONSE_MS = 300
 * const start = Date.now()
 * const user = await userRepo.findByEmail(dto.email).catch(() => null)
 * const elapsed = Date.now() - start
 * await sleep(Math.max(0, MIN_RESPONSE_MS - elapsed)) // always >= 300 ms total
 * ```
 *
 * @param ms - Desired duration in milliseconds (clamped to 0–10 000).
 *
 * @public
 * Exported from `@bymax-one/nest-auth` for use in consumer-implemented auth
 * controllers that need to apply the same constant-time anti-enumeration
 * pattern to their own endpoints.
 */
export function sleep(ms: number): Promise<void> {
  const clamped = Math.min(Math.max(0, ms), MAX_SLEEP_MS)
  return new Promise<void>((resolve) => {
    setTimeout(resolve, clamped)
  })
}
